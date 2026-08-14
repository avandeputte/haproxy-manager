"""The version check and the one-click update."""

from datetime import datetime
from datetime import timezone
from flask import jsonify, request
from pathlib import Path
import base64
import json
import os
import re
import shutil
import time
import urllib.parse
import urllib.request

from .base import (DATA_DIR, INSTALL_URL, PEER_CONNECT_TIMEOUT, PEER_READ_TIMEOUT,
    UPDATE_CHECK_HOURS, UPDATE_REF, UPDATE_REPO, VERSION, VERSION_URL, _lock,
    _requests, app, log)
from .config import load_config, save_config
from .util import run
from . import notify, peering, sync

# --------------------------------------------------------------------------

UPDATE_LOG = DATA_DIR / "update.log"
UPDATE_UNIT = "haproxy-manager-update"


def version_tuple(v):
    parts = re.split(r"[.\-+]", (v or "").strip().lstrip("vV"))
    out = []
    for p in parts[:4]:
        out.append(int(p) if p.isdigit() else 0)
    return tuple(out + [0] * (4 - len(out)))


def is_newer(candidate, current):
    return version_tuple(candidate) > version_tuple(current)


def _read_version_url(url):
    headers = {"User-Agent": "haproxy-manager/" + VERSION,
               "Cache-Control": "no-cache", "Pragma": "no-cache"}
    if "api.github.com" in url:
        headers["Accept"] = "application/vnd.github.raw"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=15) as r:
        body = r.read(4096).decode("utf-8", "replace").strip()
    if body.startswith("{"):                     # API answered with JSON metadata
        body = base64.b64decode(json.loads(body).get("content", "")).decode("utf-8", "replace").strip()
    return body


def fetch_latest_version():
    """The published version.

    Ask the GitHub API first: raw.githubusercontent.com is behind a CDN that
    serves a file for up to five minutes after it changes, so a check straight
    after a release reports the previous version. The API is not cached that
    way. Fall back to raw if the API is unreachable or rate limited.
    """
    if os.environ.get("HAM_VERSION_URL"):
        return _read_version_url(VERSION_URL)      # explicitly pointed somewhere
    urls = ["https://api.github.com/repos/%s/contents/VERSION?ref=%s" % (UPDATE_REPO, UPDATE_REF),
            VERSION_URL]
    last = None
    for url in urls:
        try:
            body = _read_version_url(url)
            if re.match(r"^v?\d+(\.\d+)*$", body):
                return body
            last = ValueError("unexpected content at %s: %r" % (url, body[:40]))
        except Exception as e:
            last = e
    raise last or ValueError("no version source answered")


def check_for_update():
    """Ask GitHub for the published version and remember the answer."""
    result = {"checked": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "latest": "", "available": False, "error": ""}
    try:
        latest = fetch_latest_version()
        if not re.match(r"^v?\d+(\.\d+)*$", latest):
            raise ValueError("unexpected content at VERSION: %r" % latest[:40])
        result["latest"] = latest
        result["available"] = is_newer(latest, VERSION)
    except Exception as e:
        result["error"] = str(e)
    with _lock:
        # Always re-read inside the lock. The fetch above can take tens of
        # seconds, and saving a configuration loaded before it would quietly
        # revert anything changed in the meantime.
        cur = load_config()
        cur["_meta"]["update"] = result      # _meta: not hashed, not synced
        save_config(cur)
    if result["available"]:
        notify.notify_transition("update:" + result["latest"], "available", "updates",
                          "haproxy-manager %s is available" % result["latest"],
                          "This node runs %s. Version %s has been published.\n\n"
                          "Update from Settings > Updates."
                          % (VERSION, result["latest"]), "info", cur)
    return result


def update_supported():
    """One-click update only makes sense for the systemd install."""
    if not Path("/run/systemd/system").exists():
        return False, "this node runs in a container -- pull a new image instead"
    if not Path("/etc/systemd/system/haproxy-manager.service").exists():
        return False, "no haproxy-manager.service was found; this is not an installer-managed node"
    return True, ""


@app.get("/api/version")
def api_version():
    cfg = load_config()
    info = cfg["_meta"].get("update") or {}
    ok, why = update_supported()
    return jsonify({
        "version": VERSION,
        "latest": info.get("latest", ""),
        # Recomputed, not read back: after an update the stored flag is stale
        # until the next daily check.
        "available": bool(info.get("latest")) and is_newer(info["latest"], VERSION),
        "checked": info.get("checked", ""),
        "error": info.get("error", ""),
        "repo": UPDATE_REPO, "ref": UPDATE_REF,
        "can_update": ok, "cannot_update_reason": why,
        "updating": _update_running(),
        # How many other nodes there are, so the page can offer to update them
        # in the same go rather than making someone visit each one.
        "peers": len(sync.enabled_peers(cfg)),
    })


@app.post("/api/version/check")
def api_version_check():
    info = check_for_update()
    return jsonify(dict(info, version=VERSION))


def _update_running():
    rc, out = run(["systemctl", "is-active", UPDATE_UNIT])
    return out.strip().startswith("activ")


def update_peers(cfg):
    """Ask every other node to update itself.

    Sent before this node starts its own: the update restarts this service, so
    a node that has already begun cannot be the one telling the others. The
    other nodes are told, and then this one goes.

    Each node runs the same installer against the same source, so there is
    nothing to hand over -- only the instruction. A node that does not answer
    is named and left alone rather than retried: an update is a thing a person
    started, and they should be the one to decide what to do about the node
    that missed it.
    """
    peers = sync.enabled_peers(cfg)
    if not peers:
        return []
    if _requests is None:
        return [{"ok": False, "name": p.get("name") or p.get("url"),
                 "error": "python3-requests is not installed on this node"}
                for p in peers]
    out = []
    for peer in peers:
        url = (peer.get("url") or "").rstrip("/")
        name = peer.get("name") or url
        try:
            r = _requests.post(url + "/api/update", json={},
                               headers={"X-API-Key": peer.get("api_key", "")},
                               timeout=(PEER_CONNECT_TIMEOUT, PEER_READ_TIMEOUT),
                               verify=bool(peer.get("verify_tls")))
            body = {}
            try:
                body = r.json()
            except Exception:
                pass
            if r.status_code == 200 and body.get("ok"):
                out.append({"ok": True, "name": name})
                log.info("update started on %s", name)
            else:
                out.append({"ok": False, "name": name,
                            "error": body.get("error") or "HTTP %s" % r.status_code})
                log.warning("update not started on %s: %s", name, out[-1]["error"])
        except Exception as e:
            out.append({"ok": False, "name": name,
                        "error": peering.peer_error(e, url, PEER_READ_TIMEOUT)})
            log.warning("update not started on %s: %s", name, out[-1]["error"])
    return out


@app.post("/api/update")
def api_update():
    ok, why = update_supported()
    if not ok:
        return jsonify({"ok": False, "error": why}), 400
    if _update_running():
        return jsonify({"ok": False, "error": "an update is already running"}), 409

    # The other nodes first, while this one is still running to ask them.
    peers = update_peers(load_config()) if (request.get_json(silent=True) or {}).get("peers") else None

    url = INSTALL_URL
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:                                    # keep the log from growing forever
        if UPDATE_LOG.stat().st_size > 256 * 1024:
            UPDATE_LOG.write_text(UPDATE_LOG.read_text()[-64 * 1024:])
    except OSError:
        pass
    with open(UPDATE_LOG, "a") as f:
        f.write("\n=== update started %s (from %s) ===\n"
                % (datetime.now(timezone.utc).isoformat(timespec="seconds"), url))

    # systemd-run puts the updater in its own unit. Running it as a child of
    # this service would kill it halfway: restarting haproxy-manager.service
    # takes down everything in that service's cgroup, the updater included.
    shell = "curl -fsSL %s | bash -s -- --update --yes >>%s 2>&1" % (url, UPDATE_LOG)
    if shutil.which("systemd-run"):
        cmd = ["systemd-run", "--unit=" + UPDATE_UNIT, "--collect", "--quiet",
               "/bin/sh", "-c", shell]
    else:
        cmd = ["setsid", "/bin/sh", "-c", shell]
    rc, out = run(cmd, timeout=30)
    if rc != 0:
        log.error("could not start the updater: %s", out)
        return jsonify({"ok": False, "error": "could not start the updater: %s" % out,
                        "nodes": peers}), 500
    log.warning("update started from %s -- this service will restart", url)
    body = {"ok": True,
            "note": "The update is running. This service restarts when it finishes."}
    if peers is not None:
        body["nodes"] = peers
        started = [p["name"] for p in peers if p["ok"]]
        if started:
            body["note"] = ("The update is running here and on %s. Each service restarts "
                            "when its own finishes; the Cluster page shows the version "
                            "each node ends up on." % ", ".join(started))
    return jsonify(body)


@app.get("/api/update/log")
def api_update_log():
    try:
        text = UPDATE_LOG.read_text()[-20000:]
    except OSError:
        text = ""
    return jsonify({"ok": True, "running": _update_running(), "version": VERSION, "log": text})


def _update_loop():
    """Check GitHub once a day."""
    time.sleep(30)                      # let the service settle before the first check
    while True:
        try:
            cfg = load_config()
            last = (cfg["_meta"].get("update") or {}).get("checked") or ""
            due = True
            if last:
                try:
                    age = datetime.now(timezone.utc) - datetime.fromisoformat(last)
                    due = age.total_seconds() >= UPDATE_CHECK_HOURS * 3600
                except ValueError:
                    due = True
            if due:
                check_for_update()
        except Exception:
            # Survive anything, but say so: a check that dies quietly is
            # discovered as a node that stopped noticing new versions.
            log.exception("the daily update check failed; it tries again in an hour")
        time.sleep(3600)


# --------------------------------------------------------------------------
# publish wizard: one URL + one target -> every object needed to serve it
