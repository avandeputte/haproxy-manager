"""Pushing the shared configuration to the other nodes, and receiving it."""

from datetime import datetime, timezone
from flask import jsonify
from flask import request
from urllib.parse import urlsplit
import base64
import concurrent.futures
import hashlib
import os
import socket
import time
import uuid

from .base import (CERT_DIR, PEER_CONNECT_TIMEOUT, PEER_READ_TIMEOUT,
    PUSH_READ_TIMEOUT, _lock, _requests, app, log)
from .config import DEFAULT_CONFIG, _merge_defaults, load_config, save_config, shared_fingerprint, shared_view
from . import apply, auth, cluster, peering, webui

# --------------------------------------------------------------------------

def shared_payload(cfg):
    certs = {}
    if CERT_DIR.exists():
        for p in sorted(CERT_DIR.glob("*.pem")):
            certs[p.name] = base64.b64encode(p.read_bytes()).decode()
    return {
        "config": shared_view(cfg),
        "certs": certs,
        "source": socket.gethostname(),
        # Which revision of the shared configuration this is. The receiver
        # compares it with its own and refuses to move backwards.
        "rev": int(cfg["_meta"].get("shared_rev") or 0),
        "fp": cfg["_meta"].get("shared_fp") or "",
        "ts": time.time(),
    }


def enabled_peers(cfg):
    return [p for p in (cfg["local"]["sync"].get("peers") or []) if p.get("enabled", True) and p.get("url")]


def push_admin(cfg):
    """Send this node's administrator record to every other node.

    The record only, never the shared configuration: the login is node-local
    by design, and this is the one case where copying it is what was asked
    for. What travels is the PBKDF2 salt and digest, not a password -- the
    receiving node cannot recover the password from it any more than this one
    can.
    """
    peers = enabled_peers(cfg)
    if not peers:
        return []
    if _requests is None:
        return [{"ok": False, "name": p.get("name") or p.get("url"),
                 "error": "python3-requests is not installed on this node"}
                for p in peers]
    admin = dict(cfg["local"].get("admin") or {})
    out = []
    for peer in peers:
        url = (peer.get("url") or "").rstrip("/")
        try:
            r = _requests.post(url + "/api/admin/receive", json={"admin": admin},
                               headers={"X-API-Key": peer.get("api_key", "")},
                               timeout=(PEER_CONNECT_TIMEOUT, PEER_READ_TIMEOUT),
                               verify=bool(peer.get("verify_tls")))
            if r.status_code != 200:
                d = {}
                try:
                    d = r.json()
                except Exception:
                    pass
                out.append({"ok": False, "name": peer.get("name") or url,
                            "error": _key_verdict(d, url) if d.get("expected_fp")
                            else (d.get("error") or "HTTP %s" % r.status_code)})
            else:
                out.append({"ok": True, "name": peer.get("name") or url})
        except Exception as e:
            out.append({"ok": False, "name": peer.get("name") or url,
                        "error": peering.peer_error(e, url, PEER_READ_TIMEOUT)})
    return out


def _key_verdict(d, url):
    """Turn a rejection into the one sentence that identifies the cause."""
    host = d.get("hostname") or url
    if not d.get("header_seen"):
        return ("%s never received the X-API-Key header -- something between the nodes is "
                "stripping it. Check any reverse proxy in front of %s." % (host, url))
    ver = (" running %s" % d["version"]) if d.get("version") else ""
    sent, want = d.get("presented_fp"), d.get("expected_fp")
    if not want:
        return "%s has no API key set, so it refuses every sync." % host
    if sent == want:
        return ("%s says the key does not match, yet both fingerprints are %s. The key is being "
                "altered in transit -- check any proxy between them." % (host, sent))
    return ("%s%s expects a key fingerprinted %s, but this node sent %s. Open Cluster > This node "
            "on %s, press Show, and paste that key into this peer's entry."
            % (host, ver, want, sent, host))


def push_to_peer(peer, payload):
    """Send the shared configuration to one node."""
    url = (peer.get("url") or "").rstrip("/")
    try:
        r = _requests.post(url + "/api/sync/receive", json=payload,
                           headers={"X-API-Key": peer.get("api_key", "")},
                           timeout=(PEER_CONNECT_TIMEOUT, PUSH_READ_TIMEOUT),
                           verify=bool(peer.get("verify_tls")))
        if r.status_code != 200:
            out = {"ok": False, "name": peer.get("name") or url,
                   "error": "HTTP %s: %s" % (r.status_code, r.text[:200])}
            try:
                d = r.json()
                if d.get("expected_fp") or d.get("presented_fp"):
                    out["error"] = _key_verdict(d, url)
                    out["diagnosis"] = d
                elif d.get("error"):
                    out["error"] = d["error"]
            except Exception:
                pass
            return out
        return {"ok": True, "name": peer.get("name") or url, "peer": r.json()}
    except Exception as e:
        return {"ok": False, "name": peer.get("name") or url,
                "error": peering.peer_error(e, url, PUSH_READ_TIMEOUT)}


def mesh_for(cfg, target):
    """The membership list to hand one node: everyone except itself, plus us.

    Only this node knows its own API key, so it is the only one that can give
    the others a working way back to it.
    """
    me = (cfg["local"].get("node_url") or "").rstrip("/")
    out = []
    tgt_url = (target.get("url") or "").rstrip("/").lower()
    for p in cfg["local"]["sync"].get("peers") or []:
        if not p.get("url"):
            continue
        if p.get("id") == target.get("id") or (tgt_url and p["url"].rstrip("/").lower() == tgt_url):
            continue
        out.append({"id": p.get("id"), "name": p.get("name"), "url": p["url"],
                    "api_key": p.get("api_key", ""), "verify_tls": p.get("verify_tls"),
                    "enabled": p.get("enabled", True)})
    if me:
        out.append({"id": "self-" + hashlib.sha256(me.encode()).hexdigest()[:12],
                    "name": socket.gethostname(), "url": me,
                    "api_key": cfg["local"].get("api_key", ""),
                    "self": True,          # authoritative: it is this node's own key
                    "verify_tls": False, "enabled": True})
    return out


def sync_push(cfg, only=None, include_peers=True, force=False):
    """Push to every enabled peer (or just one), in parallel.

    The membership list travels with every push, not just an explicit one from
    the Cluster page: otherwise the everyday path -- press Apply on the active
    node with auto-sync on -- never tells the other nodes about each other.
    """
    if _requests is None:
        return {"ok": False, "error": "python3-requests is not installed on this node"}
    peers = enabled_peers(cfg)
    if only:
        peers = [p for p in (cfg["local"]["sync"].get("peers") or []) if p.get("id") == only]
        if not peers:
            return {"ok": False, "error": "no such peer"}
    if not peers:
        return {"ok": False, "error": "no peers configured (Cluster > Other nodes)"}

    base = shared_payload(cfg)
    if force:
        # Belt and braces: the revision has already been lifted above every
        # node's, so this only matters if one of them moved in between.
        base = dict(base, force=True)

    def send(p):
        payload = dict(base, peers=mesh_for(cfg, p)) if include_peers else base
        return push_to_peer(p, payload)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(peers))) as ex:
        results = list(ex.map(send, peers))
    failed = [r for r in results if not r["ok"]]
    for r in results:
        if r["ok"]:
            log.info("synced to %s", r["name"])
        else:
            log.warning("sync to %s failed: %s", r["name"], r.get("error"))
    # What every node holds has just changed, so the health collected before
    # this says nothing useful about it.
    cluster.invalidate()
    out = {"ok": not failed, "results": results,
           "error": "; ".join("%s: %s" % (r["name"], r["error"]) for r in failed) or None}
    if include_peers and not (cfg["local"].get("node_url") or "").strip():
        out["warning"] = ("This node has no URL set, so the other nodes were told about each "
                          "other but not about this node -- they cannot sync back to it, and it "
                          "will not appear in their cluster view. Set \"This node's URL\" under "
                          "Cluster > This node.")
    return out


def make_newest(cfg):
    """Put this node's configuration ahead of every other node's.

    What "overwrite the others" has to mean. A node that was edited while it
    was passive holds a higher revision than the node you are pushing from, and
    refusing that push is the whole point of the revision -- so forcing it
    through by ignoring the check would leave the cluster agreeing on content
    while disagreeing about who is newest, and the next round would undo it.

    Instead this node's revision is lifted above the highest any node reports,
    which makes the ordinary push legitimate and leaves every node on the same
    number afterwards. The content does not change, so the fingerprint does
    not either.
    """
    highest = int(cfg["_meta"].get("shared_rev") or 0)
    seen = []
    for peer in enabled_peers(cfg):
        url = (peer.get("url") or "").rstrip("/")
        try:
            r = _requests.get(url + "/api/status",
                              headers={"X-API-Key": peer.get("api_key", "")},
                              timeout=(PEER_CONNECT_TIMEOUT, PEER_READ_TIMEOUT),
                              verify=bool(peer.get("verify_tls")))
            if r.status_code == 200:
                rev = int(r.json().get("config_rev") or 0)
                seen.append((peer.get("name") or url, rev))
                highest = max(highest, rev)
        except Exception as e:
            # A node that cannot be asked cannot be outranked either. Go above
            # what is known and say so: it is still refused if it turns out to
            # be ahead, rather than being overwritten by a smaller number.
            log.warning("overwriting: %s did not report its revision (%s)",
                        peer.get("name") or url, e)
    with _lock:
        cur = load_config()
        cur["_meta"]["shared_fp"] = shared_fingerprint(cur)
        cur["_meta"]["shared_rev"] = highest + 1
        save_config(cur)
    log.info("overwriting: this node moves to revision %d, above %s",
             highest + 1, ", ".join("%s at %d" % x for x in seen) or "nothing reported")
    return load_config()


def reconcile(cfg, nodes):
    """Push to any node that is demonstrably behind this one.

    Called from the watchdog with the health it has just collected, so no
    extra queries and no queue of pending pushes to lose. A push that failed
    is not remembered; the next round observes the same disagreement and tries
    again, which is what makes it heal rather than merely retry.

    Only from the node that holds the virtual IP, so a cluster does not have
    every node pushing at once. Standalone nodes have nowhere to push.
    """
    if _requests is None or not enabled_peers(cfg):
        return []
    # The same setting that pushes after an Apply. Someone who keeps their
    # nodes in step by hand does not want a background thread deciding to.
    if not cfg["local"]["sync"].get("auto_sync"):
        return []
    mine = int(cfg["_meta"].get("shared_rev") or 0)
    role, _held = auth.node_role(cfg)
    if role == "passive":
        return []
    by_url = {(p.get("url") or "").rstrip("/"): p for p in enabled_peers(cfg)}
    behind = []
    for n in nodes:
        if n.get("self") or not n.get("reachable"):
            continue
        peer = by_url.get((n.get("url") or "").rstrip("/"))
        # Only when the node says a revision at all: an older release does not
        # report one, and pushing at it every round would be a loop.
        if peer and n.get("config_fp") and int(n.get("config_rev") or 0) < mine:
            behind.append((peer, n))
    out = []
    for peer, n in behind:
        log.info("reconciling %s: it holds revision %s, this node holds %d",
                 n.get("name"), n.get("config_rev"), mine)
        r = push_to_peer(peer, dict(shared_payload(cfg), peers=mesh_for(cfg, peer)))
        out.append(r)
        if not r.get("ok"):
            log.warning("reconciling %s failed: %s", n.get("name"), r.get("error"))
    return out


def catch_up(cfg):
    """At startup, take the configuration from a peer that has a newer one.

    A node that has been reinstalled, or was off while the cluster moved on,
    would otherwise wait to be pushed to -- and if it is the node that holds
    the virtual IP, nothing pushes to it at all. Asking is cheap and happens
    once.
    """
    peers = enabled_peers(cfg)
    if _requests is None or not peers or not cfg["local"]["sync"].get("auto_sync"):
        return None
    mine = int(cfg["_meta"].get("shared_rev") or 0)
    best, best_rev = None, mine
    for peer in peers:
        url = (peer.get("url") or "").rstrip("/")
        try:
            r = _requests.get(url + "/api/status",
                              headers={"X-API-Key": peer.get("api_key", "")},
                              timeout=(PEER_CONNECT_TIMEOUT, PEER_READ_TIMEOUT),
                              verify=bool(peer.get("verify_tls")))
            if r.status_code != 200:
                continue
            st = r.json()
        except Exception as e:
            log.info("catching up: %s did not answer (%s)", peer.get("name"), e)
            continue
        rev = int(st.get("config_rev") or 0)
        if st.get("config_fp") and rev > best_rev:
            best, best_rev = peer, rev
    if not best:
        return None
    log.info("catching up: %s holds revision %d and this node holds %d",
             best.get("name"), best_rev, mine)
    try:
        url = (best.get("url") or "").rstrip("/")
        r = _requests.get(url + "/api/sync/pull",
                          headers={"X-API-Key": best.get("api_key", "")},
                          timeout=(PEER_CONNECT_TIMEOUT, PUSH_READ_TIMEOUT),
                          verify=bool(best.get("verify_tls")))
        if r.status_code != 200:
            log.warning("catching up from %s failed: HTTP %s", best.get("name"), r.status_code)
            return None
        data = r.json()
    except Exception as e:
        log.warning("catching up from %s failed: %s", best.get("name"),
                    peering.peer_error(e, url, PUSH_READ_TIMEOUT))
        return None
    # _receive_locked answers with a Flask response, because its usual caller
    # is a request. Here there is none, so one is supplied.
    with app.test_request_context("/api/sync/receive"):
        with _lock:
            res = _receive_locked(load_config(), data, data.get("config") or {},
                                  source=best.get("name") or url)
        body = res[0] if isinstance(res, tuple) else res
        out = body.get_json()
    if out.get("ok"):
        log.info("caught up to revision %d from %s", best_rev, best.get("name"))
    else:
        log.warning("catching up from %s was refused: %s",
                    best.get("name"), out.get("error"))
    return out


@app.post("/api/sync/push")
def api_sync_push():
    """Push the shared configuration to the other nodes.

    With "overwrite", this node's configuration is first made the newest, so a
    node that was edited while it was passive takes it instead of refusing it.
    That is the only way to discard a change made on the wrong node.
    """
    body = request.get_json(silent=True) or {}
    cfg = load_config()
    if body.get("overwrite"):
        if _requests is None:
            return jsonify({"ok": False,
                            "error": "python3-requests is not installed on this node"})
        cfg = make_newest(cfg)
    return jsonify(sync_push(cfg, only=body.get("peer"),
                             include_peers=bool(body.get("include_peers", True)),
                             force=bool(body.get("overwrite"))))

@app.get("/api/sync/pull")
def api_sync_pull():
    """Hand the shared configuration to a node that is joining.

    A read, so a passive node can still serve it. Asking it to push would be
    refused by the read-only rule, which left a joining node with nothing.
    """
    cfg = load_config()
    caller = (request.args.get("node_url") or "").strip().rstrip("/")
    payload = shared_payload(cfg)
    payload["peers"] = mesh_for(cfg, {"id": None, "url": caller})
    payload["source"] = socket.gethostname()
    return jsonify(payload)


@app.post("/api/sync/receive")
def api_sync_receive():
    cfg = load_config()
    key = cfg["local"].get("api_key", "")
    if not key:
        return jsonify({"ok": False, "error":
                        "%s has no API key set, so it refuses every sync. Set one under "
                        "Cluster > This node there." % socket.gethostname()}), 403
    presented = request.headers.get("X-API-Key")
    if not auth.key_matches(key, presented):
        return jsonify({"ok": False, "error":
                        "%s rejected the API key." % socket.gethostname(),
                        "hostname": socket.gethostname(),
                        "header_seen": presented is not None,
                        "presented_fp": auth.key_fingerprint(presented),
                        "expected_fp": auth.key_fingerprint(key)}), 401
    data = request.get_json(force=True) or {}
    conf = data.get("config") or {}
    with _lock:
        return _receive_locked(cfg, data, conf)


def _receive_locked(cfg, data, conf, source=None):
    cfg = load_config()          # re-read inside the lock: it may have moved
    # Named for the log: a push says who connected, a catch-up says who was asked.
    source = source or request.remote_addr

    # A node that was isolated, edited and then reconnected would otherwise
    # push its old configuration over the current one and nobody would know.
    # It is refused unless the caller says to overwrite deliberately.
    mine = int(cfg["_meta"].get("shared_rev") or 0)
    theirs = int(data.get("rev") or 0)
    if theirs and theirs < mine and not data.get("force"):
        log.warning("refused a configuration from %s: revision %d is older than %d",
                    source, theirs, mine)
        return jsonify({
            "ok": False, "node": socket.gethostname(), "stale": True,
            "their_rev": theirs, "my_rev": mine,
            "error": "%s holds revision %d and was offered revision %d, which is "
                     "older -- so %s was changed after the node pushing this. "
                     "Apply from whichever node is right; to discard what is on "
                     "%s, use Overwrite on the Cluster page."
                     % (socket.gethostname(), mine, theirs, socket.gethostname(),
                        socket.gethostname())}), 409

    # A straight replacement. This node's own objects are not in these sections
    # -- they live under local -- so there is nothing to rescue afterwards.
    if "haproxy" in conf:
        cfg["haproxy"] = _merge_defaults(conf["haproxy"], DEFAULT_CONFIG["haproxy"])
    if "acme" in conf:
        cfg["acme"] = _merge_defaults(conf["acme"], DEFAULT_CONFIG["acme"])
    if isinstance(conf.get("access"), dict):
        # The users and groups a published service asks visitors for. They
        # travel with the services that check them, or a failover would meet
        # people with a password no node here has heard of.
        cfg["access"] = _merge_defaults(conf["access"], DEFAULT_CONFIG["access"])
    if isinstance(conf.get("cluster"), dict):
        # Cluster-wide VRRP settings. Anything per node -- interface, priority,
        # unicast addresses -- lives in local and is deliberately untouched.
        cfg["cluster"] = _merge_defaults(conf["cluster"], DEFAULT_CONFIG["cluster"])
    if isinstance(conf.get("notify"), dict):
        # Configured once and shared: each node then alerts about its own
        # troubles through the same destinations.
        cfg["notify"] = _merge_defaults(conf["notify"], DEFAULT_CONFIG["notify"])

    # An optional membership list: every other node as seen by the sender.
    mesh = data.get("peers")
    if isinstance(mesh, list) and mesh:
        mine = (cfg["local"].get("node_url") or "").rstrip("/").lower()
        my_key = cfg["local"].get("api_key", "")
        existing = list(cfg["local"]["sync"].get("peers") or [])
        kept = []
        for p in mesh:
            if not isinstance(p, dict) or not p.get("url"):
                continue
            # Never list ourselves: by URL, or by our own key when no URL is set.
            if mine and p["url"].rstrip("/").lower() == mine:
                continue
            if my_key and p.get("api_key") == my_key:
                continue
            # A key corrected here must survive the next inbound list. The
            # sender speaks for itself, so its own entry wins; for every other
            # node the incoming key only fills a gap.
            url_l = p["url"].rstrip("/").lower()
            local = next((q for q in existing if (q.get("url") or "").rstrip("/").lower() == url_l), None)
            key = (p.get("api_key") or "").strip()
            if local and not p.get("self"):
                key = (local.get("api_key") or "").strip() or key
            kept.append({"id": (local or {}).get("id") or p.get("id") or str(uuid.uuid4()),
                         "name": p.get("name") or urlsplit(p["url"]).hostname or "peer",
                         "url": p["url"].rstrip("/"), "api_key": key,
                         "verify_tls": bool(p.get("verify_tls")),
                         "enabled": bool(p.get("enabled", True))})
        if kept:
            cfg["local"]["sync"]["peers"] = kept

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    for name, b64 in (data.get("certs") or {}).items():
        if "/" in name or ".." in name or not name.endswith(".pem"):
            continue
        p = CERT_DIR / name
        p.write_bytes(base64.b64decode(b64))
        os.chmod(p, 0o600)
    # The listener this node's UI hangs off may have been replaced wholesale by
    # the incoming configuration. Rebuilding is idempotent and re-attaches it.
    if (cfg["local"].get("web_ui") or {}).get("enabled"):
        try:
            webui.rebuild_webui(cfg)
        except Exception:
            pass
    # Take the sender's place in the sequence rather than counting this as a
    # change of our own, so the sender and this node end up on the same
    # revision.
    cfg["_meta"]["shared_fp"] = shared_fingerprint(cfg)
    cfg["_meta"]["shared_rev"] = theirs
    # Every node hashes the same thing -- the view that was sent -- so taking a
    # configuration and then not matching it means something node-specific is
    # sitting inside the shared sections without being marked as node-local.
    # That is the one failure this whole mechanism cannot see past, so it is
    # recorded and reported rather than left in a log nobody reads: the nodes
    # would otherwise be shown as disagreeing forever with no reason given.
    if data.get("fp") and cfg["_meta"]["shared_fp"] != data["fp"]:
        cfg["_meta"]["config_leak"] = {
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": source, "mine": cfg["_meta"]["shared_fp"], "theirs": data["fp"]}
        log.warning("took the configuration from %s but computed a different "
                    "fingerprint (%s here, %s there): something node-specific is "
                    "inside the shared configuration", source,
                    cfg["_meta"]["shared_fp"], data["fp"])
    else:
        cfg["_meta"].pop("config_leak", None)
    save_config(cfg)
    cluster.invalidate()
    log.info("received configuration from %s at revision %d",
             source, cfg["_meta"]["shared_rev"])
    res = apply.do_apply(cfg, allow_push=False)  # never re-push: avoids sync loops
    return jsonify({"ok": res.get("ok", False), "node": socket.gethostname(), "applied": res})
