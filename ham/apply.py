"""Render, validate, write, reload."""

from flask import jsonify
from flask import request
from pathlib import Path
import copy
import os
import re
import shutil
import socket
import tempfile

from .base import (ACME_SH, CERT_DIR, HAPROXY_CFG, KEEPALIVED_CFG, VERSION, _lock, 
    _requests, app, log)
from .config import CLUSTER_KEYS, config_hash, load_config, save_config
from .util import _by_id, cert_details, cert_path, parse_domains, run
from .validate import check_setting_types
from . import acme, auth, haproxy, keepalived, notify, sync, updates, vrrp, watchdog

# --------------------------------------------------------------------------

def _selfsigned_placeholder(path, cn):
    """Create a throwaway self-signed cert so haproxy can start before ACME runs."""
    with tempfile.TemporaryDirectory() as td:
        crt, key = Path(td) / "c.pem", Path(td) / "k.pem"
        rc, _ = run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
            "-subj", "/CN=%s" % (cn or "placeholder"), "-keyout", str(key), "-out", str(crt),
        ])
        if rc == 0:
            path.write_text(crt.read_text() + key.read_text())
            os.chmod(path, 0o600)
            return True
    return False


def ensure_cert_files(cfg):
    made = []
    certs = _by_id(cfg["acme"]["certificates"])
    for fe in cfg["haproxy"]["frontends"]:
        if not fe.get("ssl_enabled"):
            continue
        for cid in fe.get("certificates") or []:
            c = certs.get(cid)
            if not c:
                continue
            p = cert_path(c)
            if not p.exists():
                CERT_DIR.mkdir(parents=True, exist_ok=True)
                doms = parse_domains(c)
                if _selfsigned_placeholder(p, doms[0] if doms else c["name"]):
                    made.append(p.name)
    return made


def node_interfaces():
    """Interface names on this node, with their addresses and link state."""
    out_ifaces = {}
    rc, out = run(["ip", "-o", "link"])
    if rc == 0:
        for line in out.splitlines():
            m = re.match(r"\d+:\s+([^:@]+)[:@]", line)
            if m:
                name = m.group(1).strip()
                out_ifaces[name] = {"name": name, "addresses": [],
                                    "up": " state UP " in line or "LOWER_UP" in line}
    rc, out = run(["ip", "-o", "addr"])
    if rc == 0:
        for line in out.splitlines():
            m = re.match(r"\d+:\s+(\S+)\s+inet6?\s+(\S+)", line)
            if m and m.group(1) in out_ifaces:
                out_ifaces[m.group(1)]["addresses"].append(m.group(2))
    # Interfaces that actually carry an address first: a node is full of tunnel
    # stubs (gre0, sit0, ip_vti0) that are never the answer.
    return sorted(out_ifaces.values(),
                  key=lambda i: (i["name"] == "lo", not i["addresses"], not i["up"], i["name"]))


def _keepalived_hint(output, k):
    """Turn keepalived's own complaint into the thing to actually go fix."""
    text = (output or "").lower()
    m = re.search(r"interface (\S+) .*?doesn't exist", output or "", re.I)
    if m or "doesn't exist" in text:
        ifaces = [i for i in node_interfaces() if i["name"] != "lo"]
        names = [i["name"] for i in ifaces if i["addresses"]] or [i["name"] for i in ifaces]
        return ("Interface \"%s\" does not exist on this node. Interfaces here: %s. "
                "The interface is node-local -- set it separately on each node."
                % (k.get("interface", ""), ", ".join(names) or "none found"))
    if "script" in text and "security" in text:
        return "Keepalived refused the tracking script; see the output below."
    return "See the keepalived output below."


@app.get("/api/keepalived/status")
def api_keepalived_status():
    """Why this node does or does not hold the virtual IP."""
    cfg = load_config()
    k = cfg["local"]["keepalived"]
    cl = cfg["cluster"]
    ifaces = node_interfaces()
    names = [i["name"] for i in ifaces]
    configured = k.get("interface", "")

    vips = [v.strip().split("/")[0] for v in (cl.get("vips") or "").splitlines() if v.strip()]
    held = []
    rc, out = run(["ip", "-o", "addr"])
    if rc == 0:
        held = [v for v in vips if re.search(r"\binet6? %s/" % re.escape(v), out)]

    rc, svc = run(["systemctl", "is-active", "keepalived"])
    service = (svc.splitlines() or ["unknown"])[0]

    # Validate what Apply would write right now -- this is what names the fault.
    validation = {"ran": False, "ok": None, "output": ""}
    if vrrp.keepalived_wanted(cfg):
        fd, staging = tempfile.mkstemp(suffix=".conf")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(keepalived.render_keepalived(cfg))
            vrc, vout = run(["keepalived", "-t", "-f", staging], timeout=20)
            validation = {"ran": vrc != 127, "ok": vrc == 0, "output": vout[-4000:]}
        finally:
            if os.path.exists(staging):
                os.unlink(staging)

    journal = ""
    if shutil.which("journalctl"):
        lrc, lout = run(["journalctl", "-u", "keepalived", "-n", "25", "--no-pager"], timeout=20)
        if lrc == 0:
            journal = lout[-6000:]

    state = ""
    m = re.findall(r"Entering (\w+) STATE", journal)
    if m:
        state = m[-1]

    return jsonify({
        "hostname": socket.gethostname(),
        "enabled": vrrp.keepalived_wanted(cfg),
        "service": service if vrrp.keepalived_wanted(cfg) else "disabled",
        "config_present": KEEPALIVED_CFG.exists(),
        "config_path": str(KEEPALIVED_CFG),
        "interface": configured,
        "interface_exists": configured in names,
        "interfaces": ifaces,
        "vrid": cl.get("vrid"), "priority": k.get("priority"), "state_setting": cl.get("state"),
        "unicast_src": k.get("unicast_src", ""),
        "unicast_peer": [x for x in (k.get("unicast_peer") or "").split() if x],
        "vips": vips, "vip_held": held,
        "vrrp_state": state,
        "validation": validation,
        "log": journal,
    })


def check_rendered(cfg):
    """Run haproxy -c and keepalived -t over what this configuration renders to.

    Returns (ok, message). Used before saving settings, so a directive that
    cannot work is refused at the point it is typed rather than being stored
    and then blocking every Apply.
    """
    problems = []
    fd, staging = tempfile.mkstemp(suffix=".cfg")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(haproxy.render_haproxy(cfg))
        rc, out = run(["haproxy", "-c", "-f", staging], timeout=30)
        if rc not in (0, 127):
            problems.append("HAProxy rejected it:\n" + out.strip())
    except Exception as e:
        problems.append("could not render haproxy.cfg: %s" % e)
    finally:
        if os.path.exists(staging):
            os.unlink(staging)

    if vrrp.keepalived_wanted(cfg):
        fd, kstaging = tempfile.mkstemp(suffix=".conf")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(keepalived.render_keepalived(cfg))
            rc, out = run(["keepalived", "-t", "-f", kstaging], timeout=30)
            if rc not in (0, 127):
                problems.append("Keepalived rejected it:\n" + out.strip())
        except Exception as e:
            problems.append("could not render keepalived.conf: %s" % e)
        finally:
            if os.path.exists(kstaging):
                os.unlink(kstaging)

    if problems:
        return False, "\n\n".join(problems)
    return True, "haproxy -c accepts it" + (" and keepalived -t accepts it" if vrrp.keepalived_wanted(cfg) else "")


def draft_with(section, settings, cluster=False):
    """This configuration as it would be with those settings in place."""
    draft = copy.deepcopy(load_config())
    if cluster:
        draft["cluster"].update({k: v for k, v in settings.items() if k in CLUSTER_KEYS})
    else:
        draft[section]["settings"].update(settings)
    return draft


@app.post("/api/validate")
def api_validate():
    """Check settings without saving them."""
    body = request.get_json(force=True, silent=True) or {}
    section = body.get("section") or "haproxy"
    settings = body.get("settings") or {}
    if section == "cluster":
        draft = draft_with(None, settings, cluster=True)
    elif section in ("haproxy", "acme"):
        bad = check_setting_types(section, settings)
        if bad:                      # the same rules the save applies, so
            return jsonify({"ok": False, "message": bad})   # Validate cannot
        draft = draft_with(section, settings)               # pass what save rejects
    else:
        return jsonify({"ok": False, "error": "unknown section"}), 400
    ok, message = check_rendered(draft)
    return jsonify({"ok": ok, "message": message})


def do_apply(cfg=None, allow_push=True):
    with _lock:
        cfg = cfg or load_config()
        result = {"ok": False, "steps": []}

        placeholders = ensure_cert_files(cfg)
        if placeholders:
            result["steps"].append("created placeholder certificates: " + ", ".join(placeholders))

        text = haproxy.render_haproxy(cfg)
        fd, staging = tempfile.mkstemp(suffix=".cfg")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        rc, out = run(["haproxy", "-c", "-f", staging])
        result["haproxy_check"] = out
        if rc == 127:
            result["steps"].append("haproxy binary not found -- validation skipped")
        elif rc != 0:
            os.unlink(staging)
            result["error"] = "HAProxy configuration failed validation. Nothing was changed."
            log.error("apply refused: haproxy -c rejected the rendered configuration: %s",
                      out.strip()[-400:])
            notify.notify("apply", "Apply was refused on this node",
                   "The generated HAProxy configuration did not validate, so nothing was "
                   "changed and the running configuration is untouched.\n\n%s"
                   % watchdog._why_rejected(out), "error", cfg)
            return result

        HAPROXY_CFG.parent.mkdir(parents=True, exist_ok=True)
        if HAPROXY_CFG.exists():
            shutil.copy2(HAPROXY_CFG, str(HAPROXY_CFG) + ".bak")
        shutil.move(staging, HAPROXY_CFG)
        os.chmod(HAPROXY_CFG, 0o644)
        rc, out = run(["systemctl", "reload-or-restart", "haproxy"])
        result["steps"].append("haproxy reload: " + ("ok" if rc == 0 else out))
        if rc == 0:
            log.info("applied: haproxy.cfg written and reloaded")
        else:
            log.error("applied haproxy.cfg but the reload failed: %s", out.strip()[:300])
            notify.notify("apply", "HAProxy did not reload on this node",
                   "The new configuration was written and validated, but HAProxy did not "
                   "reload, so it is still running the previous one.\n\n%s"
                   % out.strip()[:400], "error", cfg)

        k = cfg["local"]["keepalived"]
        if vrrp.keepalived_wanted(cfg):
            if vrrp.derive_unicast(cfg):
                result["steps"].append(
                    "unicast peers refreshed from the node list: %s"
                    % ((k.get("unicast_peer") or "").replace("\n", ", ") or "none -- using multicast"))
            ktext = keepalived.render_keepalived(cfg)
            fd, kstaging = tempfile.mkstemp(suffix=".conf")
            with os.fdopen(fd, "w") as f:
                f.write(ktext)
            rc, out = run(["keepalived", "-t", "-f", kstaging])
            if rc not in (0, 127):
                os.unlink(kstaging)
                # Loud, not a step line: keepalived.conf is left untouched here,
                # so the node keeps whatever it had -- or never starts at all,
                # and every node sits passive with no VIP anywhere.
                result["steps"].append("keepalived config NOT updated")
                result.setdefault("warnings", []).append(
                    "Keepalived configuration was rejected, so /etc/keepalived/keepalived.conf "
                    "was left unchanged and Keepalived is still running the old configuration "
                    "(or not running at all). " + _keepalived_hint(out, k))
                result["keepalived_check"] = out
            else:
                KEEPALIVED_CFG.parent.mkdir(parents=True, exist_ok=True)
                if KEEPALIVED_CFG.exists():
                    shutil.copy2(KEEPALIVED_CFG, str(KEEPALIVED_CFG) + ".bak")
                shutil.move(kstaging, KEEPALIVED_CFG)
                rc, out = run(["systemctl", "reload-or-restart", "keepalived"])
                result["steps"].append("keepalived reload: " + ("ok" if rc == 0 else out))
                if rc != 0:
                    result.setdefault("warnings", []).append(
                        "Keepalived did not reload: %s. Without it this node cannot take the "
                        "virtual IP." % out.strip()[:300])

        cfg["_meta"]["applied_hash"] = config_hash(cfg)
        save_config(cfg)
        result["ok"] = True

    # The push talks to every other node over the network, and an unresponsive
    # one can hold it for the full timeout. That must happen with the lock
    # released, or this node's own UI is unusable until the slowest peer gives
    # up. cfg is already saved, so the snapshot being pushed is the applied one.
    if allow_push and cfg["local"]["sync"].get("auto_sync") and sync.enabled_peers(cfg):
        r = sync.sync_push(cfg)
        result["steps"].append("auto-sync to %d peer(s): " % len(sync.enabled_peers(cfg)) +
                               ("ok" if r.get("ok") else str(r.get("error"))))
        if not r.get("ok"):
            result.setdefault("warnings", []).append(
                "This node applied its own configuration, but syncing it to the other "
                "nodes failed: %s" % r.get("error"))
        if r.get("warning"):
            result.setdefault("warnings", []).append(r["warning"])
    return result


@app.get("/api/preview")
def api_preview():
    cfg = load_config()
    ka = keepalived.render_keepalived(cfg) if cfg["local"]["keepalived"].get("enabled") else \
        "# Keepalived is disabled on this node (Cluster > This node)."
    return jsonify({"haproxy": haproxy.render_haproxy(cfg), "keepalived": ka})


@app.post("/api/apply")
def api_apply():
    return jsonify(do_apply())


@app.get("/api/status")
def api_status():
    cfg = load_config()

    def svc_state(name):
        rc, out = run(["systemctl", "is-active", name])
        return out.splitlines()[0] if out else "unknown"

    vips = [v.strip().split("/")[0] for v in (cfg["cluster"].get("vips") or "").splitlines() if v.strip()]
    held = []
    if vips:
        rc, out = run(["ip", "-o", "addr"])
        if rc == 0:
            held = [v for v in vips if re.search(r"\binet6? %s/" % re.escape(v), out)]

    issue_log = cfg["_meta"].get("issue_log") or {}
    certs = []
    for c in cfg["acme"]["certificates"]:
        info = cert_details(cert_path(c))
        info["id"] = c["id"]
        info["name"] = c["name"]
        info["domains"] = parse_domains(c)
        info["auto_renew"] = c.get("auto_renew", True)
        last = issue_log.get(c["id"])
        if last:
            # The full acme.sh log is fetched on demand from /api/acme/log/<id>.
            info["last_issue"] = {k: v for k, v in last.items() if k != "log"}
            info["last_issue"]["has_log"] = bool(last.get("log"))
        else:
            info["last_issue"] = None
        certs.append(info)

    upd = cfg["_meta"].get("update") or {}
    ro, ro_why = auth.readonly_state(cfg)
    # Whether the passive-node lock has been lifted by hand, so the UI can
    # show it and offer to put it back.
    override = auth.session_unlocked(cfg) and auth.node_role(cfg)[0] == "passive" \
        and bool(sync.enabled_peers(cfg))
    return jsonify({
        "read_only": ro,
        "read_only_reason": ro_why,
        "edit_override": override,
        "hostname": socket.gethostname(),
        "version": VERSION,
        "update_available": bool(upd.get("latest")) and updates.is_newer(upd["latest"], VERSION),
        "latest_version": upd.get("latest", ""),
        "haproxy": svc_state("haproxy"),
        "keepalived": svc_state("keepalived") if vrrp.keepalived_wanted(cfg) else "disabled",
        "vips": vips,
        "vip_held": held,
        "role": ("active" if held else "passive") if vips else "standalone",
        "dirty": cfg["_meta"].get("applied_hash") != config_hash(cfg),
        "certs": certs,
        "acme_installed": Path(ACME_SH).exists(),
        "renews_here": acme.renewal_runs_here(cfg)[0],
        "renewal_note": acme.renewal_runs_here(cfg)[1],
        "peers": len(cfg["local"]["sync"].get("peers") or []),
        "api_key_fp": auth.key_fingerprint(cfg["local"].get("api_key")),
        "sync_available": _requests is not None,
    })


@app.get("/api/ping")
def api_ping():
    return jsonify({"ok": True, "node": socket.gethostname()})


# --------------------------------------------------------------------------
# ACME (acme.sh)
