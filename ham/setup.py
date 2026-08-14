"""First run: start a cluster or join one."""

from flask import jsonify
from flask import request
from urllib.parse import urlsplit
import base64
import os
import socket
import uuid

from .base import CERT_DIR, PORT, _lock, _requests, app
from .config import DEFAULT_CONFIG, _merge_defaults, load_config, save_config, shared_fingerprint
from . import apply, auth, vrrp

def _guess_node_url():
    """How this node was just reached -- a good default for how peers reach it."""
    host = request.headers.get("X-Forwarded-Host") or request.host or ""
    scheme = request.headers.get("X-Forwarded-Proto") or ("https" if request.is_secure else "http")
    return ("%s://%s" % (scheme, host)).rstrip("/") if host else ""


@app.get("/api/setup/state")
def api_setup_state():
    cfg = load_config()
    return jsonify({
        "needs_admin": auth.needs_setup(cfg),
        "complete": bool(cfg["_meta"].get("setup_complete")),
        "hostname": socket.gethostname(),
        "port": PORT,
        "suggested_url": _guess_node_url(),
        "interfaces": [i for i in apply.node_interfaces() if i["name"] != "lo"],
        "has_peers": bool(cfg["local"]["sync"].get("peers")),
        "has_services": bool(cfg["haproxy"]["frontends"]),
    })


@app.post("/api/setup/skip")
def api_setup_skip():
    with _lock:
        cfg = load_config()
        cfg["_meta"]["setup_complete"] = True
        save_config(cfg)
    return jsonify({"ok": True})


def _apply_node_identity(cfg, body):
    """The two things every node needs: a way in, and a name to be reached at."""
    loc = cfg["local"]
    loc["api_key"] = (body.get("api_key") or "").strip() or loc.get("api_key") or os.urandom(24).hex()
    loc["node_url"] = (body.get("node_url") or "").strip().rstrip("/")
    return loc["api_key"]


@app.post("/api/setup/create")
def api_setup_create():
    """Start a new cluster, or run this node on its own."""
    body = request.get_json(force=True, silent=True) or {}
    mode = body.get("mode", "standalone")
    steps = []
    with _lock:
        cfg = load_config()
        key = _apply_node_identity(cfg, body)
        steps.append("API key set on this node")
        if mode == "cluster":
            vips = (body.get("vips") or "").strip()
            if not vips:
                return jsonify({"ok": False, "error": "a virtual IP is required for a cluster"}), 400
            cfg["cluster"].update({
                "vips": vips,
                "vrid": int(body.get("vrid") or 51),
                "auth_pass": body.get("auth_pass") or "",
            })
            iface = (body.get("interface") or "").strip()
            names = [i["name"] for i in apply.node_interfaces()]
            if iface and iface not in names:
                return jsonify({"ok": False, "error":
                                "interface \"%s\" does not exist here; available: %s"
                                % (iface, ", ".join(n for n in names if n != "lo"))}), 400
            cfg["local"]["keepalived"].update({
                "interface": iface or "eth0",
                "priority": int(body.get("priority") or 150),
            })
            steps.append("Keepalived will run on %s with priority %s"
                         % (cfg["local"]["keepalived"]["interface"],
                            cfg["local"]["keepalived"]["priority"]))
            steps.append("virtual IP %s (VRID %s)" % (vips.replace("\n", ", "), cfg["cluster"]["vrid"]))
        else:
            cfg["cluster"]["vips"] = ""      # no virtual IP means no Keepalived
            steps.append("no virtual IP -- this node runs on its own")
        cfg["_meta"]["setup_complete"] = True
        save_config(cfg)

    out = {"ok": True, "steps": steps, "api_key": key, "mode": mode}
    if body.get("apply", True):
        out["applied"] = apply.do_apply()
    return jsonify(out)


@app.post("/api/setup/join")
def api_setup_join():
    """Join a cluster: register with an existing node and let it push everything here."""
    if _requests is None:
        return jsonify({"ok": False, "error": "python3-requests is not installed on this node"}), 400
    body = request.get_json(force=True, silent=True) or {}
    target = (body.get("peer_url") or "").strip().rstrip("/")
    peer_key = body.get("peer_api_key") or ""
    if not target:
        return jsonify({"ok": False, "error": "the address of an existing node is required"}), 400
    if "://" not in target:
        target = "http://" + target
    verify = bool(body.get("verify_tls"))
    steps = []

    def call(method, path, payload=None):
        return _requests.request(method, target + path, json=payload,
                                 headers={"X-API-Key": peer_key}, timeout=30, verify=verify)

    # 1. Is it there, and does the key work?
    try:
        r = call("GET", "/api/status")
    except Exception as e:
        return jsonify({"ok": False, "error": "cannot reach %s: %s" % (target, e)}), 400
    if r.status_code == 401:
        return jsonify({"ok": False, "error": "that node rejected the API key"}), 400
    if r.status_code != 200:
        return jsonify({"ok": False, "error": "%s answered HTTP %s" % (target, r.status_code)}), 400
    remote = r.json()
    steps.append("reached %s (version %s, role %s)"
                 % (remote.get("hostname", target), remote.get("version", "?"), remote.get("role", "?")))

    # The URL this node advertises must reach THIS node. A name pointing at the
    # virtual IP sends everything to whichever node holds it instead.
    my_url = (body.get("node_url") or "").strip().rstrip("/")
    level, why = vrrp.check_node_url(my_url, remote.get("vips") or [])
    if level == "error":
        return jsonify({"ok": False, "steps": steps, "error": why}), 400
    if level == "warn":
        steps.append("note: " + why)

    # 2. Give ourselves an identity the others can use, before it pushes here.
    with _lock:
        cfg = load_config()
        key = _apply_node_identity(cfg, body)
        if not cfg["local"]["node_url"]:
            return jsonify({"ok": False, "error": "this node's URL is required so the others can reach it"}), 400
        iface = (body.get("interface") or "").strip()
        names = [i["name"] for i in apply.node_interfaces()]
        if iface and iface not in names:
            return jsonify({"ok": False, "error":
                            "interface \"%s\" does not exist here; available: %s"
                            % (iface, ", ".join(n for n in names if n != "lo"))}), 400
        if iface:
            cfg["local"]["keepalived"].update({"interface": iface,
                                               "priority": int(body.get("priority") or 100)})
        my_url = cfg["local"]["node_url"]
        save_config(cfg)
    steps.append("this node is %s" % my_url)

    # 3. Register with the existing node (skip if it already knows us).
    try:
        known = call("GET", "/api/peers").json()
        if any((p.get("url") or "").rstrip("/").lower() == my_url.lower() for p in known):
            steps.append("that node already knew about this one")
        else:
            rr = call("POST", "/api/peers",
                      {"name": socket.gethostname(), "url": my_url, "api_key": key})
            if rr.status_code != 200:
                return jsonify({"ok": False, "steps": steps,
                                "error": "could not register with %s: HTTP %s %s"
                                         % (target, rr.status_code, rr.text[:200])}), 400
            steps.append("registered with %s" % remote.get("hostname", target))
    except Exception as e:
        return jsonify({"ok": False, "steps": steps, "error": "registering failed: %s" % e}), 400

    # 4. Pull the shared configuration. A read, not a push: the node being
    #    joined is often passive -- during bring-up nobody holds the virtual IP
    #    yet -- and a passive node refuses writes, so asking it to push left the
    #    joining node with nothing.
    pushed = False
    try:
        pr = _requests.get(target + "/api/sync/pull", params={"node_url": my_url},
                           headers={"X-API-Key": peer_key}, timeout=60, verify=verify)
        if pr.status_code != 200:
            steps.append("could not fetch the configuration: HTTP %s" % pr.status_code)
        else:
            data = pr.json()
            conf = data.get("config") or {}
            with _lock:
                cfg = load_config()
                # Every shared section, not a favoured few. Leaving one out is
                # not neutral: a service admitting a sign-in group this node
                # has never heard of fails closed and refuses everyone, and a
                # node without the notification settings alerts nobody -- both
                # until the first push happens to arrive.
                for section in ("haproxy", "acme", "access", "cluster", "notify"):
                    if isinstance(conf.get(section), dict):
                        cfg[section] = _merge_defaults(conf[section], DEFAULT_CONFIG[section])
                mine = (cfg["local"].get("node_url") or "").rstrip("/").lower()
                kept = []
                for p in data.get("peers") or []:
                    if not p.get("url") or p["url"].rstrip("/").lower() == mine:
                        continue
                    kept.append({"id": p.get("id") or str(uuid.uuid4()),
                                 "name": p.get("name") or urlsplit(p["url"]).hostname or "peer",
                                 "url": p["url"].rstrip("/"),
                                 "api_key": (p.get("api_key") or "").strip(),
                                 "verify_tls": bool(p.get("verify_tls")),
                                 "enabled": bool(p.get("enabled", True))})
                if kept:
                    cfg["local"]["sync"]["peers"] = kept
                CERT_DIR.mkdir(parents=True, exist_ok=True)
                for name, b64 in (data.get("certs") or {}).items():
                    if "/" in name or ".." in name or not name.endswith(".pem"):
                        continue
                    path = CERT_DIR / name
                    path.write_bytes(base64.b64decode(b64))
                    os.chmod(path, 0o600)
                # Take the sender's place in the revision sequence, exactly as
                # a sync receive does. Counted as a change of this node's own,
                # the adopted configuration would sit at revision one and read
                # as "behind" the cluster it just joined.
                cfg["_meta"]["shared_fp"] = shared_fingerprint(cfg)
                cfg["_meta"]["shared_rev"] = int(data.get("rev") or 0)
                save_config(cfg)
            pushed = True
            steps.append("received the configuration from %s: %d other node(s), %d certificate(s)"
                         % (data.get("source", target), len(kept), len(data.get("certs") or {})))
            res = apply.do_apply(load_config(), allow_push=False)
            steps.append("applied here: " + ("ok" if res.get("ok") else str(res.get("error"))))
    except Exception as e:
        steps.append("could not fetch the configuration: %s" % e)

    # 5. Introduce this node to the rest of the cluster, not just to the node we
    #    contacted. Otherwise the others only hear about it when that node next
    #    pushes -- and a passive node never does -- leaving them with a partial
    #    membership, an incomplete unicast list, and two nodes each believing
    #    they are master.
    for p in load_config()["local"]["sync"].get("peers") or []:
        purl = (p.get("url") or "").rstrip("/")
        if not purl or purl.lower() == target.lower():
            continue
        try:
            known = _requests.get(purl + "/api/peers",
                                  headers={"X-API-Key": (p.get("api_key") or "").strip()},
                                  timeout=15, verify=bool(p.get("verify_tls"))).json()
            if any((q.get("url") or "").rstrip("/").lower() == my_url.lower() for q in known):
                continue
            rr = _requests.post(purl + "/api/peers",
                                json={"name": socket.gethostname(), "url": my_url, "api_key": key},
                                headers={"X-API-Key": (p.get("api_key") or "").strip()},
                                timeout=15, verify=bool(p.get("verify_tls")))
            steps.append("introduced to %s: %s"
                         % (p.get("name"), "ok" if rr.status_code == 200 else "HTTP %s" % rr.status_code))
        except Exception as e:
            steps.append("could not introduce this node to %s: %s" % (p.get("name"), e))

    # Unicast addresses are node-local, so the push could not carry them: give
    # this node and every other one their own source and peer list now.
    if iface:
        try:
            res = vrrp.apply_unicast_plan()
            for line in res.get("steps", []) + res.get("warnings", []):
                steps.append("unicast: " + line)
            if not res.get("ok") and res.get("error"):
                steps.append("unicast: " + res["error"])
        except Exception as e:
            steps.append("could not set the unicast peers automatically: %s" % e)

    with _lock:
        cfg = load_config()
        cfg["_meta"]["setup_complete"] = True
        save_config(cfg)

    return jsonify({"ok": True, "steps": steps, "api_key": key, "synced": pushed,
                    "note": "" if pushed else
                            "Nothing was pushed yet. Press \"Sync to all nodes now\" on the active "
                            "node to send the configuration here."})
