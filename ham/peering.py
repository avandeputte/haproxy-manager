"""The other nodes: settings, testing, and asking how they are."""

from flask import abort
from flask import jsonify
from flask import request
from urllib.parse import urlsplit
import socket
import time
import urllib.parse
import urllib.request
import uuid

from .base import (PEER_CONNECT_TIMEOUT, PEER_READ_TIMEOUT, PEER_TIMEOUT, _lock, 
    _requests, app)
from .config import CLUSTER_KEYS, load_config, save_config
from . import apply, auth, sync, vrrp

@app.route("/api/cluster/settings", methods=["GET", "PUT"])
def api_cluster_settings():
    """VRRP settings every node shares. Pushed to the others like any config."""
    cfg = load_config()
    if request.method == "GET":
        return jsonify(cfg["cluster"])
    body = request.get_json(force=True) or {}
    ok, message = apply.check_rendered(apply.draft_with(None, body, shared=True))   # slow: outside the lock
    if not ok:
        return jsonify({"error": "These settings were not saved -- they do not produce a working "
                                 "configuration.\n\n" + message}), 400
    with _lock:
        cfg = load_config()
        cfg["cluster"].update({k: v for k, v in body.items() if k in CLUSTER_KEYS})
        save_config(cfg)
        return jsonify(cfg["cluster"])


@app.route("/api/peers", methods=["GET", "POST"])
def api_peers():
    cfg = load_config()
    peers = cfg["local"]["sync"].setdefault("peers", [])
    if request.method == "GET":
        # Never hand the stored keys back to the browser.
        own = auth.key_fingerprint(cfg["local"].get("api_key"))
        return jsonify([{k: v for k, v in p.items() if k != "api_key"} |
                        {"has_key": bool((p.get("api_key") or "").strip()),
                         "key_fp": auth.key_fingerprint(p.get("api_key")),
                         "is_own_key": bool(own) and auth.key_fingerprint(p.get("api_key")) == own}
                        for p in peers])
    body = request.get_json(force=True) or {}
    url = (body.get("url") or "").strip().rstrip("/")
    if not url:
        return jsonify({"error": "the peer's URL is required, e.g. http://10.0.0.2:8080"}), 400
    if "://" not in url:
        url = "http://" + url
    level, why = vrrp.check_node_url(url, vrrp.cluster_vips(cfg))   # resolves names: outside the lock
    if level == "error":
        return jsonify({"error": why}), 400
    peer = {"id": str(uuid.uuid4()),
            "name": (body.get("name") or "").strip() or (urlsplit(url).hostname or "peer"),
            "url": url, "api_key": (body.get("api_key") or "").strip(),
            "verify_tls": bool(body.get("verify_tls")), "enabled": bool(body.get("enabled", True))}
    with _lock:
        cfg = load_config()
        cfg["local"]["sync"].setdefault("peers", []).append(peer)
        save_config(cfg)
    return jsonify({k: v for k, v in peer.items() if k != "api_key"})


@app.route("/api/peers/<pid>", methods=["PUT", "DELETE"])
def api_peer_item(pid):
    with _lock:
        return _peer_item_locked(pid)


def _peer_item_locked(pid):
    cfg = load_config()
    peers = cfg["local"]["sync"].setdefault("peers", [])
    for i, p in enumerate(peers):
        if p.get("id") != pid:
            continue
        if request.method == "DELETE":
            peers.pop(i)
            save_config(cfg)
            return jsonify({"ok": True})
        body = request.get_json(force=True) or {}
        for key in ("name", "url", "verify_tls", "enabled"):
            if key in body:
                p[key] = body[key]
        if (body.get("api_key") or "").strip():   # blank means "keep the stored key"
            p["api_key"] = body["api_key"].strip()
        p["url"] = (p.get("url") or "").rstrip("/")
        save_config(cfg)
        return jsonify({k: v for k, v in p.items() if k != "api_key"})
    abort(404)


@app.post("/api/peers/<pid>/test")
def api_peer_test(pid):
    """Say exactly why a peer does or does not work, rather than leaving a 401."""
    cfg = load_config()
    peer = next((p for p in (cfg["local"]["sync"].get("peers") or []) if p.get("id") == pid), None)
    if not peer:
        abort(404)
    if _requests is None:
        return jsonify({"ok": False, "error": "python3-requests is not installed on this node"})
    url = (peer.get("url") or "").rstrip("/")
    stored = (peer.get("api_key") or "")
    if not stored.strip():
        return jsonify({"ok": False, "error":
                        "no API key is stored here for %s. Copy the key from Cluster > This node "
                        "on that node and paste it into this peer's entry." % peer.get("name")})
    if auth.key_matches(cfg["local"].get("api_key"), stored):
        return jsonify({"ok": False, "error":
                        "this entry holds THIS node's own API key (fingerprint %s), not %s's. With "
                        "a window open on each node it is easy to copy from the wrong one -- the "
                        "page header names the node it belongs to."
                        % (auth.key_fingerprint(stored), peer.get("name"))})
    try:
        r = _requests.get(url + "/api/status", headers={"X-API-Key": stored.strip()},
                          timeout=PEER_TIMEOUT, verify=bool(peer.get("verify_tls")))
    except Exception as e:
        return jsonify({"ok": False, "error": "cannot reach %s: %s" % (url, e)})

    if r.status_code == 401:
        try:
            d = r.json()
            if d.get("expected_fp") or d.get("header_seen") is not None:
                return jsonify({"ok": False, "error": sync._key_verdict(d, url), "diagnosis": d})
        except Exception:
            pass
        return jsonify({"ok": False, "error":
                        "%s rejected this key. This entry must hold the key shown under "
                        "Cluster > This node ON THAT NODE -- not this node's own key." % url})

    if r.status_code != 200:
        return jsonify({"ok": False, "error": "%s answered HTTP %s" % (url, r.status_code)})
    st = r.json()
    notes = []
    if stored != stored.strip():
        notes.append("The stored key had surrounding whitespace; it is trimmed when saved.")
    if st.get("hostname") == socket.gethostname():
        notes.append("This entry points back at THIS node -- a node should not be its own peer.")
    vips = [v.strip().split("/")[0] for v in (cfg["cluster"].get("vips") or "").splitlines() if v.strip()]
    if (urlsplit(url).hostname or "") in vips:
        notes.append("This URL is the virtual IP, so it reaches whichever node currently holds it "
                     "-- possibly this one. Use the node's own address instead.")
    return jsonify({"ok": True, "hostname": st.get("hostname"), "version": st.get("version"),
                    "role": st.get("role"), "peers": st.get("peers"), "note": " ".join(notes)})


def peer_error(exc, url="", read_timeout=None):
    """Turn a requests/urllib3 exception into something a person can act on."""
    read_timeout = PEER_READ_TIMEOUT if read_timeout is None else read_timeout
    text = str(exc)
    host = ""
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        pass
    if "NameResolution" in text or "Name or service not known" in text \
            or "Temporary failure in name resolution" in text:
        return ("the name %s could not be resolved. Cluster members are best "
                "addressed by IP: DNS may be unavailable exactly when a node is "
                "in trouble, and it may be this cluster that publishes the name."
                % (host or "in its URL"))
    if "ConnectTimeout" in type(exc).__name__ or "Connection to" in text and "timed out" in text:
        return ("no answer from %s within %gs -- it is unreachable, or a firewall "
                "is dropping the connection." % (host or url, PEER_CONNECT_TIMEOUT))
    if "ReadTimeout" in type(exc).__name__:
        return ("%s accepted the connection but did not reply within %gs. It is "
                "running but busy or wedged." % (host or url, read_timeout))
    if "ConnectionRefused" in text or "Connection refused" in text:
        return ("%s refused the connection -- haproxy-manager is not listening "
                "there, or the port is wrong." % (host or url))
    if "SSLError" in type(exc).__name__ or "CERTIFICATE_VERIFY_FAILED" in text:
        return ("the TLS certificate of %s was rejected. Untick 'Verify TLS' for "
                "this peer, or give it a certificate this node trusts." % (host or url))
    return text[:200]


def _query_peer(peer, timeout=PEER_TIMEOUT):
    """Ask one node for its status."""
    url = (peer.get("url") or "").rstrip("/")
    out = {"id": peer.get("id"), "name": peer.get("name") or url, "url": url,
           "self": False, "reachable": False, "error": ""}
    if not peer.get("enabled", True):
        out["error"] = "disabled"
        return out
    started = time.time()
    try:
        r = _requests.get(url + "/api/status", headers={"X-API-Key": peer.get("api_key", "")},
                          timeout=timeout, verify=bool(peer.get("verify_tls")))
        out["ms"] = int((time.time() - started) * 1000)
        if r.status_code == 401:
            out["error"] = "the API key this node holds for it was rejected"
            return out
        if r.status_code != 200:
            out["error"] = "HTTP %s" % r.status_code
            return out
        out.update(_node_summary(r.json()))
        out["reachable"] = True
    except Exception as e:
        out["ms"] = int((time.time() - started) * 1000)
        out["error"] = peer_error(e, url)
    return out


def _node_summary(st):
    certs = st.get("certs") or []
    return {
        "hostname": st.get("hostname", ""),
        "version": st.get("version", ""),
        "role": st.get("role", ""),
        "haproxy": st.get("haproxy", ""),
        "keepalived": st.get("keepalived", ""),
        "vips": st.get("vips") or [],
        "vip_held": st.get("vip_held") or [],
        "dirty": bool(st.get("dirty")),
        "config_rev": int(st.get("config_rev") or 0),
        "config_fp": st.get("config_fp") or "",
        "config_parts": st.get("config_parts") or {},
        "config_objects": st.get("config_objects") or {},
        "config_leak": st.get("config_leak") or None,
        "update_available": bool(st.get("update_available")),
        "certs_total": len(certs),
        "certs_bad": sum(1 for c in certs if c.get("status") in ("expired", "expiring", "placeholder", "missing")),
    }
