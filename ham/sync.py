"""Pushing the shared configuration to the other nodes, and receiving it."""

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
from .config import DEFAULT_CONFIG, _merge_defaults, load_config, save_config
from . import apply, auth, peering, webui

# --------------------------------------------------------------------------

def shared_payload(cfg):
    certs = {}
    if CERT_DIR.exists():
        for p in sorted(CERT_DIR.glob("*.pem")):
            certs[p.name] = base64.b64encode(p.read_bytes()).decode()
    return {
        "config": {"haproxy": webui.strip_local_only(cfg["haproxy"]),
                   "acme": webui.strip_local_only(cfg["acme"]),
                   "cluster": cfg["cluster"],
                   "notify": cfg.get("notify", {})},
        "certs": certs,
        "source": socket.gethostname(),
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
    admin.pop("must_change", None)
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


def sync_push(cfg, only=None, include_peers=True):
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
        return {"ok": False, "error": "no peers configured (Advanced > Keepalived > Peer sync)"}

    base = shared_payload(cfg)

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
    out = {"ok": not failed, "results": results,
           "error": "; ".join("%s: %s" % (r["name"], r["error"]) for r in failed) or None}
    if include_peers and not (cfg["local"].get("node_url") or "").strip():
        out["warning"] = ("This node has no URL set, so the other nodes were told about each "
                          "other but not about this node -- they cannot sync back to it, and it "
                          "will not appear in their cluster view. Set \"This node's URL\" under "
                          "Cluster > This node.")
    return out


@app.post("/api/sync/push")
def api_sync_push():
    body = request.get_json(silent=True) or {}
    return jsonify(sync_push(load_config(), only=body.get("peer"),
                             include_peers=bool(body.get("include_peers", True))))

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


def _receive_locked(cfg, data, conf):
    cfg = load_config()          # re-read inside the lock: it may have moved
    if "haproxy" in conf:
        cfg["haproxy"] = webui.keep_local_only(cfg["haproxy"],
                                         _merge_defaults(conf["haproxy"], DEFAULT_CONFIG["haproxy"]))
    if "acme" in conf:
        cfg["acme"] = webui.keep_local_only(cfg["acme"],
                                      _merge_defaults(conf["acme"], DEFAULT_CONFIG["acme"]))
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
    save_config(cfg)
    log.info("received configuration from %s", request.remote_addr)
    res = apply.do_apply(cfg, allow_push=False)  # never re-push: avoids sync loops
    return jsonify({"ok": res.get("ok", False), "node": socket.gethostname(), "applied": res})
