#!/usr/bin/env python3
"""
haproxy-manager -- a small self-hosted web UI for managing:

  * an HAProxy configuration (modeled on the OPNsense net/haproxy plugin:
    Public Services / Backend Pools / Real Servers / Conditions / Rules /
    Health Monitors / Settings)
  * Let's Encrypt (ACME) certificates via acme.sh (modeled on the OPNsense
    security/acme-client plugin: Accounts / Challenge Types / Certificates /
    Automations / Settings)
  * an active-passive pair using Keepalived with a shared virtual IP, with
    push-based settings + certificate sync between the two nodes.

Single JSON config store, no database. Requires: Flask, requests (for sync),
haproxy, keepalived, openssl, acme.sh. Run as root (it writes to /etc and
reloads services via systemctl).

Environment overrides:
  HAM_DATA_DIR       default /var/lib/haproxy-manager
  HAM_CERT_DIR       default /etc/haproxy/certs
  HAM_HAPROXY_CFG    default /etc/haproxy/haproxy.cfg
  HAM_KEEPALIVED_CFG default /etc/keepalived/keepalived.conf
  HAM_ACME_HOME      default ~/.acme.sh
  HAM_LISTEN / HAM_PORT   default 0.0.0.0 / 8080
  HAM_DRY_RUN=1      skip systemctl calls (development)
"""

import base64
import copy
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory

try:
    import requests as _requests
except ImportError:  # sync push disabled until python3-requests is installed
    _requests = None

DATA_DIR = Path(os.environ.get("HAM_DATA_DIR", "/var/lib/haproxy-manager"))
CONF_PATH = DATA_DIR / "config.json"
CERT_DIR = Path(os.environ.get("HAM_CERT_DIR", "/etc/haproxy/certs"))
HAPROXY_CFG = Path(os.environ.get("HAM_HAPROXY_CFG", "/etc/haproxy/haproxy.cfg"))
KEEPALIVED_CFG = Path(os.environ.get("HAM_KEEPALIVED_CFG", "/etc/keepalived/keepalived.conf"))
ACME_HOME = Path(os.environ.get("HAM_ACME_HOME", str(Path.home() / ".acme.sh")))
ACME_SH = os.environ.get("HAM_ACME_SH", str(ACME_HOME / "acme.sh"))
STATIC_DIR = Path(__file__).resolve().parent / "static"
LISTEN = os.environ.get("HAM_LISTEN", "0.0.0.0")
PORT = int(os.environ.get("HAM_PORT", "8080"))
DRY_RUN = os.environ.get("HAM_DRY_RUN") == "1"

app = Flask(__name__, static_folder=None)
_lock = threading.RLock()
_last_renew = time.time()

# --------------------------------------------------------------------------
# config store
# --------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "haproxy": {
        "settings": {
            "maxconn": 4000,
            "nbthread": "",
            "hard_stop_after": "60s",
            "ssl_min_ver": "TLSv1.2",
            "ssl_ciphers": "",
            "timeout_connect": "5s",
            "timeout_client": "50s",
            "timeout_server": "50s",
            "retries": 3,
            "redispatch": True,
            "stats_enabled": False,
            "stats_bind": "127.0.0.1:8404",
            "stats_uri": "/stats",
            "custom_global": "",
            "custom_defaults": "",
        },
        "servers": [],       # Real Servers
        "backends": [],      # Backend Pools
        "frontends": [],     # Public Services
        "healthchecks": [],  # Health Monitors
        "conditions": [],    # Conditions (named ACLs)
        "rules": [],         # Rules (actions bound to conditions)
    },
    "acme": {
        "settings": {
            "enabled": True,
            "auto_renew": True,
            "renew_hours": 24,          # how often the renew loop runs
            "challenge_port": 9080,     # local acme.sh --standalone listener
            "haproxy_integration": True,  # route /.well-known/acme-challenge/ to it
        },
        "accounts": [],
        "challenges": [],   # Challenge Types
        "certificates": [],
        "automations": [],
    },
    "local": {
        # node-local settings -- never overwritten by sync
        "api_key": "",
        "keepalived": {
            "enabled": False,
            "interface": "eth0",
            "vrid": 51,
            "state": "BACKUP",
            "priority": 100,
            "nopreempt": True,
            "advert_int": 1,
            "auth_pass": "",
            "unicast_src": "",
            "unicast_peer": "",
            "vips": "",            # one address/prefix per line
            "track_haproxy": True,
            "custom": "",
        },
        "sync": {
            "peer_url": "",
            "peer_api_key": "",
            "verify_tls": False,
            "auto_sync": False,    # push to peer after every successful Apply
        },
    },
    "_meta": {"applied_hash": ""},
}

VALID_COLLECTIONS = {
    "haproxy": {"servers", "backends", "frontends", "healthchecks", "conditions", "rules"},
    "acme": {"accounts", "challenges", "certificates", "automations"},
}


def _merge_defaults(dst, src):
    for k, v in src.items():
        if k not in dst:
            dst[k] = copy.deepcopy(v)
        elif isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge_defaults(dst[k], v)
    return dst


def load_config():
    with _lock:
        cfg = {}
        if CONF_PATH.exists():
            try:
                cfg = json.loads(CONF_PATH.read_text())
            except (ValueError, OSError):
                cfg = {}
        return _merge_defaults(cfg, DEFAULT_CONFIG)


def save_config(cfg):
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CONF_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2))
        os.replace(tmp, CONF_PATH)


def config_hash(cfg):
    payload = json.dumps(
        {"haproxy": cfg["haproxy"], "acme": cfg["acme"], "keepalived": cfg["local"]["keepalived"]},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def run(cmd, env=None, timeout=600):
    """Run a command, return (rc, combined output)."""
    if DRY_RUN and cmd[0] in ("systemctl", "keepalived"):
        return 0, "[dry-run] " + " ".join(cmd)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, "command not found: " + cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "timed out: " + " ".join(cmd)


def _sec(name):
    """Sanitize a user-supplied name for use in generated configs/filenames."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", (name or "").strip()) or "unnamed"


def _by_id(items):
    return {i["id"]: i for i in items if "id" in i}


def cert_path(cert):
    return CERT_DIR / (_sec(cert.get("name")) + ".pem")


def parse_domains(cert):
    return [d.strip() for d in re.split(r"[\s,]+", cert.get("domains", "")) if d.strip()]


# --------------------------------------------------------------------------
# auth
# --------------------------------------------------------------------------

@app.before_request
def _auth():
    if not request.path.startswith("/api/"):
        return
    if request.path == "/api/sync/receive":
        return  # enforced inside the handler (always requires a key)
    key = load_config()["local"].get("api_key", "")
    if key and not hmac.compare_digest(key, request.headers.get("X-API-Key", "")):
        abort(401)


# --------------------------------------------------------------------------
# generic CRUD
# --------------------------------------------------------------------------

@app.route("/api/<sec>/<col>", methods=["GET", "POST", "PUT"])
def collection(sec, col):
    cfg = load_config()
    if col == "settings":
        if sec not in ("haproxy", "acme"):
            abort(404)
        if request.method == "GET":
            return jsonify(cfg[sec]["settings"])
        cfg[sec]["settings"].update(request.get_json(force=True) or {})
        save_config(cfg)
        return jsonify(cfg[sec]["settings"])
    if sec not in VALID_COLLECTIONS or col not in VALID_COLLECTIONS[sec]:
        abort(404)
    if request.method == "GET":
        return jsonify(cfg[sec][col])
    if request.method == "POST":
        item = request.get_json(force=True) or {}
        if not item.get("name"):
            return jsonify({"error": "name is required"}), 400
        item["id"] = str(uuid.uuid4())
        cfg[sec][col].append(item)
        save_config(cfg)
        return jsonify(item)
    abort(405)


@app.route("/api/<sec>/<col>/<iid>", methods=["PUT", "DELETE"])
def collection_item(sec, col, iid):
    if sec not in VALID_COLLECTIONS or col not in VALID_COLLECTIONS[sec]:
        abort(404)
    cfg = load_config()
    items = cfg[sec][col]
    for i, x in enumerate(items):
        if x.get("id") == iid:
            if request.method == "PUT":
                data = request.get_json(force=True) or {}
                data["id"] = iid
                items[i] = data
                save_config(cfg)
                return jsonify(data)
            items.pop(i)
            save_config(cfg)
            return jsonify({"ok": True})
    abort(404)


@app.route("/api/local", methods=["GET", "PUT"])
def local_settings():
    cfg = load_config()
    if request.method == "GET":
        return jsonify(cfg["local"])
    body = request.get_json(force=True) or {}
    for key in ("keepalived", "sync"):
        if isinstance(body.get(key), dict):
            cfg["local"][key].update(body[key])
    if "api_key" in body:
        cfg["local"]["api_key"] = body["api_key"]
    save_config(cfg)
    return jsonify(cfg["local"])


# --------------------------------------------------------------------------
# haproxy.cfg renderer
# --------------------------------------------------------------------------

COND_MAP = {
    "host_matches":     lambda c: "hdr(host) -i %s" % c.get("value", ""),
    "host_starts_with": lambda c: "hdr_beg(host) -i %s" % c.get("value", ""),
    "host_ends_with":   lambda c: "hdr_end(host) -i %s" % c.get("value", ""),
    "path_matches":     lambda c: "path %s" % c.get("value", ""),
    "path_starts_with": lambda c: "path_beg %s" % c.get("value", ""),
    "path_ends_with":   lambda c: "path_end %s" % c.get("value", ""),
    "path_contains":    lambda c: "path_sub %s" % c.get("value", ""),
    "url_parameter":    lambda c: "url_param(%s) -i %s" % (c.get("param", ""), c.get("value", "")),
    "http_header":      lambda c: "hdr(%s) -i %s" % (c.get("param", ""), c.get("value", "")),
    "source_ip":        lambda c: "src %s" % c.get("value", ""),
    "ssl_sni":          lambda c: "req.ssl_sni -i %s" % c.get("value", ""),
    "custom":           lambda c: c.get("value", ""),
}


def _rule_line(rule, conds, backends):
    suffix = ""
    cond_ids = rule.get("conditions") or []
    names = []
    for cid in cond_ids:
        c = conds.get(cid)
        if c:
            names.append(("!" if c.get("negate") else "") + "acl_" + _sec(c["name"]))
    if names:
        joiner = " or " if rule.get("operator") == "or" else " "
        suffix = " %s %s" % (rule.get("test", "if"), joiner.join(names))
    t = rule.get("type")
    p1, p2 = rule.get("param1", ""), rule.get("param2", "")
    if t == "use_backend":
        be = backends.get(rule.get("backend"))
        return ("use_backend be_%s%s" % (_sec(be["name"]), suffix)) if be else None
    if t == "redirect_scheme_https":
        return "http-request redirect scheme https code 301" + suffix
    if t == "redirect_location":
        return "http-request redirect location %s code 302%s" % (p1, suffix)
    if t == "http_request_deny":
        return "http-request deny" + suffix
    if t == "http_request_set_header":
        return "http-request set-header %s %s%s" % (p1, p2, suffix)
    if t == "http_request_del_header":
        return "http-request del-header %s%s" % (p1, suffix)
    if t == "http_response_set_header":
        return "http-response set-header %s %s%s" % (p1, p2, suffix)
    if t == "tcp_request_content_accept":
        return "tcp-request content accept" + suffix
    if t == "tcp_request_content_reject":
        return "tcp-request content reject" + suffix
    if t == "custom":
        return (p1 + suffix) if p1 else None
    return None


def render_haproxy(cfg):
    hp = cfg["haproxy"]
    st = hp["settings"]
    ac = cfg["acme"]["settings"]
    servers = _by_id(hp["servers"])
    backends = _by_id(hp["backends"])
    checks = _by_id(hp["healthchecks"])
    conds = _by_id(hp["conditions"])
    rules = _by_id(hp["rules"])
    certs = _by_id(cfg["acme"]["certificates"])
    acme_on = bool(ac.get("enabled") and ac.get("haproxy_integration"))

    L = []
    A = L.append
    A("# Generated by haproxy-manager at %s" % datetime.now(timezone.utc).isoformat(timespec="seconds"))
    A("# Do not edit by hand -- changes are overwritten on Apply.")
    A("")
    A("global")
    A("    log /dev/log local0")
    A("    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners")
    A("    stats timeout 30s")
    A("    maxconn %s" % (st.get("maxconn") or 4000))
    if st.get("nbthread"):
        A("    nbthread %s" % st["nbthread"])
    if st.get("hard_stop_after"):
        A("    hard-stop-after %s" % st["hard_stop_after"])
    if st.get("ssl_min_ver"):
        A("    ssl-default-bind-options ssl-min-ver %s" % st["ssl_min_ver"])
    if st.get("ssl_ciphers"):
        A("    ssl-default-bind-ciphers %s" % st["ssl_ciphers"])
    for ln in (st.get("custom_global") or "").splitlines():
        if ln.strip():
            A("    " + ln.strip())
    A("")
    A("defaults")
    A("    log global")
    A("    option dontlognull")
    if st.get("redispatch", True):
        A("    option redispatch")
    A("    retries %s" % st.get("retries", 3))
    A("    timeout connect %s" % (st.get("timeout_connect") or "5s"))
    A("    timeout client %s" % (st.get("timeout_client") or "50s"))
    A("    timeout server %s" % (st.get("timeout_server") or "50s"))
    for ln in (st.get("custom_defaults") or "").splitlines():
        if ln.strip():
            A("    " + ln.strip())
    A("")
    if st.get("stats_enabled"):
        A("listen stats")
        A("    bind %s" % (st.get("stats_bind") or "127.0.0.1:8404"))
        A("    mode http")
        A("    stats enable")
        A("    stats uri %s" % (st.get("stats_uri") or "/stats"))
        A("    stats refresh 10s")
        A("")

    for fe in hp["frontends"]:
        if not fe.get("enabled", True):
            continue
        mode = fe.get("mode", "http")
        A("frontend fe_%s" % _sec(fe["name"]))
        ssl_suffix = ""
        if fe.get("ssl_enabled"):
            crts = [str(cert_path(certs[cid])) for cid in (fe.get("certificates") or []) if cid in certs]
            if crts:
                ssl_suffix = " ssl " + " ".join("crt " + p for p in crts)
            else:
                ssl_suffix = " ssl crt %s/" % CERT_DIR
            if fe.get("http2"):
                ssl_suffix += " alpn h2,http/1.1"
        for b in (fe.get("binds") or "").splitlines():
            if b.strip():
                A("    bind %s%s" % (b.strip(), ssl_suffix))
        A("    mode %s" % mode)
        A("    option httplog" if mode == "http" else "    option tcplog")
        if mode == "http" and fe.get("forwardfor", True):
            A("    option forwardfor")
        if mode == "http" and fe.get("ssl_enabled"):
            A("    http-request set-header X-Forwarded-Proto https if { ssl_fc }")
        if acme_on and mode == "http":
            A("    acl acme_challenge path_beg /.well-known/acme-challenge/")
            A("    use_backend bk_acme_challenge if acme_challenge")
        if mode == "http" and fe.get("http_to_https") and not fe.get("ssl_enabled"):
            excl = " if !acme_challenge !{ ssl_fc }" if acme_on else " unless { ssl_fc }"
            A("    http-request redirect scheme https code 301" + excl)
        # named ACLs for every condition referenced by this frontend's rules
        used = []
        for rid in fe.get("rules") or []:
            r = rules.get(rid)
            for cid in (r.get("conditions") or []) if r else []:
                if cid in conds and cid not in used:
                    used.append(cid)
        need_inspect = False
        for cid in used:
            c = conds[cid]
            expr = COND_MAP.get(c.get("type", "custom"), COND_MAP["custom"])(c)
            A("    acl acl_%s %s" % (_sec(c["name"]), expr))
            if mode == "tcp" and c.get("type") == "ssl_sni":
                need_inspect = True
        if need_inspect:
            A("    tcp-request inspect-delay 5s")
            A("    tcp-request content accept if { req_ssl_hello_type 1 }")
        for rid in fe.get("rules") or []:
            r = rules.get(rid)
            if r:
                ln = _rule_line(r, conds, backends)
                if ln:
                    A("    " + ln)
        db = backends.get(fe.get("default_backend"))
        if db:
            A("    default_backend be_%s" % _sec(db["name"]))
        for ln in (fe.get("custom") or "").splitlines():
            if ln.strip():
                A("    " + ln.strip())
        A("")

    if acme_on:
        A("backend bk_acme_challenge")
        A("    mode http")
        A("    server acme_sh 127.0.0.1:%s" % ac.get("challenge_port", 9080))
        A("")

    for be in hp["backends"]:
        if not be.get("enabled", True):
            continue
        mode = be.get("mode", "http")
        A("backend be_%s" % _sec(be["name"]))
        A("    mode %s" % mode)
        A("    balance %s" % be.get("balance", "roundrobin"))
        hc = checks.get(be.get("healthcheck")) if be.get("healthcheck_enabled") else None
        inter = (hc.get("interval") if hc else None) or "2s"
        if hc:
            if hc.get("type") == "http" and mode == "http":
                A("    option httpchk %s %s" % (hc.get("http_method", "GET"), hc.get("http_uri", "/")))
                if hc.get("expect_status"):
                    A("    http-check expect status %s" % hc["expect_status"])
            elif hc.get("type") == "ssl":
                A("    option ssl-hello-chk")
        use_cookie = be.get("persistence") == "cookie" and mode == "http"
        if use_cookie:
            A("    cookie %s insert indirect nocache" % (be.get("cookie_name") or "SRVID"))
        for sid in be.get("servers") or []:
            sv = servers.get(sid)
            if not sv or not sv.get("enabled", True):
                continue
            parts = ["server %s %s:%s" % (_sec(sv["name"]), sv.get("address", ""), sv.get("port", ""))]
            if be.get("healthcheck_enabled"):
                parts.append("check inter %s" % inter)
            if sv.get("weight"):
                parts.append("weight %s" % sv["weight"])
            if sv.get("ssl"):
                parts.append("ssl")
                parts.append("verify required" if sv.get("ssl_verify") else "verify none")
            if sv.get("backup"):
                parts.append("backup")
            if use_cookie:
                parts.append("cookie %s" % _sec(sv["name"]))
            A("    " + " ".join(parts))
        for ln in (be.get("custom") or "").splitlines():
            if ln.strip():
                A("    " + ln.strip())
        A("")

    return "\n".join(L).rstrip() + "\n"


# --------------------------------------------------------------------------
# keepalived.conf renderer
# --------------------------------------------------------------------------

def render_keepalived(cfg):
    k = cfg["local"]["keepalived"]
    L = []
    A = L.append
    A("# Generated by haproxy-manager at %s" % datetime.now(timezone.utc).isoformat(timespec="seconds"))
    A("# Node-local file -- not synchronized between nodes.")
    A("")
    if k.get("track_haproxy", True):
        # keepalived >= 2.0 refuses to load a config with tracking scripts
        # unless script security is enabled explicitly.
        A("global_defs {")
        A("    enable_script_security")
        A("    script_user root")
        A("}")
        A("")
        A("vrrp_script chk_haproxy {")
        A('    script "/usr/bin/pgrep -x haproxy"')
        A("    interval 2")
        A("    fall 2")
        A("    rise 2")
        A("    weight -30")
        A("}")
        A("")
    A("vrrp_instance HAPROXY_VIP {")
    A("    state %s" % k.get("state", "BACKUP"))
    A("    interface %s" % k.get("interface", "eth0"))
    A("    virtual_router_id %s" % k.get("vrid", 51))
    A("    priority %s" % k.get("priority", 100))
    A("    advert_int %s" % k.get("advert_int", 1))
    if k.get("nopreempt"):
        A("    nopreempt")
    if k.get("auth_pass"):
        A("    authentication {")
        A("        auth_type PASS")
        A("        auth_pass %s" % k["auth_pass"][:8])  # keepalived uses max 8 chars
        A("    }")
    if k.get("unicast_src") and k.get("unicast_peer"):
        A("    unicast_src_ip %s" % k["unicast_src"])
        A("    unicast_peer {")
        for p in k["unicast_peer"].replace(",", "\n").splitlines():
            if p.strip():
                A("        " + p.strip())
        A("    }")
    A("    virtual_ipaddress {")
    for v in (k.get("vips") or "").splitlines():
        if v.strip():
            A("        " + v.strip())
    A("    }")
    if k.get("track_haproxy", True):
        A("    track_script {")
        A("        chk_haproxy")
        A("    }")
    for ln in (k.get("custom") or "").splitlines():
        if ln.strip():
            A("    " + ln.strip())
    A("}")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------
# apply / preview / status
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


def do_apply(cfg=None, allow_push=True):
    with _lock:
        cfg = cfg or load_config()
        result = {"ok": False, "steps": []}

        placeholders = ensure_cert_files(cfg)
        if placeholders:
            result["steps"].append("created placeholder certificates: " + ", ".join(placeholders))

        text = render_haproxy(cfg)
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
            return result

        HAPROXY_CFG.parent.mkdir(parents=True, exist_ok=True)
        if HAPROXY_CFG.exists():
            shutil.copy2(HAPROXY_CFG, str(HAPROXY_CFG) + ".bak")
        shutil.move(staging, HAPROXY_CFG)
        os.chmod(HAPROXY_CFG, 0o644)
        rc, out = run(["systemctl", "reload-or-restart", "haproxy"])
        result["steps"].append("haproxy reload: " + ("ok" if rc == 0 else out))

        k = cfg["local"]["keepalived"]
        if k.get("enabled"):
            ktext = render_keepalived(cfg)
            fd, kstaging = tempfile.mkstemp(suffix=".conf")
            with os.fdopen(fd, "w") as f:
                f.write(ktext)
            rc, out = run(["keepalived", "-t", "-f", kstaging])
            if rc not in (0, 127):
                os.unlink(kstaging)
                result["steps"].append("keepalived config validation failed: " + out)
            else:
                KEEPALIVED_CFG.parent.mkdir(parents=True, exist_ok=True)
                if KEEPALIVED_CFG.exists():
                    shutil.copy2(KEEPALIVED_CFG, str(KEEPALIVED_CFG) + ".bak")
                shutil.move(kstaging, KEEPALIVED_CFG)
                rc, out = run(["systemctl", "reload-or-restart", "keepalived"])
                result["steps"].append("keepalived reload: " + ("ok" if rc == 0 else out))

        cfg["_meta"]["applied_hash"] = config_hash(cfg)
        save_config(cfg)
        result["ok"] = True

        if allow_push and cfg["local"]["sync"].get("auto_sync") and cfg["local"]["sync"].get("peer_url"):
            r = sync_push(cfg)
            result["steps"].append("auto-sync to peer: " + ("ok" if r.get("ok") else str(r.get("error"))))
        return result


@app.get("/api/preview")
def api_preview():
    cfg = load_config()
    ka = render_keepalived(cfg) if cfg["local"]["keepalived"].get("enabled") else \
        "# Keepalived is disabled on this node (High Availability > Keepalived)."
    return jsonify({"haproxy": render_haproxy(cfg), "keepalived": ka})


@app.post("/api/apply")
def api_apply():
    return jsonify(do_apply())


@app.get("/api/status")
def api_status():
    cfg = load_config()

    def svc_state(name):
        rc, out = run(["systemctl", "is-active", name])
        return out.splitlines()[0] if out else "unknown"

    k = cfg["local"]["keepalived"]
    vips = [v.strip().split("/")[0] for v in (k.get("vips") or "").splitlines() if v.strip()]
    held = []
    if vips:
        rc, out = run(["ip", "-o", "addr"])
        if rc == 0:
            held = [v for v in vips if re.search(r"\binet6? %s/" % re.escape(v), out)]

    certs = []
    for c in cfg["acme"]["certificates"]:
        p = cert_path(c)
        info = {"id": c["id"], "name": c["name"], "deployed": p.exists(), "expires": None, "issuer": None}
        if p.exists():
            rc, out = run(["openssl", "x509", "-enddate", "-issuer", "-noout", "-in", str(p)])
            if rc == 0:
                m = re.search(r"notAfter=(.+)", out)
                info["expires"] = m.group(1).strip() if m else None
                m = re.search(r"issuer=(.+)", out)
                info["issuer"] = m.group(1).strip() if m else None
        certs.append(info)

    return jsonify({
        "hostname": socket.gethostname(),
        "haproxy": svc_state("haproxy"),
        "keepalived": svc_state("keepalived") if k.get("enabled") else "disabled",
        "vips": vips,
        "vip_held": held,
        "role": ("active" if held else "passive") if (k.get("enabled") and vips) else "standalone",
        "dirty": cfg["_meta"].get("applied_hash") != config_hash(cfg),
        "certs": certs,
        "acme_installed": Path(ACME_SH).exists(),
        "peer_url": cfg["local"]["sync"].get("peer_url", ""),
        "sync_available": _requests is not None,
    })


@app.get("/api/ping")
def api_ping():
    return jsonify({"ok": True, "node": socket.gethostname()})


# --------------------------------------------------------------------------
# ACME (acme.sh)
# --------------------------------------------------------------------------

CA_SERVERS = {
    "letsencrypt": "letsencrypt",
    "letsencrypt_test": "letsencrypt_test",
    "zerossl": "zerossl",
    "buypass": "buypass",
    "google": "google",
}
KEYLEN = {"ec-256": "ec-256", "ec-384": "ec-384", "rsa-2048": "2048", "rsa-4096": "4096"}


def acme_run(args, env_extra=None):
    if not Path(ACME_SH).exists():
        return 127, "acme.sh not found at %s -- run install.sh or set HAM_ACME_SH" % ACME_SH
    env = os.environ.copy()
    env.update(env_extra or {})
    return run([ACME_SH, "--home", str(ACME_HOME)] + args, env=env)


def ensure_account(acc):
    args = ["--register-account", "-m", acc.get("email", ""),
            "--server", CA_SERVERS.get(acc.get("ca", "letsencrypt"), "letsencrypt")]
    if acc.get("eab_kid"):
        args += ["--eab-kid", acc["eab_kid"], "--eab-hmac-key", acc.get("eab_hmac", "")]
    return acme_run(args)


def acme_issue(cfg, cert, force=False):
    accounts = _by_id(cfg["acme"]["accounts"])
    challenges = _by_id(cfg["acme"]["challenges"])
    acc = accounts.get(cert.get("account"))
    ch = challenges.get(cert.get("challenge"))
    if not acc or not ch:
        return {"ok": False, "error": "certificate needs both an account and a challenge type"}
    doms = parse_domains(cert)
    if not doms:
        return {"ok": False, "error": "certificate has no domain names"}

    log = []
    rc, out = ensure_account(acc)
    log.append(out)
    if rc != 0:
        return {"ok": False, "error": "ACME account registration failed", "log": "\n".join(log)}

    args = ["--issue", "--server", CA_SERVERS.get(acc.get("ca", "letsencrypt"), "letsencrypt")]
    for d in doms:
        args += ["-d", d]
    args += ["--keylength", KEYLEN.get(cert.get("key_type", "ec-256"), "ec-256")]
    env = {}
    if ch.get("method") == "dns01":
        args += ["--dns", ch.get("dns_provider", "")]
        for line in (ch.get("dns_credentials") or "").splitlines():
            if "=" in line:
                kk, vv = line.split("=", 1)
                env[kk.strip()] = vv.strip()
    else:
        args += ["--standalone", "--httpport", str(cfg["acme"]["settings"].get("challenge_port", 9080))]
    if force:
        args += ["--force"]

    rc, out = acme_run(args, env)
    log.append(out)
    if rc not in (0, 2):  # 2 = cert not yet due for renewal, treat as success
        return {"ok": False, "error": "issuance failed -- see log", "log": "\n".join(log)}

    dep = deploy_cert(cfg, cert)
    log.append(dep.get("log", ""))
    res = {"ok": dep["ok"], "log": "\n".join(x for x in log if x)}
    if not dep["ok"]:
        res["error"] = dep.get("error")
    return res


def deploy_cert(cfg, cert):
    """Copy fullchain+key from acme.sh into a combined PEM HAProxy can load."""
    doms = parse_domains(cert)
    main = doms[0]
    with tempfile.TemporaryDirectory() as td:
        fc, key = Path(td) / "fullchain.pem", Path(td) / "key.pem"
        args = ["--install-cert", "-d", main, "--fullchain-file", str(fc), "--key-file", str(key)]
        if cert.get("key_type", "ec-256").startswith("ec"):
            args.append("--ecc")
        rc, out = acme_run(args)
        if rc != 0 or not fc.exists() or not key.exists():
            return {"ok": False, "error": "acme.sh --install-cert failed", "log": out}
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        p = cert_path(cert)
        p.write_text(fc.read_text() + key.read_text())
        os.chmod(p, 0o600)
    auto = run_automations(cfg, cert)
    return {"ok": True, "log": (out + ("\n" + auto if auto else "")).strip()}


def run_automations(cfg, cert):
    autos = _by_id(cfg["acme"]["automations"])
    msgs = []
    for aid in cert.get("automations") or []:
        a = autos.get(aid)
        if not a:
            continue
        t = a.get("type")
        if t == "reload_haproxy":
            rc, out = run(["systemctl", "reload-or-restart", "haproxy"])
            msgs.append("reload haproxy: " + ("ok" if rc == 0 else out))
        elif t == "restart_haproxy":
            rc, out = run(["systemctl", "restart", "haproxy"])
            msgs.append("restart haproxy: " + ("ok" if rc == 0 else out))
        elif t == "sync_to_peer":
            r = sync_push(cfg)
            msgs.append("sync to peer: " + ("ok" if r.get("ok") else str(r.get("error"))))
        elif t == "custom" and a.get("command"):
            rc, out = run(["/bin/sh", "-c", a["command"]])
            msgs.append("%s: %s" % (a.get("name", "command"), "ok" if rc == 0 else out[-300:]))
    return "; ".join(msgs)


@app.post("/api/acme/issue/<cid>")
def api_acme_issue(cid):
    cfg = load_config()
    cert = _by_id(cfg["acme"]["certificates"]).get(cid)
    if not cert:
        abort(404)
    force = bool((request.get_json(silent=True) or {}).get("force"))
    return jsonify(acme_issue(cfg, cert, force=force))


@app.post("/api/acme/renew")
def api_acme_renew():
    cfg = load_config()
    results = {}
    for cert in cfg["acme"]["certificates"]:
        if cert.get("auto_renew", True):
            results[cert["name"]] = acme_issue(cfg, cert)
    return jsonify({"ok": all(r.get("ok") for r in results.values()) if results else True,
                    "results": results})


def _renew_loop():
    global _last_renew
    while True:
        time.sleep(600)
        try:
            cfg = load_config()
            st = cfg["acme"]["settings"]
            if not (st.get("enabled") and st.get("auto_renew")):
                continue
            interval = max(1, int(st.get("renew_hours") or 24)) * 3600
            if time.time() - _last_renew >= interval:
                _last_renew = time.time()
                for cert in cfg["acme"]["certificates"]:
                    if cert.get("auto_renew", True):
                        acme_issue(cfg, cert)
        except Exception:
            pass


# --------------------------------------------------------------------------
# node sync (active-passive)
# --------------------------------------------------------------------------

def shared_payload(cfg):
    certs = {}
    if CERT_DIR.exists():
        for p in sorted(CERT_DIR.glob("*.pem")):
            certs[p.name] = base64.b64encode(p.read_bytes()).decode()
    return {
        "config": {"haproxy": cfg["haproxy"], "acme": cfg["acme"]},
        "certs": certs,
        "source": socket.gethostname(),
        "ts": time.time(),
    }


def sync_push(cfg):
    s = cfg["local"]["sync"]
    if _requests is None:
        return {"ok": False, "error": "python3-requests is not installed on this node"}
    url = (s.get("peer_url") or "").rstrip("/")
    if not url:
        return {"ok": False, "error": "no peer URL configured (High Availability > Sync)"}
    try:
        r = _requests.post(
            url + "/api/sync/receive",
            json=shared_payload(cfg),
            headers={"X-API-Key": s.get("peer_api_key", "")},
            timeout=90,
            verify=bool(s.get("verify_tls")),
        )
        if r.status_code != 200:
            return {"ok": False, "error": "peer returned HTTP %s: %s" % (r.status_code, r.text[:300])}
        return {"ok": True, "peer": r.json()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/sync/push")
def api_sync_push():
    return jsonify(sync_push(load_config()))


@app.post("/api/sync/test")
def api_sync_test():
    cfg = load_config()
    s = cfg["local"]["sync"]
    if _requests is None:
        return jsonify({"ok": False, "error": "python3-requests is not installed on this node"})
    url = (s.get("peer_url") or "").rstrip("/")
    if not url:
        return jsonify({"ok": False, "error": "no peer URL configured"})
    try:
        r = _requests.get(url + "/api/ping", headers={"X-API-Key": s.get("peer_api_key", "")},
                          timeout=10, verify=bool(s.get("verify_tls")))
        if r.status_code != 200:
            return jsonify({"ok": False, "error": "peer returned HTTP %s" % r.status_code})
        return jsonify({"ok": True, "peer": r.json().get("node")})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.post("/api/sync/receive")
def api_sync_receive():
    cfg = load_config()
    key = cfg["local"].get("api_key", "")
    if not key:
        return jsonify({"error": "this node has no API key set -- refusing sync"}), 403
    if not hmac.compare_digest(key, request.headers.get("X-API-Key", "")):
        abort(401)
    data = request.get_json(force=True) or {}
    conf = data.get("config") or {}
    if "haproxy" in conf:
        cfg["haproxy"] = _merge_defaults(conf["haproxy"], DEFAULT_CONFIG["haproxy"])
    if "acme" in conf:
        cfg["acme"] = _merge_defaults(conf["acme"], DEFAULT_CONFIG["acme"])
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    for name, b64 in (data.get("certs") or {}).items():
        if "/" in name or ".." in name or not name.endswith(".pem"):
            continue
        p = CERT_DIR / name
        p.write_bytes(base64.b64decode(b64))
        os.chmod(p, 0o600)
    save_config(cfg)
    res = do_apply(cfg, allow_push=False)  # never re-push: avoids sync loops
    return jsonify({"ok": res.get("ok", False), "node": socket.gethostname(), "applied": res})


# --------------------------------------------------------------------------
# static
# --------------------------------------------------------------------------

@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not CONF_PATH.exists():
        save_config(load_config())
    threading.Thread(target=_renew_loop, daemon=True).start()
    app.run(host=LISTEN, port=PORT, threaded=True)
