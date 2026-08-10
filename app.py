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
import sys
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
        # UI login. The password is only ever stored as a PBKDF2 hash.
        "admin": {"username": "admin", "salt": "", "hash": "", "iterations": 0, "updated": ""},
        "session_secret": "",      # HMAC key for session cookies; rotating it logs everyone out
        "session_hours": 12,
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


# Certificates count as "expiring" this many days before notAfter.
EXPIRY_WARN_DAYS = 15


def cert_details(p):
    """Inspect a deployed PEM.

    Distinguishes a real certificate from the self-signed placeholder that
    Apply drops in before the first issuance -- otherwise "deployed" says yes
    for a certificate that was never actually issued.
    """
    info = {"deployed": False, "status": "missing", "file": str(p),
            "expires": None, "expires_iso": None, "days_left": None,
            "issuer": None, "subject": None, "self_signed": False}
    if not p.exists():
        return info
    info["deployed"] = True

    rc, out = run(["openssl", "x509", "-noout", "-enddate", "-issuer", "-subject", "-in", str(p)])
    if rc != 0:
        info["status"] = "unreadable"
        return info

    def _grab(field):
        m = re.search(r"^%s=(.+)$" % field, out, re.M)
        return m.group(1).strip() if m else None

    info["issuer"] = _grab("issuer")
    info["subject"] = _grab("subject")
    info["self_signed"] = bool(info["issuer"]) and info["issuer"] == info["subject"]
    info["expires"] = _grab("notAfter")

    if info["expires"]:
        try:
            exp = datetime.strptime(info["expires"], "%b %d %H:%M:%S %Y %Z")
            exp = exp.replace(tzinfo=timezone.utc)
            info["expires_iso"] = exp.isoformat(timespec="seconds")
            info["days_left"] = int((exp - datetime.now(timezone.utc)).total_seconds() // 86400)
        except ValueError:
            pass

    if info["self_signed"]:
        info["status"] = "placeholder"
    elif info["days_left"] is None:
        info["status"] = "unknown"
    elif info["days_left"] < 0:
        info["status"] = "expired"
    elif info["days_left"] <= EXPIRY_WARN_DAYS:
        info["status"] = "expiring"
    else:
        info["status"] = "valid"
    return info


def parse_domains(cert):
    return [d.strip() for d in re.split(r"[\s,]+", cert.get("domains", "")) if d.strip()]


# --------------------------------------------------------------------------
# auth
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# authentication: interactive login for people, API key for the peer/scripts
# --------------------------------------------------------------------------

PBKDF2_ITERATIONS = 240000
SESSION_COOKIE = "ham_session"
_login_fails = {}       # remote address -> [failure count, locked-until timestamp]
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SECONDS = 60


def hash_password(password, salt=None, iterations=PBKDF2_ITERATIONS):
    salt = salt or os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations)
    return {"salt": salt, "hash": dk.hex(), "iterations": iterations}


def verify_password(password, admin):
    if not (admin.get("hash") and admin.get("salt")):
        return False
    got = hash_password(password, admin["salt"], admin.get("iterations") or PBKDF2_ITERATIONS)
    return hmac.compare_digest(got["hash"], admin["hash"])


def set_admin(cfg, username, password):
    rec = hash_password(password)
    rec["username"] = (username or "admin").strip() or "admin"
    rec["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cfg["local"]["admin"] = rec
    return cfg


def needs_setup(cfg):
    """True while no administrator exists -- the UI then offers to create one."""
    return not (cfg["local"].get("admin") or {}).get("hash")


def session_secret(cfg):
    secret = cfg["local"].get("session_secret") or ""
    if not secret:
        secret = os.urandom(32).hex()
        cfg["local"]["session_secret"] = secret
        save_config(cfg)
    return secret


def make_session(cfg, username):
    exp = int(time.time()) + max(1, int(cfg["local"].get("session_hours") or 12)) * 3600
    payload = "%s|%d" % (username, exp)
    sig = hmac.new(session_secret(cfg).encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(("%s|%s" % (payload, sig)).encode()).decode()


def read_session(cfg, token):
    """Return the username carried by a valid, unexpired token, else None."""
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, exp, sig = raw.rsplit("|", 2)
    except Exception:
        return None
    payload = "%s|%s" % (username, exp)
    want = hmac.new(session_secret(cfg).encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, sig):
        return None
    try:
        if int(exp) < time.time():
            return None
    except ValueError:
        return None
    return username


def current_user(cfg=None):
    cfg = cfg or load_config()
    token = request.cookies.get(SESSION_COOKIE, "")
    return read_session(cfg, token) if token else None


PUBLIC_PATHS = {"/api/login", "/api/whoami", "/api/setup"}


@app.before_request
def _auth():
    if not request.path.startswith("/api/"):
        return
    if request.path in PUBLIC_PATHS:
        return
    if request.path == "/api/sync/receive":
        return  # enforced inside the handler (always requires the API key)

    cfg = load_config()
    if needs_setup(cfg) and not cfg["local"].get("api_key"):
        return  # first run: no administrator yet, nothing to check against

    if current_user(cfg):
        return
    key = cfg["local"].get("api_key", "")
    if key and hmac.compare_digest(key, request.headers.get("X-API-Key", "")):
        return
    abort(401)


@app.get("/api/whoami")
def api_whoami():
    cfg = load_config()
    return jsonify({
        "authenticated": bool(current_user(cfg)),
        "username": current_user(cfg) or "",
        "needs_setup": needs_setup(cfg),
        "admin_username": (cfg["local"].get("admin") or {}).get("username", "admin"),
    })


def _login_ok(cfg, username, resp_body):
    resp = jsonify(resp_body)
    resp.set_cookie(
        SESSION_COOKIE, make_session(cfg, username),
        max_age=max(1, int(cfg["local"].get("session_hours") or 12)) * 3600,
        httponly=True, samesite="Strict", secure=request.is_secure, path="/",
    )
    return resp


@app.post("/api/setup")
def api_setup():
    """Create the first administrator. Only possible while none exists."""
    cfg = load_config()
    if not needs_setup(cfg):
        return jsonify({"ok": False, "error": "an administrator already exists"}), 409
    body = request.get_json(force=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username:
        return jsonify({"ok": False, "error": "a username is required"}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "error": "the password must be at least 8 characters"}), 400
    set_admin(cfg, username, password)
    save_config(cfg)
    return _login_ok(cfg, username, {"ok": True, "username": username})


@app.post("/api/login")
def api_login():
    cfg = load_config()
    ip = request.remote_addr or "?"
    fails, until = _login_fails.get(ip, [0, 0])
    if until > time.time():
        return jsonify({"ok": False, "error": "too many failed attempts -- try again in %d seconds"
                                              % int(until - time.time())}), 429

    body = request.get_json(force=True) or {}
    admin = cfg["local"].get("admin") or {}
    username = (body.get("username") or "").strip()
    ok = (hmac.compare_digest(username.encode(), admin.get("username", "").encode()) and
          verify_password(body.get("password") or "", admin))
    if not ok:
        fails += 1
        if fails >= LOGIN_MAX_FAILS:
            _login_fails[ip] = [0, time.time() + LOGIN_LOCK_SECONDS]   # locked; counter restarts
        else:
            _login_fails[ip] = [fails, 0]
        time.sleep(0.5)  # blunt the rate of online guessing
        return jsonify({"ok": False, "error": "invalid username or password"}), 401

    _login_fails.pop(ip, None)
    return _login_ok(cfg, username, {"ok": True, "username": username})


@app.post("/api/logout")
def api_logout():
    resp = jsonify({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.post("/api/password")
def api_password():
    """Change the administrator username and/or password (session required)."""
    cfg = load_config()
    user = current_user(cfg)
    if not user:
        return jsonify({"ok": False, "error": "log in first"}), 401
    body = request.get_json(force=True) or {}
    admin = cfg["local"].get("admin") or {}
    if not verify_password(body.get("current") or "", admin):
        time.sleep(0.5)
        return jsonify({"ok": False, "error": "the current password is not correct"}), 401
    new = body.get("new") or ""
    if len(new) < 8:
        return jsonify({"ok": False, "error": "the new password must be at least 8 characters"}), 400
    username = (body.get("username") or admin.get("username") or "admin").strip()
    set_admin(cfg, username, new)
    save_config(cfg)
    return _login_ok(cfg, username, {"ok": True, "username": username})


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


def record_issue(cert, res, started):
    """Remember the outcome of an issuance attempt so the UI can show it.

    Kept in _meta rather than on the certificate itself: _meta is outside
    config_hash (so a renewal does not flag the configuration as changed) and
    outside the payload pushed to the peer.
    """
    cid = cert.get("id")
    if not cid:
        return
    with _lock:
        cur = load_config()
        cur["_meta"].setdefault("issue_log", {})[cid] = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "seconds": round(time.time() - started, 1),
            "ok": bool(res.get("ok")),
            "error": res.get("error") or "",
            "log": (res.get("log") or "")[-6000:],
        }
        save_config(cur)


def acme_issue(cfg, cert, force=False):
    started = time.time()
    res = _acme_issue(cfg, cert, force=force)
    try:
        record_issue(cert, res, started)
    except OSError:
        pass  # never fail an issuance because the log could not be written
    return res


def _acme_issue(cfg, cert, force=False):
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


@app.get("/api/acme/log/<cid>")
def api_acme_log(cid):
    """The acme.sh output of the last issue/renew attempt for one certificate."""
    entry = (load_config()["_meta"].get("issue_log") or {}).get(cid)
    if not entry:
        return jsonify({"ok": False, "error": "no issuance has been attempted for this certificate yet"})
    return jsonify({"ok": True, "entry": entry})


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
# export / import
# --------------------------------------------------------------------------

BACKUP_FORMAT = 1


def _download(text, filename, mime="text/plain"):
    return app.response_class(text, mimetype=mime, headers={
        "Content-Disposition": 'attachment; filename="%s"' % filename,
        "Cache-Control": "no-store",
    })


@app.get("/api/export/haproxy.cfg")
def api_export_haproxy():
    """The haproxy.cfg this configuration renders to, as a download."""
    return _download(render_haproxy(load_config()), "haproxy.cfg")


@app.get("/api/export/keepalived.conf")
def api_export_keepalived():
    cfg = load_config()
    if not cfg["local"]["keepalived"].get("enabled"):
        return _download("# Keepalived is disabled on this node.\n", "keepalived.conf")
    return _download(render_keepalived(cfg), "keepalived.conf")


@app.get("/api/export/config")
def api_export_config():
    """Everything the UI manages, as a restorable JSON backup.

    Node-local settings (Keepalived, sync target, API key, login) and the
    private keys under the certificate directory are deliberately left out: a
    backup should be safe to copy around, and node-local settings differ per
    node by design.
    """
    cfg = load_config()
    payload = {
        "format": BACKUP_FORMAT,
        "exported": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": socket.gethostname(),
        "config": {"haproxy": cfg["haproxy"], "acme": cfg["acme"]},
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return _download(json.dumps(payload, indent=2) + "\n",
                     "haproxy-manager-%s-%s.json" % (socket.gethostname(), stamp),
                     "application/json")


def _count_objects(section):
    return {k: len(v) for k, v in section.items() if isinstance(v, list)}


@app.post("/api/import/config")
def api_import_config():
    """Restore a backup. Replaces the shared objects, keeps node-local settings.

    Nothing is applied: the caller reviews the result and presses Apply.
    """
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "the file is not valid JSON"}), 400

    incoming = body.get("config") if isinstance(body.get("config"), dict) else body
    if not isinstance(incoming, dict) or not any(k in incoming for k in ("haproxy", "acme")):
        return jsonify({"ok": False, "error":
                        "not a haproxy-manager backup -- expected a \"haproxy\" or \"acme\" section"}), 400
    fmt = body.get("format", BACKUP_FORMAT)
    if isinstance(fmt, int) and fmt > BACKUP_FORMAT:
        return jsonify({"ok": False, "error":
                        "this backup was written by a newer version (format %s)" % fmt}), 400

    with _lock:
        cfg = load_config()
        restored = {}
        for section in ("haproxy", "acme"):
            part = incoming.get(section)
            if not isinstance(part, dict):
                continue
            for coll in VALID_COLLECTIONS[section]:
                if coll in part and not isinstance(part[coll], list):
                    return jsonify({"ok": False, "error":
                                    "%s/%s should be a list" % (section, coll)}), 400
            cfg[section] = _merge_defaults(copy.deepcopy(part), DEFAULT_CONFIG[section])
            restored[section] = _count_objects(cfg[section])
        # Anything without an id would be invisible to the CRUD endpoints.
        for section in ("haproxy", "acme"):
            for coll in VALID_COLLECTIONS[section]:
                for item in cfg[section].get(coll, []):
                    if not item.get("id"):
                        item["id"] = str(uuid.uuid4())
        save_config(cfg)

    return jsonify({"ok": True, "restored": restored, "source": body.get("source", ""),
                    "exported": body.get("exported", ""),
                    "note": "Review the imported objects, then press Apply."})


# --------------------------------------------------------------------------
# static
# --------------------------------------------------------------------------

@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


def _cli(argv):
    """Small maintenance CLI so installers do not reimplement the hashing.

        app.py set-admin <username> <password>   create/replace the UI login
        app.py set-admin <username> -            read the password from stdin
        app.py show-admin                        print the configured username
    """
    cmd = argv[0]
    if cmd == "set-admin":
        if len(argv) != 3:
            print("usage: app.py set-admin <username> <password|->", file=sys.stderr)
            return 2
        # "-" keeps the password out of the process list.
        password = sys.stdin.read().rstrip("\n") if argv[2] == "-" else argv[2]
        if len(password) < 8:
            print("the password must be at least 8 characters", file=sys.stderr)
            return 1
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        cfg = load_config()
        set_admin(cfg, argv[1], password)
        save_config(cfg)
        print("administrator '%s' set" % cfg["local"]["admin"]["username"])
        return 0
    if cmd == "show-admin":
        admin = load_config()["local"].get("admin") or {}
        print(admin.get("username", "") if admin.get("hash") else "")
        return 0
    print("unknown command: %s" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(_cli(sys.argv[1:]))
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not CONF_PATH.exists():
        save_config(load_config())
    threading.Thread(target=_renew_loop, daemon=True).start()
    app.run(host=LISTEN, port=PORT, threaded=True)
