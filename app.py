#!/usr/bin/env python3
"""
HAProxy Cluster Manager -- a small self-hosted web UI for managing:

  * an HAProxy configuration: Public Services, Backend Pools, Real Servers,
    Conditions, Rules, Health Monitors and settings, published through a
    service wizard that creates and updates those objects together
  * Let's Encrypt (ACME) certificates via acme.sh: accounts, challenge types
    and certificates, renewed automatically by the node that holds the VIP and
    pushed to the others
  * a cluster of any number of nodes using Keepalived on a shared virtual IP,
    with push-based settings and certificate sync between them
  * a watchdog that restarts HAProxy and Keepalived when they stop answering,
    and notifications by email, Pushover or webhook when something needs a
    person

One JSON config store, no database. Everything HAProxy and Keepalived read is
generated from it and validated before it is written.

Requires: Flask, requests, waitress, haproxy, keepalived, openssl, acme.sh.
Runs as root -- it writes /etc/haproxy and /etc/keepalived and reloads services
through systemctl. Served by waitress as a single process with a thread pool;
see _serve() for why it must not be run with multiple worker processes.

Configuration lives in the UI. Environment overrides are documented in
docs/configuration.md; HAM_DRY_RUN=1 renders and validates without reloading
anything, which is how the tests run.
"""

import base64
import concurrent.futures
import logging
import logging.handlers
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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
import urllib.parse
import urllib.request

from flask import Flask, Response, abort, jsonify, request, send_from_directory

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
STATS_SOCK = Path(os.environ.get("HAM_STATS_SOCK", "/run/haproxy/admin.sock"))

# Where the daily update check looks, and what a one-click update installs.
UPDATE_REPO = os.environ.get("HAM_REPO", "avandeputte/haproxy-manager")
UPDATE_REF = os.environ.get("HAM_REF", "main")
UPDATE_CHECK_HOURS = 24
# Overridable so a fork, a private mirror or a test rig can be pointed at.
VERSION_URL = os.environ.get(
    "HAM_VERSION_URL", "https://raw.githubusercontent.com/%s/%s/VERSION" % (UPDATE_REPO, UPDATE_REF))
INSTALL_URL = os.environ.get(
    "HAM_INSTALL_URL", "https://raw.githubusercontent.com/%s/%s/install.sh" % (UPDATE_REPO, UPDATE_REF))


def _read_version():
    """The VERSION file shipped next to app.py is the single source of truth."""
    try:
        return (Path(__file__).with_name("VERSION")).read_text().strip() or "0"
    except OSError:
        return "0"


VERSION = _read_version()


# --------------------------------------------------------------------------
# logging
# --------------------------------------------------------------------------

LOG_PATH = Path(os.environ.get("HAM_LOG_FILE", str(DATA_DIR / "haproxy-manager.log")))
LOG_MAX_BYTES = 4 * 1024 * 1024
log = logging.getLogger("haproxy-manager")


def setup_logging():
    """Log to a rotating file and to stdout, so both the journal and the log
    viewer see the same lines."""
    if log.handlers:
        return
    log.setLevel(logging.DEBUG if os.environ.get("HAM_DEBUG") else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S%z")
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(LOG_PATH, maxBytes=LOG_MAX_BYTES, backupCount=3)
        fh.setFormatter(fmt)
        log.addHandler(fh)
        os.chmod(LOG_PATH, 0o600)          # it records who signed in from where
    except OSError:
        pass                               # stdout alone is better than nothing
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    log.propagate = False       # the root logger would print every line twice


setup_logging()

LISTEN = os.environ.get("HAM_LISTEN", "0.0.0.0")
PORT = int(os.environ.get("HAM_PORT", "8080"))
THREADS = max(4, int(os.environ.get("HAM_THREADS", "16")))
# How long to wait on another node before calling it unreachable, as
# (connect, read). requests applies a bare number to BOTH phases, so a plain
# timeout=6 can take 12 seconds against a node that accepts the connection and
# then stops answering -- which is exactly what a node busy in an Apply does.
PEER_CONNECT_TIMEOUT = float(os.environ.get("HAM_PEER_CONNECT_TIMEOUT", "3"))
PEER_READ_TIMEOUT = float(os.environ.get("HAM_PEER_READ_TIMEOUT", "5"))
PEER_TIMEOUT = (PEER_CONNECT_TIMEOUT, PEER_READ_TIMEOUT)
# A push is a whole configuration and the far side applies it, so it gets a
# much longer read budget than a health poll -- but the same connect budget.
PUSH_READ_TIMEOUT = float(os.environ.get("HAM_PUSH_READ_TIMEOUT", "90"))
# Node health is collected in the background by the watchdog and served from
# that snapshot, so a page load never waits on the network. If the snapshot is
# older than this the request collects it inline instead -- the refresher has
# stopped, and stale health is worse than a slow page.
CLUSTER_POLL_SECONDS = float(os.environ.get("HAM_CLUSTER_POLL", "15"))
CLUSTER_SNAPSHOT_MAX_AGE = float(os.environ.get("HAM_CLUSTER_MAX_AGE", "60"))
# How long a liveness probe may take before the service counts as unresponsive.
WATCHDOG_PROBE_TIMEOUT = float(os.environ.get("HAM_WATCHDOG_PROBE_TIMEOUT", "5"))
WATCHDOG_SELF_TIMEOUT = float(os.environ.get("HAM_WATCHDOG_SELF_TIMEOUT", "10"))
DRY_RUN = os.environ.get("HAM_DRY_RUN") == "1"

app = Flask(__name__, static_folder=None)
# A request body is read into memory before a handler sees it. The largest
# legitimate one is a sync payload carrying certificates, which is well under
# a megabyte; anything past this is refused with 413 rather than buffered.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
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
    },
    # Cluster-wide VRRP settings: identical on every node, so they sync.
    "cluster": {
        # The name that should reach whichever node is currently active. It is
        # shared, because every node has to answer for it -- the one holding the
        # virtual IP is the one that will.
        "ui_url": "",
        "vrid": 51,
        "vips": "",            # one address/prefix per line
        "auth_pass": "",
        "advert_int": 1,
        "state": "BACKUP",
        "nopreempt": True,
        "track_haproxy": True,
        "custom": "",
    },
    "notify": {
        # Shared, so it is configured once and propagates: every node then
        # alerts about its own troubles using the same destinations.
        "enabled": True,
        "min_severity": "warning",       # info | warning | error
        "repeat_hours": 6,               # re-tell an unresolved problem this often
        "events": {"certificates": True, "watchdog": True, "apply": True,
                   "cluster": True, "updates": True},
        # [{id, name, type, enabled, ...type-specific fields}]
        "destinations": [],
    },
    "local": {
        # node-local settings -- never overwritten by sync
        "api_key": "",
        "node_url": "",        # how the OTHER nodes should reach this one
        "web_ui": {"enabled": False, "url": "", "certificate": "auto", "rule_id": ""},
        # UI login. The password is only ever stored as a PBKDF2 hash.
        # email: who to reach about this node. Offered as the default when an
        # ACME account is created, and as the recipient when notifications are
        # set up, so it is only typed once.
        "admin": {"username": "admin", "email": "", "salt": "", "hash": "",
                  "iterations": 0, "updated": ""},
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
        "watchdog": {
            # Supervises the services this node runs. Node-local: each node
            # watches its own, and a passive node still restarts its HAProxy.
            "enabled": True,
            "interval": 20,             # seconds between rounds
            "haproxy": True,
            "keepalived": True,
            "max_restarts": 3,          # per window, before it stops trying
            "window": 900,
        },
        "sync": {
            # One entry per other node: {id, name, url, api_key, verify_tls, enabled}
            "peers": [],
            "auto_sync": False,    # push to every peer after a successful Apply
            # Legacy single-peer fields, migrated into "peers" on load.
            "peer_url": "",
            "peer_api_key": "",
            "verify_tls": False,
        },
    },
    "_meta": {"applied_hash": ""},
}

VALID_COLLECTIONS = {
    "haproxy": {"servers", "backends", "frontends", "healthchecks", "conditions", "rules"},
    "acme": {"accounts", "challenges", "certificates"},
}


def _merge_defaults(dst, src):
    for k, v in src.items():
        if k not in dst:
            dst[k] = copy.deepcopy(v)
        elif isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge_defaults(dst[k], v)
    return dst


CLUSTER_KEYS = ("vrid", "vips", "auth_pass", "advert_int", "state",
                "nopreempt", "track_haproxy", "custom")


def _looks_configured(cfg):
    """Has this node been set up already, by any route?

    The setup wizard records a flag, but every install that predates it has
    none -- and a node that was configured by hand, or that received its
    configuration from a peer, must not be greeted as if it were brand new.
    """
    hp = cfg["haproxy"]
    return bool(
        cfg["local"]["sync"].get("peers")
        or (cfg["cluster"].get("vips") or "").strip()
        or cfg["local"]["keepalived"].get("enabled")
        or hp["frontends"] or hp["backends"] or hp["servers"]
        or cfg["acme"]["certificates"] or cfg["acme"]["accounts"]
    )


def _migrate(cfg):
    """Bring an older config forward. Idempotent; persisted on the next save."""
    if not cfg["_meta"].get("setup_complete") and _looks_configured(cfg):
        cfg["_meta"]["setup_complete"] = True
    # The unlock used to be stored here and outlived every session.
    cfg["local"].pop("allow_edit_when_passive", None)
    # VRRP settings that must match across nodes moved from local.keepalived
    # into the shared cluster section.
    k, cl = cfg["local"]["keepalived"], cfg["cluster"]
    if not cl.get("vips") and k.get("vips"):
        for key in CLUSTER_KEYS:
            if key in k:
                cl[key] = k[key]

    s = cfg["local"]["sync"]
    if s.get("peer_url") and not s.get("peers"):
        s["peers"] = [{
            "id": str(uuid.uuid4()),
            "name": urlsplit(s["peer_url"]).hostname or "peer",
            "url": s["peer_url"].rstrip("/"),
            "api_key": s.get("peer_api_key", ""),
            "verify_tls": bool(s.get("verify_tls")),
            "enabled": True,
        }]
    return cfg


def load_config():
    """Read the configuration. Deliberately does NOT take _lock.

    save_config writes a temporary file and renames it into place, and rename
    is atomic: a reader sees either the whole old file or the whole new one,
    never a half-written mixture. Taking the write lock here would mean every
    read -- every page of the UI -- queues behind whatever slow write is in
    flight, so one Apply pushing to an unresponsive node froze the entire UI
    for as long as the push took. Writers still hold _lock across their own
    load/modify/save, which is what makes those sequences atomic.
    """
    cfg = {}
    if CONF_PATH.exists():
        try:
            cfg = json.loads(CONF_PATH.read_text())
        except (ValueError, OSError):
            cfg = {}
    return _migrate(_merge_defaults(cfg, DEFAULT_CONFIG))


def save_config(cfg):
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CONF_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2))
        # It holds the API key, the session secret, the peers' keys and the
        # password hash. The directory is 0700, but the file should not rely
        # on that alone -- a backup or a loosened directory would expose it.
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONF_PATH)


def config_hash(cfg):
    payload = json.dumps(
        {"haproxy": cfg["haproxy"], "acme": cfg["acme"], "cluster": cfg["cluster"],
         "keepalived": cfg["local"]["keepalived"]},
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
    # Children must not inherit NOTIFY_SOCKET. With NotifyAccess=main, systemd
    # logs "Got notification message from PID ..., but reception only permitted
    # for main PID ..." for every helper that touches it -- one line of noise
    # per subprocess, and this app runs a lot of them.
    child_env = dict(env if env is not None else os.environ)
    child_env.pop("NOTIFY_SOCKET", None)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=child_env, timeout=timeout)
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
SESSION_COOKIE = "ham_session_" + hashlib.sha256(
    ("%s:%s" % (socket.gethostname(), PORT)).encode()).hexdigest()[:8]
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


def key_fingerprint(key):
    """A short, stable tag for a key, so two nodes can be compared by eye."""
    key = (key or "").strip()
    return hashlib.sha256(key.encode()).hexdigest()[:8] if key else ""


def key_matches(stored, presented):
    """Compare API keys, ignoring whitespace a copy-and-paste picked up.

    A key pasted with a trailing newline looks identical on screen but fails a
    byte comparison, which surfaces only as an unexplained 401.
    """
    stored = (stored or "").strip()
    presented = (presented or "").strip()
    if not stored or not presented:
        return False
    try:
        return hmac.compare_digest(stored.encode(), presented.encode())
    except (UnicodeEncodeError, TypeError):
        return False


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


def make_session(cfg, username, unlocked=False):
    exp = int(time.time()) + max(1, int(cfg["local"].get("session_hours") or 12)) * 3600
    payload = "%s|%d|%d" % (username, exp, 1 if unlocked else 0)
    sig = hmac.new(session_secret(cfg).encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(("%s|%s" % (payload, sig)).encode()).decode()


def read_session(cfg, token):
    """Return the username carried by a valid, unexpired token, else None."""
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        body, sig = raw.rsplit("|", 1)
        parts = body.split("|")
        username, exp = parts[0], parts[1]
        unlocked = len(parts) > 2 and parts[2] == "1"
    except Exception:
        return None
    payload = body
    want = hmac.new(session_secret(cfg).encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, sig):
        return None
    try:
        if int(exp) < time.time():
            return None
    except ValueError:
        return None
    return {"user": username, "unlocked": unlocked}


def current_session(cfg=None):
    cfg = cfg or load_config()
    token = request.cookies.get(SESSION_COOKIE, "")
    return (read_session(cfg, token) if token else None) or {}


def current_user(cfg=None):
    return current_session(cfg).get("user")


def session_unlocked(cfg=None):
    """Has this session lifted the passive-node lock? It cannot outlive it."""
    try:
        return bool(current_session(cfg).get("unlocked"))
    except RuntimeError:            # no request context: background threads
        return False


PUBLIC_PATHS = {"/api/login", "/api/whoami", "/api/setup"}   # /api/setup creates the first admin

# Shared configuration is edited on the node that holds the virtual IP and
# pushed out from there. Everything a passive node needs to fix ITSELF -- its
# interface, priority, login, API key, peer list, updates -- stays editable,
# otherwise a node that cannot take the VIP could never be repaired.
LOCAL_WRITE_PREFIXES = (
    "/api/local", "/api/password", "/api/logout", "/api/peers",
    "/api/update", "/api/version", "/api/apply", "/api/sync/receive", "/api/setup",
    "/api/webui",          # this node's own UI address, not shared
    "/api/unlock",         # lifting the lock cannot itself be blocked by it
)


def node_role(cfg):
    vips = cluster_vips(cfg)
    if not vips:
        return "standalone", []
    rc, out = run(["ip", "-o", "addr"])
    held = [v for v in vips if rc == 0 and re.search(r"\binet6? %s/" % re.escape(v), out)]
    return ("active" if held else "passive"), held


def readonly_state(cfg):
    """(read_only, reason). Only a passive node is read-only, and only if asked."""
    if session_unlocked(cfg):
        return False, ""
    role, _ = node_role(cfg)
    if role != "passive":
        return False, ""
    if not enabled_peers(cfg):
        # Nothing to defer to. A lone node that has not won the virtual IP --
        # during bring-up, or because VRRP is broken -- must stay usable.
        return False, ""
    return True, ("This node is passive: another node holds the virtual IP and serves traffic. "
                  "Change the shared configuration there and push it here, so the two cannot "
                  "diverge. This node's own settings stay editable.")


@app.after_request
def _audit(resp):
    """One line per change, so the log says who did what from where."""
    if request.path.startswith("/api/") and request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if request.path not in ("/api/login", "/api/whoami"):
            try:
                who = current_user() or ("api-key" if request.headers.get("X-API-Key") else "anonymous")
            except Exception:
                who = "?"
            what = ""
            if request.is_json:
                # the name only -- request bodies carry passwords and API keys
                try:
                    name = (request.get_json(silent=True) or {}).get("name")
                    what = " '%s'" % str(name)[:80] if name else ""
                except Exception:
                    what = ""
            level = log.info if resp.status_code < 400 else log.warning
            level("%s %s %s%s -> %s (%s)", who, request.method, request.path,
                  what, resp.status_code, request.remote_addr)
    return resp


@app.before_request
def _auth():
    if not request.path.startswith("/api/"):
        return

    # Flask's MAX_CONTENT_LENGTH is only applied by the form parser on the
    # Werkzeug that ships with Debian, so a JSON body of any size is read into
    # memory. Check it here, before anything reads the stream.
    limit = app.config.get("MAX_CONTENT_LENGTH") or 0
    if limit and (request.content_length or 0) > limit:
        return jsonify({"ok": False, "error":
                        "the request body is too large (%d bytes, limit %d)"
                        % (request.content_length, limit)}), 413
    if request.path in PUBLIC_PATHS:
        return
    if request.path == "/api/sync/receive":
        return  # enforced inside the handler (always requires the API key)

    cfg = load_config()
    if needs_setup(cfg) and not cfg["local"].get("api_key"):
        # First run. Only the calls that create the administrator are open;
        # everything else stays shut, so a node waiting to be set up does not
        # hand its configuration to whoever reaches it first.
        if request.path == "/api/setup/state":
            return
        return jsonify({"ok": False, "needs_setup": True, "error":
                        "This node has no administrator yet. Open it in a browser and create "
                        "one; until then only setup is available."}), 401

    authorised = bool(current_user(cfg))
    if not authorised:
        authorised = key_matches(cfg["local"].get("api_key"), request.headers.get("X-API-Key"))
    if not authorised:
        presented = request.headers.get("X-API-Key")
        # header_seen is always reported: a request that arrives with no key at
        # all is the signature of something stripping it in transit.
        body = {"ok": False, "hostname": socket.gethostname(), "version": VERSION,
                "header_seen": presented is not None,
                "error": "not authorised: sign in, or present this node's API key as X-API-Key"}
        if presented is not None:          # a machine tried a key: help it compare
            body.update({"presented_fp": key_fingerprint(presented),
                         "expected_fp": key_fingerprint(cfg["local"].get("api_key"))})
        return jsonify(body), 401

    if request.method in ("POST", "PUT", "DELETE", "PATCH") and \
            not request.path.startswith(LOCAL_WRITE_PREFIXES):
        ro, why = readonly_state(cfg)
        if ro:
            return jsonify({"ok": False, "error": why, "read_only": True}), 409


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(413)
@app.errorhandler(500)
def _json_errors(e):
    """API callers get JSON, not Werkzeug's HTML page."""
    if not request.path.startswith("/api/"):
        return e
    code = getattr(e, "code", 500)
    limit = app.config.get("MAX_CONTENT_LENGTH") or 0
    if code == 400 and limit and (request.content_length or 0) > limit:
        code = 413                       # Werkzeug reports the parse failure, not the size
    text = {400: "the request body was not valid JSON",
            404: "no such endpoint or object",
            405: "that method is not allowed here",
            413: "the request body is too large",
            500: "the node hit an unexpected error"}.get(code, str(e))
    return jsonify({"ok": False, "error": text}), code


@app.get("/api/whoami")
def api_whoami():
    cfg = load_config()
    user = current_user(cfg)
    if not user:
        # Unauthenticated: only what the sign-in screen has to know. The
        # administrator's name, the hostname and the version are not for
        # anyone who can merely reach the port.
        return jsonify({"authenticated": False, "needs_setup": needs_setup(cfg)})
    return jsonify({
        "authenticated": True,
        "username": user,
        "email": (cfg["local"].get("admin") or {}).get("email", ""),
        "version": VERSION,
        "hostname": socket.gethostname(),
        "needs_setup": False,
        "admin_username": (cfg["local"].get("admin") or {}).get("username", "admin"),
    })


def _prune_login_fails():
    """Drop finished entries: one per source address would otherwise accumulate."""
    now = time.time()
    for addr in [a for a, (fails, until) in _login_fails.items() if until and until < now]:
        _login_fails.pop(addr, None)
    if len(_login_fails) > 5000:            # a flood from many addresses
        _login_fails.clear()


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
    with _lock:
        cfg = load_config()
        if not needs_setup(cfg):        # someone else got there first
            return jsonify({"ok": False, "error": "an administrator already exists"}), 409
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
        _prune_login_fails()
        log.warning("failed sign-in for %r from %s (%d in a row)", username, ip, fails)
        time.sleep(0.5)  # blunt the rate of online guessing
        return jsonify({"ok": False, "error": "invalid username or password"}), 401

    _login_fails.pop(ip, None)
    log.info("signed in: %s from %s", username, ip)
    return _login_ok(cfg, username, {"ok": True, "username": username})


@app.post("/api/unlock")
def api_unlock():
    """Lift or restore the passive-node lock for this session only.

    Kept in the session rather than the configuration so it cannot outlive the
    person who set it: signing out or back in restores the lock.
    """
    cfg = load_config()
    user = current_user(cfg)
    if not user:
        return jsonify({"ok": False, "error": "sign in first"}), 401
    on = bool((request.get_json(silent=True) or {}).get("on"))
    resp = jsonify({"ok": True, "unlocked": on})
    resp.set_cookie(SESSION_COOKIE, make_session(cfg, user, unlocked=on),
                    max_age=max(1, int(cfg["local"].get("session_hours") or 12)) * 3600,
                    httponly=True, samesite="Strict", secure=request.is_secure, path="/")
    return resp


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
    new = body.get("new") or ""
    wants_name = (body.get("username") or admin.get("username") or "admin").strip() \
        != (admin.get("username") or "admin")
    # The current password is what proves it is still you at the keyboard, so
    # anything that changes how you sign in requires it. The email is not a
    # credential and there is no reset-by-email here, so a session is enough.
    if new or wants_name:
        if not verify_password(body.get("current") or "", admin):
            time.sleep(0.5)
            return jsonify({"ok": False, "error":
                            "the current password is not correct"}), 401
    # The email can be changed on its own; a password only when one is given.
    email = body.get("email")
    if email is not None:
        email = str(email).strip()
        if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return jsonify({"ok": False, "error": "that does not look like an email address"}), 400
    if new and len(new) < 8:
        return jsonify({"ok": False, "error": "the new password must be at least 8 characters"}), 400
    username = (body.get("username") or admin.get("username") or "admin").strip()
    with _lock:
        cfg = load_config()
        if new:
            set_admin(cfg, username, new)
        else:
            cfg["local"]["admin"]["username"] = username
        if email is not None:
            cfg["local"]["admin"]["email"] = email
        save_config(cfg)
    if new or wants_name:
        return _login_ok(cfg, username, {"ok": True, "username": username})
    return jsonify({"ok": True, "username": username,
                    "email": cfg["local"]["admin"].get("email", "")})


# --------------------------------------------------------------------------
# settings validation
#
# `haproxy -c` is the authority on whether a configuration works, but it is
# lenient about types: `maxconn not-a-number` parses as zero and validates
# clean, silently capping the proxy at nothing. So the obviously-typed fields
# are checked here first, before anything is written.
# --------------------------------------------------------------------------

NUMERIC_SETTINGS = {
    "haproxy": {"maxconn": (1, 2000000), "nbthread": (1, 256), "retries": (0, 100)},
    "acme": {"challenge_port": (1, 65535), "renew_hours": (1, 8760)},
}
TIME_SETTINGS = {"haproxy": ["timeout_client", "timeout_connect", "timeout_server",
                             "hard_stop_after"]}
TIME_RE = re.compile(r"^\d+(us|ms|s|m|h|d)?$")


def check_setting_types(sec, proposed):
    """Return a human-readable complaint, or "" when the values make sense."""
    problems = []
    for key, (lo, hi) in NUMERIC_SETTINGS.get(sec, {}).items():
        if key not in proposed:
            continue
        raw = proposed[key]
        if raw in ("", None):                  # empty means "use the default"
            continue
        try:
            val = int(str(raw).strip())
        except (TypeError, ValueError):
            problems.append("%s must be a whole number, not %r." % (key, raw))
            continue
        if not lo <= val <= hi:
            problems.append("%s must be between %d and %d." % (key, lo, hi))
    for key in TIME_SETTINGS.get(sec, []):
        raw = proposed.get(key)
        if raw in ("", None):
            continue
        if not TIME_RE.match(str(raw).strip()):
            problems.append("%s must be a time such as 50s, 5000 or 1m -- not %r." % (key, raw))
    return "\n".join(problems)


# --------------------------------------------------------------------------
# generic CRUD
# --------------------------------------------------------------------------

def service_owned(cfg):
    """Which HAProxy objects exist because a service was published.

    Derived from what the services actually reference rather than from a mark
    written at creation time: a mark goes stale the moment something is edited
    or rebuilt, and this cannot. Returns {object id: service name}.
    """
    hp = cfg["haproxy"]
    rules, backends = _by_id(hp["rules"]), _by_id(hp["backends"])
    owned = {}

    def claim(oid, name):
        if oid and oid not in owned:
            owned[oid] = name

    for fe in hp.get("frontends") or []:
        for rid in (fe.get("rules") or []):
            rule = rules.get(rid)
            if not rule or rule.get("type") != "use_backend":
                continue
            pool = backends.get(rule.get("backend"))
            if not pool:
                continue
            name = pool.get("name") or rule.get("name") or "a service"
            claim(rule.get("id"), name)
            claim(pool.get("id"), name)
            for cid in (rule.get("conditions") or []):
                claim(cid, name)
            for sid in (pool.get("servers") or []):
                claim(sid, name)
            if pool.get("healthcheck"):
                claim(pool["healthcheck"], name)
    # a TCP service is a listener with a default backend and no rule at all
    for fe in hp.get("frontends") or []:
        pool = backends.get(fe.get("default_backend"))
        if not pool:
            continue
        name = pool.get("name") or fe.get("name") or "a service"
        claim(fe.get("id"), name)
        claim(pool.get("id"), name)
        for sid in (pool.get("servers") or []):
            claim(sid, name)
        if pool.get("healthcheck"):
            claim(pool["healthcheck"], name)
    return owned


@app.route("/api/<sec>/<col>", methods=["GET", "POST", "PUT"])
def collection(sec, col):
    if col == "settings":
        if sec not in ("haproxy", "acme"):
            abort(404)
        if request.method == "GET":
            return jsonify(load_config()[sec]["settings"])
        proposed = request.get_json(force=True) or {}
        bad = check_setting_types(sec, proposed)
        if bad:
            return jsonify({"error": "These settings were not saved.\n\n" + bad}), 400
        # validated outside the lock: it runs haproxy -c, which is slow
        ok, message = check_rendered(draft_with(sec, proposed))
        if not ok:
            return jsonify({"error": "These settings were not saved -- they do not produce a "
                                     "working configuration.\n\n" + message}), 400
        with _lock:
            cfg = load_config()
            cfg[sec]["settings"].update(proposed)
            save_config(cfg)
            return jsonify(cfg[sec]["settings"])
    if sec not in VALID_COLLECTIONS or col not in VALID_COLLECTIONS[sec]:
        abort(404)
    if request.method == "GET":
        cfg = load_config()
        items = cfg[sec][col]
        if sec == "haproxy":
            # Say which of these a published service is responsible for, so the
            # advanced pages can warn before someone edits one by hand.
            owned = service_owned(cfg)
            items = [dict(i, managed_by=owned[i["id"]]) if i.get("id") in owned else i
                     for i in items]
        return jsonify(items)
    if request.method == "POST":
        item = request.get_json(force=True) or {}
        if not item.get("name"):
            return jsonify({"error": "name is required"}), 400
        with _lock:
            cfg = load_config()
            item["id"] = str(uuid.uuid4())
            cfg[sec][col].append(item)
            save_config(cfg)
        return jsonify(item)
    abort(405)


@app.route("/api/<sec>/<col>/<iid>", methods=["PUT", "DELETE"])
def collection_item(sec, col, iid):
    if sec not in VALID_COLLECTIONS or col not in VALID_COLLECTIONS[sec]:
        abort(404)
    with _lock:
        cfg = load_config()
        items = cfg[sec][col]
        for i, x in enumerate(items):
            if x.get("id") != iid:
                continue
            if x.get(LOCAL_ONLY):
                return jsonify({"error":
                                "\"%s\" is part of this node's web UI service and is managed from "
                                "System > Web UI access. Change it there, or turn it off."
                                % x.get("name", iid)}), 409
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
    if request.method == "GET":
        return jsonify(load_config()["local"])
    body = request.get_json(force=True) or {}
    with _lock:
        cfg = load_config()
        for key in ("keepalived", "sync"):
            if isinstance(body.get(key), dict):
                cfg["local"][key].update(body[key])
        for key in ("api_key", "node_url"):
            if key in body:
                cfg["local"][key] = body[key].strip() if isinstance(body[key], str) else body[key]
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


# Two words per certificate against HAProxy's 64-word line limit, less the
# words the bind line already uses. Twenty is comfortably under it.
MAX_INLINE_CERTS = 20


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
            # HAProxy truncates a configuration line after 64 words, and every
            # certificate costs two of them ("crt" and its path), so a listener
            # with enough HTTPS services silently loses the rest and fails to
            # parse. Past a safe count, point it at the directory instead: every
            # certificate this app deploys lives there, and SNI picks the right
            # one either way.
            if len(crts) > MAX_INLINE_CERTS:
                A("    # %d certificates: loading the whole directory, because a"
                  % len(crts))
                A("    # bind line cannot name that many.")
                crts = []
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
        # HAProxy runs every http-request rule before any use_backend, whatever
        # order they appear in, and warns on each reload when the file does not
        # say so. Group them the way it will actually evaluate them: ACLs, then
        # request rules, then routing.
        acls, requests, routes = [], [], []

        if mode == "http" and fe.get("ssl_enabled"):
            requests.append("http-request set-header X-Forwarded-Proto https if { ssl_fc }")
        if acme_on and mode == "http":
            acls.append("acl acme_challenge path_beg /.well-known/acme-challenge/")
            routes.append("use_backend bk_acme_challenge if acme_challenge")
        if mode == "http" and fe.get("http_to_https") and not fe.get("ssl_enabled"):
            excl = " if !acme_challenge !{ ssl_fc }" if acme_on else " unless { ssl_fc }"
            requests.append("http-request redirect scheme https code 301" + excl)

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
            acls.append("acl acl_%s %s" % (_sec(c["name"]), expr))
            if mode == "tcp" and c.get("type") == "ssl_sni":
                need_inspect = True
        if need_inspect:
            requests.append("tcp-request inspect-delay 5s")
            requests.append("tcp-request content accept if { req_ssl_hello_type 1 }")

        for rid in fe.get("rules") or []:
            r = rules.get(rid)
            if not r:
                continue
            ln = _rule_line(r, conds, backends)
            if not ln:
                continue
            # Relative order is preserved inside each group, so first-match
            # routing and rule precedence are unchanged.
            (routes if ln.startswith("use_backend") else requests).append(ln)

        for ln in acls + requests + routes:
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
            htype = hc.get("type")
            if htype == "http":
                # An HTTP check can front a TCP service -- Patroni's /master on
                # 8008 deciding which PostgreSQL takes connections on 5432.
                method = hc.get("http_method", "GET")
                uri = hc.get("http_uri", "/")
                ver, host_hdr = hc.get("http_version"), hc.get("http_host")
                if ver or host_hdr:
                    # the form that can carry a version and headers
                    A("    option httpchk")
                    send = "    http-check send meth %s uri %s" % (_sec(method), uri)
                    if ver in ("HTTP/1.0", "HTTP/1.1", "HTTP/2"):
                        send += " ver %s" % ver      # the slash must survive sanitising
                    if host_hdr:
                        send += " hdr Host %s" % _sec(host_hdr)
                    A(send)
                else:
                    A("    option httpchk %s %s" % (method, uri))
                if hc.get("expect_status"):
                    A("    http-check expect status %s" % hc["expect_status"])
            elif htype == "ssl":
                A("    option ssl-hello-chk")
            elif htype == "pgsql":
                # HAProxy opens a PostgreSQL startup packet as this user; the
                # server only has to answer the handshake, no password is sent.
                A("    option pgsql-check user %s" % _sec(hc.get("db_user") or "postgres"))
            elif htype == "mysql":
                A("    option mysql-check user %s%s" % (_sec(hc.get("db_user") or "haproxy"),
                                                        " post-41" if hc.get("mysql_post41", True) else ""))
            # "tcp" needs nothing here: `check` on the server line is a connect test
        if be.get("log_health_checks"):
            A("    option log-health-checks")
        for key, directive in (("timeout_connect", "timeout connect"),
                               ("timeout_server", "timeout server"),
                               ("timeout_check", "timeout check")):
            if be.get(key):
                A("    %s %s" % (directive, _sec(str(be[key]))))
        use_cookie = be.get("persistence") == "cookie" and mode == "http"
        if use_cookie:
            A("    cookie %s insert indirect nocache" % (be.get("cookie_name") or "SRVID"))
        elif be.get("persistence") == "source":
            # Pin a client to one server by source address -- the usual choice
            # for TCP services, where there is no cookie to work with.
            # HAProxy spells the IPv4 type "ip"; "ipv4" is rejected outright.
            stype = be.get("stick_type") if be.get("stick_type") in ("ip", "ipv6") else "ip"
            A("    stick-table type %s size %s expire %s" % (
                stype, _sec(be.get("stick_size") or "50k"), _sec(be.get("stick_expire") or "30m")))
            A("    stick on src")
        for sid in be.get("servers") or []:
            sv = servers.get(sid)
            if not sv or not sv.get("enabled", True):
                continue
            parts = ["server %s %s:%s" % (_sec(sv["name"]), sv.get("address", ""), sv.get("port", ""))]
            if be.get("healthcheck_enabled"):
                parts.append("check inter %s" % inter)
                if sv.get("check_port"):
                    parts.append("port %s" % _sec(str(sv["check_port"])))
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
    """Cluster-wide VRRP settings come from cfg["cluster"]; the rest is per node."""
    k = cfg["local"]["keepalived"]
    cl = cfg["cluster"]
    L = []
    A = L.append
    A("# Generated by haproxy-manager at %s" % datetime.now(timezone.utc).isoformat(timespec="seconds"))
    A("# Generated from the cluster settings plus this node's own.")
    A("")
    if cl.get("track_haproxy", True):
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
    A("    state %s" % cl.get("state", "BACKUP"))
    A("    interface %s" % k.get("interface", "eth0"))
    A("    virtual_router_id %s" % cl.get("vrid", 51))
    A("    priority %s" % k.get("priority", 100))
    A("    advert_int %s" % cl.get("advert_int", 1))
    if cl.get("nopreempt"):
        A("    nopreempt")
    if cl.get("auth_pass"):
        A("    authentication {")
        A("        auth_type PASS")
        A("        auth_pass %s" % cl["auth_pass"][:8])  # keepalived uses max 8 chars
        A("    }")
    # Unicast VRRP: list every OTHER node. The source address is optional --
    # keepalived falls back to the interface's own address.
    peers = [p.strip() for p in re.split(r"[\s,]+", k.get("unicast_peer") or "") if p.strip()]
    if peers:
        if k.get("unicast_src"):
            A("    unicast_src_ip %s" % k["unicast_src"].strip())
        A("    unicast_peer {")
        for p in peers:
            A("        " + p)
        A("    }")
    A("    virtual_ipaddress {")
    for v in (cl.get("vips") or "").splitlines():
        if v.strip():
            A("        " + v.strip())
    A("    }")
    if cl.get("track_haproxy", True):
        A("    track_script {")
        A("        chk_haproxy")
        A("    }")
    for ln in (cl.get("custom") or "").splitlines():
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
    if keepalived_wanted(cfg):
        fd, staging = tempfile.mkstemp(suffix=".conf")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(render_keepalived(cfg))
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
        "enabled": keepalived_wanted(cfg),
        "service": service if keepalived_wanted(cfg) else "disabled",
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
            f.write(render_haproxy(cfg))
        rc, out = run(["haproxy", "-c", "-f", staging], timeout=30)
        if rc not in (0, 127):
            problems.append("HAProxy rejected it:\n" + out.strip())
    except Exception as e:
        problems.append("could not render haproxy.cfg: %s" % e)
    finally:
        if os.path.exists(staging):
            os.unlink(staging)

    if keepalived_wanted(cfg):
        fd, kstaging = tempfile.mkstemp(suffix=".conf")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(render_keepalived(cfg))
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
    return True, "haproxy -c accepts it" + (" and keepalived -t accepts it" if keepalived_wanted(cfg) else "")


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
            log.error("apply refused: haproxy -c rejected the rendered configuration: %s",
                      out.strip()[-400:])
            notify("apply", "Apply was refused on this node",
                   "The generated HAProxy configuration did not validate, so nothing was "
                   "changed and the running configuration is untouched.\n\n%s"
                   % _why_rejected(out), "error", cfg)
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
            notify("apply", "HAProxy did not reload on this node",
                   "The new configuration was written and validated, but HAProxy did not "
                   "reload, so it is still running the previous one.\n\n%s"
                   % out.strip()[:400], "error", cfg)

        k = cfg["local"]["keepalived"]
        if keepalived_wanted(cfg):
            if derive_unicast(cfg):
                result["steps"].append(
                    "unicast peers refreshed from the node list: %s"
                    % ((k.get("unicast_peer") or "").replace("\n", ", ") or "none -- using multicast"))
            ktext = render_keepalived(cfg)
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
    if allow_push and cfg["local"]["sync"].get("auto_sync") and enabled_peers(cfg):
        r = sync_push(cfg)
        result["steps"].append("auto-sync to %d peer(s): " % len(enabled_peers(cfg)) +
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
    ka = render_keepalived(cfg) if cfg["local"]["keepalived"].get("enabled") else \
        "# Keepalived is disabled on this node (Cluster > This node)."
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
    ro, ro_why = readonly_state(cfg)
    # Whether the passive-node lock has been lifted by hand, so the UI can
    # show it and offer to put it back.
    override = session_unlocked(cfg) and node_role(cfg)[0] == "passive" \
        and bool(enabled_peers(cfg))
    return jsonify({
        "read_only": ro,
        "read_only_reason": ro_why,
        "edit_override": override,
        "hostname": socket.gethostname(),
        "version": VERSION,
        "update_available": bool(upd.get("latest")) and is_newer(upd["latest"], VERSION),
        "latest_version": upd.get("latest", ""),
        "haproxy": svc_state("haproxy"),
        "keepalived": svc_state("keepalived") if keepalived_wanted(cfg) else "disabled",
        "vips": vips,
        "vip_held": held,
        "role": ("active" if held else "passive") if vips else "standalone",
        "dirty": cfg["_meta"].get("applied_hash") != config_hash(cfg),
        "certs": certs,
        "acme_installed": Path(ACME_SH).exists(),
        "renews_here": renewal_runs_here(cfg)[0],
        "renewal_note": renewal_runs_here(cfg)[1],
        "peers": len(cfg["local"]["sync"].get("peers") or []),
        "api_key_fp": key_fingerprint(cfg["local"].get("api_key")),
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
    # --log makes acme.sh keep its own log in ACME_HOME, which is what the log
    # viewer reads back. Left at the default level: level 2 traces the DNS hook
    # calls, and those carry API credentials.
    return run([ACME_SH, "--home", str(ACME_HOME), "--log"] + args, env=env)


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


def propagate_certificate(cfg, cert):
    """Send a freshly issued certificate to the other nodes.

    The deployed PEMs travel with a configuration push, so the other nodes get
    the file and reload. Without this a renewal only ever reached the node that
    performed it, and a failover served the old certificate.
    """
    peers = enabled_peers(cfg)
    if not peers:
        return ""
    r = sync_push(load_config())
    if r.get("ok"):
        return "sent to %d other node(s)" % len(peers)
    return "could not send it to the other nodes: %s" % r.get("error")


def acme_issue(cfg, cert, force=False):
    started = time.time()
    res = _acme_issue(cfg, cert, force=force)
    try:
        record_issue(cert, res, started)
        if not res.get("ok"):
            log.error("certificate %s failed: %s", cert.get("name"), res.get("error"))
            notify_transition(
                "cert:" + str(cert.get("id")), "failed", "certificates",
                "Certificate %s could not be issued" % cert.get("name"),
                "Issuing %s failed.\n\n%s\n\nDomains: %s\n\nUntil this succeeds the "
                "existing certificate stays in use, and it will eventually expire."
                % (cert.get("name"), res.get("error"), ", ".join(parse_domains(cert))),
                "error", cfg)
    except OSError:
        pass  # never fail an issuance because the log could not be written
    if res.get("ok"):
        log.info("certificate issued: %s (%s)", cert.get("name"), ", ".join(parse_domains(cert)))
        notify("certificates", "Certificate %s issued" % cert.get("name"),
               "The certificate %s was issued and deployed.\n\nDomains: %s"
               % (cert.get("name"), ", ".join(parse_domains(cert))), "info", cfg)
        note = propagate_certificate(cfg, cert)
        if note:
            res["propagated"] = note
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

    trace = []
    rc, out = ensure_account(acc)
    trace.append(out)
    if rc != 0:
        return {"ok": False, "error": "ACME account registration failed", "log": "\n".join(trace)}

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
    trace.append(out)
    if rc not in (0, 2):  # 2 = cert not yet due for renewal, treat as success
        return {"ok": False, "error": "issuance failed -- see log", "log": "\n".join(trace)}

    dep = deploy_cert(cfg, cert)
    trace.append(dep.get("log", ""))
    res = {"ok": dep["ok"], "log": "\n".join(x for x in trace if x)}
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
    auto = after_certificate_deployed(cfg, cert)
    return {"ok": True, "log": (out + ("\n" + auto if auto else "")).strip()}


def after_certificate_deployed(cfg, cert):
    """What always has to happen once a certificate lands on disk.

    HAProxy holds certificates in memory, so a new file changes nothing until
    it reloads -- this used to be an optional Automation, which meant a renewed
    certificate could sit on disk unserved. Sending it to the other nodes is
    handled by the caller.
    """
    rc, out = run(["systemctl", "reload-or-restart", "haproxy"])
    return "reloaded HAProxy" if rc == 0 else "HAProxy did not reload: %s" % out.strip()[:200]


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
    ok, why = renewal_runs_here(cfg)
    if not ok:
        return jsonify({"ok": False, "error": why}), 409
    results = {}
    for cert in cfg["acme"]["certificates"]:
        if cert.get("auto_renew", True):
            results[cert["name"]] = acme_issue(cfg, cert)
    return jsonify({"ok": all(r.get("ok") for r in results.values()) if results else True,
                    "results": results})


def renewal_runs_here(cfg):
    """Only the node serving traffic renews.

    Every node used to run this loop. HTTP-01 validation arrives at the virtual
    IP, so a passive node cannot answer it; with DNS-01 the nodes would instead
    race each other for the same certificate and burn the CA's rate limits.
    """
    role, _ = node_role(cfg)
    if role == "passive":
        return False, "this node is passive; the node holding the virtual IP renews"
    return True, ""


# --------------------------------------------------------------------------
# notifications
#
# SMTP and Pushover are built in and need nothing beyond the standard library
# and requests, which are already here. A generic webhook covers anything else:
# it posts JSON, so a small script can forward it wherever it is wanted.
#
# The hard part is not sending: it is not sending too much. The watchdog runs
# every twenty seconds, so anything that reports a *condition* would arrive
# hundreds of times a day. Alerts therefore fire on transitions, and an
# unresolved problem is repeated only on a slow timer.
# --------------------------------------------------------------------------

SEVERITY = {"info": 0, "warning": 1, "error": 2}
_notify_state = {}          # key -> {"state":..., "since":..., "last_sent":...}
_notify_lock = threading.Lock()
_notify_log = []            # recent attempts, newest first, for the UI


def _note_attempt(dest, ok, detail):
    entry = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "destination": dest, "ok": ok, "detail": detail[:300]}
    with _notify_lock:
        _notify_log.insert(0, entry)
        del _notify_log[30:]


def send_smtp(d, subject, body):
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = d.get("from") or d.get("username") or "haproxy-manager@localhost"
    to = [x.strip() for x in re.split(r"[,;\s]+", d.get("to") or "") if x.strip()]
    if not to:
        raise ValueError("no recipient address is set")
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.set_content(body)
    host = d.get("host") or "localhost"
    port = int(d.get("port") or (465 if d.get("security") == "ssl" else 587))
    timeout = float(d.get("timeout") or 20)
    if d.get("security") == "ssl":
        srv = smtplib.SMTP_SSL(host, port, timeout=timeout)
    else:
        srv = smtplib.SMTP(host, port, timeout=timeout)
    try:
        srv.ehlo()
        if d.get("security") == "starttls":
            srv.starttls()
            srv.ehlo()
        if d.get("username"):
            srv.login(d["username"], d.get("password") or "")
        srv.send_message(msg)
    finally:
        try:
            srv.quit()
        except Exception:
            pass


def send_pushover(d, subject, body, severity):
    if _requests is None:
        raise RuntimeError("python3-requests is not installed on this node")
    data = {"token": d.get("token") or "", "user": d.get("user") or "",
            "title": subject[:250], "message": body[:1024],
            # -1 quiet, 0 normal, 1 high. Emergency (2) needs acknowledgement
            # parameters, so it is deliberately not used.
            "priority": {"info": -1, "warning": 0, "error": 1}.get(severity, 0)}
    if d.get("device"):
        data["device"] = d["device"]
    r = _requests.post("https://api.pushover.net/1/messages.json", data=data,
                       timeout=(PEER_CONNECT_TIMEOUT, 15))
    if r.status_code != 200:
        raise RuntimeError("Pushover replied HTTP %s: %s" % (r.status_code, r.text[:200]))


def send_webhook(d, subject, body, severity, event):
    if _requests is None:
        raise RuntimeError("python3-requests is not installed on this node")
    payload = {"subject": subject, "message": body, "severity": severity,
               "event": event, "node": socket.gethostname(),
               "time": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    headers = {"Content-Type": "application/json"}
    for line in (d.get("headers") or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    r = _requests.post(d.get("url") or "", json=payload, headers=headers,
                       timeout=(PEER_CONNECT_TIMEOUT, 15),
                       verify=bool(d.get("verify_tls", True)))
    if r.status_code >= 300:
        raise RuntimeError("the endpoint replied HTTP %s: %s" % (r.status_code, r.text[:200]))


def send_to(dest, subject, body, severity="warning", event=""):
    """Deliver to one destination. Raises with a readable reason."""
    kind = (dest.get("type") or "").lower()
    if kind == "smtp":
        send_smtp(dest, subject, body)
    elif kind == "pushover":
        send_pushover(dest, subject, body, severity)
    elif kind == "webhook":
        send_webhook(dest, subject, body, severity, event)
    else:
        raise ValueError("unknown destination type %r -- expected smtp, pushover "
                         "or webhook" % kind)


def notify(event, subject, body, severity="warning", cfg=None):
    """Send to every enabled destination. Never raises: a failing mail server
    must not take down the thing that noticed the problem."""
    cfg = cfg or load_config()
    n = cfg.get("notify") or {}
    if not n.get("enabled", True):
        return {"sent": 0, "skipped": "notifications are switched off"}
    if SEVERITY.get(severity, 1) < SEVERITY.get(n.get("min_severity", "warning"), 1):
        return {"sent": 0, "skipped": "below the configured severity"}
    if event and not (n.get("events") or {}).get(event, True):
        return {"sent": 0, "skipped": "the %s category is switched off" % event}
    dests = [d for d in (n.get("destinations") or []) if d.get("enabled", True)]
    if not dests:
        return {"sent": 0, "skipped": "no destinations are configured"}

    host = socket.gethostname()
    full = "%s\n\n-- \nHAProxy Cluster Manager %s on %s" % (body, VERSION, host)
    sent = 0
    for d in dests:
        name = d.get("name") or d.get("type") or "?"
        try:
            send_to(d, "[%s] %s" % (host, subject), full, severity, event)
            sent += 1
            _note_attempt(name, True, "sent")
            log.info("notified %s: %s", name, subject)
        except Exception as e:
            _note_attempt(name, False, str(e))
            log.error("could not notify %s: %s", name, str(e)[:200])
    return {"sent": sent, "destinations": len(dests)}


def notify_transition(key, state, event, subject, body, severity="warning", cfg=None):
    """Alert when something *changes*, not while it stays broken.

    Reporting a condition on every watchdog round would send hundreds of
    messages a day. This sends when the state changes, and then only again
    after repeat_hours if it has not recovered.
    """
    cfg = cfg or load_config()
    n = cfg.get("notify") or {}
    repeat = float(n.get("repeat_hours") or 6) * 3600
    now = time.time()
    with _notify_lock:
        prev = _notify_state.get(key) or {}
        changed = prev.get("state") != state
        stale = (now - prev.get("last_sent", 0)) > repeat
        if not changed and not (stale and state != "ok"):
            _notify_state[key] = dict(prev, state=state)
            return {"sent": 0, "skipped": "no change"}
        _notify_state[key] = {"state": state, "since": prev.get("since", now)
                              if not changed else now, "last_sent": now}
    return notify(event, subject, body, severity, cfg)


@app.get("/api/notify")
def api_notify_get():
    cfg = load_config()
    n = json.loads(json.dumps(cfg.get("notify") or {}))
    # Never hand secrets back to the browser; say only whether they are set.
    for d in n.get("destinations") or []:
        for secret in ("password", "token", "user"):
            if secret in d:
                d["has_" + secret] = bool((d.get(secret) or "").strip())
                d.pop(secret)
    with _notify_lock:
        recent = list(_notify_log)
    return jsonify({"ok": True, "settings": n, "recent": recent})


@app.put("/api/notify")
def api_notify_put():
    body = request.get_json(force=True, silent=True) or {}
    with _lock:
        cfg = load_config()
        n = cfg.setdefault("notify", json.loads(json.dumps(DEFAULT_CONFIG["notify"])))
        if "enabled" in body:
            n["enabled"] = bool(body["enabled"])
        if body.get("min_severity") in SEVERITY:
            n["min_severity"] = body["min_severity"]
        if "repeat_hours" in body:
            try:
                n["repeat_hours"] = max(0.25, float(body["repeat_hours"]))
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "repeat_hours must be a number"}), 400
        if isinstance(body.get("events"), dict):
            for k, v in body["events"].items():
                n.setdefault("events", {})[k] = bool(v)
        if isinstance(body.get("destinations"), list):
            existing = {d.get("id"): d for d in (n.get("destinations") or [])}
            out = []
            for d in body["destinations"]:
                if not isinstance(d, dict):
                    continue
                cur = dict(existing.get(d.get("id")) or {})
                cur.update({k: v for k, v in d.items()
                            if not (k in ("password", "token", "user")
                                    and not str(v or "").strip())})
                # a blank secret means "keep the stored one", never "clear it"
                cur["id"] = cur.get("id") or str(uuid.uuid4())
                out.append(cur)
            n["destinations"] = out
        save_config(cfg)
    log.info("notification settings changed (%d destination(s))",
             len(n.get("destinations") or []))
    return jsonify({"ok": True})


@app.post("/api/notify/test")
def api_notify_test():
    """Send a real message to one destination, so it is proven before it is
    needed. Uses the stored secrets when the browser sends blanks."""
    body = request.get_json(force=True, silent=True) or {}
    cfg = load_config()
    dest = None
    if body.get("id"):
        dest = _find(cfg.get("notify", {}).get("destinations") or [],
                     lambda d: d.get("id") == body["id"])
    if dest is None:
        return jsonify({"ok": False, "error": "save the destination first, then test it"}), 400
    try:
        send_to(dest, "[%s] Test message" % socket.gethostname(),
                "This is a test from HAProxy Cluster Manager %s on %s.\n\n"
                "If you are reading it, alerts will reach you here."
                % (VERSION, socket.gethostname()),
                "info", "test")
    except Exception as e:
        _note_attempt(dest.get("name") or dest.get("type"), False, str(e))
        log.warning("test notification to %s failed: %s", dest.get("name"), str(e)[:200])
        return jsonify({"ok": False, "error": str(e)[:400]})
    _note_attempt(dest.get("name") or dest.get("type"), True, "test message sent")
    return jsonify({"ok": True, "message": "Sent. Check that it arrived."})


# --------------------------------------------------------------------------
# watchdog
#
# `systemctl is-active` answers "is the process there", which is not the
# question. A process that has stopped answering looks perfectly healthy by
# that measure, and it is the failure that actually takes a site down. So each
# service gets a liveness probe that requires it to *do* something, and a
# restart is a considered action: never against a configuration that cannot
# work, and never more than a few times in a window.
# --------------------------------------------------------------------------

WATCHDOG_UNITS = ("haproxy", "keepalived")
_watchdog = {
    "enabled": False,
    "running": False,
    "last_run": "",
    "services": {},        # unit -> {state, detail, since, restarts, gave_up}
    "events": [],          # most recent first, capped
    "self": {"ok": True, "detail": "", "ms": 0},
}
_watchdog_lock = threading.Lock()
# Only one round may run at a time. The background timer and the "Check now"
# button would otherwise both find the same dead service and restart it twice,
# spending two of its restart budget on one fault.
_watchdog_round_lock = threading.Lock()
_restart_history = {}      # unit -> [epoch, ...]


def _wd_event(unit, message, level="info"):
    entry = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "unit": unit, "message": message, "level": level}
    with _watchdog_lock:
        _watchdog["events"].insert(0, entry)
        del _watchdog["events"][40:]
    {"info": log.info, "warning": log.warning, "error": log.error}[level](
        "watchdog: %s: %s", unit, message)


def service_state(unit):
    """active / inactive / failed / activating / unknown."""
    rc, out = run(["systemctl", "is-active", unit], timeout=15)
    word = (out or "").strip().splitlines()[-1] if out.strip() else ""
    if word in ("active", "inactive", "failed", "activating", "deactivating", "unknown"):
        return word
    return "active" if rc == 0 else "unknown"


def unit_wanted(unit):
    """Whether the operator wants this unit running at all.

    A masked or disabled unit is a deliberate "leave this alone" -- someone
    taking a node out of service for maintenance should not have the watchdog
    start it behind them.
    """
    rc, out = run(["systemctl", "is-enabled", unit], timeout=15)
    word = (out or "").strip().splitlines()[-1] if out.strip() else ""
    if word in ("masked", "disabled"):
        return False, word
    return True, word or "enabled"


def probe_haproxy(cfg):
    """Alive is not enough: make HAProxy answer on its stats socket.

    A process wedged on a lock, out of file descriptors or stuck in a bad
    reload still shows as active. `show info` requires it to accept a
    connection and produce a reply, which is what "serving" means here.
    """
    state = service_state("haproxy")
    if state in ("inactive", "failed"):
        return "down", "the service is %s" % state
    if state == "activating":
        return "starting", "the service is still starting"
    if not STATS_SOCK.exists():
        # Only a fault once a configuration has been applied -- a fresh node
        # legitimately has no socket yet.
        if not HAPROXY_CFG.exists():
            return "idle", "nothing has been applied yet"
        return "hung", "the stats socket %s is missing" % STATS_SOCK
    started = time.time()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sk:
            sk.settimeout(WATCHDOG_PROBE_TIMEOUT)
            sk.connect(str(STATS_SOCK))
            sk.sendall(b"show info\n")
            data = sk.recv(4096)
    except socket.timeout:
        return "hung", ("it did not answer on its stats socket within %gs"
                        % WATCHDOG_PROBE_TIMEOUT)
    except OSError as e:
        return "hung", "its stats socket could not be used: %s" % e
    if b"Process_num" not in data and b"Name:" not in data:
        return "hung", "its stats socket gave an answer that was not recognisable"
    return "ok", "answered in %d ms" % int((time.time() - started) * 1000)


def probe_keepalived(cfg):
    """Keepalived exposes no query interface, so this is deliberately modest:
    it reports whether the service is running when the cluster wants it."""
    if not keepalived_wanted(cfg):
        return "disabled", "this node is not running Keepalived"
    if not KEEPALIVED_CFG.exists():
        return "idle", "no configuration has been written yet"
    state = service_state("keepalived")
    if state in ("inactive", "failed"):
        return "down", "the service is %s" % state
    if state == "activating":
        return "starting", "the service is still starting"
    return "ok", "running"


def _why_rejected(out):
    """The lines that say what is wrong, not a blind tail of the output.

    Daemons print their version and paths before the complaint, so cutting the
    last N characters lands mid-sentence in the preamble.
    """
    lines = [ln.strip() for ln in (out or "").splitlines()
             if "ALERT" in ln or "error" in ln.lower() or "cannot" in ln.lower()]
    text = " ".join(lines) if lines else (out or "").strip()
    # PIDs change every run; without dropping them the same fault looks new
    # each round and would be reported over and over.
    text = re.sub(r"\(\d+\)\s*:\s*", "", text)
    return text[:280]


def config_is_usable(unit):
    """Would a restart even help? Restarting against a configuration the
    daemon rejects is a loop that hides the real fault."""
    if unit == "haproxy":
        if not HAPROXY_CFG.exists():
            return False, "there is no %s to start from" % HAPROXY_CFG
        rc, out = run(["haproxy", "-c", "-f", str(HAPROXY_CFG)], timeout=30)
        if rc == 127:
            return True, ""                      # cannot check; let it try
        if rc != 0:
            return False, "its configuration does not validate: %s" % _why_rejected(out)
    if unit == "keepalived":
        if not KEEPALIVED_CFG.exists():
            return False, "there is no %s to start from" % KEEPALIVED_CFG
        rc, out = run(["keepalived", "-t", "-f", str(KEEPALIVED_CFG)], timeout=30)
        if rc not in (0, 127):
            return False, "its configuration does not validate: %s" % _why_rejected(out)
    return True, ""


def _restart_allowed(unit, limit, window):
    now = time.time()
    hist = [t for t in _restart_history.get(unit, []) if now - t < window]
    _restart_history[unit] = hist
    return len(hist) < limit, len(hist)


def watchdog_round(cfg=None):
    """One pass. Returns the per-service report it also stores."""
    with _watchdog_round_lock:
        return _watchdog_round_locked(cfg)


def _watchdog_round_locked(cfg=None):
    cfg = cfg or load_config()
    wd = cfg["local"].get("watchdog") or {}
    limit = int(wd.get("max_restarts") or 3)
    window = int(wd.get("window") or 900)
    report = {}

    for unit, probe in (("haproxy", probe_haproxy), ("keepalived", probe_keepalived)):
        if not wd.get(unit, True):
            report[unit] = {"state": "unwatched", "detail": "not supervised by the watchdog"}
            continue
        try:
            state, detail = probe(cfg)
        except Exception as e:                    # a broken probe must not stop the loop
            log.exception("watchdog: the %s probe failed", unit)
            report[unit] = {"state": "unknown", "detail": "the probe itself failed: %s" % e}
            continue
        entry = {"state": state, "detail": detail,
                 "checked": datetime.now(timezone.utc).isoformat(timespec="seconds")}

        if state == "starting":
            report[unit] = entry
            continue                              # give it a round to come up
        if state in ("down", "hung"):
            wanted, how = unit_wanted(unit)
            if not wanted:
                entry["action"] = "none"
                entry["blocked"] = "the %s service is %s -- left alone deliberately" % (unit, how)
                report[unit] = entry
                continue
            usable, why = config_is_usable(unit)
            if not usable:
                entry["action"] = "none"
                entry["blocked"] = why
                prev = _watchdog["services"].get(unit, {})
                if prev.get("blocked") != why:     # say it once, not every round
                    _wd_event(unit, "%s and will not be restarted, because %s"
                              % ("is not running" if state == "down" else "is not responding", why),
                              "error")
                notify_transition(
                    "watchdog:" + unit, "blocked:" + why[:60], "watchdog",
                    "%s is down and cannot be restarted" % unit,
                    "%s is not running, and the watchdog will not restart it because %s"
                    % (unit, why), "error", cfg)
            else:
                allowed, used = _restart_allowed(unit, limit, window)
                if not allowed:
                    entry["action"] = "gave up"
                    entry["gave_up"] = True
                    prev = _watchdog["services"].get(unit, {})
                    if not prev.get("gave_up"):
                        _wd_event(unit, "restarted %d times in %d minutes without staying "
                                        "healthy -- leaving it alone so the fault is visible"
                                  % (used, window // 60), "error")
                        notify_transition(
                            "watchdog:" + unit, "gave-up", "watchdog",
                            "%s keeps failing -- the watchdog has stopped restarting it" % unit,
                            "%s was restarted %d times in %d minutes and did not stay healthy, "
                            "so the watchdog has stopped trying.\n\nIt needs looking at by hand."
                            % (unit, used, window // 60), "error", cfg)
                else:
                    _restart_history.setdefault(unit, []).append(time.time())
                    _wd_event(unit, "%s -- restarting it (%s)"
                              % ("is not running" if state == "down" else "is not responding",
                                 detail), "warning")
                    rc, out = run(["systemctl", "restart", unit], timeout=60)
                    entry["action"] = "restarted"
                    # Judge by the probe, not by the exit status. Restarting a
                    # stopped process makes some service managers report an
                    # abnormal termination even though the daemon came back
                    # fine, and "the restart failed" next to a working service
                    # is worse than no message at all.
                    time.sleep(2)                  # let it come up before re-probing
                    after, adetail = probe(cfg)
                    entry["state"], entry["detail"] = after, adetail
                    if after in ("ok", "starting", "idle", "disabled"):
                        _wd_event(unit, "restarted; it is now %s (%s)" % (after, adetail), "info")
                        notify_transition(
                            "watchdog:" + unit, "restarted", "watchdog",
                            "%s was restarted" % unit,
                            "%s stopped %s and the watchdog restarted it.\n\n"
                            "It is answering again now (%s)."
                            % (unit, "running" if state == "down" else "responding", adetail),
                            "warning", cfg)
                    else:
                        entry["restart_error"] = out.strip()[:300] if rc != 0 else ""
                        notify_transition(
                            "watchdog:" + unit, "failed", "watchdog",
                            "%s is down and will not come back" % unit,
                            "%s is %s and a restart did not fix it.\n\n%s\n\n"
                            "Traffic through this node is affected."
                            % (unit, after, adetail), "error", cfg)
                        _wd_event(unit, "restarted but it is still %s (%s)%s"
                                  % (after, adetail,
                                     "; the service manager said: " + out.strip()[:150]
                                     if rc != 0 else ""), "error")
        elif state == "ok":
            _restart_history.pop(unit, None)       # healthy again: forget the history
            notify_transition("watchdog:" + unit, "ok", "watchdog",
                              "%s is healthy again" % unit,
                              "%s is answering normally again (%s)." % (unit, detail),
                              "info", cfg)
        report[unit] = entry

    with _watchdog_lock:
        _watchdog["services"] = report
        _watchdog["last_run"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return report


def probe_self():
    """Ask this process to serve a real request.

    A thread checking a flag proves nothing: the failure worth catching is a
    worker pool with every thread blocked, where the process is healthy and
    the UI answers nothing. Only a request that goes through the socket and
    out of the WSGI server tests that.
    """
    started = time.time()
    url = "http://127.0.0.1:%d/api/whoami" % PORT
    try:
        with urllib.request.urlopen(url, timeout=WATCHDOG_SELF_TIMEOUT) as r:
            ok = r.status == 200
        return ok, ("" if ok else "the UI answered HTTP %s" % r.status), \
            int((time.time() - started) * 1000)
    except Exception as e:
        return False, "the UI did not answer: %s" % str(e)[:120], \
            int((time.time() - started) * 1000)


def sd_notify(message):
    """Talk to systemd without a dependency on python3-systemd."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):                       # abstract namespace
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sk:
            sk.connect(addr)
            sk.sendall(message.encode())
        return True
    except OSError:
        return False


def _watchdog_loop():
    """Supervise the services, and let systemd supervise us.

    The WATCHDOG=1 ping is deliberately gated on probe_self(): if this process
    stops serving, the ping stops, and systemd restarts it. Pinging
    unconditionally would tell systemd everything is fine from inside a
    process that answers nothing.
    """
    # systemd publishes its deadline in WATCHDOG_USEC. Ping at no less than
    # half of it, whatever the configured interval says, or a slow round would
    # look like a hang and systemd would restart a perfectly healthy process.
    deadline = 0.0
    try:
        deadline = int(os.environ.get("WATCHDOG_USEC", "0")) / 1000000.0
    except ValueError:
        pass
    # The listener is started after this thread, so wait for it before judging
    # anything. Reporting "the UI does not answer" while it is still coming up
    # would be wrong, and on systemd it would withhold the first ping.
    for _ in range(60):
        ok, _detail, _ms = probe_self()
        if ok:
            break
        time.sleep(1)
    else:
        log.error("watchdog: the UI was not answering on 127.0.0.1:%d a minute after start", PORT)
    if sd_notify("READY=1") and deadline:
        log.info("watchdog: systemd is supervising this process, deadline %gs", deadline)
    while True:
        cfg = load_config()
        wd = cfg["local"].get("watchdog") or {}
        interval = max(5, int(wd.get("interval") or 20))
        if deadline:
            interval = min(interval, max(2.0, deadline / 2.0))
        enabled = bool(wd.get("enabled", True))
        _watchdog["enabled"] = enabled

        ok, detail, ms = probe_self()
        with _watchdog_lock:
            _watchdog["self"] = {"ok": ok, "detail": detail, "ms": ms}
        if ok:
            sd_notify("WATCHDOG=1")
        else:
            # No ping: if systemd is watching, it will restart us. Say why
            # first, so the reason survives the restart in the log.
            log.error("watchdog: this node's own UI is not answering (%s) -- "
                      "not pinging systemd, so it will be restarted if WatchdogSec is set",
                      detail)

        if enabled:
            _watchdog["running"] = True
            try:
                watchdog_round(cfg)
            except Exception:
                log.exception("watchdog: the round failed")
        else:
            _watchdog["running"] = False

        # Collect every node's health here, on a schedule, so the UI reads a
        # snapshot instead of fanning out to the cluster on every page load.
        if cfg["local"]["sync"].get("peers") and \
                time.time() - _cluster_cache["at"] >= CLUSTER_POLL_SECONDS:
            try:
                cluster_snapshot(cfg)
            except Exception:
                log.exception("watchdog: collecting node health failed")

        time.sleep(interval)


@app.get("/api/watchdog")
def api_watchdog():
    cfg = load_config()
    with _watchdog_lock:
        state = json.loads(json.dumps(_watchdog))
    state["settings"] = cfg["local"].get("watchdog") or {}
    state["systemd"] = bool(os.environ.get("NOTIFY_SOCKET"))
    return jsonify(state)


@app.put("/api/watchdog")
def api_watchdog_settings():
    body = request.get_json(force=True, silent=True) or {}
    keys = ("enabled", "interval", "haproxy", "keepalived", "max_restarts", "window")
    with _lock:
        cfg = load_config()
        wd = cfg["local"].setdefault("watchdog", {})
        for k in keys:
            if k not in body:
                continue
            if k in ("interval", "max_restarts", "window"):
                try:
                    wd[k] = max(1, int(body[k]))
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "error":
                                    "%s must be a whole number" % k}), 400
            else:
                wd[k] = bool(body[k])
        wd["interval"] = max(5, int(wd.get("interval") or 20))
        save_config(cfg)
    log.info("watchdog settings changed: %s", json.dumps(wd, sort_keys=True))
    return jsonify({"ok": True, "settings": wd})


@app.post("/api/watchdog/check")
def api_watchdog_check():
    """Run a round now, so the page does not have to wait for the timer."""
    return jsonify({"ok": True, "services": watchdog_round()})


def _renew_loop():
    global _last_renew
    while True:
        time.sleep(600)
        try:
            cfg = load_config()
            st = cfg["acme"]["settings"]
            if not (st.get("enabled") and st.get("auto_renew")):
                continue
            ok, why = renewal_runs_here(cfg)
            if not ok:
                with _lock:
                    cur = load_config()
                    cur["_meta"]["renewal"] = {
                        "checked": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "ran": False, "reason": why}
                    save_config(cur)
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
# node sync: one active node holds the virtual IP, any number stand ready
# --------------------------------------------------------------------------

def shared_payload(cfg):
    certs = {}
    if CERT_DIR.exists():
        for p in sorted(CERT_DIR.glob("*.pem")):
            certs[p.name] = base64.b64encode(p.read_bytes()).decode()
    return {
        "config": {"haproxy": strip_local_only(cfg["haproxy"]),
                   "acme": strip_local_only(cfg["acme"]),
                   "cluster": cfg["cluster"],
                   "notify": cfg.get("notify", {})},
        "certs": certs,
        "source": socket.gethostname(),
        "ts": time.time(),
    }


def enabled_peers(cfg):
    return [p for p in (cfg["local"]["sync"].get("peers") or []) if p.get("enabled", True) and p.get("url")]


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
                "error": peer_error(e, url, PUSH_READ_TIMEOUT)}


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


# --------------------------------------------------------------------------
# peers: the other nodes in the cluster
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# first run: join an existing cluster, or start a new one
# --------------------------------------------------------------------------

def _guess_node_url():
    """How this node was just reached -- a good default for how peers reach it."""
    host = request.headers.get("X-Forwarded-Host") or request.host or ""
    scheme = request.headers.get("X-Forwarded-Proto") or ("https" if request.is_secure else "http")
    return ("%s://%s" % (scheme, host)).rstrip("/") if host else ""


@app.get("/api/setup/state")
def api_setup_state():
    cfg = load_config()
    return jsonify({
        "needs_admin": needs_setup(cfg),
        "complete": bool(cfg["_meta"].get("setup_complete")),
        "hostname": socket.gethostname(),
        "port": PORT,
        "suggested_url": _guess_node_url(),
        "interfaces": [i for i in node_interfaces() if i["name"] != "lo"],
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
            names = [i["name"] for i in node_interfaces()]
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
        out["applied"] = do_apply()
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
    level, why = check_node_url(my_url, remote.get("vips") or [])
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
        names = [i["name"] for i in node_interfaces()]
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
                for section in ("haproxy", "acme", "cluster"):
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
                save_config(cfg)
            pushed = True
            steps.append("received the configuration from %s: %d other node(s), %d certificate(s)"
                         % (data.get("source", target), len(kept), len(data.get("certs") or {})))
            res = do_apply(load_config(), allow_push=False)
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
            res = apply_unicast_plan()
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


@app.route("/api/cluster/settings", methods=["GET", "PUT"])
def api_cluster_settings():
    """VRRP settings every node shares. Pushed to the others like any config."""
    cfg = load_config()
    if request.method == "GET":
        return jsonify(cfg["cluster"])
    body = request.get_json(force=True) or {}
    ok, message = check_rendered(draft_with(None, body, cluster=True))   # slow: outside the lock
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
        own = key_fingerprint(cfg["local"].get("api_key"))
        return jsonify([{k: v for k, v in p.items() if k != "api_key"} |
                        {"has_key": bool((p.get("api_key") or "").strip()),
                         "key_fp": key_fingerprint(p.get("api_key")),
                         "is_own_key": bool(own) and key_fingerprint(p.get("api_key")) == own}
                        for p in peers])
    body = request.get_json(force=True) or {}
    url = (body.get("url") or "").strip().rstrip("/")
    if not url:
        return jsonify({"error": "the peer's URL is required, e.g. http://10.0.0.2:8080"}), 400
    if "://" not in url:
        url = "http://" + url
    level, why = check_node_url(url, cluster_vips(cfg))   # resolves names: outside the lock
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
    if key_matches(cfg["local"].get("api_key"), stored):
        return jsonify({"ok": False, "error":
                        "this entry holds THIS node's own API key (fingerprint %s), not %s's. With "
                        "a window open on each node it is easy to copy from the wrong one -- the "
                        "page header names the node it belongs to."
                        % (key_fingerprint(stored), peer.get("name"))})
    try:
        r = _requests.get(url + "/api/status", headers={"X-API-Key": stored.strip()},
                          timeout=PEER_TIMEOUT, verify=bool(peer.get("verify_tls")))
    except Exception as e:
        return jsonify({"ok": False, "error": "cannot reach %s: %s" % (url, e)})

    if r.status_code == 401:
        try:
            d = r.json()
            if d.get("expected_fp") or d.get("header_seen") is not None:
                return jsonify({"ok": False, "error": _key_verdict(d, url), "diagnosis": d})
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
        "update_available": bool(st.get("update_available")),
        "certs_total": len(certs),
        "certs_bad": sum(1 for c in certs if c.get("status") in ("expired", "expiring", "placeholder", "missing")),
    }


# --------------------------------------------------------------------------
# unicast VRRP addresses: every node needs the others' real IPs
# --------------------------------------------------------------------------

def keepalived_wanted(cfg):
    """Keepalived runs wherever the cluster has a virtual IP.

    It used to be a per-node checkbox, which let a node sit in a cluster with
    VRRP quietly switched off, never taking the address.
    """
    return bool(cluster_vips(cfg))


def cluster_vips(cfg):
    return [v.strip().split("/")[0] for v in (cfg["cluster"].get("vips") or "").splitlines() if v.strip()]


def resolve_host(host):
    """Every IPv4 address a name resolves to, in a stable order."""
    if not host:
        return []
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError:
        return []


def own_addresses():
    return {a.split("/")[0] for i in node_interfaces() for a in i["addresses"]}


def check_node_url(url, vips):
    """A node's URL must reach that node, not the address that moves."""
    host = urlsplit(url).hostname or ""
    ips = resolve_host(host)
    if not ips:
        return "warn", "%s does not resolve here; the other nodes may still be able to reach it." % host
    hit = [ip for ip in ips if ip in (vips or [])]
    if hit:
        return "error", ("%s resolves to the virtual IP (%s). That address moves between nodes, so "
                         "the others would reach whichever node currently holds it -- and this node "
                         "would never receive anything. Use this node's own address or a name that "
                         "resolves to it." % (host, ", ".join(hit)))
    mine = own_addresses()
    if not (set(ips) & mine):
        return "warn", ("%s resolves to %s, which is not an address on this node. Make sure it "
                        "reaches this node and not another." % (host, ", ".join(ips)))
    return "ok", ""


def local_vrrp_address(cfg):
    """This node's own address on the interface that carries the virtual IP."""
    iface = cfg["local"]["keepalived"].get("interface") or ""
    vips = cluster_vips(cfg)
    for i in node_interfaces():
        if i["name"] != iface:
            continue
        for a in i["addresses"]:
            ip = a.split("/")[0]
            if ip not in vips:               # never advertise from the shared address
                return ip
    return ""


def peer_vrrp_address(peer, vips, verify=None):
    """The address to send this peer's VRRP to: (address, how, warning)."""
    url = (peer.get("url") or "").rstrip("/")
    host = urlsplit(url).hostname or ""

    # Best source is the node itself: it knows which address its own VRRP
    # interface carries. A name can point at the virtual IP, which moves.
    if _requests is not None and peer.get("api_key"):
        try:
            r = _requests.get(url + "/api/keepalived/status",
                              headers={"X-API-Key": (peer.get("api_key") or "").strip()},
                              timeout=PEER_TIMEOUT, verify=bool(peer.get("verify_tls")))
            if r.status_code == 200:
                d = r.json()
                for i in d.get("interfaces", []):
                    if i.get("name") != d.get("interface"):
                        continue
                    for a in i.get("addresses", []):
                        ip = a.split("/")[0]
                        if ip not in vips:
                            return ip, "%s reports it on %s" % (peer.get("name"), i["name"]), ""
        except Exception:
            pass

    ips = resolve_host(host)
    usable = [ip for ip in ips if ip not in vips]
    if usable:
        warn = ""
        if len(ips) != len(usable):
            warn = ("%s also resolves to the virtual IP, which moves between nodes -- "
                    "using %s instead." % (host, usable[0]))
        return usable[0], "%s resolves to it" % host, warn
    if ips:
        return "", "", ("%s resolves only to the virtual IP (%s), which cannot be a unicast peer. "
                        "Give this node's own address." % (host, ", ".join(ips)))
    return "", "", "could not resolve %s" % (host or url)


def unicast_plan(cfg):
    """Which address every node should use, and who each should talk to."""
    vips = cluster_vips(cfg)
    nodes = []
    me = local_vrrp_address(cfg)
    nodes.append({"self": True, "name": socket.gethostname(), "address": me,
                  "how": "this node's %s" % (cfg["local"]["keepalived"].get("interface") or "?"),
                  "warning": "" if me else
                             "this node has no usable address on %s"
                             % (cfg["local"]["keepalived"].get("interface") or "(no interface set)"),
                  "peer": None})
    for p in cfg["local"]["sync"].get("peers") or []:
        if not p.get("enabled", True):
            continue
        addr, how, warn = peer_vrrp_address(p, vips)
        nodes.append({"self": False, "name": p.get("name"), "address": addr,
                      "how": how, "warning": warn, "peer": p})
    return nodes


@app.get("/api/cluster/unicast")
def api_cluster_unicast():
    nodes = unicast_plan(load_config())
    return jsonify({"ok": True,
                    "nodes": [{k: v for k, v in n.items() if k != "peer"} for n in nodes],
                    "addresses": [n["address"] for n in nodes if n["address"] and not n["self"]]})


def derive_unicast(cfg):
    """This node's own unicast addresses, worked out from the membership.

    Cheap enough for every Apply: local interfaces and name resolution only,
    no calls to the other nodes. Each node derives its own, so the cluster
    stays correct as members come and go.
    """
    k = cfg["local"]["keepalived"]
    if not keepalived_wanted(cfg):
        return False
    vips = cluster_vips(cfg)
    addrs = []
    for p in cfg["local"]["sync"].get("peers") or []:
        if not p.get("enabled", True):
            continue
        for ip in resolve_host(urlsplit(p.get("url") or "").hostname or ""):
            if ip not in vips and ip not in addrs:
                addrs.append(ip)
                break                        # one address per node
    new_peer = "\n".join(addrs) if addrs else ""
    new_src = local_vrrp_address(cfg) if addrs else ""
    if (k.get("unicast_peer") or "") == new_peer and (k.get("unicast_src") or "") == new_src:
        return False
    k["unicast_peer"], k["unicast_src"] = new_peer, new_src
    return True


def apply_unicast_plan():
    """Give every node its own source address and the list of the others.

    Unicast addresses are node-local, so they cannot ride along with a
    configuration push -- each node has to be told its own.
    """
    cfg = load_config()
    nodes = unicast_plan(cfg)
    steps, warnings = [], [n["warning"] for n in nodes if n["warning"]]
    known = {n["name"]: n["address"] for n in nodes if n["address"]}
    if len(known) < 2:
        return {"ok": False, "error":
                "at least two nodes need a usable address; found %s"
                % (", ".join("%s=%s" % kv for kv in known.items()) or "none"),
                "warnings": warnings, "steps": []}

    def others(name):
        return "\n".join(a for n, a in known.items() if n != name)

    with _lock:
        cur = load_config()
        mine = next((n for n in nodes if n["self"]), None)
        if mine and mine["address"]:
            cur["local"]["keepalived"]["unicast_src"] = mine["address"]
            cur["local"]["keepalived"]["unicast_peer"] = others(mine["name"])
            save_config(cur)
            steps.append("this node: source %s, peers %s"
                         % (mine["address"], others(mine["name"]).replace("\n", ", ") or "(none)"))

    for n in nodes:
        if n["self"] or not n["address"]:
            continue
        p = n["peer"]
        try:
            r = _requests.put((p["url"].rstrip("/")) + "/api/local",
                              json={"keepalived": {"unicast_src": n["address"],
                                                   "unicast_peer": others(n["name"])}},
                              headers={"X-API-Key": (p.get("api_key") or "").strip()},
                              timeout=15, verify=bool(p.get("verify_tls")))
            if r.status_code == 200:
                steps.append("%s: source %s, peers %s"
                             % (n["name"], n["address"], others(n["name"]).replace("\n", ", ")))
            else:
                warnings.append("%s did not accept its unicast settings (HTTP %s)"
                                % (n["name"], r.status_code))
        except Exception as e:
            warnings.append("%s could not be updated: %s" % (n["name"], e))

    return {"ok": True, "steps": steps, "warnings": warnings,
            "note": "Press Apply on each node to write keepalived.conf."}


@app.post("/api/cluster/unicast/apply")
def api_cluster_unicast_apply():
    res = apply_unicast_plan()
    return jsonify(res), (200 if res.get("ok") else 400)


_cluster_cache = {"at": 0.0, "value": None}
_cluster_cache_lock = threading.Lock()


def cluster_snapshot(cfg=None):
    """Ask every node how it is. Slow by nature -- it waits on the network."""
    cfg = cfg or load_config()
    peers = cfg["local"]["sync"].get("peers") or []

    with app.test_request_context("/api/status"):
        me = _node_summary(json.loads(api_status().get_data()))
    me.update({"id": "self", "name": me["hostname"] or "this node", "url": "",
               "self": True, "reachable": True, "error": "", "ms": 0})

    nodes = [me]
    if peers:
        if _requests is None:
            nodes += [dict(_query_peer(p), error="python3-requests is not installed on this node")
                      for p in peers]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(peers))) as ex:
                nodes += list(ex.map(_query_peer, peers))

    reachable = [n for n in nodes if n.get("reachable")]
    holders = [n for n in reachable if n.get("vip_held")]
    warnings = []
    if len(nodes) - len(reachable):
        warnings.append("%d of %d nodes did not answer." % (len(nodes) - len(reachable), len(nodes)))
    vips_configured = any(n.get("vips") for n in reachable)
    if vips_configured and not holders:
        warnings.append("No node holds the virtual IP, so nothing is being served on it. "
                        "Check Keepalived on each node.")
    if len(holders) > 1:
        warnings.append("%d nodes hold the virtual IP at the same time (split brain): %s. "
                        "They are not seeing each other's VRRP."
                        % (len(holders), ", ".join(n["name"] for n in holders)))
    dirty = [n["name"] for n in reachable if n.get("dirty")]
    if dirty:
        warnings.append("Unapplied changes on: %s." % ", ".join(dirty))
    versions = {n.get("version") for n in reachable if n.get("version")}
    if len(versions) > 1:
        warnings.append("Nodes run different versions: %s." % ", ".join(sorted(versions)))

    # Each node reports what it can see, so a node that vanishes is reported
    # by each of its peers -- which also tells you who lost sight of it.
    for n in nodes:
        if n.get("self"):
            continue
        key = "node:" + (n.get("url") or n.get("name") or "?")
        if n.get("reachable"):
            notify_transition(key, "ok", "cluster",
                              "Node %s is reachable again" % n.get("name"),
                              "%s is answering again." % n.get("url") or "", "info", cfg)
        elif n.get("error") != "disabled":
            notify_transition(key, "unreachable", "cluster",
                              "Node %s is not answering" % n.get("name"),
                              "%s could not be reached from %s.\n\n%s\n\nIf it holds the "
                              "virtual IP, check that another node has taken it over."
                              % (n.get("url"), socket.gethostname(), n.get("error")),
                              "error", cfg)
    if len(holders) > 1:
        notify_transition("cluster:splitbrain", "split", "cluster",
                          "Split brain: %d nodes hold the virtual IP" % len(holders),
                          "%s hold the virtual IP at the same time, so they are not seeing "
                          "each other's VRRP traffic. Traffic to the VIP is being answered "
                          "by more than one node."
                          % ", ".join(n["name"] for n in holders), "error", cfg)
    elif holders:
        notify_transition("cluster:splitbrain", "ok", "cluster",
                          "The virtual IP is held by one node again",
                          "%s holds it." % holders[0]["name"], "info", cfg)

    payload = {
        "ok": True, "nodes": nodes,
        "summary": {"total": len(nodes), "reachable": len(reachable),
                    "active": len(holders), "warnings": warnings},
        "taken": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    with _cluster_cache_lock:
        _cluster_cache["value"], _cluster_cache["at"] = payload, time.time()
    return payload


@app.get("/api/cluster")
def api_cluster():
    """Every node's health -- served from the snapshot the watchdog keeps.

    The fan-out waits on the slowest node, so doing it inside a page load put
    that wait in front of the user. The background loop refreshes it instead,
    and the UI reads whatever was last collected, with its age attached so it
    can say how old it is. `?fresh=1` forces a live round.
    """
    if request.args.get("fresh") == "1":
        payload = cluster_snapshot()
        return jsonify(dict(payload, age_seconds=0, live=True))
    with _cluster_cache_lock:
        hit = _cluster_cache["value"]
        age = time.time() - _cluster_cache["at"]
    if hit is None or age > CLUSTER_SNAPSHOT_MAX_AGE:
        # Nothing collected yet (or the refresher has stalled): do it inline
        # once rather than show the user nothing.
        payload = cluster_snapshot()
        return jsonify(dict(payload, age_seconds=0, live=True))
    return jsonify(dict(hit, age_seconds=int(age), live=False))


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
    if not key_matches(key, presented):
        return jsonify({"ok": False, "error":
                        "%s rejected the API key." % socket.gethostname(),
                        "hostname": socket.gethostname(),
                        "header_seen": presented is not None,
                        "presented_fp": key_fingerprint(presented),
                        "expected_fp": key_fingerprint(key)}), 401
    data = request.get_json(force=True) or {}
    conf = data.get("config") or {}
    with _lock:
        return _receive_locked(cfg, data, conf)


def _receive_locked(cfg, data, conf):
    cfg = load_config()          # re-read inside the lock: it may have moved
    if "haproxy" in conf:
        cfg["haproxy"] = keep_local_only(cfg["haproxy"],
                                         _merge_defaults(conf["haproxy"], DEFAULT_CONFIG["haproxy"]))
    if "acme" in conf:
        cfg["acme"] = keep_local_only(cfg["acme"],
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
            rebuild_webui(cfg)
        except Exception:
            pass
    save_config(cfg)
    log.info("received configuration from %s", request.remote_addr)
    res = do_apply(cfg, allow_push=False)  # never re-push: avoids sync loops
    return jsonify({"ok": res.get("ok", False), "node": socket.gethostname(), "applied": res})


# --------------------------------------------------------------------------
# live statistics, straight from HAProxy's admin socket
# --------------------------------------------------------------------------

def _socket_command(cmd):
    """Send one command to the HAProxy stats socket and return its output."""
    if not STATS_SOCK.exists():
        return None, ("HAProxy is not running, or its stats socket is missing at %s. "
                      "Press Apply once -- the generated configuration creates it." % STATS_SOCK)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(str(STATS_SOCK))
            s.sendall((cmd + "\n").encode())
            chunks = []
            while True:
                buf = s.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
        return b"".join(chunks).decode("utf-8", "replace"), None
    except OSError as e:
        return None, "could not talk to the HAProxy stats socket: %s" % e


# Columns worth showing; the socket reports about a hundred.
_STAT_KEEP = ("status", "weight", "act", "bck", "scur", "smax", "slim", "stot",
              "bin", "bout", "qcur", "qmax", "ereq", "econ", "eresp", "dreq", "dresp",
              "wretr", "wredis", "chkfail", "chkdown", "lastchg", "downtime",
              "check_status", "check_code", "check_duration", "rate", "rate_max",
              "lastsess", "addr", "mode", "algo")


def haproxy_stats():
    text, err = _socket_command("show stat")
    if err:
        return {"ok": False, "error": err}
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines or not lines[0].startswith("#"):
        return {"ok": False, "error": "unexpected output from the stats socket"}

    header = [h.strip() for h in lines[0].lstrip("# ").split(",")]
    frontends, backends, order = [], {}, []
    for line in lines[1:]:
        row = dict(zip(header, line.split(",")))
        px, sv = row.get("pxname", ""), row.get("svname", "")
        if not px or not sv:
            continue
        keep = {k: row.get(k, "") for k in _STAT_KEEP}
        keep["proxy"] = px
        keep["name"] = sv
        if sv == "FRONTEND":
            frontends.append(keep)
        elif sv == "BACKEND":
            backends.setdefault(px, {"proxy": px, "servers": []}).update(keep)
            if px not in order:
                order.append(px)
        else:
            backends.setdefault(px, {"proxy": px, "servers": []})["servers"].append(keep)
            if px not in order:
                order.append(px)

    for be in backends.values():
        # "no check" means health checking is off, and HAProxy still routes to
        # the server -- counting it as down would misreport a working pool.
        up = sum(1 for s in be["servers"]
                 if s.get("status", "").startswith("UP") or s.get("status") == "no check")
        be["servers_up"] = up
        be["servers_total"] = len(be["servers"])
    return {"ok": True, "frontends": frontends,
            "backends": [backends[p] for p in order],
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds")}


@app.get("/api/stats")
def api_stats():
    return jsonify(haproxy_stats())


# --------------------------------------------------------------------------
# log collection
#
# Four programs write logs four different ways, and where they land depends on
# how haproxy-manager was installed. On a systemd host HAProxy and Keepalived
# log through syslog into the journal; in the container there is no journal, so
# a collector tees /dev/log to a file. Each reader below therefore tries the
# journal first and falls back to files, and every reader returns the same
# shape so the viewer can merge them into one timeline.
# --------------------------------------------------------------------------

SYSLOG_FILES = ["/var/log/ham-syslog.log", "/var/log/haproxy.log",
                "/var/log/syslog", "/var/log/messages"]
MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
# syslog severities 0-7; anything at warning or worse is worth colouring
SYSLOG_LEVELS = ["ERROR", "ERROR", "ERROR", "ERROR",
                 "WARNING", "INFO", "INFO", "DEBUG"]


def _tail(path, lines):
    """Last `lines` lines of a file, read from the end so a large log is cheap."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    want = min(size, max(4096, lines * 400))
    try:
        with open(path, "rb") as fh:
            fh.seek(size - want)
            data = fh.read()
    except OSError:
        return []
    if want < size:
        data = data.split(b"\n", 1)[-1]        # drop the partial first line
    return data.decode("utf-8", "replace").splitlines()[-lines:]


def _epoch(dt):
    return dt.replace(tzinfo=dt.tzinfo or timezone.utc).timestamp()


def _level_of(text):
    up = text.upper()
    for word in ("CRITICAL", "ALERT", "EMERG", "FATAL"):
        if word in up:
            return "ERROR"
    if "ERROR" in up or "ERR:" in up or "FAILED" in up or "FAILURE" in up:
        return "ERROR"
    if "WARNING" in up or "WARN " in up or "WARN:" in up:
        return "WARNING"
    if "DEBUG" in up:
        return "DEBUG"
    return "INFO"


def _entry(ts, source, level, text):
    return {"ts": ts, "source": source, "level": level, "text": text.rstrip()}


def _parse_syslog_date(token_month, token_day, token_time):
    """Classic syslog stamps carry no year; assume the most recent one."""
    try:
        now = datetime.now()
        dt = datetime(now.year, MONTHS[token_month], int(token_day),
                      *[int(x) for x in token_time.split(":")])
        if dt > now + timedelta(days=1):        # December log read in January
            dt = dt.replace(year=now.year - 1)
        return dt.astimezone().timestamp()
    except (KeyError, ValueError):
        return None


def read_manager_log(lines):
    """Our own log: '2026-08-10T12:00:00+0000 INFO message'."""
    out = []
    for line in _tail(str(LOG_PATH), lines):
        stamp, level, text = None, None, line
        parts = line.split(" ", 2)
        if len(parts) == 3 and "T" in parts[0]:
            try:
                stamp = _epoch(datetime.strptime(parts[0], "%Y-%m-%dT%H:%M:%S%z"))
                level, text = parts[1], parts[2]
            except ValueError:
                stamp = None
        if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            level, text = _level_of(line), line
        out.append(_entry(stamp, "manager", "ERROR" if level == "CRITICAL" else level, text))
    return out


def read_journal(unit, source, lines):
    """journalctl, when there is a journal to read."""
    if not shutil.which("journalctl"):
        return None
    rc, out = run(["journalctl", "-u", unit, "-n", str(lines),
                   "-o", "short-iso", "--no-pager"], timeout=20)
    if rc != 0:
        return None
    entries = []
    for line in out.splitlines():
        if not line or line.startswith("-- "):   # "-- No entries --", boot markers
            continue
        stamp, text = None, line
        head = line.split(" ", 1)
        if len(head) == 2:
            try:
                stamp = _epoch(datetime.strptime(head[0], "%Y-%m-%dT%H:%M:%S%z"))
                # strip the hostname, keep 'unit[pid]: message'
                rest = head[1].split(" ", 1)
                text = rest[1] if len(rest) == 2 else head[1]
            except ValueError:
                pass
        entries.append(_entry(stamp, source, _level_of(text), text))
    return entries


def parse_syslog_line(line):
    """Split one syslog line into (timestamp, program, message, level).

    Two shapes have to work. Datagrams read straight off /dev/log keep their
    '<134>' priority prefix and carry no hostname; lines written by a syslog
    daemon drop the priority and add one. Rather than guess by position, find
    the field that ends in ':' -- that is the program -- and treat whatever
    precedes it as the hostname.
    """
    level = None
    if line.startswith("<") and ">" in line[:6]:
        pri, _, line = line[1:].partition(">")
        if pri.isdigit():
            level = SYSLOG_LEVELS[int(pri) % 8]
    parts = line.split(None, 3)
    if len(parts) < 4 or parts[0] not in MONTHS:
        return None, "", line, level
    stamp = _parse_syslog_date(parts[0], parts[1], parts[2])
    rest = parts[3]
    prog, message = "", rest
    for i, tok in enumerate(rest.split(None, 2)[:2]):
        if tok.endswith(":"):
            prog = tok[:-1].split("[")[0]       # 'haproxy[1234]:' -> 'haproxy'
            message = rest.split(None, i + 1)[i + 1] if len(rest.split(None, i + 1)) > i + 1 else ""
            break
    return stamp, prog, "%s: %s" % (prog, message) if prog else message, level


def read_syslog_files(match, source, lines):
    """Fallback for hosts without a journal, and for the container's collector.

    /var/log/syslog holds every program's output, so filtering on the program
    field (not the whole line) keeps a HAProxy message that happens to mention
    keepalived out of the Keepalived view.
    """
    needle = match.lower()
    entries = []
    for path in SYSLOG_FILES:
        if not os.path.exists(path):
            continue
        for line in _tail(path, lines * 6):
            stamp, prog, text, level = parse_syslog_line(line)
            if needle not in (prog or line).lower():
                continue
            entries.append(_entry(stamp, source, level or _level_of(text), text))
        if entries:
            break                               # first file that has anything wins
    return entries[-lines:]


def read_service_log(unit, match, source, lines):
    entries = read_journal(unit, source, lines)
    if entries:
        return entries
    return read_syslog_files(match, source, lines)


def read_acme_log(lines):
    """acme.sh's own log, plus the outcome of each issuance we ran."""
    entries = []
    for line in _tail(str(ACME_HOME / "acme.sh.log"), lines):
        stamp, text = None, line
        if line.startswith("["):
            head, _, rest = line[1:].partition("]")
            for fmt in ("%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y"):
                try:
                    stamp = _epoch(datetime.strptime(head.strip(), fmt))
                    text = rest.strip()
                    break
                except ValueError:
                    continue
        entries.append(_entry(stamp, "acme", _level_of(text), text))
    # issuance results are kept in _meta by record_issue(); surface them here so
    # a failed renewal is visible even when acme.sh wrote nothing useful
    cfg = load_config()
    names = {c.get("id"): c.get("name", "?") for c in cfg["acme"].get("certificates", [])}
    for cid, rec in (cfg.get("_meta", {}).get("issue_log") or {}).items():
        stamp = None
        try:
            stamp = _epoch(datetime.fromisoformat(rec.get("time", "")))
        except ValueError:
            pass
        ok = rec.get("ok")
        entries.append(_entry(
            stamp, "acme", "INFO" if ok else "ERROR",
            "certificate %s: %s in %ss%s" % (
                names.get(cid, cid), "issued" if ok else "failed",
                rec.get("seconds", "?"),
                "" if ok else " -- " + (rec.get("error") or "no detail"))))
    return entries


LOG_SOURCES = [
    ("manager", "Web UI", lambda n: read_manager_log(n)),
    ("haproxy", "HAProxy", lambda n: read_service_log("haproxy", "haproxy", "haproxy", n)),
    ("acme", "acme.sh", lambda n: read_acme_log(n)),
    ("keepalived", "Keepalived",
     lambda n: read_service_log("keepalived", "Keepalived", "keepalived", n)),
]
LEVEL_ORDER = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}


def collect_logs(sources, lines, query="", min_level="DEBUG"):
    wanted = [s for s in LOG_SOURCES if s[0] in sources]
    entries, failed = [], []
    for key, _label, reader in wanted:
        try:
            entries.extend(reader(lines) or [])
        except Exception as exc:                # one unreadable source must not
            failed.append("%s: %s" % (key, exc))  # blank the whole viewer
            log.exception("could not read the %s log", key)
    floor = LEVEL_ORDER.get(min_level, 0)
    if floor:
        entries = [e for e in entries if LEVEL_ORDER.get(e["level"], 1) >= floor]
    if query:
        needle = query.lower()
        entries = [e for e in entries if needle in e["text"].lower()]
    # entries with no parsable timestamp sort to the end of their source rather
    # than to 1970, which would bury them
    fallback = max([e["ts"] for e in entries if e["ts"]] or [time.time()])
    entries.sort(key=lambda e: e["ts"] if e["ts"] else fallback)
    return entries[-lines:], failed


@app.get("/api/logs")
def api_logs():
    args = request.args
    sources = [s for s in (args.get("sources") or "").split(",") if s]
    if not sources:
        sources = [s[0] for s in LOG_SOURCES]
    try:
        lines = max(1, min(2000, int(args.get("lines", "300"))))
    except ValueError:
        lines = 300
    entries, failed = collect_logs(sources, lines, args.get("q", "").strip(),
                                   (args.get("level") or "DEBUG").upper())
    if args.get("format") == "text":
        body = "\n".join(
            "%s  %-10s %-7s %s" % (
                datetime.fromtimestamp(e["ts"], timezone.utc).isoformat(timespec="seconds")
                if e["ts"] else "-" * 25, e["source"], e["level"], e["text"])
            for e in entries)
        return Response(body + "\n", mimetype="text/plain", headers={
            "Content-Disposition": "attachment; filename=haproxy-manager-logs.txt"})
    return jsonify({"ok": True, "entries": entries, "failed": failed,
                    "sources": [{"key": k, "label": lab} for k, lab, _ in LOG_SOURCES]})


# --------------------------------------------------------------------------
# version and one-click update
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


def check_for_update(cfg=None):
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
        cur = cfg or load_config()
        cur["_meta"]["update"] = result      # _meta: not hashed, not synced
        save_config(cur)
    if result["available"]:
        notify_transition("update:" + result["latest"], "available", "updates",
                          "haproxy-manager %s is available" % result["latest"],
                          "This node runs %s. Version %s has been published.\n\n"
                          "Update from System > Version & updates."
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
    })


@app.post("/api/version/check")
def api_version_check():
    info = check_for_update()
    return jsonify(dict(info, version=VERSION))


def _update_running():
    rc, out = run(["systemctl", "is-active", UPDATE_UNIT])
    return out.strip().startswith("activ")


@app.post("/api/update")
def api_update():
    ok, why = update_supported()
    if not ok:
        return jsonify({"ok": False, "error": why}), 400
    if _update_running():
        return jsonify({"ok": False, "error": "an update is already running"}), 409

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
        return jsonify({"ok": False, "error": "could not start the updater: %s" % out}), 500
    log.warning("update started from %s -- this service will restart", url)
    return jsonify({"ok": True, "note": "The update is running. This service restarts when it finishes."})


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
                check_for_update(cfg)
        except Exception:
            pass
        time.sleep(3600)


# --------------------------------------------------------------------------
# publish wizard: one URL + one target -> every object needed to serve it
# --------------------------------------------------------------------------

def _split_url(raw, what, default_scheme="http", allow=("http", "https", "tcp")):
    """Parse a user-typed URL into scheme/host/port/path (and an optional name).

    Targets may carry an explicit server name: galera1=192.168.1.81:3306.
    """
    raw = (raw or "").strip()
    if not raw:
        return None, "%s is required" % what
    label = ""
    # A target may carry both, as pve1=https://10.0.0.1:8006. Looking for the
    # "=" only after the scheme missed that form; what actually distinguishes a
    # name from an "=" inside a URL is whether anything precedes the scheme.
    if "=" in raw and "://" not in raw.split("=")[0]:
        label, raw = raw.split("=", 1)
        label, raw = label.strip(), raw.strip()
    if "://" not in raw:
        raw = default_scheme + "://" + raw   # be forgiving: 192.168.1.100:1781
    parts = urlsplit(raw)
    if parts.scheme not in allow:
        return None, "%s must be one of %s" % (what, ", ".join(s + "://" for s in allow))
    if not parts.hostname:
        return None, "%s has no host name" % what
    try:
        port = parts.port
    except ValueError:
        return None, "%s has an invalid port" % what
    if not port:
        if parts.scheme == "tcp":
            return None, "%s needs an explicit port, e.g. tcp://0.0.0.0:3306" % what
        port = 443 if parts.scheme == "https" else 80
    path = parts.path or ""
    if path in ("/", ""):
        path = ""
    return {"scheme": parts.scheme, "host": parts.hostname, "port": port,
            "path": path, "label": label}, None


def _uniq_name(existing, base):
    base = _sec(base)
    if base not in existing:
        return base
    n = 2
    while "%s-%d" % (base, n) in existing:
        n += 1
    return "%s-%d" % (base, n)


def _find(items, pred):
    for it in items:
        if pred(it):
            return it
    return None


def _bind_ports(fe):
    ports = set()
    for line in (fe.get("binds") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        hostport = line.split()[0]
        if ":" in hostport:
            tail = hostport.rsplit(":", 1)[1]
            if tail.isdigit():
                ports.add(int(tail))
    return ports


WIZARD_MARK = "created by the publish wizard"


def domain_covers(pattern, host):
    """Does a certificate domain entry cover this host name?

    Wildcards follow what browsers accept (RFC 6125): the wildcard is only the
    leftmost label and matches exactly one label, so *.example.com covers
    a.example.com but neither example.com nor a.b.example.com.
    """
    pattern = (pattern or "").strip().strip(".").lower()
    host = (host or "").strip().strip(".").lower()
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not suffix or not host.endswith("." + suffix):
            return False
        label = host[:-(len(suffix) + 1)]
        return bool(label) and "." not in label
    return False


def cert_for_host(certificates, host):
    """The best existing certificate for a host: (cert, "exact"|"wildcard") or (None, None).

    An exact name wins over a wildcard that would also cover it.
    """
    wildcard = None
    for c in certificates:
        for d in parse_domains(c):
            if d.strip().lower() == (host or "").strip().lower():
                return c, "exact"
            if d.strip().startswith("*.") and domain_covers(d, host) and wildcard is None:
                wildcard = c
    return (wildcard, "wildcard") if wildcard else (None, None)


# --------------------------------------------------------------------------
# acme.sh DNS hooks: what exists, and what each one needs
# --------------------------------------------------------------------------

_dnsapi_cache = {"stamp": None, "hooks": []}


def _parse_dnsapi(path):
    """Read one acme.sh dnsapi script's self-description.

    acme.sh 3.x embeds a machine-readable block in every hook:

        dns_cf_info='CloudFlare
        Site: CloudFlare.com
        Docs: github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cf
        Options:
         CF_Key API Key
         CF_Email Your account email
        OptionsAlt:
         CF_Token API Token
        '
    """
    hook = path.stem
    info = {"hook": hook, "title": hook, "site": "", "docs": "",
            "options": [], "options_alt": []}
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return info

    m = re.search(r"^dns_[A-Za-z0-9_]+_info='(.*?)'\s*$", text, re.S | re.M)
    if not m:
        # No description block: fall back to the variables the script reads.
        seen = []
        for v in re.findall(r'_readaccountconf_mutable\s+"?([A-Za-z][A-Za-z0-9_]*)"?', text):
            if v not in seen:
                seen.append(v)
        info["options"] = [{"name": v, "desc": "", "optional": False} for v in seen]
        return info

    block = m.group(1)

    # A few hooks declare their options as JSON instead of prose (dns_czechia).
    if block.lstrip().startswith("["):
        try:
            for entry in json.loads(block):
                info["options"].append({
                    "name": entry.get("name", ""),
                    "desc": entry.get("usage", ""),
                    "optional": str(entry.get("required", "1")) not in ("1", "true", "True"),
                })
            return info
        except (ValueError, AttributeError, TypeError):
            pass

    lines = block.splitlines()
    if lines:
        info["title"] = lines[0].strip() or hook

    # Section driven, not indentation driven, and tolerant of the three header
    # dialects in the wild: options flush left (dns_poweradmin), an "Optional:"
    # sub-heading (dns_hetznercloud), and a header with trailing prose
    # ("Options: For old API version v1", dns_selectel).
    meta_keys = ("site", "docs", "issues", "author", "domains")
    bucket, optional_here = None, False
    for line in lines[1:]:
        text_ = line.strip()
        if not text_:
            continue
        head = text_.split(":", 1)[0].strip().lower() if ":" in text_ else ""
        if head in ("options", "optionsalt"):
            bucket, optional_here = head, False
            continue
        if head == "optional":                 # sub-heading inside the options
            optional_here = True
            continue
        if head in meta_keys or text_.endswith(":"):   # metadata, or any other section
            if head in ("site", "docs"):
                info[head] = text_.split(": ", 1)[1].strip()
            bucket = None                      # stop collecting: Notes, Issues, ...
            continue
        if bucket:
            parts = text_.split(None, 1)
            desc = parts[1].strip() if len(parts) > 1 else ""
            entry = {"name": parts[0], "desc": desc,
                     "optional": optional_here or "optional" in desc.lower()}
            (info["options_alt"] if bucket == "optionsalt" else info["options"]).append(entry)
    return info


def dnsapi_hooks():
    """Every DNS hook the installed acme.sh provides, parsed and cached."""
    d = ACME_HOME / "dnsapi"
    try:
        stamp = d.stat().st_mtime
    except OSError:
        return []
    if _dnsapi_cache["stamp"] == stamp:
        return _dnsapi_cache["hooks"]
    hooks = [_parse_dnsapi(p) for p in sorted(d.glob("dns_*.sh"))]
    hooks.sort(key=lambda h: h["title"].lower())
    _dnsapi_cache.update(stamp=stamp, hooks=hooks)
    return hooks


@app.get("/api/acme/health")
def api_acme_health():
    """Whether this node can actually obtain a certificate.

    Existence is not enough: the file has to be runnable, its home has to be
    writable for account keys and issued certificates, and the tools it shells
    out to have to be there.
    """
    path = Path(ACME_SH)
    out = {"ok": False, "path": str(path), "home": str(ACME_HOME),
           "version": "", "problem": "", "hint": ""}

    if not path.exists():
        out["problem"] = "acme.sh is not installed at %s." % path
        out["hint"] = ("Re-run the installer on this node -- it installs acme.sh when it is "
                       "missing -- or point HAM_ACME_SH at an existing copy. Nodes installed "
                       "before this was fixed never got it: the old installer reported success "
                       "while acme.sh failed to install.")
        return jsonify(out)

    if not os.access(str(path), os.X_OK):
        out["problem"] = "%s is not executable." % path
        out["hint"] = "chmod +x %s" % path
        return jsonify(out)

    rc, text = run([str(path), "--home", str(ACME_HOME), "--version"], timeout=30)
    if rc != 0:
        out["problem"] = "acme.sh will not run: %s" % (text.strip()[:300] or "exit code %s" % rc)
        out["hint"] = "Check that bash and curl are installed, then re-run the installer."
        return jsonify(out)
    out["version"] = next((l.strip() for l in reversed(text.splitlines())
                           if l.strip().startswith("v")), text.strip()[:40])

    if not os.access(str(ACME_HOME), os.W_OK):
        out["problem"] = "%s is not writable, so account keys and certificates cannot be stored." % ACME_HOME
        out["hint"] = "Fix the ownership of that directory; the service runs as root."
        return jsonify(out)

    missing = [t for t in ("curl", "openssl") if not shutil.which(t)]
    if missing:
        out["problem"] = "acme.sh needs %s, which is not installed." % " and ".join(missing)
        out["hint"] = "apt-get install -y " + " ".join(missing)
        return jsonify(out)
    if not shutil.which("socat"):
        out["ok"] = True
        out["problem"] = ""
        out["warning"] = ("socat is not installed, so HTTP-01 validation with acme.sh's standalone "
                          "listener will fail. DNS-01 is unaffected.")
        return jsonify(out)

    out["ok"] = True
    return jsonify(out)


@app.get("/api/acme/dnsapi")
def api_acme_dnsapi():
    hooks = dnsapi_hooks()
    return jsonify({"ok": True, "count": len(hooks), "hooks": hooks,
                    "acme_home": str(ACME_HOME),
                    "note": "" if hooks else
                            "acme.sh was not found at %s, so its DNS hooks could not be listed. "
                            "Type the hook name by hand." % ACME_HOME})


@app.post("/api/wizard/certificate")
def api_wizard_certificate():
    """Request a certificate, creating the account and challenge type it needs.

    account/challenge are either {"id": "<existing>"} or a full object to
    create, so the whole thing is one round trip from the UI.
    """
    body = request.get_json(force=True, silent=True) or {}
    domains = [d for d in re.split(r"[\s,]+", body.get("domains") or "") if d]
    if not domains:
        return jsonify({"ok": False, "error": "at least one domain name is required"}), 400
    bad = [d for d in domains if not re.match(r"^\*?[A-Za-z0-9_.-]+$", d)]
    if bad:
        return jsonify({"ok": False, "error": "not a domain name: %s" % ", ".join(bad[:3])}), 400

    acts, warns = [], []
    dry_run = bool(body.get("dry_run"))

    with _lock:
        cfg = load_config()
        draft = copy.deepcopy(cfg)
        ac = draft["acme"]

        def pick(kind, spec, defaults, label_field="name"):
            """Reuse the referenced object, or create one from the given fields."""
            spec = spec or {}
            if spec.get("id"):
                found = _by_id(ac[kind]).get(spec["id"])
                if not found:
                    raise ValueError("the selected %s no longer exists" % kind[:-1])
                acts.append({"action": "reused", "type": label_field and kind[:-1].title(),
                             "name": found.get("name", "")})
                return found
            obj = dict(defaults)
            obj.update({k: v for k, v in spec.items() if k != "id"})
            if not obj.get("name"):
                raise ValueError("a name is required for the new %s" % kind[:-1])
            obj["id"] = str(uuid.uuid4())
            obj["name"] = _uniq_name({x["name"] for x in ac[kind]}, obj["name"])
            ac[kind].append(obj)
            acts.append({"action": "created", "type": kind[:-1].title(), "name": obj["name"]})
            return obj

        try:
            account = pick("accounts", body.get("account"),
                           {"name": "", "email": "", "ca": "letsencrypt", "eab_kid": "", "eab_hmac": ""})
            challenge = pick("challenges", body.get("challenge"),
                             {"name": "", "method": "http01", "dns_provider": "", "dns_credentials": ""})
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

        if not account.get("email"):
            warns.append("The ACME account has no e-mail address. Let's Encrypt accepts that, "
                         "but you will get no expiry warnings from them.")
        wildcards = [d for d in domains if d.startswith("*.")]
        if wildcards and challenge.get("method") != "dns01":
            warns.append("%s is a wildcard, and wildcards can only be validated with DNS-01. "
                         "Pick or create a DNS-01 challenge type." % wildcards[0])
        if challenge.get("method") == "dns01" and not challenge.get("dns_provider"):
            warns.append("The DNS-01 challenge type has no DNS API hook set, so acme.sh cannot "
                         "create the validation record.")

        name = (body.get("name") or "").strip() or domains[0].replace("*.", "wildcard-")
        existing = _find(ac["certificates"], lambda c: set(parse_domains(c)) == set(domains))
        if existing:
            existing.update({"account": account["id"], "challenge": challenge["id"],
                             "key_type": body.get("key_type") or existing.get("key_type", "ec-256"),
                             "auto_renew": bool(body.get("auto_renew", True))})
            cert = existing
            acts.append({"action": "updated", "type": "Certificate", "name": cert["name"]})
        else:
            cert = {"id": str(uuid.uuid4()),
                    "name": _uniq_name({c["name"] for c in ac["certificates"]}, name),
                    "domains": " ".join(domains),
                    "account": account["id"], "challenge": challenge["id"],
                    "key_type": body.get("key_type") or "ec-256",
                    "auto_renew": bool(body.get("auto_renew", True)),
                    }
            ac["certificates"].append(cert)
            acts.append({"action": "created", "type": "Certificate", "name": cert["name"]})

        summary = {"ok": True, "actions": acts, "warnings": warns, "dry_run": dry_run,
                   "domains": domains, "certificate": cert["name"], "certificate_id": cert["id"]}
        if dry_run:
            return jsonify(summary)
        save_config(draft)
        cfg = draft

    if body.get("issue"):
        summary["issued"] = acme_issue(cfg, cert, force=bool(body.get("force")))
    return jsonify(summary)


@app.get("/api/acme/cover")
def api_acme_cover():
    """Which configured certificate, if any, already covers this host name."""
    host = (request.args.get("host") or "").strip()
    if not host:
        return jsonify({"ok": False, "error": "host is required"}), 400
    cfg = load_config()
    cert, how = cert_for_host(cfg["acme"]["certificates"], host)
    if not cert:
        return jsonify({"ok": True, "host": host, "covered": False})
    info = cert_details(cert_path(cert))
    return jsonify({"ok": True, "host": host, "covered": True, "how": how,
                    "id": cert["id"], "name": cert["name"],
                    "domains": parse_domains(cert), "status": info["status"],
                    "expires_iso": info["expires_iso"], "days_left": info["days_left"]})


def _drop_orphan_wizard_servers(hp, candidate_ids, acts):
    """Remove wizard-made Real Servers that no pool references any more.

    Hand-made servers are left alone even when unused -- someone may be keeping
    them on purpose, and the Real Servers page is where those belong.
    """
    referenced = {s for b in hp["backends"] for s in (b.get("servers") or [])}
    for sid in candidate_ids:
        if sid in referenced:
            continue
        srv = _by_id(hp["servers"]).get(sid)
        if srv and srv.get("description") == WIZARD_MARK:
            hp["servers"] = [s for s in hp["servers"] if s.get("id") != sid]
            acts.append({"action": "removed", "type": "Real Server", "name": srv.get("name")})


def _place_rule(hp, rule_ids, rule):
    """Position a rule among a frontend's rules by how specific it is.

    HAProxy takes the first matching use_backend, so a rule for
    host + /api must come before the host-only rule it refines -- otherwise
    the broader one swallows the traffic and the narrower one never fires.
    """
    rules = _by_id(hp["rules"])
    ids = [r for r in rule_ids if r != rule["id"]]
    mine = set(rule.get("conditions") or [])
    for i, rid in enumerate(ids):
        other = rules.get(rid)
        if other and set(other.get("conditions") or []) < mine:
            return ids[:i] + [rule["id"]] + ids[i:]
    return ids + [rule["id"]]


def wizard_publish(cfg, pubs, tgts, name=None, want_cert=True, account=None,
                   challenge=None, http_redirect=True, health=None,
                   certificate_id=None, new_certificate=False,
                   balance=None, persistence=None, stick_size=None, stick_expire=None,
                   stick_type=None, log_health_checks=False, check_port=None,
                   timeout_connect=None, timeout_server=None, service_id=None):
    """Create (or update) everything needed to serve `pub` from `tgts`.

    Re-running for the same public host updates that mapping instead of adding
    a second one, so the wizard is safe to use as an editor.
    """
    hp, ac = cfg["haproxy"], cfg["acme"]
    acts, warns = [], []
    # One service can answer for several host names. They share a listener, so
    # they must agree on scheme and port; the first one names things.
    pubs = pubs if isinstance(pubs, list) else [pubs]
    pub = pubs[0]
    hosts = [p["host"] for p in pubs]

    def act(action, kind, nm):
        acts.append({"action": action, "type": kind, "name": nm})

    # What this service already consists of, when one is being edited. Editing
    # must change these objects, never leave them behind and build a second set.
    existing_rule = existing_fe = None
    if service_id:
        if service_id.startswith("fe:"):
            existing_fe = _by_id(hp["frontends"]).get(service_id[3:])
        else:
            existing_rule = _by_id(hp["rules"]).get(service_id)
    existing_pool = _by_id(hp["backends"]).get(
        (existing_rule or existing_fe or {}).get("backend")
        or (existing_fe or {}).get("default_backend") or "")
    existing_monitor = _by_id(hp["healthchecks"]).get((existing_pool or {}).get("healthcheck") or "")
    old_hosts = [c.get("value") for c in
                 (_by_id(hp["conditions"]).get(cid) for cid in (existing_rule or {}).get("conditions") or [])
                 if c and c.get("type") == "host_matches" and c.get("value")]

    is_tcp = pub["scheme"] == "tcp"
    if name and name.strip():
        base = name.strip()
    elif is_tcp:
        base = "tcp-%d" % pub["port"]
    else:
        base = pub["host"].split(".")[0] + \
            ("-" + _sec(pub["path"].strip("/")).replace("/", "-") if pub["path"] else "")

    # -- Real Servers -----------------------------------------------------
    # The targets given here ARE the pool's servers: publishing the same URL
    # again repoints it instead of quietly adding a second server behind it.
    srv_ids = []
    for t in tgts:
        # A target already claimed by an earlier entry cannot be claimed again:
        # two targets sharing one address:port would otherwise both resolve to
        # the same server, and the pool would list it twice -- which HAProxy
        # rejects as "another server named 'a' was already defined".
        label = (t.get("label") or "").strip()
        srv = None
        if label:
            # An explicitly named target names the server, so match on that
            # first: editing galera2's address should repoint galera2, not
            # invent a second server.
            srv = _find(hp["servers"], lambda s: s.get("name") == label
                        and s["id"] not in srv_ids)
            if srv:
                srv["address"], srv["port"] = t["host"], t["port"]
                srv["ssl"] = t["scheme"] == "https"
        if srv is None:
            srv = _find(hp["servers"], lambda s: s.get("address") == t["host"]
                        and str(s.get("port")) == str(t["port"])
                        and bool(s.get("ssl")) == (t["scheme"] == "https")
                        and s["id"] not in srv_ids)
        if srv:
            act("reused", "Real Server", srv["name"])
        else:
            default_name = base + "-srv" if len(tgts) == 1 else "%s-%s" % (base, t["host"])
            srv = {"id": str(uuid.uuid4()),
                   "name": _uniq_name({s["name"] for s in hp["servers"]},
                                      t.get("label") or default_name),
                   "address": t["host"], "port": t["port"], "enabled": True,
                   "ssl": t["scheme"] == "https", "ssl_verify": False,
                   "description": WIZARD_MARK}
            hp["servers"].append(srv)
            act("created", "Real Server", srv["name"])
        if check_port:
            srv["check_port"] = check_port
        if srv["id"] not in srv_ids:
            srv_ids.append(srv["id"])

    pool_opts = {
        "mode": "tcp" if is_tcp else "http",
        "balance": balance or ("source" if is_tcp else "roundrobin"),
        "persistence": persistence or "none",
        "stick_size": stick_size or "50k",
        "stick_expire": stick_expire or "30m",
        "stick_type": stick_type if stick_type in ("ip", "ipv6") else "ip",
        "log_health_checks": bool(log_health_checks),
        "timeout_connect": timeout_connect or "",
        "timeout_server": timeout_server or "",
    }

    # -- Health Monitor ---------------------------------------------------
    monitor = None
    if health is None and existing_monitor is not None:
        # An edit that says nothing about health checking leaves it alone,
        # rather than reading silence as "switch it off".
        monitor = existing_monitor
        htype = existing_monitor.get("type") or "none"
        act("reused", "Health Monitor", monitor["name"])
    else:
        htype = (health or {}).get("type") or "none"
    if monitor is None and htype != "none":
        want = {"type": htype,
                "interval": (health.get("interval") or "2s"),
                "http_method": (health.get("method") or "GET"),
                "http_uri": health.get("uri") or "/",
                "http_version": health.get("version") or "",
                "http_host": health.get("host") or "",
                "expect_status": str(health.get("status") or "") if htype == "http" else "",
                "db_user": health.get("user") or ("postgres" if htype == "pgsql" else "haproxy"),
                "mysql_post41": bool(health.get("post41", True))}
        # The monitor this service already has is the one to change -- unless
        # another pool shares it, in which case editing here must not alter
        # that one too.
        shared = existing_monitor is not None and any(
            b.get("healthcheck") == existing_monitor["id"] and b is not existing_pool
            for b in hp["backends"])
        monitor = None
        if existing_monitor is not None and not shared:
            changed = any(str(existing_monitor.get(k, "")) != str(v) for k, v in want.items())
            existing_monitor.update(want)
            monitor = existing_monitor
            act("updated" if changed else "reused", "Health Monitor", monitor["name"])
        if monitor is None:
            monitor = _find(hp["healthchecks"], lambda m: all(
                str(m.get(k, "")) == str(v) for k, v in want.items() if k != "mysql_post41"))
        if monitor and monitor is not existing_monitor:
            act("reused", "Health Monitor", monitor["name"])
        if monitor is None:
            monitor = dict(want)
            monitor["id"] = str(uuid.uuid4())
            monitor["name"] = _uniq_name({m["name"] for m in hp["healthchecks"]}, base + "-check")
            hp["healthchecks"].append(monitor)
            act("created", "Health Monitor", monitor["name"])
        if htype in ("pgsql", "mysql"):
            warns.append("A %s check expects the servers behind this service to speak that database "
                         "protocol. Point it at the database itself, not at a web server, or every "
                         "server will be marked down." % ("PostgreSQL" if htype == "pgsql" else "MySQL/MariaDB"))

    # A monitor this service alone was using, now switched off
    if htype == "none" and existing_monitor is not None:
        if not any(b.get("healthcheck") == existing_monitor["id"] and b is not existing_pool
                   for b in hp["backends"]):
            hp["healthchecks"] = [m for m in hp["healthchecks"] if m["id"] != existing_monitor["id"]]
            acts.append({"action": "removed", "type": "Health Monitor",
                         "name": existing_monitor.get("name")})

    # -- Backend Pool -----------------------------------------------------
    # The pool this service already uses, whatever it is called: matching by
    # name alone would strand it as soon as the name changed.
    pool = existing_pool or _find(hp["backends"], lambda b: b.get("name") == _sec(base))
    if pool is not None and pool is existing_pool and pool.get("name") != _sec(base) and name:
        renamed = _uniq_name({b["name"] for b in hp["backends"] if b is not pool}, base)
        acts.append({"action": "renamed", "type": "Backend Pool",
                     "name": "%s -> %s" % (pool["name"], renamed)})
        pool["name"] = renamed
    if pool:
        previous = list(pool.get("servers") or [])
        pool["servers"] = srv_ids
        pool["healthcheck_enabled"] = bool(monitor)
        pool["healthcheck"] = monitor["id"] if monitor else ""
        pool.update(pool_opts)
        act("updated" if previous != srv_ids else "reused", "Backend Pool", pool["name"])
        _drop_orphan_wizard_servers(hp, previous, acts)
    else:
        pool = {"id": str(uuid.uuid4()),
                "name": _uniq_name({b["name"] for b in hp["backends"]}, base),
                "enabled": True, "servers": srv_ids,
                "healthcheck_enabled": bool(monitor),
                "healthcheck": monitor["id"] if monitor else ""}
        pool.update(pool_opts)
        hp["backends"].append(pool)
        act("created", "Backend Pool", pool["name"])

    # -- TCP: a listening port sent straight to the pool ------------------
    # TCP carries no host name, so a port serves exactly one pool: no
    # conditions, no rules, just bind + default_backend.
    if is_tcp:
        fe = None
        if service_id and service_id.startswith("fe:"):
            fe = _by_id(hp["frontends"]).get(service_id[3:])
            if fe:                       # the port may be what changed
                fe["binds"] = "%s:%d" % (pub["host"] or "0.0.0.0", pub["port"])
                clash = _find(hp["frontends"], lambda f: f is not fe and pub["port"] in _bind_ports(f))
                if clash:
                    raise ValueError("port %d is already used by \"%s\"" % (pub["port"], clash["name"]))
        fe = fe or _find(hp["frontends"], lambda f: pub["port"] in _bind_ports(f))
        if fe:
            if fe.get("mode") != "tcp":
                raise ValueError("port %d is already used by the HTTP service \"%s\"" % (pub["port"], fe["name"]))
            if fe.get("default_backend") and fe["default_backend"] != pool["id"]:
                other = _by_id(hp["backends"]).get(fe["default_backend"])
                raise ValueError("port %d already forwards to the pool \"%s\"; delete that service first"
                                 % (pub["port"], other["name"] if other else "?"))
            fe["default_backend"] = pool["id"]
            act("updated", "Public Service", fe["name"])
        else:
            fe = {"id": str(uuid.uuid4()),
                  "name": _uniq_name({f["name"] for f in hp["frontends"]}, base + "-listener"),
                  "enabled": True, "mode": "tcp",
                  "binds": "%s:%d" % (pub["host"] or "0.0.0.0", pub["port"]),
                  "ssl_enabled": False, "certificates": [], "rules": [],
                  "default_backend": pool["id"], "custom": ""}
            hp["frontends"].append(fe)
            act("created", "Public Service", fe["name"])
        return acts, warns

    # -- Conditions: host, and a path prefix when the URL has one ---------
    cond_ids = []
    for h in hosts:
        host_cond = _find(hp["conditions"], lambda c: c.get("type") == "host_matches"
                          and (c.get("value") or "").lower() == h.lower())
        if host_cond:
            act("reused", "Condition", host_cond["name"])
        else:
            suffix = base if len(hosts) == 1 else _sec(h.split(".")[0])
            host_cond = {"id": str(uuid.uuid4()),
                         "name": _uniq_name({c["name"] for c in hp["conditions"]}, "host-" + suffix),
                         "type": "host_matches", "value": h,
                         "description": "created by the publish wizard"}
            hp["conditions"].append(host_cond)
            act("created", "Condition", host_cond["name"])
        cond_ids.append(host_cond["id"])

    if pub["path"]:
        pc = _find(hp["conditions"], lambda c: c.get("type") == "path_starts_with"
                   and c.get("value") == pub["path"])
        if pc:
            act("reused", "Condition", pc["name"])
        else:
            pc = {"id": str(uuid.uuid4()),
                  "name": _uniq_name({c["name"] for c in hp["conditions"]}, "path-" + base),
                  "type": "path_starts_with", "value": pub["path"],
                  "description": "created by the publish wizard"}
            hp["conditions"].append(pc)
            act("created", "Condition", pc["name"])
        cond_ids.append(pc["id"])

    # -- Rule -------------------------------------------------------------
    # When a service is being edited, follow its id: the conditions are derived
    # from the URL, so a changed URL no longer matches and would otherwise leave
    # the old mapping in place beside the new one.
    rule = None
    if service_id and not service_id.startswith("fe:"):
        rule = _by_id(hp["rules"]).get(service_id)
    if rule is None:
        rule = _find(hp["rules"], lambda r: r.get("type") == "use_backend"
                     and set(r.get("conditions") or []) == set(cond_ids))
    if rule:
        previous_conds = list(rule.get("conditions") or [])
        rule["conditions"] = cond_ids
        rule["operator"] = "or" if len(hosts) > 1 else "and"
        rule["backend"] = pool["id"]
        act("updated", "Rule", rule["name"])
        # conditions the old URL needed and nothing else uses
        still_used = {c for r in hp["rules"] for c in (r.get("conditions") or [])}
        for cid in previous_conds:
            if cid in still_used:
                continue
            gone = _by_id(hp["conditions"]).get(cid)
            if gone:
                hp["conditions"] = [c for c in hp["conditions"] if c.get("id") != cid]
                acts.append({"action": "removed", "type": "Condition", "name": gone.get("name")})
    else:
        rule = {"id": str(uuid.uuid4()),
                "name": _uniq_name({r["name"] for r in hp["rules"]}, "to-" + base),
                "type": "use_backend", "test": "if",
                # several host names are alternatives; a host and a path are not
                "operator": "or" if len(hosts) > 1 else "and",
                "conditions": cond_ids, "backend": pool["id"]}
        hp["rules"].append(rule)
        act("created", "Rule", rule["name"])

    # -- Certificate (https only; the object also gives Apply a placeholder)
    cert = None
    if pub["scheme"] == "https" and want_cert:
        how = None
        if certificate_id:
            cert = _by_id(ac["certificates"]).get(certificate_id)
            how = "chosen" if cert else None
        if not cert and not new_certificate:
            # a single certificate has to cover every name, or it is no use here
            cert, how = cert_for_host(ac["certificates"], pub["host"])
            if cert and not all(cert_for_host([cert], h)[0] for h in hosts):
                missing = [h for h in hosts if not cert_for_host([cert], h)[0]]
                extra = " ".join(parse_domains(cert) + missing)
                cert["domains"] = extra
                act("updated", "Certificate", "%s covers %s" % (cert["name"], ", ".join(missing)))
                how = "extended"
        if cert:
            act("reused", "Certificate", cert["name"] +
                (" (wildcard %s covers %s)" % (next((d for d in parse_domains(cert)
                                                     if domain_covers(d, pub["host"]) and d.startswith("*.")), ""),
                                               pub["host"]) if how == "wildcard" else ""))
        else:
            accounts, challenges = ac["accounts"], ac["challenges"]
            acc_id = account or (accounts[0]["id"] if len(accounts) == 1 else "")
            ch_id = challenge or (challenges[0]["id"] if len(challenges) == 1 else "")
            stale = None
            for old in old_hosts:
                if old.lower() == pub["host"].lower():
                    continue
                candidate = _find(ac["certificates"], lambda c: parse_domains(c) == [old])
                if candidate and cert_details(cert_path(candidate))["status"] in ("missing", "placeholder"):
                    stale = candidate
                    break
            if stale is not None:
                # never issued, and for a name this service has stopped using
                stale["domains"] = " ".join(hosts)
                if acc_id:
                    stale["account"] = stale.get("account") or acc_id
                if ch_id:
                    stale["challenge"] = stale.get("challenge") or ch_id
                cert = stale
                act("updated", "Certificate", "%s -> %s" % (cert["name"], pub["host"]))
            else:
                cert = {"id": str(uuid.uuid4()),
                        "name": _uniq_name({c["name"] for c in ac["certificates"]}, base),
                        "domains": " ".join(hosts), "account": acc_id, "challenge": ch_id,
                        "key_type": "ec-256", "auto_renew": True}
                ac["certificates"].append(cert)
                act("created", "Certificate", cert["name"])
                if old_hosts and old_hosts[0].lower() != pub["host"].lower():
                    warns.append("The certificate for %s was kept: it has been issued, so it is not "
                                 "repointed automatically. Remove it under Certificates if it is no "
                                 "longer wanted." % old_hosts[0])
            if not acc_id or not ch_id:
                warns.append("The certificate has no %s yet, so it cannot be issued. Apply installs a "
                             "self-signed placeholder meanwhile; add one under ACME and press Issue."
                             % (" and ".join([x for x in ["ACME account" if not acc_id else "",
                                                          "challenge type" if not ch_id else ""] if x])))

    # -- Public Service (frontend) ---------------------------------------
    want_ssl = pub["scheme"] == "https"
    fe = _find(hp["frontends"], lambda f: pub["port"] in _bind_ports(f)
               and bool(f.get("ssl_enabled")) == want_ssl)
    if fe:
        act("updated", "Public Service", fe["name"])
    else:
        fe = {"id": str(uuid.uuid4()),
              "name": _uniq_name({f["name"] for f in hp["frontends"]},
                                 ("https" if want_ssl else "http") + "-" + str(pub["port"])),
              "enabled": True, "mode": "http", "binds": "0.0.0.0:%d" % pub["port"],
              "ssl_enabled": want_ssl, "http2": want_ssl, "forwardfor": True,
              "certificates": [], "rules": [], "custom": ""}
        hp["frontends"].append(fe)
        act("created", "Public Service", fe["name"])
    fe["rules"] = _place_rule(hp, fe.get("rules") or [], rule)
    if cert and cert["id"] not in (fe.get("certificates") or []):
        fe.setdefault("certificates", []).append(cert["id"])
    if not fe.get("default_backend"):
        warns.append("Public Service \"%s\" has no default Backend Pool, so requests for any other host "
                     "get a 503. That is usually what you want." % fe["name"])

    # -- Optional :80 service that redirects to https ---------------------
    if want_ssl and http_redirect:
        red = _find(hp["frontends"], lambda f: 80 in _bind_ports(f) and not f.get("ssl_enabled"))
        if red:
            if not red.get("http_to_https"):
                red["http_to_https"] = True
                act("updated", "Public Service", red["name"])
            else:
                act("reused", "Public Service", red["name"])
        else:
            red = {"id": str(uuid.uuid4()),
                   "name": _uniq_name({f["name"] for f in hp["frontends"]}, "http-redirect"),
                   "enabled": True, "mode": "http", "binds": "0.0.0.0:80",
                   "ssl_enabled": False, "forwardfor": True, "http_to_https": True,
                   "certificates": [], "rules": [], "custom": ""}
            hp["frontends"].append(red)
            act("created", "Public Service", red["name"])

    return acts, warns


# --------------------------------------------------------------------------
# front the management UI itself with HAProxy + a certificate
# --------------------------------------------------------------------------

WEBUI_NAME = "haproxy-manager-ui"
LOCAL_ONLY = "local_only"       # this object belongs to this node alone


def webui_pubs(cfg, pub):
    """This node's own name, plus the shared one if it fits on the same listener.

    Both point at this node's local UI. On the node holding the virtual IP the
    shared name resolves there, so it always reaches whichever node is active,
    while the per-node names stay reachable individually.
    """
    pubs = [pub]
    shared = (cfg.get("cluster") or {}).get("ui_url") or ""
    if not shared:
        return pubs
    sp, err = _split_url(shared, "The shared UI address", default_scheme="https",
                         allow=("http", "https"))
    if err or sp["host"].lower() == pub["host"].lower():
        return pubs
    if sp["scheme"] != pub["scheme"] or sp["port"] != pub["port"]:
        return pubs          # one listener cannot serve both; validated on save
    pubs.append(sp)
    return pubs


def build_webui(cfg, pub, mode="auto", http_redirect=True):
    """Create (or re-attach) this node's own UI service and mark it node-local."""
    target = {"scheme": "http", "host": "127.0.0.1", "port": PORT, "path": "", "label": WEBUI_NAME}
    acts, warns = wizard_publish(cfg, webui_pubs(cfg, pub), [target], name=WEBUI_NAME,
                                 want_cert=(mode != "none"), new_certificate=(mode == "new"),
                                 http_redirect=http_redirect,
                                 health={"type": "http", "interval": "5s", "uri": "/", "status": "200"})
    hp = cfg["haproxy"]
    pool = _find(hp["backends"], lambda b: b.get("name") == WEBUI_NAME)
    rule = _find(hp["rules"], lambda r: r.get("backend") == (pool or {}).get("id"))
    ids = {(pool or {}).get("id"), (rule or {}).get("id"), (pool or {}).get("healthcheck")}
    ids |= set((pool or {}).get("servers") or [])
    ids |= set((rule or {}).get("conditions") or [])
    _tag_local(hp, {i for i in ids if i})
    return acts, warns


def rebuild_webui(cfg):
    """Re-run the build from the stored setting, after a configuration arrives."""
    s = cfg["local"].get("web_ui") or {}
    if not (s.get("enabled") and s.get("url")):
        return
    pub, err = _split_url(s["url"], "The web UI address", default_scheme="https",
                          allow=("http", "https"))
    if err:
        return
    build_webui(cfg, pub, s.get("certificate", "auto"), True)


def _tag_local(hp, ids):
    """Mark the objects the web UI service is made of as node-local."""
    for coll in ("servers", "backends", "conditions", "rules", "healthchecks"):
        for item in hp.get(coll) or []:
            if item.get("id") in ids:
                item[LOCAL_ONLY] = True


def keep_local_only(mine, incoming):
    """Put this node's own objects back after adopting a shared configuration."""
    for coll, items in mine.items():
        if not isinstance(items, list):
            continue
        local = [i for i in items if i.get(LOCAL_ONLY)]
        if not local:
            continue
        have = {i.get("id") for i in incoming.get(coll) or []}
        incoming.setdefault(coll, []).extend(i for i in local if i.get("id") not in have)
    # re-attach them to whatever they were bound to
    # Match on name as well as id: each node created its own https-443, so the
    # same listener has a different id everywhere and an id-only match found
    # nothing -- which quietly dropped this node's UI rule from the listener.
    by_id = {f.get("id"): f for f in mine.get("frontends") or []}
    by_name = {f.get("name"): f for f in mine.get("frontends") or []}
    for fe in incoming.get("frontends") or []:
        was = by_id.get(fe.get("id")) or by_name.get(fe.get("name"))
        if not was:
            continue
        local_ids = {i.get("id") for coll in ("rules", "certificates")
                     for i in (mine.get("rules") or []) + (mine.get("certificates") or [])
                     if i.get(LOCAL_ONLY)}
        for key in ("rules", "certificates"):
            extra = [x for x in (was.get(key) or []) if x in local_ids and x not in (fe.get(key) or [])]
            if extra:
                fe[key] = (fe.get(key) or []) + extra
    return incoming


def strip_local_only(section):
    """A copy of a config section with this node's own objects removed.

    The UI service points at 127.0.0.1, so sending it to the other nodes would
    make each of them answer for this node's host name -- which is what
    happened: every node inherited node1's address.
    """
    out = copy.deepcopy(section)
    dropped = set()
    for coll, items in list(out.items()):
        if not isinstance(items, list):
            continue
        keep = []
        for item in items:
            if item.get(LOCAL_ONLY):
                dropped.add(item.get("id"))
            else:
                keep.append(item)
        out[coll] = keep
    # drop references to anything removed
    for fe in out.get("frontends") or []:
        for key in ("rules", "certificates"):
            if isinstance(fe.get(key), list):
                fe[key] = [x for x in fe[key] if x not in dropped]
        if fe.get("default_backend") in dropped:
            fe["default_backend"] = ""
    for be in out.get("backends") or []:
        if isinstance(be.get("servers"), list):
            be["servers"] = [x for x in be["servers"] if x not in dropped]
    return out


def _webui_setting(cfg):
    """Node-local: each node publishes its own name for its own UI."""
    old = (cfg["haproxy"]["settings"].pop("web_ui", None) or {})   # migrate off the shared section
    cur = cfg["local"].setdefault(
        "web_ui", {"enabled": False, "url": "", "certificate": "auto", "rule_id": ""})
    for k, v in old.items():
        cur.setdefault(k, v)
    return cur


@app.get("/api/webui")
def api_webui_get():
    cfg = load_config()
    s = _webui_setting(cfg)
    return jsonify({
        "enabled": bool(s.get("enabled")), "url": s.get("url", ""),
        "shared_url": (cfg.get("cluster") or {}).get("ui_url", ""),
        "certificate": s.get("certificate", "auto"), "rule_id": s.get("rule_id", ""),
        "port": PORT, "listen": LISTEN,
        "exposed_directly": LISTEN not in ("127.0.0.1", "localhost", "::1"),
    })


@app.post("/api/webui")
def api_webui_set():
    """Publish (or withdraw) the management UI as a normal HAProxy service."""
    body = request.get_json(force=True, silent=True) or {}
    enabled = bool(body.get("enabled"))

    with _lock:
        cfg = load_config()
        s = _webui_setting(cfg)

        if not enabled:
            removed = []
            rid = s.get("rule_id")
            if rid:
                removed = _remove_service_objects(cfg["haproxy"], rid)
            s.update({"enabled": False, "rule_id": ""})
            save_config(cfg)
            return jsonify({"ok": True, "enabled": False, "removed": removed,
                            "note": "Press Apply to stop serving it."})

        pub, err = _split_url(body.get("url"), "The web UI address",
                              default_scheme="https", allow=("http", "https"))
        if err:
            return jsonify({"ok": False, "error": err}), 400

        # The shared name is cluster-wide: every node answers for it, and the
        # one holding the virtual IP is the one reached. Both names sit on the
        # same listener, so they have to agree on scheme and port.
        shared_raw = (body.get("shared_url") or "").strip()
        shared = None
        if shared_raw:
            shared, serr = _split_url(shared_raw, "The shared address",
                                      default_scheme="https", allow=("http", "https"))
            if serr:
                return jsonify({"ok": False, "error": serr}), 400
            if shared["host"].lower() == pub["host"].lower():
                return jsonify({"ok": False, "error":
                                "The shared address must differ from this node's own address."}), 400
            if shared["scheme"] != pub["scheme"] or shared["port"] != pub["port"]:
                return jsonify({"ok": False, "error":
                                "Both addresses are served by one listener, so they must use the "
                                "same scheme and port. This node's is %s://%s:%s."
                                % (pub["scheme"], pub["host"], pub["port"])}), 400
        cfg["cluster"]["ui_url"] = ("%s://%s" % (shared["scheme"], shared["host"])) if shared else ""

        # Refuse to take a host name that already points somewhere else.
        hp = cfg["haproxy"]
        conds = _by_id(hp["conditions"])
        for rule in hp["rules"]:
            if rule.get("type") != "use_backend" or rule.get("id") == s.get("rule_id"):
                continue
            hosts = [conds[c].get("value", "").lower() for c in (rule.get("conditions") or [])
                     if c in conds and conds[c].get("type") == "host_matches"]
            if pub["host"].lower() in hosts:
                pool = _by_id(hp["backends"]).get(rule.get("backend"))
                if not pool or pool.get("name") != WEBUI_NAME:
                    return jsonify({"ok": False, "error":
                                    "%s already points at the service \"%s\". Choose another host name "
                                    "for the UI, or remove that service first."
                                    % (pub["host"], pool["name"] if pool else rule.get("name", "?"))}), 409

        draft = copy.deepcopy(cfg)
        mode = body.get("certificate", "auto")
        try:
            acts, warns = build_webui(draft, pub, mode, bool(body.get("http_redirect", True)))
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

        pool = _find(draft["haproxy"]["backends"], lambda b: b.get("name") == WEBUI_NAME)
        rule = _find(draft["haproxy"]["rules"], lambda r: r.get("backend") == (pool or {}).get("id"))
        ws = _webui_setting(draft)
        ws.update({"enabled": True, "url": "%s://%s" % (pub["scheme"], pub["host"]),
                   "certificate": mode, "rule_id": (rule or {}).get("id", "")})

        if LISTEN not in ("127.0.0.1", "localhost", "::1"):
            warns.append("The UI still answers directly on %s:%d in plain HTTP. Once this works, set "
                         "HAM_LISTEN=127.0.0.1 in the service unit so only HAProxy can reach it."
                         % (LISTEN, PORT))
        if pub["scheme"] != "https":
            warns.append("This publishes the UI over plain HTTP: the password and session cookie "
                         "would cross the network in the clear.")
        save_config(draft)
        cfg = draft

    result = {"ok": True, "enabled": True, "actions": acts, "warnings": warns,
              "url": ws["url"], "note": "Press Apply to start serving it."}
    if body.get("apply"):
        result["applied"] = do_apply()
    return jsonify(result)


@app.get("/api/services")
def api_services():
    """The published mappings, derived from the objects the wizard creates.

    A service is a use_backend rule whose conditions pin a host name; that is
    exactly what the wizard builds, and it also picks up equivalent rules made
    by hand on the Advanced pages.
    """
    cfg = load_config()
    hp = cfg["haproxy"]
    conds, backends = _by_id(hp["conditions"]), _by_id(hp["backends"])
    servers, rules = _by_id(hp["servers"]), _by_id(hp["rules"])
    certs = _by_id(cfg["acme"]["certificates"])

    monitors = _by_id(hp["healthchecks"])

    def pool_settings(pool):
        """Everything the wizard would need to re-create this mapping unchanged."""
        if not pool:
            return {}
        first = next((servers[s] for s in (pool.get("servers") or []) if s in servers), {})
        m = monitors.get(pool.get("healthcheck")) if pool.get("healthcheck_enabled") else None
        return {
            "balance": pool.get("balance") or "roundrobin",
            "persistence": pool.get("persistence") or "none",
            "stick_type": pool.get("stick_type") or "ip",
            "stick_size": pool.get("stick_size") or "50k",
            "stick_expire": pool.get("stick_expire") or "30m",
            "log_health_checks": bool(pool.get("log_health_checks")),
            "check_port": first.get("check_port") or "",
            "timeout_connect": pool.get("timeout_connect") or "",
            "timeout_server": pool.get("timeout_server") or "",
            "health": {"type": m.get("type") if m else "none",
                       "interval": (m or {}).get("interval") or "2s",
                       "uri": (m or {}).get("http_uri") or "/",
                       "status": (m or {}).get("expect_status") or "",
                       "user": (m or {}).get("db_user") or "",
                       "method": (m or {}).get("http_method") or "GET",
                       "version": (m or {}).get("http_version") or "",
                       "host": (m or {}).get("http_host") or ""},
        }

    def pool_targets(pool):
        out = []
        for sid in (pool.get("servers") if pool else []) or []:
            s = servers.get(sid)
            if s:
                out.append("%s://%s:%s" % ("https" if s.get("ssl") else "http",
                                           s.get("address"), s.get("port")))
        return out

    out = []
    for fe in hp["frontends"]:
        ports = sorted(_bind_ports(fe))
        scheme = "https" if fe.get("ssl_enabled") else "http"

        # A TCP listener carries no host name: the port itself is the service.
        if fe.get("mode") == "tcp":
            pool = backends.get(fe.get("default_backend"))
            if not pool:
                continue
            bind = (fe.get("binds") or "").splitlines()[0].strip() if fe.get("binds") else ""
            out.append(dict(pool_settings(pool), **{
                "id": "fe:" + fe["id"],
                "url": "tcp://%s" % (bind or (":%d" % ports[0] if ports else "?")),
                "host": bind.rsplit(":", 1)[0] if ":" in bind else "", "path": "", "scheme": "tcp",
                "port": ports[0] if ports else None,
                "targets": [t.replace("http://", "tcp://") for t in pool_targets(pool)],
                "pool": pool["name"], "frontend": fe["name"], "frontend_id": fe["id"],
                "enabled": fe.get("enabled", True) and pool.get("enabled", True),
                "certificate": None, "certificate_id": None, "certificate_match": None,
                "certificate_status": None, "expires_iso": None, "days_left": None,
            }))
            continue

        for rid in fe.get("rules") or []:
            rule = rules.get(rid)
            if not rule or rule.get("type") != "use_backend":
                continue
            all_hosts, path = [], ""
            for cid in rule.get("conditions") or []:
                c = conds.get(cid)
                if not c:
                    continue
                if c.get("type") == "host_matches" and c.get("value"):
                    all_hosts.append(c["value"])
                elif c.get("type") == "path_starts_with":
                    path = c.get("value") or ""
            if not all_hosts:
                continue
            host = all_hosts[0]

            pool = backends.get(rule.get("backend"))
            targets = pool_targets(pool)
            default_port = 443 if scheme == "https" else 80
            shown_port = "" if (not ports or ports[0] == default_port) else ":%d" % ports[0]

            attached = [certs[cid] for cid in (fe.get("certificates") or []) if cid in certs]
            cert, match = cert_for_host(attached, host)
            uncovered = [h for h in all_hosts if not cert_for_host(attached, h)[0]]
            info = cert_details(cert_path(cert)) if cert else None

            out.append(dict(pool_settings(pool), **{
                "id": rule["id"],
                "managed": "web-ui" if rule.get(LOCAL_ONLY) else "",
                "url": "%s://%s%s%s" % (scheme, host, shown_port, path),
                "urls": ["%s://%s%s%s" % (scheme, h, shown_port, path) for h in all_hosts],
                "hosts": all_hosts,
                "certificate_uncovered": uncovered,
                "host": host, "path": path, "scheme": scheme,
                "port": ports[0] if ports else None,
                "targets": targets,
                "pool": pool["name"] if pool else None,
                "frontend": fe["name"], "frontend_id": fe["id"],
                "enabled": fe.get("enabled", True) and (pool.get("enabled", True) if pool else False),
                "certificate": cert["name"] if cert else None,
                "certificate_id": cert["id"] if cert else None,
                "certificate_match": match,          # "exact" or "wildcard"
                "certificate_status": info["status"] if info else None,
                "expires_iso": info["expires_iso"] if info else None,
                "days_left": info["days_left"] if info else None,
            }))
    return jsonify(out)


def _remove_service_objects(hp, rid):
    """Drop a use_backend rule and everything only it was using."""
    rule = _by_id(hp["rules"]).get(rid)
    if not rule:
        return []
    for fe in hp["frontends"]:
        if rid in (fe.get("rules") or []):
            fe["rules"] = [x for x in fe["rules"] if x != rid]
    hp["rules"] = [r for r in hp["rules"] if r.get("id") != rid]
    removed = [{"type": "Rule", "name": rule.get("name")}]

    still_used = {c for r in hp["rules"] for c in (r.get("conditions") or [])}
    for cid in rule.get("conditions") or []:
        if cid in still_used:
            continue
        cond = _by_id(hp["conditions"]).get(cid)
        if cond:
            hp["conditions"] = [c for c in hp["conditions"] if c.get("id") != cid]
            removed.append({"type": "Condition", "name": cond.get("name")})

    pool_id = rule.get("backend")
    pool = _by_id(hp["backends"]).get(pool_id)
    pool_used = any(r.get("backend") == pool_id for r in hp["rules"]) or \
        any(f.get("default_backend") == pool_id for f in hp["frontends"])
    if pool and not pool_used:
        server_ids = list(pool.get("servers") or [])
        hp["backends"] = [b for b in hp["backends"] if b.get("id") != pool_id]
        removed.append({"type": "Backend Pool", "name": pool.get("name")})
        in_use = {s for b in hp["backends"] for s in (b.get("servers") or [])}
        for sid in server_ids:
            if sid in in_use:
                continue
            srv = _by_id(hp["servers"]).get(sid)
            if srv:
                hp["servers"] = [s for s in hp["servers"] if s.get("id") != sid]
                removed.append({"type": "Real Server", "name": srv.get("name")})
    return removed


@app.delete("/api/services/<rid>")
def api_service_delete(rid):
    """Remove a mapping and every object it alone was using."""
    with _lock:
        cfg = load_config()
        hp = cfg["haproxy"]

        # "fe:<id>" is a TCP listener: the frontend itself is the service.
        if rid.startswith("fe:"):
            fe = _by_id(hp["frontends"]).get(rid[3:])
            if not fe:
                abort(404)
            pool_id = fe.get("default_backend")
            hp["frontends"] = [f for f in hp["frontends"] if f.get("id") != fe["id"]]
            removed = [{"type": "Public Service", "name": fe.get("name")}]
            pool = _by_id(hp["backends"]).get(pool_id)
            still_used = any(r.get("backend") == pool_id for r in hp["rules"]) or \
                any(f.get("default_backend") == pool_id for f in hp["frontends"])
            if pool and not still_used:
                server_ids = list(pool.get("servers") or [])
                hp["backends"] = [b for b in hp["backends"] if b.get("id") != pool_id]
                removed.append({"type": "Backend Pool", "name": pool.get("name")})
                dropped = []
                _drop_orphan_wizard_servers(hp, server_ids, dropped)
                removed.extend({"type": d["type"], "name": d["name"]} for d in dropped)
            save_config(cfg)
            return jsonify({"ok": True, "removed": removed, "note": "Press Apply."})

        target = _by_id(hp["rules"]).get(rid)
        if not target:
            abort(404)
        if target.get(LOCAL_ONLY):
            return jsonify({"ok": False, "error":
                            "This is the node's own web UI service. Turn it off under "
                            "System > Web UI access instead."}), 409
        removed = _remove_service_objects(hp, rid)
        save_config(cfg)
    return jsonify({"ok": True, "removed": removed,
                    "note": "Certificates and Public Services were left in place. Press Apply."})


# --------------------------------------------------------------------------
# recipes
#
# The wizard asks for a dozen settings, and for most well-known services there
# is one right answer for nearly all of them: which port, whether it is TCP or
# HTTP, how to tell a working server from a broken one. A recipe fills those in
# and leaves the two things only the operator knows -- the name to publish and
# the servers behind it.
#
# One JSON file per recipe in static/recipes/, read when asked for rather than
# compiled in: a new one is a file to drop in, and a local one is not lost on
# upgrade the way an edit to this file would be. A broken file is skipped and
# logged, because one bad recipe should not empty the list.
# --------------------------------------------------------------------------

RECIPE_DIR = STATIC_DIR / "recipes"


def load_recipes():
    """Every recipe on disk, ordered for the picker."""
    out = []
    for path in sorted(RECIPE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except (ValueError, OSError) as e:
            log.warning("ignoring recipe %s: %s", path.name, e)
            continue
        if not isinstance(data, dict) or not data.get("name") or \
                not isinstance(data.get("fields"), dict):
            log.warning("ignoring recipe %s: it needs a name and a fields object",
                        path.name)
            continue
        data["id"] = path.stem          # the filename is the identity
        data.setdefault("category", "Other")
        data.setdefault("summary", "")
        data.setdefault("notes", "")
        out.append(data)
    # Category order is deliberate rather than alphabetical -- the generic ones
    # first, the specialist ones last. Inside a category the list is long
    # enough that the only useful order is the one you can predict, so it is
    # sorted by name. Case is folded so "phpMyAdmin" lands under p rather than
    # ahead of every capitalised name.
    rank = {"Web": 0, "Databases": 1, "Applications": 2, "Infrastructure": 3}
    out.sort(key=lambda r: (rank.get(r["category"], 9), r["name"].casefold()))
    return out


@app.get("/api/recipes")
def api_recipes():
    recipes = load_recipes()
    if not recipes:
        log.warning("no recipes found in %s", RECIPE_DIR)
    return jsonify({"ok": True, "recipes": recipes, "directory": str(RECIPE_DIR)})


@app.post("/api/wizard/publish")
def api_wizard_publish():
    body = request.get_json(force=True, silent=True) or {}
    raw_urls = [u for u in re.split(r"[\s,]+", body.get("url") or "") if u]
    if not raw_urls:
        return jsonify({"ok": False, "error": "The public URL is required"}), 400
    pubs = []
    for raw in raw_urls:
        p, err = _split_url(raw, "The public URL \"%s\"" % raw, default_scheme="https")
        if err:
            return jsonify({"ok": False, "error": err}), 400
        pubs.append(p)
    pub = pubs[0]
    if len(pubs) > 1:
        if any(p["scheme"] != pub["scheme"] for p in pubs):
            return jsonify({"ok": False, "error":
                            "every URL on one service must use the same scheme"}), 400
        if any(p["port"] != pub["port"] for p in pubs):
            return jsonify({"ok": False, "error":
                            "every URL on one service must use the same port"}), 400
        if pub["scheme"] == "tcp":
            return jsonify({"ok": False, "error":
                            "a tcp:// service is one listening port, so it takes one URL"}), 400
        if any(p["path"] for p in pubs):
            return jsonify({"ok": False, "error":
                            "URLs with a path cannot be combined on one service: a host and a path "
                            "must both match, while several host names are alternatives. Publish "
                            "the path as its own service."}), 400
        seen = set()
        for p in pubs:
            if p["host"].lower() in seen:
                return jsonify({"ok": False, "error": "%s is listed twice" % p["host"]}), 400
            seen.add(p["host"].lower())

    raw_targets = [t for t in re.split(r"[\s,]+", body.get("target") or "") if t]
    if not raw_targets:
        return jsonify({"ok": False, "error": "The target address is required"}), 400
    tgts = []
    for raw in raw_targets:
        # A tcp:// service forwards raw TCP, so its targets default to tcp too.
        t, err = _split_url(raw, "The target address \"%s\"" % raw,
                            default_scheme="tcp" if pub["scheme"] == "tcp" else "http")
        if err:
            return jsonify({"ok": False, "error": err}), 400
        tgts.append(t)

    dry_run = bool(body.get("dry_run"))
    with _lock:
        cfg = load_config()
        draft = copy.deepcopy(cfg)
        try:
            acts, warns = wizard_publish(
                draft, pubs, tgts,
                name=body.get("name"),
                want_cert=body.get("certificate", True),
                account=body.get("account") or None,
                challenge=body.get("challenge") or None,
                http_redirect=body.get("http_redirect", True),
                health=body.get("health") or None,
                certificate_id=body.get("certificate_id") or None,
                new_certificate=bool(body.get("new_certificate")),
                service_id=(body.get("service_id") or "").strip() or None,
                balance=body.get("balance") or None,
                persistence=body.get("persistence") or None,
                stick_size=body.get("stick_size") or None,
                stick_expire=body.get("stick_expire") or None,
                stick_type=body.get("stick_type") or None,
                log_health_checks=bool(body.get("log_health_checks")),
                check_port=body.get("check_port") or None,
                timeout_connect=body.get("timeout_connect") or None,
                timeout_server=body.get("timeout_server") or None,
            )
        except ValueError as e:                     # a rejected request, not a crash
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception as e:                      # a malformed draft must not corrupt the store
            return jsonify({"ok": False, "error": "could not build the configuration: %s" % e}), 400

        summary = {"ok": True, "actions": acts, "warnings": warns, "dry_run": dry_run,
                   "public": "%s://%s%s" % (pub["scheme"], pub["host"], pub["path"]),
                   "target": ", ".join("%s://%s:%d" % (t["scheme"], t["host"], t["port"]) for t in tgts)}
        try:
            summary["preview"] = render_haproxy(draft)
        except Exception as e:
            return jsonify({"ok": False, "error": "the resulting configuration is not renderable: %s" % e}), 400
        if dry_run:
            return jsonify(summary)
        save_config(draft)

    if body.get("apply"):
        summary["applied"] = do_apply()
    return jsonify(summary)


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

# Flask's own static route is switched off (static_folder=None), so this is the
# only way anything is served from disk. Allowed by extension rather than by a
# list of names, now that the UI is a directory of modules -- send_from_directory
# refuses to escape STATIC_DIR, so the extension is the whole policy. They answer
# without a session because the sign-in page itself has to render before anyone
# can sign in.
STATIC_SUFFIXES = (".css", ".js", ".svg", ".png", ".ico", ".map", ".woff2")


@app.get("/")
def index():
    """The page, with the version stamped into the asset URLs.

    A browser that kept yesterday's JavaScript would load a mixture of old and
    new modules, which fails in ways that look like nothing else. So the page
    itself is never cached, and everything it asks for lives under a path that
    contains the version -- change the version, change every URL, including the
    ones inside `import "./shell.js"`, because those resolve relative to the
    module that wrote them.
    """
    html = (STATIC_DIR / "index.html").read_text().replace("__VERSION__", VERSION)
    return Response(html, mimetype="text/html", headers={
        "Cache-Control": "no-cache, must-revalidate",
    })


@app.get("/static/v/<ver>/<path:name>")
def static_versioned(ver, name):
    """Immutable: the URL changes whenever the version does."""
    if not name.endswith(STATIC_SUFFIXES):
        abort(404)
    resp = send_from_directory(STATIC_DIR, name)
    resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return resp


@app.get("/static/<path:name>")
def static_asset(name):
    """Unversioned, for things referenced from outside the page -- the icons a
    browser or a phone asks for by name. Revalidated rather than held."""
    if not name.endswith(STATIC_SUFFIXES):
        abort(404)
    return send_from_directory(STATIC_DIR, name, max_age=0, conditional=True)


@app.get("/favicon.ico")
def favicon():
    """Browsers ask for this whether or not the page links to it."""
    return send_from_directory(STATIC_DIR, "favicon.ico", max_age=86400)


def _cli(argv):
    """Small maintenance CLI so installers do not reimplement the hashing.

        app.py set-admin <username> <password>   create/replace the UI login
        app.py set-admin <username> -            read the password from stdin
        app.py show-admin                        print the configured username
        app.py set-api-key <key>                 set this node's API key
        app.py set-api-key -                     read it from stdin
        app.py keys                              print key fingerprints, for comparing nodes
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
    if cmd == "keys":
        cfg = load_config()
        loc = cfg["local"]
        print("node:      %s" % socket.gethostname())
        print("url:       %s" % (loc.get("node_url") or "(not set)"))
        print("api key:   %s  fingerprint %s"
              % ("(not set)" if not (loc.get("api_key") or "").strip() else "set",
                 key_fingerprint(loc.get("api_key")) or "-"))
        print("           other nodes must hold a key with THIS fingerprint for this node")
        peers = loc["sync"].get("peers") or []
        print("peers:     %d" % len(peers))
        seen = {}
        for p in peers:
            host = urlsplit(p.get("url") or "").hostname or "?"
            fp = key_fingerprint(p.get("api_key")) or "-"
            flags = []
            if fp != "-" and fp == key_fingerprint(loc.get("api_key")):
                flags.append("THIS NODE'S OWN KEY")
            if host in seen:
                flags.append("duplicate of %s" % seen[host])
            seen.setdefault(host, p.get("url"))
            if not p.get("enabled", True):
                flags.append("disabled")
            print("  %-28s %-34s fingerprint %s%s"
                  % (p.get("name", "?"), p.get("url", "?"), fp,
                     "   <-- " + ", ".join(flags) if flags else ""))
        return 0
    if cmd == "set-api-key":
        if len(argv) != 2:
            print("usage: app.py set-api-key <key|->", file=sys.stderr)
            return 2
        key = sys.stdin.read().strip() if argv[1] == "-" else argv[1]
        if not key:
            print("the key must not be empty", file=sys.stderr)
            return 2
        # Read, change, write -- never replace the file wholesale, which would
        # discard everything else on an existing installation.
        with _lock:
            cfg = load_config()
            cfg["local"]["api_key"] = key
            save_config(cfg)
        print(key_fingerprint(key))
        return 0
    if cmd == "show-admin":
        admin = load_config()["local"].get("admin") or {}
        print(admin.get("username", "") if admin.get("hash") else "")
        return 0
    print("unknown command: %s" % cmd, file=sys.stderr)
    return 2


def _serve():
    """Serve with waitress, a production WSGI server.

    Deliberately one process with a thread pool: this app keeps state in
    process globals -- the write lock that makes configuration changes atomic,
    the failed-sign-in counters and the renewal timer -- so a multi-process
    server would give each worker its own copy and reintroduce lost updates.
    Waitress is threaded within a single process, which is exactly right here.
    """
    try:
        from waitress import serve as waitress_serve
    except ImportError:
        log.warning("waitress is not installed; falling back to the development "
                    "server, which is not meant for production. Install it with "
                    "'apt-get install -y python3-waitress'.")
        app.run(host=LISTEN, port=PORT, threaded=True)
        return
    for name in ("waitress", "waitress.queue"):
        wl = logging.getLogger(name)
        wl.handlers = list(log.handlers)
        wl.setLevel(logging.INFO)
        wl.propagate = False
    log.info("haproxy-manager %s listening on %s:%s (waitress)", VERSION, LISTEN, PORT)
    waitress_serve(app, host=LISTEN, port=PORT, threads=THREADS,
                   ident="haproxy-manager", clear_untrusted_proxy_headers=True,
                   max_request_body_size=app.config["MAX_CONTENT_LENGTH"],
                   channel_timeout=120, asyncore_use_poll=True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(_cli(sys.argv[1:]))
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not CONF_PATH.exists():
        save_config(load_config())
    threading.Thread(target=_renew_loop, daemon=True).start()
    threading.Thread(target=_update_loop, daemon=True).start()
    threading.Thread(target=_watchdog_loop, daemon=True).start()
    _serve()
