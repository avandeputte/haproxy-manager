"""The configuration store: defaults, migrations, atomic save."""

from urllib.parse import urlsplit
import copy
import hashlib
import json
import os
import uuid

from .base import CONF_PATH, DATA_DIR, _lock

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
    # A passive-node unlock is per session, so any copy sitting in the stored
    # configuration is stale by definition and is dropped.
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
