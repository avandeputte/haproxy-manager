"""The configuration store: defaults, migrations, atomic save."""

from urllib.parse import urlsplit
import copy
import hashlib
import json
import os
import uuid

from .base import CONF_PATH, DATA_DIR, _lock, log

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
        # How the tracking script decides HAProxy is up. "responding" asks it
        # through its admin socket, so an instance that is running but wedged
        # gives the virtual IP up; "process" only checks that a process by
        # that name exists.
        "track_mode": "responding",
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
            # Push after a successful Apply, bring a node that has fallen
            # behind back into step, and take the newest configuration from
            # the cluster at startup. On by default: a cluster whose nodes
            # hold different configurations is the failure this exists to
            # prevent, and it only ever does anything once peers are added.
            # An existing installation keeps whatever it was set to.
            "auto_sync": True,
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
                "nopreempt", "track_haproxy", "track_mode", "custom")


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


def _migrate_webui_certs(cfg):
    """Take the management UI certificates out of the shared configuration.

    Every node publishes its own UI under the same service name, so each makes
    a certificate for its own host name. Those certificates were not marked as
    belonging to the node, so they travelled with every sync: each node kept
    the ones it was sent and made its own alongside, and no two nodes held the
    same configuration again -- which the Cluster page now reports as a
    disagreement that never settles.

    Ours is marked. Removed, along with the listener's reference to them, are
    the ones that are plainly another node's -- named for this service but
    covering a host this node does not answer for -- and any duplicate for
    names a certificate here already covers.
    """
    ours = {h for h in ((cfg["local"].get("web_ui") or {}).get("url", ""),
                        cfg["cluster"].get("ui_url", ""))
            for h in [urlsplit(h if "//" in h else "//" + h).hostname or ""] if h}
    keep, drop, seen = [], [], set()
    for cert in cfg["acme"]["certificates"]:
        if not is_webui_cert(cert):
            keep.append(cert)
            continue
        hosts = frozenset(d.strip().lower() for d in
                          (cert.get("domains") or "").replace(",", " ").split())
        if ours and not hosts & ours:
            drop.append(cert)            # another node's, and unusable here
        elif hosts in seen:
            drop.append(cert)            # a duplicate for the same names
        else:
            seen.add(hosts)
            cert[LOCAL_ONLY] = True      # ours, and it stays here
            keep.append(cert)
    if not drop:
        return
    cfg["acme"]["certificates"] = keep
    gone = {c.get("id") for c in drop}
    for fe in cfg["haproxy"]["frontends"]:
        if isinstance(fe.get("certificates"), list):
            fe["certificates"] = [x for x in fe["certificates"] if x not in gone]
    log.info("removed %d management-UI certificate(s) that were duplicates or "
             "belonged to another node: %s",
             len(drop), ", ".join(c.get("name", "?") for c in drop))


def _migrate(cfg):
    """Bring an older config forward. Idempotent; persisted on the next save."""
    if not cfg["_meta"].get("setup_complete") and _looks_configured(cfg):
        cfg["_meta"]["setup_complete"] = True
    # A passive-node unlock is per session, so any copy sitting in the stored
    # configuration is stale by definition and is dropped.
    cfg["local"].pop("allow_edit_when_passive", None)
    _migrate_webui_certs(cfg)
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


def shared_view(cfg):
    """The parts every node is meant to hold identically.

    Node-local settings are excluded, and so are the objects a node owns
    alone, because two nodes that differ only in those two respects are in
    agreement.
    """
    mine = local_only_ids(cfg)
    return {"haproxy": strip_local_only(cfg["haproxy"], mine),
            "acme": strip_local_only(cfg["acme"], mine),
            "cluster": cfg["cluster"],
            "notify": cfg.get("notify", {})}


def _fp(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:16]


def shared_fingerprint(cfg):
    """A short tag for the shared configuration. Equal tags mean agreement."""
    return _fp(shared_view(cfg))


def shared_parts(cfg):
    """The same, one tag per collection.

    "The nodes disagree" is not a useful thing to be told on its own: it takes
    a byte-by-byte comparison of two configurations to find out about what.
    These say which part differs, which is nearly always enough to see why.
    """
    view = shared_view(cfg)
    out = {}
    for section, body in view.items():
        if not isinstance(body, dict):
            out[section] = _fp(body)
            continue
        for coll, items in sorted(body.items()):
            out["%s.%s" % (section, coll)] = _fp(items)
    return out


def save_config(cfg):
    with _lock:
        # The revision counts changes to the shared configuration, and is what
        # lets a node tell "the same as mine", "older than mine" and "newer
        # than mine" apart. It is bumped here rather than at each call site so
        # that no change can escape being counted. A node that has just taken
        # a configuration from a peer sets both fields first, so adopting is
        # not itself counted as a change.
        meta = cfg.setdefault("_meta", {})
        fp = shared_fingerprint(cfg)
        if fp != meta.get("shared_fp"):
            meta["shared_fp"] = fp
            meta["shared_rev"] = int(meta.get("shared_rev") or 0) + 1
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CONF_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2))
        # It holds the API key, the session secret, the peers' keys and the
        # password hash. The directory is 0700, but the file should not rely
        # on that alone -- a backup or a loosened directory would expose it.
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONF_PATH)


LOCAL_ONLY = "local_only"       # this object belongs to this node alone
WEBUI_NAME = "haproxy-manager-ui"   # the service each node publishes its own UI as


def is_webui_cert(cert):
    """Was this certificate created for a node's own management UI service?

    Every node publishes that service under the same name, so the certificate
    is named for it too -- and belongs to the node that made it, never to the
    cluster.
    """
    name = (cert.get("name") or "")
    return name == WEBUI_NAME or name.startswith(WEBUI_NAME + "-")


def local_only_ids(cfg):
    """Every id this node owns alone, across all the shared sections.

    Gathered across sections because a certificate lives under acme while the
    listener that names it lives under haproxy: dropping the first without the
    second would leave a reference to something that is not there.
    """
    out = set()
    for name in ("haproxy", "acme"):
        for items in (cfg.get(name) or {}).values():
            if not isinstance(items, list):
                continue
            out |= {i.get("id") for i in items if isinstance(i, dict) and i.get(LOCAL_ONLY)}
    return {i for i in out if i}


def strip_local_only(section, dropped=None):
    """A copy of a config section with this node's own objects removed.

    Some objects belong to one node alone -- the service that publishes this
    node's own management UI points at 127.0.0.1 and carries this node's host
    name. They are marked, and this is what takes them out, both of what is
    sent to the other nodes and of what the nodes compare.
    """
    out = copy.deepcopy(section)
    dropped = set(dropped or ())
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


def config_hash(cfg):
    payload = json.dumps(
        {"haproxy": cfg["haproxy"], "acme": cfg["acme"], "cluster": cfg["cluster"],
         "keepalived": cfg["local"]["keepalived"]},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


# --------------------------------------------------------------------------
# helpers
