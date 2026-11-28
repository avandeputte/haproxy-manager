"""The configuration store: defaults, migrations, atomic save."""

from datetime import datetime
from datetime import timezone
import copy
import hashlib
import json
import os
import pathlib
import shutil
import tempfile

from .base import CONF_PATH, DATA_DIR, _lock, log
from .util import rule_cond_ids

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
            # How long an upgraded connection -- a WebSocket -- may sit idle.
            # Without it the client and server timeouts apply, and an idle
            # WebSocket is cut after 50 seconds.
            "timeout_tunnel": "1h",
            # Listen on IPv6 as well as IPv4 wherever a service listens on
            # every address. Off for a node whose IPv6 is broken rather than
            # absent; absent is detected and IPv4 alone used.
            "ipv6": True,
            # What a request for a host no service answers gets: HAProxy's
            # 503 (as before), a 404, the connection dropped, or a redirect.
            "default_site": "503",
            "default_site_url": "",
        },
        "servers": [],       # Real Servers
        "backends": [],      # Backend Pools
        "frontends": [],     # Public Services
        "healthchecks": [],  # Health Monitors
        "conditions": [],    # Conditions (named ACLs)
        "rules": [],         # Rules (actions bound to conditions)
        # Named sets of networks: a pool's allow-list or a condition names
        # the list, so an address that changes is changed in one place.
        "addresslists": [],
        # What HAProxy answers with when it cannot forward: a page per set of
        # status codes, written to disk on every node at Apply.
        "errorpages": [],
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
    # Who may reach a service that asks visitors to sign in. Shared: a service
    # is published on every node, so the credentials it checks have to be there
    # too. These are nothing to do with the login for this UI.
    "access": {
        "users": [],     # {id, username, hash, groups, enabled, description}
        "groups": [],    # {id, name, description}
        # Single sign-on through an OpenID Connect provider. Shared, so every
        # node can validate the cookie and any node can hold the sign-in flow
        # after a failover. The secret signs the session cookie; it is
        # generated here, never typed, and rotating it signs everyone out.
        "oauth": {
            "enabled": False,
            "issuer": "",             # e.g. https://auth.example.com/application/o/ham/
            "client_id": "",
            "client_secret": "",
            "auth_host": "",          # the name HAProxy routes to this app's sign-in
            "cookie_domain": "",      # the cookie's scope; auth_host must sit under it
            "scopes": "openid email profile",
            "session_hours": 12,
            # Accept an ID token whose email_verified is false. Off, because
            # the allow-lists are only as true as the addresses they match.
            "allow_unverified": False,
            "secret": "",
        },
    },
    # CrowdSec: where the bouncer on every node asks for decisions, and what
    # HAProxy does with them. Shared, since every node protects the same
    # services; a node may hold its own API key under local.crowdsec.
    "crowdsec": {
        "enabled": False,
        "api_url": "",               # the LAPI, e.g. http://192.168.1.5:8080/
        "api_key": "",               # from: cscli bouncers add haproxy-manager
        "insecure_skip_verify": False,
        "mode": "ban",               # ban: a 403 page; captcha: a challenge first
        "captcha_provider": "",      # hcaptcha, recaptcha or turnstile
        "captcha_site_key": "",
        "captcha_secret_key": "",
        "captcha_signing_key": "",   # generated once; the same on every node
        "contact_url": "",           # shown on the ban page, when set
        "skip_lists": [],            # address lists never asked about: the LAN
        # AppSec, CrowdSec's WAF: where the bouncer sends each request to be
        # inspected, e.g. http://192.168.1.5:7422/. Empty: not used.
        "appsec_url": "",
        "appsec_reject_large": False,   # 413 for a body too large to inspect
    },
    # Cloudflare Tunnel: services reached through Cloudflare, with Access in
    # front of the ones that ask for it. Shared: every node runs the same
    # connector with the same token, and Cloudflare spreads visitors over
    # whichever of them are connected.
    "cloudflare": {
        "enabled": False,
        "api_token": "",             # Tunnel, DNS and Access edit rights
        "account_id": "",            # found from the token when it sees one account
        "tunnel_name": "haproxy-manager",
        "tunnel_id": "",             # filled in when the tunnel is made
        "tunnel_token": "",          # what cloudflared presents; from the API
        # The first of the loopback ports cloudflared reaches HAProxy on: one
        # per listener that carries a service published this way.
        "origin_port": 7811,
        # What Cloudflare was last told, as a fingerprint: set by the node
        # that told it, read by all of them. Not part of what Apply compares.
        "told": "",
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
        # Whether the daily version check also reads the beta branch. The
        # cluster's choice, not a node's: a cluster runs one version, and a
        # node that offered betas alone showed a different Updates page from
        # the others -- and from itself, once the virtual IP had moved.
        "beta_updates": False,
    },
    "notify": {
        # Shared, so it is configured once and propagates: every node then
        # alerts about its own troubles using the same destinations.
        "enabled": True,
        "min_severity": "warning",       # info | warning | error
        "repeat_hours": 6,               # re-tell an unresolved problem this often
        # Wait this long before alerting that a service has lost servers, so a
        # reboot or an update that takes it down for a few seconds does not
        # page anyone. 0 disables the wait (alert on the first round).
        "service_grace_seconds": 30,
        # Service alerts that fire within this window of each other go out as
        # one message listing them all, instead of one email per service. 0
        # still combines the alerts of a single check round.
        "service_batch_seconds": 60,
        "events": {"certificates": True, "watchdog": True, "apply": True,
                   "cluster": True, "updates": True},
        # [{id, name, type, enabled, ...type-specific fields}]
        "destinations": [],
        # Home Assistant, by MQTT discovery. Shared like the destinations:
        # every node talks to the same broker, each reporting itself.
        "mqtt": {"enabled": False, "host": "", "port": 1883, "username": "",
                 "password": "", "tls": False,
                 "discovery_prefix": "homeassistant",
                 "base_topic": "haproxy-manager",
                 # Whether Home Assistant may pause and resume services.
                 # Off by default: whoever can publish to the broker holds
                 # this power the moment it is on.
                 "allow_control": False},
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
        # A copy of cluster.beta_updates, kept in step by save_config for what
        # reads this file from outside -- the Proxmox container's update
        # script. Until 2.4.1 this was the setting itself, one per node; a
        # record without "shared" is such a tick, not yet handed to the
        # cluster (updates.adopt_own_tick).
        "updates": {"beta": False},
        # What VRRP needs from this node alone. Everything the nodes share --
        # the virtual IPs, the router id, the password -- lives under cluster;
        # the copies that once sat here were left behind when it moved, and a
        # stored file that still carries them is read without complaint.
        "keepalived": {
            "interface": "eth0",
            "priority": 100,
            "unicast_src": "",
            "unicast_peer": "",
        },
        # Objects this node owns. Not a copy of the shared ones and not a
        # filtered view of them: the shared sections hold what every node has,
        # these hold what only this node has, and nothing has to decide which
        # is which after the fact. The management UI's own service lives here.
        "haproxy": {"servers": [], "backends": [], "healthchecks": [],
                    "conditions": [], "rules": []},
        "acme": {"certificates": []},
        # How they hook onto shared listeners, keyed by listener name -- names
        # are the same on every node, ids are not.
        "attach": {},
        "watchdog": {
            # Supervises the services this node runs. Node-local: each node
            # watches its own, and a passive node still restarts its HAProxy.
            "enabled": True,
            "interval": 20,             # seconds between rounds
            "haproxy": True,
            "keepalived": True,
            "max_restarts": 3,          # per window, before it stops trying
            "window": 900,
            # Ask for every published URL the way a browser would, from the
            # active node. The one check that sees the whole chain.
            "probe_urls": True,
        },
        # The MCP server at /mcp: off, and read-only, until turned on. Its own
        # token, kept with its hash (requests are checked against the hash) -- see ham/mcp.py.
        "mcp": {"enabled": False, "allow_writes": False, "token": "", "token_hash": "", "token_fp": "",
                "token_created": ""},
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
        },
    },
    "_meta": {"applied_hash": ""},
}

# The sections every node holds identically: what a push carries, what a
# snapshot keeps, what a receive or a join may take. One list, because the
# six places that each spelled it out drifted apart -- CrowdSec and Cloudflare
# were missing from the join until 2.5.1 (issue #44).
SHARED_SECTIONS = ("haproxy", "acme", "access", "cluster", "notify", "crowdsec", "cloudflare")

VALID_COLLECTIONS = {
    "haproxy": {"servers", "backends", "frontends", "healthchecks", "conditions", "rules",
                "addresslists", "errorpages"},
    "acme": {"accounts", "challenges", "certificates"},
}


def _merge_defaults(dst, src):
    for k, v in src.items():
        if k not in dst:
            dst[k] = copy.deepcopy(v)
        elif isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge_defaults(dst[k], v)
    return dst


def check_section(name, body):
    """Why a shared section offered by another node cannot be taken, or "".

    _merge_defaults fills what is missing and leaves what is there alone,
    whatever its type -- so a section that arrived as null, or a `settings`
    that did, was adopted and saved, and every request on the node then
    failed on it until someone edited the file by hand. The shape is checked
    against the defaults before anything is written: a dict where the
    default has a dict, a list where it has a list, and in the collections
    objects rather than bare values.
    """
    if name not in SHARED_SECTIONS:
        return "%s is not a shared section" % name
    if not isinstance(body, dict):
        return "section %s is not an object" % name

    def shape(dst, src, where):
        for k, v in src.items():
            if k not in dst:
                continue
            here = "%s.%s" % (where, k)
            if isinstance(v, dict):
                if not isinstance(dst[k], dict):
                    return "%s is not an object" % here
                bad = shape(dst[k], v, here)
                if bad:
                    return bad
            elif isinstance(v, list) and not isinstance(dst[k], list):
                return "%s is not a list" % here
        return ""

    bad = shape(body, DEFAULT_CONFIG[name], name)
    if bad:
        return bad
    collections = set(VALID_COLLECTIONS.get(name) or ())
    if name == "access":
        collections = {"users", "groups"}
    for coll in collections:
        if any(not isinstance(i, dict) for i in body.get(coll) or []):
            return "%s.%s holds something that is not an object" % (name, coll)
    return ""


CLUSTER_KEYS = ("vrid", "vips", "auth_pass", "advert_int", "state",
                "nopreempt", "track_haproxy", "track_mode", "custom")


def _move_node_objects_into_local(cfg):
    """One move: put what belongs to this node where it belongs.

    Until now an object in the shared sections carried a flag saying it was
    this node's, and everything that shared, compared or received a
    configuration had to honour that flag. Four separate faults came from a
    place that did not. Where an object lives says it now, so there is nothing
    left to honour.

    Objects are moved, never dropped, and what a listener referred to it still
    refers to -- through an attachment recorded by the listener's name, because
    the other nodes give that listener a different id.
    """
    ids = {i.get("id") for sec in LOCAL_SECTIONS
           for coll in (cfg.get(sec) or {}).values() if isinstance(coll, list)
           for i in coll if isinstance(i, dict) and i.get("local_only")}
    ids |= webui_object_ids(cfg)
    ids |= {c["id"] for c in (cfg.get("acme") or {}).get("certificates") or []
            if is_webui_cert(c)}
    moved = move_to_local(cfg, ids)
    if moved:
        log.info("moved %d object(s) belonging to this node out of the shared "
                 "configuration; they are no longer sent to the other nodes", moved)
    return moved


def write_private(path, data):
    """Write a file nobody but its owner may read, with no moment in between.

    Writing in place and then tightening the mode leaves a window -- and a
    file that already existed keeps whatever mode it had until the chmod. So
    the bytes go to a fresh file beside it, created with mode 0600 and
    refused if the name is somehow taken, and then take the path's place.
    What held a private key or a password hash never had another mode.
    """
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix="." + path.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data.encode() if isinstance(data, str) else data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
    unreadable = False
    if CONF_PATH.exists():
        try:
            cfg = json.loads(CONF_PATH.read_text())
        except (ValueError, OSError) as e:
            # The file is there but will not parse. Returning bare defaults
            # here would make the node look like it has never been set up --
            # no admin, no API key -- which opens /api/setup to whoever
            # reaches the port and lets their first save overwrite the real
            # (recoverable) configuration. Mark it instead: the setup path
            # refuses, so a corrupt file fails closed rather than open.
            log.error("config.json exists but will not parse (%s); refusing to "
                      "treat this as first-run setup", e)
            cfg, unreadable = {}, True
    # An upgrade that adds a collection the stored file never had -- address
    # lists and error pages in 2.0 -- must not read as an unapplied change:
    # nothing HAProxy serves is different. The marker the last Apply stored
    # was computed over what was there, so when it still matches that, it is
    # carried over to cover the defaults being added now. Only the hashed
    # sections matter, and only while the file lacks something: once saved,
    # the carried-over marker is in the file and this costs nothing.
    # Computed the way the version that stored the marker computed it: a file
    # from before the formula changed says nothing of the formula, and that
    # silence names the old one.
    formula = int((cfg.get("_meta") or {}).get("applied_hash_formula") or 1) if cfg else HASH_FORMULA
    before = None
    if cfg and _lacks_defaults(cfg):
        try:
            before = config_hash(cfg, formula)
        except (KeyError, TypeError):
            before = None
    cfg = _merge_defaults(cfg, DEFAULT_CONFIG)
    if before is not None and cfg["_meta"].get("applied_hash") == before:
        cfg["_meta"]["applied_hash"] = config_hash(cfg, formula)
    if formula != HASH_FORMULA:
        # The formula changed with an upgrade, not the configuration. A marker
        # that matched under the old formula still means "applied", so it is
        # restated under the new one; one that did not match keeps saying
        # "unapplied", as it should. The next save writes the formula down.
        if cfg["_meta"].get("applied_hash") == config_hash(cfg, formula):
            cfg["_meta"]["applied_hash"] = config_hash(cfg)
    cfg["_meta"]["applied_hash_formula"] = HASH_FORMULA
    if unreadable:
        cfg["_meta"]["unreadable"] = True
    _move_node_objects_into_local(cfg)
    return cfg


def _lacks_defaults(cfg):
    """Does the stored file lack a key, at any depth, in a section the applied
    marker hashes?"""
    def lacks(dst, src):
        for k, v in src.items():
            if k not in dst:
                return True
            if isinstance(v, dict) and isinstance(dst.get(k), dict) and lacks(dst[k], v):
                return True
        return False
    parts = [(cfg.get(sec), DEFAULT_CONFIG[sec]) for sec in SHARED_SECTIONS if sec != "notify"]
    parts.append(((cfg.get("local") or {}).get("keepalived"), DEFAULT_CONFIG["local"]["keepalived"]))
    return any(not isinstance(dst, dict) or lacks(dst, src) for dst, src in parts)


LOCAL_SECTIONS = ("haproxy", "acme")


def merged(cfg):
    """The configuration as this node sees it: shared plus its own.

    Everything that reads the configuration to do something -- render it,
    validate it, list it -- wants this. Only what is sent to the other nodes
    wants the shared sections alone, and that is simply those sections, with
    nothing to strip.
    """
    out = copy.deepcopy(cfg)
    loc = cfg.get("local") or {}
    for sec in LOCAL_SECTIONS:
        for coll, items in (loc.get(sec) or {}).items():
            if isinstance(items, list) and isinstance(out.get(sec, {}).get(coll), list):
                have = {i.get("id") for i in out[sec][coll]}
                out[sec][coll] = out[sec][coll] + [copy.deepcopy(i) for i in items
                                                   if i.get("id") not in have]
    for name, att in (loc.get("attach") or {}).items():
        for fe in out.get("haproxy", {}).get("frontends") or []:
            if fe.get("name") != name:
                continue
            for key in ("rules", "certificates"):
                extra = [x for x in (att.get(key) or []) if x not in (fe.get(key) or [])]
                if not extra:
                    continue
                have = list(fe.get(key) or [])
                for x in extra:
                    where = (att.get("at") or {}).get(x)
                    if where is None or where > len(have):
                        have.append(x)
                    else:
                        have.insert(where, x)
                fe[key] = have
    return out


def move_to_local(cfg, ids):
    """Move objects out of the shared configuration into this node's own.

    Used when the management UI's service is built, and once on an existing
    configuration to put what was there in the right place. Objects are moved,
    never dropped: what a listener referred to it still refers to, through an
    attachment recorded by the listener's name rather than by an id the other
    nodes do not have.
    """
    ids = {i for i in (ids or []) if i}
    if not ids:
        return 0
    loc = cfg.setdefault("local", {})
    moved = 0
    for sec in LOCAL_SECTIONS:
        dest = loc.setdefault(sec, {})
        for coll, items in list((cfg.get(sec) or {}).items()):
            if not isinstance(items, list):
                continue
            take = [i for i in items if i.get("id") in ids]
            if not take:
                continue
            cfg[sec][coll] = [i for i in items if i.get("id") not in ids]
            here = dest.setdefault(coll, [])
            have = {i.get("id") for i in here}
            for i in take:
                i.pop("local_only", None)      # where it lives is what says so now
                if i.get("id") not in have:
                    here.append(i)
                    moved += 1
    attach = loc.setdefault("attach", {})
    for fe in cfg.get("haproxy", {}).get("frontends") or []:
        for key in ("rules", "certificates"):
            if not isinstance(fe.get(key), list):
                continue
            mine = [x for x in fe[key] if x in ids]
            if not mine:
                continue
            # Where they sat, not just that they were there. HAProxy takes the
            # first use_backend that matches, and the first crt is what a
            # client that sends no SNI is given -- so putting them back at the
            # end would be a change of behaviour, not of formatting.
            slot = attach.setdefault(fe.get("name") or "", {})
            at = slot.setdefault("at", {})
            for x in mine:
                at[x] = fe[key].index(x)
            fe[key] = [x for x in fe[key] if x not in ids]
            slot[key] = [x for x in (slot.get(key) or []) if x not in mine] + mine
    return moved


def promote_local(cfg):
    """Put this node's objects back into the shared collections, temporarily.

    The publish wizard finds what a service already consists of by looking in
    the shared collections, and updates it in place -- that is what makes it an
    editor rather than something that builds a second set every time. Objects
    it cannot find, it creates.

    So building this node's own service is: put its objects where the wizard
    looks, let it work, then move them back. Both halves happen inside one call
    and nothing is saved in between, so the shared configuration is never
    written with them in it.
    """
    loc = cfg.get("local") or {}
    moved = set()
    for sec in LOCAL_SECTIONS:
        for coll, items in list((loc.get(sec) or {}).items()):
            if not isinstance(items, list) or not items:
                continue
            dest = cfg.setdefault(sec, {}).setdefault(coll, [])
            have = {i.get("id") for i in dest}
            for i in items:
                if i.get("id") not in have:
                    dest.append(i)
                moved.add(i.get("id"))
            loc[sec][coll] = []
    for name, att in list((loc.get("attach") or {}).items()):
        for fe in cfg.get("haproxy", {}).get("frontends") or []:
            if fe.get("name") != name:
                continue
            for key in ("rules", "certificates"):
                extra = [x for x in (att.get(key) or []) if x not in (fe.get(key) or [])]
                have = list(fe.get(key) or [])
                for x in extra:
                    where = (att.get("at") or {}).get(x)
                    if where is None or where > len(have):
                        have.append(x)
                    else:
                        have.insert(where, x)
                fe[key] = have
    loc["attach"] = {}
    return moved


def shared_view(cfg):
    """The parts every node is meant to hold identically.

    Node-local settings are excluded, and so are the objects a node owns
    alone, because two nodes that differ only in those two respects are in
    agreement.

    So is the note of what Cloudflare was last told. Writing it down changes
    nothing any node serves, yet as part of the view it moved the revision
    and left a snapshot at every Apply that spoke to Cloudflare. It still
    travels with a push (sync.shared_payload puts it back), so a passive node
    can say whether Cloudflare is in step; it just does not count.
    """
    out = {sec: cfg.get(sec, {}) for sec in SHARED_SECTIONS}
    if isinstance(out.get("cloudflare"), dict) and "told" in out["cloudflare"]:
        out["cloudflare"] = {k: v for k, v in out["cloudflare"].items() if k != "told"}
    return out


def _fp(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:16]


def shared_fingerprint(cfg):
    """A short tag for the shared configuration. Equal tags mean agreement."""
    return _fp(shared_view(cfg))


def shared_objects(cfg, limit=20000):
    """Every shared object, with a tag for its contents.

    A tag per collection can only say "these differ", which leaves the reader
    to compare two configurations by hand. This says which object: what is on
    one node and not another, and what has the same identity but different
    contents.

    Capped, because it travels between nodes -- though since 1.100.2 only
    when they disagree, which is what let the cap go from 4,000 objects (about
    800 services) to 20,000. Over it the answer is None, not {}, so a reader
    can say "too many to list" rather than "this node does not report them".
    """
    out, seen = {}, 0
    for section, body in shared_view(cfg).items():
        if not isinstance(body, dict):
            continue
        for coll, items in sorted(body.items()):
            if not isinstance(items, list):
                continue
            rows = []
            for i, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                rows.append([item.get("id") or "#%d" % i,
                             item.get("name") or item.get("id") or "#%d" % i,
                             _fp(item)])
            seen += len(rows)
            if seen > limit:
                return None        # too many to be worth sending
            out["%s.%s" % (section, coll)] = rows
    return out


def shared_parts(cfg):
    """The same, one tag per collection.

    "The nodes disagree" is not a useful thing to be told on its own: it takes
    a byte-by-byte comparison of two configurations to find out about what.
    These say which part differs, which is nearly always enough to see why.
    """
    view = shared_view(cfg)
    out = {}
    for section, body in view.items():
        # A section of plain settings is one part: tagging each key would
        # send a tag per secret around the cluster for no reader's benefit.
        if not isinstance(body, dict) or not any(isinstance(v, (list, dict)) for v in body.values()):
            out[section] = _fp(body)
            continue
        for coll, items in sorted(body.items()):
            out["%s.%s" % (section, coll)] = _fp(items)
    return out


# --------------------------------------------------------------------------
# History: the shared configuration as it was, kept so a bad change can be
# looked at and undone. One file per state it has passed through, on this
# node's own disk -- each node remembers what it saw, which includes what a
# peer pushed over it.

HISTORY_DIR = DATA_DIR / "history"
HISTORY_KEEP = 50


def _history_files():
    try:
        return sorted(p for p in HISTORY_DIR.iterdir()
                      if p.name.endswith(".json") and not p.name.startswith("."))
    except OSError:
        return []


def _snapshot(cfg, fp):
    """Keep this state, if it is not the one already kept.

    Compared against the newest snapshot rather than against the revision:
    adopting a peer's configuration takes the peer's revision number without
    counting as a change of our own, and that is exactly the moment worth
    remembering -- it is how a good configuration gets overwritten by a bad
    one.
    """
    files = _history_files()
    if files:
        try:
            if json.loads(files[-1].read_text()).get("fp") == fp:
                return
        except (OSError, ValueError):
            pass
    try:
        HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc)
        name = "%s-r%d.json" % (now.strftime("%Y%m%d-%H%M%S-%f"),
                                int(cfg["_meta"].get("shared_rev") or 0))
        write_private(HISTORY_DIR / name, json.dumps({
            "at": now.isoformat(timespec="seconds"),
            "rev": int(cfg["_meta"].get("shared_rev") or 0),
            "fp": fp,
            "view": shared_view(cfg),
        }, separators=(",", ":")))
        for old in _history_files()[:-HISTORY_KEEP]:
            old.unlink(missing_ok=True)
    except OSError as e:
        log.warning("could not keep a configuration snapshot: %s", e)


def save_config(cfg):
    with _lock:
        # Never overwrite a config file that could not be read. This cfg was
        # built from bare defaults because the on-disk file would not parse;
        # writing it back would turn a recoverable file (rename it, fix the
        # JSON) into a permanent loss of everything it held. The flag is not a
        # persisted field, so a normally-loaded config never carries it.
        if (cfg.get("_meta") or {}).get("unreadable"):
            raise RuntimeError(
                "refusing to overwrite an unreadable config.json -- repair or "
                "move %s aside first" % CONF_PATH)
        # The revision counts changes to the shared configuration, and is what
        # lets a node tell "the same as mine", "older than mine" and "newer
        # than mine" apart. It is bumped here rather than at each call site so
        # that no change can escape being counted. A node that has just taken
        # a configuration from a peer sets both fields first, so adopting is
        # not itself counted as a change.
        meta = cfg.setdefault("_meta", {})
        mirror = (cfg.get("local") or {}).get("updates")
        if isinstance(mirror, dict) and mirror.get("shared"):
            mirror["beta"] = bool((cfg.get("cluster") or {}).get("beta_updates"))
        fp = shared_fingerprint(cfg)
        if fp != meta.get("shared_fp"):
            meta["shared_fp"] = fp
            meta["shared_rev"] = int(meta.get("shared_rev") or 0) + 1
            # A change made here is what the peers take next, from this node:
            # a note that this node once took something it did not match is
            # about a configuration that no longer exists. Only a receive or
            # this clears it, and the node holding the virtual IP seldom
            # receives -- which is how the note outlived its cause (#44).
            meta.pop("config_leak", None)
        _snapshot(cfg, fp)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        # The previous configuration, kept beside the current one. haproxy.cfg
        # has had this from the start and config.json has not, which is the
        # wrong way round: haproxy.cfg is generated and can be produced again,
        # while this file is the only copy of everything. A migration that gets
        # something wrong was, until now, not undoable.
        if CONF_PATH.exists():
            try:
                shutil.copy2(CONF_PATH, str(CONF_PATH) + ".bak")
            except OSError as e:
                log.warning("could not keep a backup of %s: %s", CONF_PATH, e)
        # It holds the API key, the session secret, the peers' keys and the
        # password hash. The directory is 0700, but the file should not rely
        # on that alone -- a backup or a loosened directory would expose it.
        write_private(CONF_PATH, json.dumps(cfg, indent=2))


WEBUI_NAME = "haproxy-manager-ui"   # the service each node publishes its own UI as


def is_webui_name(name, prefix=""):
    """Is this the name the UI service uses, or one of its numbered variants?

    When an object of that name already exists the wizard makes another called
    "...-2", "...-4" and so on. Matching only the plain name is what let those
    escape being marked as node-local, so they travelled to the other nodes,
    collided there, and produced more of themselves.
    """
    name = name or ""
    base = prefix + WEBUI_NAME
    return name == base or name.startswith(base + "-")


def webui_object_ids(cfg):
    """Every HAProxy object that is part of a node's own UI service.

    Found from the object graph rather than by name alone: the pools named for
    the service, everything they are built from, the rules that route to them
    and the conditions those rules test. A user's own object is only included
    if one of those rules actually refers to it.
    """
    hp = cfg.get("haproxy") or {}
    pools = [b for b in hp.get("backends") or [] if is_webui_name(b.get("name"))]
    ids = {p.get("id") for p in pools}
    for pool in pools:
        ids |= set(pool.get("servers") or [])
        if pool.get("healthcheck"):
            ids.add(pool["healthcheck"])
    for rule in hp.get("rules") or []:
        if rule.get("backend") in ids or is_webui_name(rule.get("name"), "to-"):
            ids.add(rule.get("id"))
            ids |= set(rule_cond_ids(rule))
    return {i for i in ids if i}


def is_webui_cert(cert):
    """Was this certificate created for a node's own management UI service?

    Every node publishes that service under the same name, so the certificate
    is named for it too -- and belongs to the node that made it, never to the
    cluster.
    """
    name = (cert.get("name") or "")
    return name == WEBUI_NAME or name.startswith(WEBUI_NAME + "-")


# What refers to what, so a reference can be followed without hard-coding the
# same list in four places.


# Which formula the applied marker was computed with. Bumped when what is
# hashed changes, so load_config can tell a marker stored by an older version
# apart from a real unapplied change and restate it instead of making every
# node of an upgraded cluster read dirty once:
#   1  up to 2.5.1: the sign-in users were left out, so adding or disabling
#      one never asked for an Apply although the userlist is rendered; and
#      the whole of local.keepalived was hashed, dead copies included.
#   2  the access section counts; of local.keepalived only what is rendered.
HASH_FORMULA = 2
_KEEPALIVED_RENDERED = ("interface", "priority", "unicast_src", "unicast_peer")


def config_hash(cfg, formula=HASH_FORMULA):
    """What an Apply must have covered for nothing to be waiting."""
    # A section a file from before its time lacks is left out, so the hash
    # of that file is what the version that wrote it computed; load_config
    # then carries the applied marker over the defaults it adds. notify is
    # not in it: nothing HAProxy serves depends on where alerts go.
    skip = {"notify"} | ({"access"} if formula < 2 else set())
    parts = {sec: cfg[sec] for sec in SHARED_SECTIONS if sec not in skip and sec in cfg}
    k = cfg["local"]["keepalived"]
    parts["keepalived"] = k if formula < 2 else {key: k.get(key) for key in _KEEPALIVED_RENDERED}
    if "cloudflare" in parts:
        # Without the note of what Cloudflare was last told: writing it down
        # changes nothing HAProxy serves, and must not read as unapplied.
        parts["cloudflare"] = {k: v for k, v in parts["cloudflare"].items() if k != "told"}
    payload = json.dumps(parts, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


# --------------------------------------------------------------------------
# helpers
