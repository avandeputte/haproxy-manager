"""Cloudflare Tunnel: services reached through Cloudflare, with Access in front.

cloudflared runs beside HAProxy on every node and holds an outbound
connection to Cloudflare; a visitor reaches Cloudflare, and Cloudflare hands
the request down that connection. Nothing listens on the internet here, which
is the point for a node behind a NAT it does not control. Access, Cloudflare's
sign-in, sits in front of the services that ask for it and decides who gets
that far.

The tunnel is managed remotely: Cloudflare holds its routing, this module
tells it. For each HTTP service ticked "through Cloudflare" it keeps three
things in step at Apply -- the tunnel's route for the host name, the DNS
record that points the name at the tunnel, and the Access application with its
policy -- and, for a service limited to countries, a Firewall custom rule in
the zone. Only what it made is ever changed: a DNS record that points at this
tunnel, an Access application holding the policy named below, the custom
rules with the ref below. A service limited to countries whose rule could not
be written is not published at all: the limit lives in Cloudflare's rule, and
a route without it would be open to the world.

cloudflared reaches HAProxy, not the servers: on a loopback port added to the
listener that carries the service, so health checks, rules, rate limits and
CrowdSec all still apply. On that port alone the visitor's address is taken
from CF-Connecting-IP -- nobody but cloudflared can connect there, so nobody
else can claim one.
"""

from flask import jsonify
from flask import request
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .base import (CLOUDFLARED_BIN, CLOUDFLARED_ENV, CLOUDFLARED_UNIT_FILE, DATA_DIR,
                   PEER_CONNECT_TIMEOUT, _lock, _requests, app, log)
from .config import DEFAULT_CONFIG, load_config, save_config
from .util import _by_id, rule_cond_ids, run, run_script
from . import oauth, wizard

UNIT = "ham-cloudflared"
API = os.environ.get("HAM_CLOUDFLARE_API", "https://api.cloudflare.com/client/v4").rstrip("/")
# The policy every Access application made here holds, and how one is told
# from an application somebody made in the dashboard.
POLICY_NAME = "haproxy-manager"
SESSION = "24h"
ACCESS_MODES = ("public", "allow")
_HOST = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")

# A route this app wrote: to HAProxy on the node's own loopback. Anything else
# in the tunnel's routing was put there by somebody, and is theirs.
_OUR_SERVICE = re.compile(r"^http://127\.0\.0\.1:\d+$")
DNS_COMMENT = "haproxy-manager"

# The countries a service may be limited to: ISO 3166-1 alpha-2, as Cloudflare
# names a visitor's country, plus Cloudflare's own XK (Kosovo), T1 (Tor) and
# XX (no country known).
COUNTRIES = frozenset((
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR "
    "BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ "
    "EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW "
    "GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY "
    "KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV "
    "MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY "
    "QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG "
    "TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM "
    "ZW XK T1 XX").split())
# Codes people write that are not ISO's, and what they mean.
_COUNTRY_SLIPS = {"UK": "GB", "EL": "GR"}

# The Firewall custom rule this app keeps in a zone, and how it is told from
# the zone's other rules. Every service limited to countries in that zone is
# a part of it: the Free plan allows five custom rules a zone. Only when the
# services outgrow what one expression may hold is a second written, with a
# number after the ref.
WAF_REF = "haproxy-manager-countries"
_WAF_REF = re.compile(r"^%s(-\d+)?$" % re.escape(WAF_REF))
WAF_DESCRIPTION = "haproxy-manager: services limited to countries (managed by haproxy-manager)"
WAF_PHASE = "http_request_firewall_custom"
WAF_MAX_EXPRESSION = 4096

# What the renderer strips from a value before HAProxy reads it, so that a
# value is one line (haproxy._line_safe). Cloudflare is told the value
# HAProxy will act on; and its rules language refuses a control character
# outright, which would have held up every service in the zone.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# Cloudflare's API: the connect budget every call to another machine gets
# (base.py says why a bare number is the wrong shape), and a read budget of
# its own -- an answer takes a second or two, and a tunnel's configuration
# is one document.
TIMEOUT = (PEER_CONNECT_TIMEOUT, 30)
RETRY_WAIT_MAX = 10


class CloudflareError(Exception):
    status = 0


def parse_countries(value):
    """The country codes typed for a service: (codes, refused). Upper-cased,
    each once, in the order given; separated by spaces, commas or lines."""
    if isinstance(value, (list, tuple)):
        value = " ".join(str(x) for x in value)
    codes, bad = [], []
    for tok in re.split(r"[\s,;]+", str(value or "").strip()):
        if not tok:
            continue
        code = tok.upper()
        if code in COUNTRIES:
            if code not in codes:
                codes.append(code)
        else:
            bad.append(tok)
    return codes, bad


def check_countries(value):
    """The stored form of a country list, or ValueError saying which code is wrong."""
    codes, bad = parse_countries(value)
    if bad:
        hint = ["%s (did you mean %s?)" % (b, _COUNTRY_SLIPS[b.upper()]) if b.upper() in _COUNTRY_SLIPS
                else b for b in bad[:3]]
        raise ValueError("not a two-letter country code: %s -- use ISO codes such as US, CA or GB"
                         % ", ".join(hint))
    return " ".join(codes)


def check_values(values, service):
    """Refuse a host name or path that holds a control character, before it
    is stored for a service published through Cloudflare. The renderer would
    drop the character and route by what is left, so the service would be
    published under a value nobody typed. Raises ValueError naming the service."""
    for v in values:
        if _CONTROL.search(str(v or "")):
            raise ValueError("\"%s\": the host name or path %r holds a control character, which neither "
                             "HAProxy nor Cloudflare takes; type it again" % (service, _CONTROL.sub("?", str(v))))


def _route_countries(value):
    """What a stored list limits a route to. A list that is set but holds no
    code this app knows (a restored or hand-edited configuration) admits
    nobody rather than everybody: a limit misread must not open a service."""
    codes, bad = parse_countries(value)
    if bad and not codes:
        return ["ZZ"]                       # no visitor is in ZZ
    return codes


def settings_of(cfg):
    out = dict(DEFAULT_CONFIG["cloudflare"])
    out.update(cfg.get("cloudflare") or {})
    return out


def connected(cfg):
    """Has a tunnel been made, and is its token here."""
    s = settings_of(cfg)
    return bool(s.get("tunnel_id") and s.get("tunnel_token"))


def configured(cfg):
    """Is Cloudflare meant to be carrying services: switched on, with a tunnel."""
    return bool(settings_of(cfg).get("enabled")) and connected(cfg)


def installed():
    return CLOUDFLARED_BIN.exists()


def origin_port(cfg):
    try:
        return int(settings_of(cfg).get("origin_port") or DEFAULT_CONFIG["cloudflare"]["origin_port"])
    except (TypeError, ValueError):
        return DEFAULT_CONFIG["cloudflare"]["origin_port"]


def check(new, cur):
    """Refuse settings that cannot work, with the reason. Raises ValueError.
    Leaves the first loopback port a number."""
    try:
        new["origin_port"] = int(new.get("origin_port"))
    except (TypeError, ValueError):
        raise ValueError("the first loopback port must be a number")
    if not 1024 <= new["origin_port"] <= 65000:
        raise ValueError("the first loopback port must be between 1024 and 65000")
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$", new.get("tunnel_name") or ""):
        raise ValueError("a tunnel name is letters, digits, spaces, dots, dashes and underscores")
    if new.get("account_id") and not re.match(r"^[0-9a-f]{32}$", new["account_id"]):
        raise ValueError("an Account ID is 32 hexadecimal characters; it is on the right of a zone's Overview page")
    # Another name or another account is another tunnel.
    if cur.get("tunnel_id") and (new["tunnel_name"] != cur.get("tunnel_name")
                                 or (new.get("account_id") or cur.get("account_id")) != cur.get("account_id")):
        raise ValueError("this installation is connected to the tunnel \"%s\". Disconnect it first; a "
                         "different name or account is a different tunnel." % cur.get("tunnel_name"))
    if new.get("enabled") and not new.get("api_token"):
        raise ValueError("Cloudflare needs an API token with Cloudflare Tunnel, Access: Apps and Policies "
                         "and DNS, all Edit, and Zone Read -- and Zone WAF: Edit to limit services to countries")


# --------------------------------------------------------------------------
# which services, and where cloudflared finds them

def routes(cfg):
    """The services published through Cloudflare, one entry per host name.

    Read from the shared configuration, never a node's own objects: the
    tunnel's routing is one thing for the whole cluster, so it can only name
    what every node serves. A service on several listeners is reached on one
    of them, the HTTPS one when there is one.

    The loopback port belongs to the listener: the first port plus the
    listener's place in the list, so it is the same on every node.

    The entries come in the order the listener tries its rules, which is
    what decides where a request goes when two of them match; the country
    rule is built from that order.

    A condition names alternatives separated by spaces, and HAProxy takes
    any of them; so does the tunnel, with a route for each host name and
    each path. Only a path prefix narrows a route: the tunnel, Access and
    the country rule can all say "this host, from this path on", and none
    of them "ends with" or "contains". A rule tested on another kind of path
    condition is published for its whole host -- never less than HAProxy
    routes to it, so nothing slips past a limit, though a sibling path on
    that host published by another rule then inherits its sign-in.
    """
    if not configured(cfg):
        return []
    hp = cfg["haproxy"]
    conds, pools, rules = _by_id(hp["conditions"]), _by_id(hp["backends"]), _by_id(hp["rules"])
    base = origin_port(cfg)
    out, seen = [], set()
    order = sorted(enumerate(hp["frontends"]), key=lambda x: (not x[1].get("ssl_enabled"), x[0]))
    for idx, fe in order:
        if not fe.get("enabled", True) or fe.get("mode", "http") != "http":
            continue
        for rid in fe.get("rules") or []:
            rule = rules.get(rid)
            if not rule or rule.get("type") != "use_backend" or rid in seen:
                continue
            pool = pools.get(rule.get("backend"))
            if not pool or not pool.get("cf_tunnel") or pool.get("mode", "http") != "http":
                continue
            hosts, paths = [], []
            for cid in rule_cond_ids(rule):
                c = conds.get(cid)
                if not c:
                    continue
                # Without control characters, as the renderer writes it: the
                # value HAProxy acts on is the one Cloudflare is told.
                values = _CONTROL.sub("", str(c.get("value") or "")).split()
                if c.get("type") == "host_matches":
                    hosts += [v.lower() for v in values if v.lower() not in hosts]
                elif c.get("type") == "path_starts_with":
                    paths += [v for v in values if v not in paths]
            if not hosts:
                continue
            seen.add(rid)
            entries, _bad = oauth.parse_allow(pool.get("cf_access_allow"))
            for host in hosts:
                for path in paths or [""]:
                    out.append({"host": host, "path": path, "valid": bool(_HOST.match(host)),
                                "pool": pool["id"], "name": pool.get("name") or host,
                                "frontend": fe["id"], "port": base + idx,
                                "access": pool.get("cf_access") if pool.get("cf_access") in ACCESS_MODES else "public",
                                "allow": entries,
                                "countries": _route_countries(pool.get("cf_countries"))})
    return out


def frontend_port(found, fe):
    """The loopback port cloudflared reaches this listener on, or None."""
    return next((r["port"] for r in found if r["frontend"] == fe.get("id")), None)


def frontend_lines(found, fe):
    """What a listener that carries such a service gains: (binds, declarations, requests).

    The requests come before everything else the listener does, so the
    visitor's address is the real one by the time anything looks at it.
    """
    port = frontend_port(found, fe)
    if port is None:
        return [], [], []
    req = [
        # Only cloudflared can connect to this port, so the header is its own.
        "http-request set-src req.hdr(CF-Connecting-IP) if cf_tunnel { req.hdr(CF-Connecting-IP) -m found }",
        # The visitor spoke HTTPS to Cloudflare, whatever this hop is.
        "http-request set-header X-Forwarded-Proto https if cf_tunnel",
    ]
    return ["127.0.0.1:%d" % port], ["acl cf_tunnel dst_port %d" % port], req


def backend_lines(found, be):
    """What a pool says about the tunnel.

    One that is not published through Cloudflare refuses whatever came down
    it. The tunnel routes by host name alone, so a service ticked for one
    path of a host would otherwise bring the host's other services to the
    internet with it -- and with no sign-in, since Access covers the path
    that asked for one.

    One reached through Cloudflare only refuses everything else. Without a
    tunnel to come down, that is everything -- a service half-protected is
    not a little protected.
    """
    if be.get("mode", "http") != "http":
        return []
    if not be.get("cf_tunnel"):
        ports = sorted({r["port"] for r in found})
        return (["http-request deny deny_status 403 if { dst_port %s }" % " ".join(str(p) for p in ports)]
                if ports else [])
    if not be.get("cf_only"):
        return []
    ports = sorted({r["port"] for r in found if r["pool"] == be.get("id")})
    if not ports:
        return ["# reached through Cloudflare only, and Cloudflare is not connected",
                "http-request deny deny_status 403"]
    return ["http-request deny deny_status 403 unless { dst_port %s }" % " ".join(str(p) for p in ports)]


def port_clash(cfg):
    """A listener already bound to one of the loopback ports, or ""."""
    base, n = origin_port(cfg), len(cfg["haproxy"]["frontends"])
    for fe in cfg["haproxy"]["frontends"]:
        hit = [p for p in wizard._bind_ports(fe) if base <= p < base + max(n, 1)]
        if hit:
            return ("port %d is used by the listener \"%s\"; the ports from %d on are kept for cloudflared -- "
                    "choose another first port" % (hit[0], fe.get("name"), base))
    return ""


# --------------------------------------------------------------------------
# Cloudflare's API

def _call(token, method, path, body=None, params=None, again=True):
    """One call: the whole answer on success, CloudflareError saying why otherwise."""
    if _requests is None:
        raise CloudflareError("python3-requests is not installed on this node")
    try:
        r = _requests.request(method, API + path, json=body, params=params, timeout=TIMEOUT,
                              headers={"Authorization": "Bearer " + token})
    except Exception as e:
        raise CloudflareError("Cloudflare did not answer: %s" % e)
    # Cloudflare's rate limit, which an Apply over many services can brush:
    # asked once more, after the pause it names -- a short one, since an
    # Apply is waiting on the answer.
    if r.status_code == 429 and again:
        try:
            wait = min(float((getattr(r, "headers", None) or {}).get("Retry-After") or 1), RETRY_WAIT_MAX)
        except (TypeError, ValueError):
            wait = 1
        time.sleep(max(wait, 0))
        return _call(token, method, path, body, params, again=False)
    try:
        data = r.json()
    except ValueError:
        data = None
    if not isinstance(data, dict):
        raise CloudflareError("Cloudflare answered %d, and not with JSON" % r.status_code)
    if not data.get("success"):
        why = "; ".join("%s (%s)" % (e.get("message"), e.get("code")) for e in data.get("errors") or []
                        if isinstance(e, dict))
        err = CloudflareError(why or "Cloudflare answered %d" % r.status_code)
        err.status = r.status_code
        raise err
    return data


def _all(token, path, params=None):
    """Every page of a list."""
    out, page = [], 1
    while page <= 50:
        data = _call(token, "GET", path, params=dict(params or {}, page=page, per_page=50))
        out += data.get("result") or []
        info = data.get("result_info") or {}
        if page >= int(info.get("total_pages") or 1):
            break
        page += 1
    return out


def find_account(token, account_id=""):
    """The account to work in: the one named, or the only one the token sees."""
    if account_id:
        return account_id
    accounts = _all(token, "/accounts")
    if len(accounts) == 1:
        return accounts[0]["id"]
    if not accounts:
        raise CloudflareError("the token sees no account; give the Account ID, and check the token's "
                              "Account Resources")
    raise CloudflareError("the token sees %d accounts; give the Account ID of the one to use" % len(accounts))


def connect(token, account_id, name):
    """Make the tunnel: (account, tunnel id, tunnel token).

    A tunnel of that name that is already there is used only while it is
    empty. One with routes or connections is somebody's -- a NAS, another
    installation -- and Apply would replace its routes with this one's.
    """
    account = find_account(token, account_id)
    found = _call(token, "GET", "/accounts/%s/cfd_tunnel" % account,
                  params={"name": name, "is_deleted": "false"}).get("result") or []
    found = [t for t in found if t.get("name") == name]
    if found:
        tunnel = found[0]
        if tunnel.get("config_src") not in (None, "cloudflare"):
            raise CloudflareError("a tunnel named \"%s\" exists, but it is configured from a file on its "
                                  "own machine; choose another tunnel name" % name)
        held = (_call(token, "GET", "/accounts/%s/cfd_tunnel/%s/configurations" % (account, tunnel["id"]))
                .get("result") or {}).get("config") or {}
        hosts = [i.get("hostname") for i in held.get("ingress") or [] if isinstance(i, dict) and i.get("hostname")]
        if hosts or tunnel.get("connections"):
            raise CloudflareError(
                "a tunnel named \"%s\" is already in use in this account (%s). Using it here would replace "
                "its routes. Choose another tunnel name, or delete that tunnel in Cloudflare first."
                % (name, (", ".join(hosts[:3]) + (", ..." if len(hosts) > 3 else "")) if hosts
                   else "a connector is connected to it"))
    else:
        tunnel = _call(token, "POST", "/accounts/%s/cfd_tunnel" % account,
                       body={"name": name, "config_src": "cloudflare"}).get("result") or {}
    tid = tunnel.get("id")
    if not tid:
        raise CloudflareError("Cloudflare made a tunnel without saying which")
    secret = _call(token, "GET", "/accounts/%s/cfd_tunnel/%s/token" % (account, tid)).get("result")
    if not isinstance(secret, str) or not secret:
        raise CloudflareError("Cloudflare did not hand over the tunnel's token")
    return account, tid, secret


def _zone_for(zones, host):
    """The zone a host name belongs to: the longest name it ends in."""
    bare = host[2:] if host.startswith("*.") else host
    best = None
    for z in zones:
        name = (z.get("name") or "").lower()
        if name and (bare == name or bare.endswith("." + name)) and (best is None or len(name) > len(best["name"])):
            best = z
    return best


def _include(entries):
    out = []
    for e in entries:
        if e == "*":
            out.append({"everyone": {}})
        elif e.startswith("@"):
            out.append({"email_domain": {"domain": e[1:]}})
        else:
            out.append({"email": {"email": e}})
    return out


def _ours(app_obj):
    return any(isinstance(p, dict) and p.get("name") == POLICY_NAME for p in app_obj.get("policies") or [])


def desired(cfg):
    """What Cloudflare should hold for this configuration, in a form that
    compares: the routes while Cloudflare is on, nothing while it is off."""
    s = settings_of(cfg)
    return {"tunnel": s.get("tunnel_id") or "", "account": s.get("account_id") or "",
            "routes": [[r["host"], r["path"], r["port"], r["access"], r["allow"], r["name"]]
                       + ([r["countries"]] if r["countries"] else [])
                       for r in routes(cfg) if r["valid"]]}


def _fingerprint(cfg):
    return hashlib.sha256(json.dumps(desired(cfg), sort_keys=True).encode()).hexdigest()


def _told(cfg):
    """What Cloudflare was last told, by whichever node told it. Kept in the
    shared configuration, so the node that takes over knows what the last
    one said, and a passive node can say whether Cloudflare is behind."""
    return settings_of(cfg).get("told") or ""


def _remember(fp):
    """Record what Cloudflare now holds. Not part of what Apply compares:
    saying it leaves nothing unapplied."""
    with _lock:
        cfg = load_config()
        if _told(cfg) != fp and isinstance(cfg.get("cloudflare"), dict):
            cfg["cloudflare"]["told"] = fp
            save_config(cfg)


def _apps_for(token, account, hosts):
    """The Access applications on these host names, whatever path they are
    for: (the ones made here by domain, the domains of the others)."""
    ours, theirs = {}, set()
    if not hosts:
        return ours, theirs
    for a in _all(token, "/accounts/%s/access/apps" % account):
        domain = a.get("domain") or ""
        if domain.split("/", 1)[0] not in hosts:
            continue
        if "policies" not in a:
            a["policies"] = _all(token, "/accounts/%s/access/apps/%s/policies" % (account, a["id"]))
        if _ours(a):
            ours[domain] = a
        else:
            theirs.add(domain)
    return ours, theirs


def _drop_dns(token, zones, host, target):
    """Remove the record that points a name at this tunnel, if it is the one
    made here: same target, and this app's mark on it."""
    zone = _zone_for(zones, host)
    if not zone:
        return []
    out = []
    for x in _call(token, "GET", "/zones/%s/dns_records" % zone["id"],
                   params={"name": host, "type": "CNAME"}).get("result") or []:
        if (x.get("content") or "").lower() == target and (x.get("comment") or "") == DNS_COMMENT:
            _call(token, "DELETE", "/zones/%s/dns_records/%s" % (zone["id"], x["id"]))
            out.append("cloudflare: DNS record for %s removed" % host)
    return out


# --------------------------------------------------------------------------
# countries: a Firewall custom rule per zone -- more only when one cannot
# hold every service

def _q(text):
    """A string literal in Cloudflare's rules language. A control character
    is dropped, as the renderer drops it: Cloudflare would refuse the whole
    expression over one."""
    return '"%s"' % _CONTROL.sub("", str(text)).replace("\\", "\\\\").replace('"', '\\"')


def _host_test(host):
    # wildcard is case-insensitive and on every plan. Its * spans dots, where
    # the listener's own *.example.com takes one label: _claim takes the
    # deeper names out again.
    return ("http.host wildcard %s" % _q(host)) if host.startswith("*.") else ("http.host eq %s" % _q(host))


def _one_label(host, wild):
    """Is this name one label under the wildcard, as the listener matches
    *.example.com: shop.example.com, not a.b.example.com."""
    return host.endswith(wild[1:]) and "." not in host[:-len(wild) + 1]


def _meet(a, b):
    """The names both of these host names take, as the listener matches
    them -- a name itself, a wildcard the one label under it -- as the test
    for Cloudflare's rules language; None when they share no name."""
    if a == b:
        return _host_test(a)
    if a.startswith("*.") and not b.startswith("*.") and _one_label(b, a):
        return _host_test(b)
    if b.startswith("*.") and not a.startswith("*.") and _one_label(a, b):
        return _host_test(a)
    return None


def _path_test(path):
    return "starts_with(http.request.uri.path, %s)" % _q(path)


def _claim(r, everyone):
    """The requests Cloudflare should take to be this route's, or "" when
    none reach it.

    The tunnel routes by host name; the listener then takes the first of its
    rules that matches. So a route owns its host and path, less what the
    routes before it on the same listener already take -- a wildcard placed
    before the name it covers takes that name too, whatever a reader of the
    list might expect -- and a route an earlier one takes whole owns nothing.
    The order is the listener's, not what is particular: the rule must say
    what HAProxy will do, or a service is limited to countries on paper.

    A wildcard's test here spans dots where the listener's takes one label,
    so the deeper names other routes own are taken out of it as well.
    """
    parts = [_host_test(r["host"])]
    if r["path"]:
        parts.append(_path_test(r["path"]))
    for o in everyone:
        if o is r:
            break
        if o.get("port") != r.get("port"):
            continue
        met = _meet(o["host"], r["host"])
        if met is None:
            continue
        whole = met == parts[0]            # the other takes every name this one has
        if r["path"].startswith(o["path"]):
            if whole:
                return ""
            taken = met
        elif o["path"].startswith(r["path"]):
            taken = _path_test(o["path"]) if whole else "(%s and %s)" % (met, _path_test(o["path"]))
        else:
            continue
        if "not " + taken not in parts:
            parts.append("not " + taken)
    if r["host"].startswith("*."):
        for o in everyone:
            if (o is not r and o["host"] != r["host"] and o["host"].endswith(r["host"][1:])
                    and _meet(o["host"], r["host"]) is None and "not " + _host_test(o["host"]) not in parts):
                parts.append("not " + _host_test(o["host"]))
    return " and ".join(parts)


def _clauses(expression):
    """The clauses of an expression this app wrote, as a set: each is
    parenthesised, and they are joined by " or ". Read back to tell whether
    a change to a rule only adds to what it blocks, or only takes from it."""
    return frozenset(re.split(r"(?<=\)) or (?=\()", expression or ""))


def firewall_expressions(found, zones):
    """What each zone's rules should say: {zone id: (zone name, expressions,
    routes left out)}. A zone none of whose services is limited to countries
    is not in it. The clauses are packed into as few expressions as
    Cloudflare's length allows; a route whose clause alone is too long is
    left out, and named, so its host is not published."""
    everyone = [r for r in found if r["valid"]]
    by_zone = {}
    for r in everyone:
        if not r["countries"]:
            continue
        zone = _zone_for(zones, r["host"])
        if not zone:
            continue
        claim = _claim(r, everyone)
        if not claim:
            continue                        # another route takes everything it would
        clause = "(%s and not ip.src.country in {%s})" % (claim, " ".join(_q(c) for c in r["countries"]))
        name, clauses = by_zone.setdefault(zone["id"], (zone["name"], []))
        if clause not in [c for c, _r in clauses]:
            clauses.append((clause, r))
    out = {}
    for zid, (name, clauses) in by_zone.items():
        exprs, left = [], []
        for clause, r in clauses:
            if len(clause) > WAF_MAX_EXPRESSION:
                left.append(r)
            elif exprs and len(exprs[-1]) + len(" or ") + len(clause) <= WAF_MAX_EXPRESSION:
                exprs[-1] += " or " + clause
            else:
                exprs.append(clause)
        out[zid] = (name, exprs, left)
    return out


def _waf_rule(expression, ref):
    return {"ref": ref, "description": WAF_DESCRIPTION, "expression": expression,
            "action": "block", "enabled": True}


def _ours_waf(rule):
    return isinstance(rule, dict) and (bool(_WAF_REF.match(str(rule.get("ref") or "")))
                                       or rule.get("description") == WAF_DESCRIPTION)


def _free_ref(taken):
    """The ref for another rule in a zone: the plain one, else the first number not in use."""
    if WAF_REF not in taken:
        return WAF_REF
    n = 2
    while "%s-%d" % (WAF_REF, n) in taken:
        n += 1
    return "%s-%d" % (WAF_REF, n)


def _entrypoint(token, zone_id):
    """The zone's custom rules ruleset, or None when it has none yet."""
    try:
        return _call(token, "GET", "/zones/%s/rulesets/phases/%s/entrypoint" % (zone_id, WAF_PHASE)).get("result")
    except CloudflareError as e:
        if e.status == 404:
            return None
        raise


def _why_not(e):
    """What kept a zone's rule from being written, for the warning."""
    if e.status in (401, 403):
        return ("the API token may not change this zone's Firewall rules (%s). Give it Zone WAF: "
                "Edit, which limiting a service to countries needs" % e)
    return str(e)


def _firewall(token, zones, found, hosts):
    """Bring the country rules of every zone these host names are in into
    step, as far as can be done before the routes: (steps, unmet, later).

    `unmet` is every route limited to countries whose limit is not in place,
    with why: its zone is not one the token sees, its clause is too long for
    one rule, or Cloudflare would not take the zone's rules. The caller
    publishes none of those -- a service limited to countries on paper alone
    is open to the world. `later()` is what must wait until the routes are
    gone: a rule that would block less, or nothing, is changed or removed
    only then, so a service is never reachable for a moment from a country
    it was closed to. It returns (steps, warnings).

    Only the rules this app made are read, changed or removed; the zone's
    other rules are not touched, and keep their order. A zone where nothing
    is limited is only cleared, and a token without the right to look leaves
    it as it is: before 2.5 none was made.
    """
    steps, unmet, after = [], [], []
    wanted = firewall_expressions(found, zones)
    limited = {}
    for r in found:
        if r["valid"] and r["countries"]:
            z = _zone_for(zones, r["host"])
            if z is None:
                unmet.append((r, "its zone is not one this API token sees; give the token Zone Read on it"))
            else:
                limited.setdefault(z["id"], []).append(r)
    seen = {}
    for h in hosts:
        z = _zone_for(zones, h)
        if z:
            seen[z["id"]] = z["name"]
    for zid, (name, _exprs, _left) in wanted.items():
        seen[zid] = name
    for zid, name in seen.items():
        _name, exprs, left = wanted.get(zid, (name, [], []))
        for r in left:
            unmet.append((r, "its rule alone would be more than Cloudflare's %d characters; publish it on a "
                             "shorter path, or with fewer services beside it" % WAF_MAX_EXPRESSION))
        try:
            rs = _entrypoint(token, zid)
        except CloudflareError as e:
            if exprs:                       # nothing wanted: nothing it may see
                unmet += [(r, _why_not(e)) for r in limited.get(zid, [])]
            continue
        ours = [x for x in (rs or {}).get("rules") or [] if _ours_waf(x)]
        spare = [x for x in ours if x.get("expression") not in exprs or x.get("action") != "block"
                 or x.get("enabled") is False]
        kept = [x for x in ours if x not in spare]
        todo = [e for e in exprs if e not in [x.get("expression") for x in kept]]
        refs = {x.get("ref") for x in ours}
        now = []                            # (method, rule or None, expression)
        for e in todo:
            # A rule this expression only adds to is changed now; one it
            # only takes from, once the routes are gone. One it does both to
            # is first widened to the two together, and narrowed to the new
            # one later -- so it keeps its place and the zone's count of
            # rules, which a plan limits. Only when the two together would be
            # too long is a rule written new, and the old one removed later.
            grow = next((x for x in spare if _clauses(x.get("expression")) <= _clauses(e)), None)
            if grow is not None:
                spare.remove(grow)
                now.append(("PATCH", grow, e))
                continue
            shrink = next((x for x in spare if _clauses(e) <= _clauses(x.get("expression"))), None)
            if shrink is not None:
                spare.remove(shrink)
                after.append((zid, name, rs, "PATCH", shrink, e))
                continue
            if spare:
                x = spare.pop(0)
                both = " or ".join([x.get("expression") or ""]
                                   + [c for c in re.split(r"(?<=\)) or (?=\()", e) if c not in _clauses(x.get("expression"))])
                if len(both) <= WAF_MAX_EXPRESSION:
                    now.append(("PATCH", x, both))
                    after.append((zid, name, rs, "PATCH", x, e))
                    continue
                after.append((zid, name, rs, "DELETE", x, ""))
            now.append(("POST", None, e))
        after += [(zid, name, rs, "DELETE", x, "") for x in spare]
        try:
            if rs is None and now:
                bodies = []
                for _m, _x, e in now:
                    bodies.append(_waf_rule(e, _free_ref(refs)))
                    refs.add(bodies[-1]["ref"])
                _call(token, "PUT", "/zones/%s/rulesets/phases/%s/entrypoint" % (zid, WAF_PHASE),
                      body={"rules": bodies})
                steps.append("cloudflare: country rule for %s" % name)
                continue
            for method, x, e in now:
                if method == "PATCH":
                    ref = x.get("ref") if _WAF_REF.match(str(x.get("ref") or "")) else _free_ref(refs)
                    refs.add(ref)
                    _call(token, "PATCH", "/zones/%s/rulesets/%s/rules/%s" % (zid, rs["id"], x["id"]),
                          body=_waf_rule(e, ref))
                    steps.append("cloudflare: country rule for %s updated" % name)
                else:
                    ref = _free_ref(refs)
                    refs.add(ref)
                    _call(token, "POST", "/zones/%s/rulesets/%s/rules" % (zid, rs["id"]), body=_waf_rule(e, ref))
                    steps.append("cloudflare: country rule for %s" % name)
        except CloudflareError as e:
            unmet += [(r, _why_not(e)) for r in limited.get(zid, [])]
            after = [a for a in after if a[0] != zid]   # a zone that would not have it is left as it is

    def later():
        out, warnings = [], []
        for zid, name, rs, method, x, e in after:
            try:
                if method == "DELETE":
                    _call(token, "DELETE", "/zones/%s/rulesets/%s/rules/%s" % (zid, rs["id"], x["id"]))
                    out.append("cloudflare: country rule for %s removed" % name)
                else:
                    ref = x.get("ref") if _WAF_REF.match(str(x.get("ref") or "")) else WAF_REF
                    _call(token, "PATCH", "/zones/%s/rulesets/%s/rules/%s" % (zid, rs["id"], x["id"]),
                          body=_waf_rule(e, ref))
                    out.append("cloudflare: country rule for %s updated" % name)
            except CloudflareError as err:
                # The rule still blocks what it did: too much, never too little.
                warnings.append("the country rule for %s was not brought in step (%s); it blocks what it "
                                "blocked before, and is tried again at the next Apply" % (name, _why_not(err)))
        return out, warnings
    return steps, unmet, later


def _reconcile(cfg, also=()):
    """Bring Cloudflare in step: (steps, warnings, pending). Raises
    CloudflareError when Cloudflare would not have it. `also` are host names
    to treat as published before, whatever the tunnel says. `pending` means
    something was left for the next Apply to try again."""
    s = settings_of(cfg)
    token, account, tid = (s.get("api_token") or "").strip(), s.get("account_id"), s.get("tunnel_id")
    want = [r for r in routes(cfg) if r["valid"]]
    steps, pending = [], False
    warnings = ["\"%s\" is not a host name Cloudflare can route, so it is not published through the tunnel"
                % r["host"] for r in routes(cfg) if not r["valid"]]
    target = "%s.cfargotunnel.com" % tid
    prev = (_call(token, "GET", "/accounts/%s/cfd_tunnel/%s/configurations" % (account, tid))
            .get("result") or {}).get("config") or {}
    prev_ingress = prev.get("ingress") or []
    named = [i for i in prev_ingress if isinstance(i, dict) and i.get("hostname")]
    # Only the routes this app wrote are its to change. One somebody added to
    # the tunnel in the dashboard stays where it is.
    foreign = [i for i in named if not _OUR_SERVICE.match(str(i.get("service") or ""))]
    prev_hosts = [i["hostname"] for i in named if i not in foreign] + list(also)
    want_hosts = list(dict.fromkeys(r["host"] for r in want))

    # 1. Countries: the zones' Firewall rules, before the route, so a service
    #    limited to countries is never reachable from elsewhere for a moment.
    #    A host name one of whose services is limited, and whose limit could
    #    not be set, is not published at all -- the tunnel routes by host
    #    name, so the host's other services would bring it along -- and what
    #    it had is taken away below, as if it had been unticked.
    zones = _all(token, "/zones") if (want_hosts or prev_hosts) else []
    more, unmet, later = _firewall(token, zones, want, set(prev_hosts) | set(want_hosts))
    steps += more
    held = {}
    for r, why in unmet:
        held.setdefault(r["host"], (r, why))
    for host, (r, why) in held.items():
        pending = True
        warnings.append("%s is not published through the tunnel: \"%s\" is limited to countries, and that "
                        "limit could not be set -- %s" % (host, r["name"], why))
    want = [r for r in want if r["host"] not in held]
    want_hosts = [h for h in want_hosts if h not in held]

    # 2. Access: an application per host and path that asks for a sign-in.
    wanted_apps = {r["host"] + r["path"]: r for r in want if r["access"] == "allow"}
    ours, theirs = _apps_for(token, account, set(prev_hosts) | set(want_hosts))
    for domain, r in wanted_apps.items():
        policy = {"name": POLICY_NAME, "decision": "allow", "include": _include(r["allow"]), "precedence": 1}
        if domain in theirs and domain not in ours:
            warnings.append("%s already has an Access application that was not made here; it was left "
                            "as it is, and decides who gets in" % domain)
            continue
        body = {"name": r["name"], "domain": domain, "type": "self_hosted",
                "session_duration": SESSION, "app_launcher_visible": False}
        if domain not in ours:
            made = _call(token, "POST", "/accounts/%s/access/apps" % account, body=body).get("result") or {}
            _call(token, "POST", "/accounts/%s/access/apps/%s/policies" % (account, made["id"]), body=policy)
            steps.append("cloudflare: Access application for %s" % domain)
            continue
        have = ours[domain]
        if have.get("name") != r["name"]:
            _call(token, "PUT", "/accounts/%s/access/apps/%s" % (account, have["id"]), body=body)
        held = next(p for p in have["policies"] if p.get("name") == POLICY_NAME)
        if held.get("include") != policy["include"] or held.get("decision") != "allow":
            _call(token, "PUT", "/accounts/%s/access/apps/%s/policies/%s" % (account, have["id"], held["id"]),
                  body=policy)
            steps.append("cloudflare: Access policy for %s updated" % domain)

    # 3. The tunnel's routes. This app's own are written whole; anybody
    #    else's follow them untouched, and so does everything else Cloudflare
    #    keeps in the same document. Cloudflare takes the first route that
    #    matches: exact names before wildcards, the deeper wildcard before
    #    the shallower. Sorted, too, so the same services in another order
    #    are the same document.
    port_of = {}
    for r in want:
        port_of.setdefault(r["host"], r["port"])
    mine = [{"hostname": h, "service": "http://127.0.0.1:%d" % port_of[h], "originRequest": {}} for h in want_hosts]
    mine.sort(key=lambda i: (i["hostname"].startswith("*."), -i["hostname"].count("."), i["hostname"]))
    last = [i for i in prev_ingress if isinstance(i, dict) and not i.get("hostname")][-1:] \
        or [{"service": "http_status:404"}]
    ingress = mine + [i for i in foreign if i["hostname"] not in want_hosts] + last
    if ingress != prev_ingress:
        _call(token, "PUT", "/accounts/%s/cfd_tunnel/%s/configurations" % (account, tid),
              body={"config": dict(prev, ingress=ingress)})
        steps.append("cloudflare: tunnel routes for %d host name(s)" % len(mine))

    # 4. DNS: the name points at the tunnel. A record that is already there
    #    and points elsewhere is somebody's, and is left alone -- and asked
    #    about again at the next Apply, by when it may be gone.
    for host in want_hosts:
        zone = _zone_for(zones, host)
        if not zone:
            pending = True
            warnings.append("%s is in no zone this API token can see, so it has no DNS record; "
                            "the tunnel is ready for it" % host)
            continue
        records = _call(token, "GET", "/zones/%s/dns_records" % zone["id"], params={"name": host}).get("result") or []
        records = [x for x in records if x.get("type") in ("A", "AAAA", "CNAME")]
        if any(x.get("type") == "CNAME" and (x.get("content") or "").lower() == target for x in records):
            continue
        if records:
            x = records[0]
            pending = True
            warnings.append("%s already has a DNS record (%s %s), so visitors still go there and not "
                            "through the tunnel. Delete it in Cloudflare, then Apply again."
                            % (host, x.get("type"), x.get("content")))
            continue
        _call(token, "POST", "/zones/%s/dns_records" % zone["id"],
              body={"type": "CNAME", "name": host, "content": target, "proxied": True, "comment": DNS_COMMENT})
        steps.append("cloudflare: DNS record for %s" % host)
    for host in dict.fromkeys(prev_hosts):
        if host not in want_hosts:
            steps += _drop_dns(token, zones, host, target)

    # 5. Country rules that would now block less, or nothing, after the
    #    routes: a service is unpublished before its limit is lifted.
    more, warned = later()
    steps += more
    warnings += warned
    pending = pending or bool(warned)

    # 6. Access applications nothing asks for any more, last: a service is
    #    unpublished before its sign-in goes.
    for domain, a in ours.items():
        if domain not in wanted_apps:
            _call(token, "DELETE", "/accounts/%s/access/apps/%s" % (account, a["id"]))
            steps.append("cloudflare: Access application for %s removed" % domain)
    return steps, warnings, pending


# Why the last telling fell short, on this node, for the status: "" when it
# did not. What was told is in the shared configuration; this is only the
# reason, for the node that saw it.
_behind = {"why": ""}


def reconcile(cfg, force=False):
    """Bring Cloudflare in step with the configuration: (steps, warnings).

    The country rule and the sign-in first, then the route, then the name:
    a service limited to countries or asking for a sign-in is never reachable
    for a moment without them. Taking away, the other way round: the route
    first, then the rule and the sign-in. Skipped when nothing it would say
    has changed since Cloudflare was last told -- unless that telling left
    something undone, or failed.
    """
    s = settings_of(cfg)
    if not ((s.get("api_token") or "").strip() and s.get("account_id") and s.get("tunnel_id")):
        return [], []
    fp = _fingerprint(cfg)
    if not force and fp == _told(cfg):
        return [], []
    try:
        steps, warnings, pending = _reconcile(cfg)
    except CloudflareError as e:
        log.warning("cloudflare: not brought in step: %s", e)
        # Whatever Cloudflare was told before, it does not hold this now:
        # forgotten, so the next Apply asks again rather than skipping it.
        _remember("")
        _behind["why"] = str(e)
        return [], ["Cloudflare was not brought in step with this configuration: %s. "
                    "What is published there may be partly as it was; Apply again, or use "
                    "Sync now under Access > Cloudflare." % e]
    # Something left undone is not remembered as done: the next Apply asks again.
    _remember("" if pending else fp)
    _behind["why"] = ""
    return steps, warnings


# --------------------------------------------------------------------------
# cloudflared on this node

UNIT_TEXT = """# Written by haproxy-manager -- do not edit by hand.
[Unit]
Description=cloudflared for haproxy-manager (Cloudflare Tunnel)
After=network-online.target
Wants=network-online.target

[Service]
# The tunnel's token, in a file only root reads; systemd hands it over.
EnvironmentFile=%(env)s
ExecStart=%(bin)s --no-autoupdate tunnel run
Restart=always
RestartSec=5
DynamicUser=yes

[Install]
WantedBy=multi-user.target
"""


def _write(path, text, mode):
    """Write a file with its final mode from the first moment; say whether it changed."""
    try:
        if path.exists() and path.read_text() == text and (path.stat().st_mode & 0o777) == mode:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix="." + path.name)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


def write_files(cfg):
    """The token file cloudflared starts from, and under systemd its unit; say what changed."""
    if not configured(cfg):
        return []
    changed = []
    # Quoted as a shell would want it: the container's start script sources
    # this file as root, and systemd reads the same quoting. A token is
    # base64 today, which needs none, so the file is as it always was.
    if _write(CLOUDFLARED_ENV, "TUNNEL_TOKEN=%s\n" % shlex.quote(str(settings_of(cfg)["tunnel_token"])), 0o600):
        changed.append(CLOUDFLARED_ENV.name)
    # A container has no systemd: supervisord runs it there, from the image.
    if Path("/run/systemd/system").is_dir() or os.environ.get("HAM_CLOUDFLARED_UNIT_FILE"):
        if _write(CLOUDFLARED_UNIT_FILE, UNIT_TEXT % {"env": CLOUDFLARED_ENV, "bin": CLOUDFLARED_BIN}, 0o644):
            run(["systemctl", "daemon-reload"])
            changed.append(CLOUDFLARED_UNIT_FILE.name)
    return changed


def service_state():
    rc, out = run(["systemctl", "is-active", UNIT])
    return (out.splitlines() or ["unknown"])[0].strip() if out else "unknown"


def ensure_service(cfg, changed=False):
    """cloudflared running while Cloudflare is on, stopped while it is off:
    (step, warning), like the CrowdSec bouncer."""
    if configured(cfg):
        if not installed():
            ok, _out = ensure_installed(cfg)
            if not ok:
                return "", ("Cloudflare is on, but cloudflared is not installed on this node, so this node "
                            "carries none of the tunnel's traffic. Install it under Access > Cloudflare.")
            write_files(cfg)
        state = service_state()
        if changed and state in ("active", "activating"):
            rc, out = run(["systemctl", "restart", UNIT])
            step = "cloudflared restarted with its new token"
        elif state not in ("active", "activating"):
            run(["systemctl", "enable", "--quiet", UNIT])
            rc, out = run(["systemctl", "start", UNIT])
            step = "cloudflared started"
        else:
            return "", ""
        if rc != 0:
            return "", "cloudflared did not start: %s" % (out or "").strip()[:300]
        return step, ""
    if installed() and service_state() not in ("inactive", "unknown"):
        run(["systemctl", "stop", UNIT])
        run(["systemctl", "disable", "--quiet", UNIT])
        try:
            CLOUDFLARED_ENV.unlink()
        except OSError:
            pass
        return "cloudflared stopped: Cloudflare is off", ""
    return "", ""


TRIED = DATA_DIR / "cloudflared-install-tried"
RETRY_AFTER = 6 * 3600


def _tried_recently():
    try:
        return time.time() - float(TRIED.read_text().strip()) < RETRY_AFTER
    except (OSError, ValueError):
        return False


def ensure_installed(cfg):
    """Put cloudflared on a node that wants it and lacks it: (ok, message).
    Only once Cloudflare is switched on, and not retried at every Apply."""
    if installed():
        return True, "installed"
    if not configured(cfg):
        return False, "Cloudflare is off"
    if _tried_recently():
        return False, "an install failed recently; not retried yet"
    ok, out = install()
    if ok:
        TRIED.unlink(missing_ok=True)
        log.info("installed cloudflared")
    else:
        TRIED.parent.mkdir(parents=True, exist_ok=True)
        TRIED.write_text(str(time.time()))
        log.warning("cloudflared could not be installed: %s", out.strip()[-300:])
    return ok, out


def startup():
    """At startup: a node that boots with Cloudflare on brings its connector up."""
    try:
        cfg = load_config()
        if configured(cfg):
            ensure_installed(cfg)
            if installed():
                write_files(cfg)
                ensure_service(cfg)
    except Exception:
        log.exception("cloudflared at startup failed")


def summary(cfg):
    """For the status every page polls."""
    on = configured(cfg)
    return {"on": on, "installed": installed(),
            "connector": service_state() if on and installed() else ("missing" if on else "off")}


def _version():
    if not installed():
        return ""
    try:
        r = subprocess.run([str(CLOUDFLARED_BIN), "--version"], capture_output=True, text=True, timeout=5)
        m = re.search(r"(\d{4}\.\d+\.\d+)", r.stdout + r.stderr)
        return m.group(1) if m else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def status(cfg):
    s = settings_of(cfg)
    found = routes(cfg)
    return {"installed": installed(), "version": _version(),
            "service": service_state() if installed() else "missing",
            "configured": configured(cfg), "connected": connected(cfg),
            "tunnel_id": s.get("tunnel_id") or "", "hosts": sorted({r["host"] for r in found}),
            "in_step": _fingerprint(cfg) == _told(cfg) if (s.get("tunnel_id") and s.get("api_token")) else True,
            "last_error": _behind["why"]}


# --------------------------------------------------------------------------
# the API

@app.route("/api/cloudflare/settings", methods=["GET", "PUT"])
def api_cloudflare_settings():
    if request.method == "GET":
        cfg = load_config()
        s = settings_of(cfg)
        out = {k: v for k, v in s.items() if k not in ("api_token", "tunnel_token")}
        out["has_api_token"] = bool(s.get("api_token"))
        out["status"] = status(cfg)
        return jsonify(out)
    body = request.get_json(force=True, silent=True) or {}
    cur = settings_of(load_config())
    new = dict(cur)
    if "enabled" in body:
        new["enabled"] = bool(body["enabled"])
    for k in ("account_id", "tunnel_name"):
        if k in body:
            new[k] = (body.get(k) or "").strip() if isinstance(body.get(k), str) else ""
    # A secret left empty keeps the stored one: it cannot be read back.
    if isinstance(body.get("api_token"), str) and body["api_token"].strip():
        new["api_token"] = body["api_token"].strip()
    if "origin_port" in body:
        new["origin_port"] = body["origin_port"]
    new["tunnel_name"] = new.get("tunnel_name") or DEFAULT_CONFIG["cloudflare"]["tunnel_name"]
    try:
        check(new, cur)
        new["account_id"] = new["account_id"] or cur.get("account_id") or ""
        if new["enabled"] and not (new.get("tunnel_id") and new.get("tunnel_token")):
            # Asked of Cloudflare before the lock is taken: a slow answer must
            # not hold every other save behind it.
            new["account_id"], new["tunnel_id"], new["tunnel_token"] = connect(
                new["api_token"], new["account_id"], new["tunnel_name"])
    except (ValueError, CloudflareError) as e:
        return jsonify({"error": "These settings were not saved.\n\n" + str(e)}), 400
    with _lock:
        cfg = load_config()
        cfg["cloudflare"] = new
        clash = port_clash(cfg) if new["enabled"] else ""
        if clash:
            return jsonify({"error": "These settings were not saved.\n\n" + clash}), 400
        from . import apply   # here, not at the top: apply imports this module
        ok, message = apply.check_rendered(cfg)
        if not ok:
            return jsonify({"error": "These settings were not saved -- they do not produce a "
                                     "working configuration.\n\n" + message}), 400
        save_config(cfg)
        return jsonify({"ok": True, "status": status(cfg)})


@app.post("/api/cloudflare/test")
def api_cloudflare_test():
    """Ask Cloudflare what this token can see, and how the tunnel is doing."""
    body = request.get_json(force=True, silent=True) or {}
    cfg = load_config()
    s = settings_of(cfg)
    token = (body.get("api_token") or "").strip() if isinstance(body.get("api_token"), str) else ""
    token = token or (s.get("api_token") or "")
    if not token:
        return jsonify({"ok": False, "message": "an API token is needed first"})
    typed = (body.get("account_id") or "").strip() if isinstance(body.get("account_id"), str) else ""
    try:
        account = find_account(token, typed or s.get("account_id") or "")
        _call(token, "GET", "/accounts/%s/cfd_tunnel" % account, params={"is_deleted": "false", "per_page": 1})
        zones = _all(token, "/zones")
        parts = ["the token works: it can manage tunnels, and sees %d zone(s)%s"
                 % (len(zones), (" (" + ", ".join(z["name"] for z in zones[:5])
                                 + (", ..." if len(zones) > 5 else "") + ")") if zones else "")]
        try:
            _call(token, "GET", "/accounts/%s/access/apps" % account, params={"per_page": 1})
        except CloudflareError as e:
            parts.append("Access did not answer it (%s) -- open Zero Trust once in the dashboard, and "
                         "check the token has Access: Apps and Policies" % e)
        if zones:
            # Zone WAF can be given for some zones and not others, so each is
            # asked; a token that sees very many is asked about the first 25.
            asked = zones[:25]
            denied = []
            for z in asked:
                try:
                    _entrypoint(token, z["id"])
                except CloudflareError:
                    denied.append(z["name"])
            if not denied:
                parts.append("it may manage Firewall rules, so services can be limited to countries")
            elif len(denied) == len(asked):
                parts.append("it may not manage Firewall rules in any zone: limiting a service to countries "
                             "needs Zone WAF: Edit as well")
            else:
                parts.append("it may manage Firewall rules in %d of %d zone(s), so services in those can be "
                             "limited to countries; not in %s" % (len(asked) - len(denied), len(asked),
                                                                  ", ".join(denied[:3]) + (", ..." if len(denied) > 3 else "")))
        if s.get("tunnel_id") and account == s.get("account_id"):
            t = _call(token, "GET", "/accounts/%s/cfd_tunnel/%s" % (account, s["tunnel_id"])).get("result") or {}
            parts.append("tunnel \"%s\" is %s, with %d connection(s)"
                         % (t.get("name") or s.get("tunnel_name"), t.get("status") or "unknown",
                            len(t.get("connections") or [])))
        if not zones:
            return jsonify({"ok": False, "message": "the token sees no zone, so no DNS record can be made: "
                                                    "give it Zone Read and DNS Edit on the zone"})
    except CloudflareError as e:
        return jsonify({"ok": False, "message": str(e)})
    return jsonify({"ok": True, "message": "; ".join(parts)})


@app.post("/api/cloudflare/sync")
def api_cloudflare_sync():
    """Tell Cloudflare again, whether or not anything changed here: for a
    record or an application somebody removed in the dashboard."""
    cfg = load_config()
    if not connected(cfg):
        return jsonify({"ok": False, "error": "not connected to a tunnel yet"}), 400
    steps, warnings = reconcile(cfg, force=True)
    cfg = load_config()                                  # what was remembered is in it now
    return jsonify({"ok": not warnings, "steps": steps, "warnings": warnings, "status": status(cfg),
                    "message": "\n".join(steps + warnings) or "Cloudflare already holds exactly this"})


def _tunnel_gone(token, account, tid):
    """Is the tunnel no longer in Cloudflare: deleted in the dashboard, or
    named by a configuration put back from before a Disconnect."""
    try:
        t = _call(token, "GET", "/accounts/%s/cfd_tunnel/%s" % (account, tid)).get("result") or {}
    except CloudflareError as e:
        if "not found" in str(e).lower():
            return True
        raise
    return bool(t.get("deleted_at"))


@app.post("/api/cloudflare/disconnect")
def api_cloudflare_disconnect():
    """Take everything made here out of Cloudflare, the tunnel last, and forget it.

    Switched off and applied first, so cloudflared stops here and on the
    other nodes: Cloudflare will not delete a tunnel that is connected. With
    {"forget": true} nothing is asked of Cloudflare: the way out when it will
    not answer, or the tunnel is already gone there.

    The lock is held only to change the configuration, never across a
    conversation with Cloudflare.
    """
    body = request.get_json(force=True, silent=True) or {}
    forget = bool(body.get("forget"))
    from . import apply   # here, not at the top: apply imports this module
    with _lock:
        cfg = load_config()
        s = settings_of(cfg)
        if not s.get("tunnel_id"):
            return jsonify({"ok": False, "error": "not connected to a tunnel"}), 400
        # What is published, read as if it were on: a Disconnect that failed
        # halfway left it switched off, and is tried again from there.
        asked = dict(cfg, cloudflare=dict(s, enabled=True))
        hosts = sorted({r["host"] for r in routes(asked) if r["valid"]})
        s["enabled"] = False
        cfg["cloudflare"] = s
        save_config(cfg)
    token, account, tid = (s.get("api_token") or "").strip(), s.get("account_id"), s["tunnel_id"]
    res = apply.do_apply()
    steps = [x for x in res.get("steps") or [] if x.startswith(("cloudflare", "cloudflared"))]
    if not forget:
        try:
            if _tunnel_gone(token, account, tid):
                # No routes to read what was published from: what this
                # configuration published is cleared, by name.
                target = "%s.cfargotunnel.com" % tid
                zones = _all(token, "/zones") if hosts else []
                for host in hosts:
                    steps += _drop_dns(token, zones, host, target)
                for domain, a in _apps_for(token, account, set(hosts))[0].items():
                    _call(token, "DELETE", "/accounts/%s/access/apps/%s" % (account, a["id"]))
                    steps.append("cloudflare: Access application for %s removed" % domain)
                more, _unmet, later = _firewall(token, zones, [], hosts)
                steps += more + later()[0]   # no routes to wait for: the rules go now
                steps.append("cloudflare: the tunnel was already gone there")
            else:
                more, _warnings, _pending = _reconcile(load_config(), also=hosts)   # off: nothing is wanted
                steps += more
                # Cloudflare refuses to delete a tunnel that still has connections.
                _call(token, "DELETE", "/accounts/%s/cfd_tunnel/%s/connections" % (account, tid))
                _call(token, "DELETE", "/accounts/%s/cfd_tunnel/%s" % (account, tid))
                steps.append("cloudflare: tunnel \"%s\" deleted" % s.get("tunnel_name"))
        except CloudflareError as e:
            # "error" is what the interface shows for an answer that is not a success.
            return jsonify({"ok": False, "steps": steps, "status": status(load_config()),
                            "error": "Cloudflare is switched off here, but the tunnel was not removed "
                                     "there: %s. Try Disconnect again, or forget the tunnel on this "
                                     "installation and remove what is left in Cloudflare by hand." % e}), 502
    with _lock:
        cfg = load_config()
        s = settings_of(cfg)
        s["tunnel_id"], s["tunnel_token"], s["told"] = "", "", ""
        cfg["cloudflare"] = s
        save_config(cfg)
    apply.do_apply()                       # the other nodes forget it too
    if forget:
        steps.append("cloudflare: the tunnel is forgotten here; nothing was asked of Cloudflare")
    cfg = load_config()
    return jsonify({"ok": True, "steps": steps, "status": status(cfg), "message": "\n".join(steps)})


# Cloudflare's own package repository. Its key is fetched over HTTPS and held
# to this fingerprint, so a wrong key installs nothing -- and so does a file
# holding another key beside the right one, which a check for the one
# fingerprint among many would let through.
REPO_KEY_URL = "https://pkg.cloudflare.com/cloudflare-main.gpg"
REPO_KEY_FPR = "CC94B39C77AE7342A68B89628A682D308D4E5E73"
# The fingerprints of the keys in a keyring listing, one a line: the fpr
# record that follows each pub record. A subkey's fpr follows its sub record,
# and is not a key of its own.
KEY_FPRS = "awk -F: '$1==\"pub\"{p=1;next} $1==\"fpr\"&&p{print $10;p=0}'"
APT_INSTALL = """set -e
export DEBIAN_FRONTEND=noninteractive
command -v gpg >/dev/null || apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends gnupg
mkdir -p /usr/share/keyrings
curl -fsSL --max-time 60 %(key)s -o /usr/share/keyrings/cloudflare-main.gpg
[ "$(gpg --show-keys --with-colons /usr/share/keyrings/cloudflare-main.gpg | %(fprs)s)" = "%(fpr)s" ] || { echo "Cloudflare's key does not match the expected fingerprint"; rm -f /usr/share/keyrings/cloudflare-main.gpg; exit 1; }
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' > /etc/apt/sources.list.d/cloudflared.list
apt-get -o DPkg::Lock::Timeout=120 -o Acquire::http::Timeout=30 -o Acquire::Retries=2 update -q
apt-get -o DPkg::Lock::Timeout=120 -o Acquire::http::Timeout=30 -o Acquire::Retries=2 install -y --no-install-recommends cloudflared
""" % {"key": REPO_KEY_URL, "fpr": REPO_KEY_FPR, "fprs": KEY_FPRS}
RPM_INSTALL = """set -e
curl -fsSL --max-time 60 https://pkg.cloudflare.com/cloudflared.repo -o /etc/yum.repos.d/cloudflared.repo
if command -v dnf >/dev/null; then dnf install -y cloudflared; else yum install -y cloudflared; fi
"""


def install():
    """Put cloudflared on this node from Cloudflare's repository: (ok, output)."""
    if installed():
        return True, "cloudflared is already installed"
    if shutil.which("apt-get"):
        script = APT_INSTALL
    elif shutil.which("dnf") or shutil.which("yum"):
        script = RPM_INSTALL
    else:
        return False, ("this node has neither apt-get nor dnf; install cloudflared from "
                       "pkg.cloudflare.com by hand")
    rc, out = run_script(script, timeout=900)
    if rc != 0 or not installed():
        return False, "the install did not finish:\n" + (out or "").strip()[-1500:]
    return True, "installed; it starts when Cloudflare is on and Apply runs"


@app.post("/api/cloudflare/install")
def api_cloudflare_install():
    """Install cloudflared on this node, from Cloudflare's repository."""
    ok, message = install()
    if ok:
        TRIED.unlink(missing_ok=True)
    return jsonify({"ok": ok, "message": message, "error": "" if ok else message,
                    "status": status(load_config())}), (200 if ok else 500)
