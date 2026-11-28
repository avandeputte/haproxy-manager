#!/usr/bin/env python3
"""Cloudflare: a service limited to countries, by a Firewall custom rule.

    HAM_DATA_DIR=/tmp/x python3 tools/test-cloudflare-countries.py

Checked against a Cloudflare that lives in this file: the codes a service
takes, the rule each zone is given and what it says, the zone's own rules left
as they are, the rule written before the route, changed and removed with the
services, a token without the right to it, and Disconnect.

And what the rule must mirror: the listener takes the first of its rules that
matches, so a wildcard placed before a name takes that name, and the rule says
so. A service whose limit could not be set -- a zone the token does not see,
a right it lacks, a clause too long -- is not published rather than published
open; too many services for one rule become several; a path condition with
two values is two routes; a control character never reaches Cloudflare; and
taking a limit away, the route goes before the rule.
"""
import os
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-cfc-"))
D = os.environ["HAM_DATA_DIR"]
os.environ["HAM_CERT_DIR"] = os.path.join(D, "certs")
os.environ["HAM_ERROR_DIR"] = os.path.join(D, "error-pages")
os.environ["HAM_CLOUDFLARED_BIN"] = os.path.join(D, "cloudflared-bin")
os.environ["HAM_CLOUDFLARED_ENV"] = os.path.join(D, "run", "cloudflared.env")
os.environ["HAM_CLOUDFLARED_UNIT_FILE"] = os.path.join(D, "units", "ham-cloudflared.service")
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import apply, cloudflare   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


class Answer:
    def __init__(self, result=None, status=200, errors=None, pages=1):
        self.status_code = status
        self._body = {"success": not errors, "errors": errors or [], "result": result,
                      "result_info": {"total_pages": pages}}

    def json(self):
        return self._body


ENTRY = "/rulesets/phases/http_request_firewall_custom/entrypoint"


class Cloudflare:
    """Tunnels, DNS, Access, and the zones' custom rules, with a memory."""
    ACCOUNT = "a" * 32

    def __init__(self):
        self.tunnels, self.config, self.records, self.apps, self.calls = {}, {}, {}, {}, []
        self.rulesets = {}                  # zone id -> {"id", "rules"}
        self.waf_denied = False
        self.zones = [{"id": "z1", "name": "example.com"}, {"id": "z2", "name": "dev.example.com"}]
        self.n = 0

    def _id(self, prefix):
        self.n += 1
        return "%s%04d" % (prefix, self.n)

    def request(self, method, url, json=None, params=None, timeout=None, headers=None):
        path = url.split("/client/v4", 1)[1]
        self.calls.append((method, path, json))
        if headers.get("Authorization") != "Bearer good-token":
            return Answer(status=403, errors=[{"code": 9109, "message": "Invalid access token"}])
        params = params or {}
        acct = "/accounts/%s" % self.ACCOUNT
        m = re.match
        if path == "/accounts":
            return Answer([{"id": self.ACCOUNT}])
        if path == "/zones":
            return Answer(self.zones)
        x = m(r"^/zones/([^/]+)/rulesets(.*)$", path)
        if x:
            zone, rest = x.groups()
            if self.waf_denied is True or self.waf_denied == zone:
                return Answer(status=403, errors=[{"code": 10000, "message": "Authentication error"}])
            if rest == ENTRY[len("/rulesets"):]:
                if method == "GET":
                    if zone not in self.rulesets:
                        return Answer(status=404, errors=[{"code": 10003, "message": "could not find entrypoint ruleset"}])
                    return Answer(self.rulesets[zone])
                if method == "PUT":
                    rs = {"id": "rs-" + zone, "rules": [dict(r, id=self._id("rule")) for r in json["rules"]]}
                    self.rulesets[zone] = rs
                    return Answer(rs)
            y = m(r"^/([^/]+)/rules(?:/([^/]+))?$", rest)
            if y and zone in self.rulesets and y.group(1) == self.rulesets[zone]["id"]:
                rs, rid = self.rulesets[zone], y.group(2)
                if method == "POST" and not rid:
                    rs["rules"].append(dict(json, id=self._id("rule")))
                    return Answer(rs)
                if method == "PATCH" and rid:
                    rs["rules"] = [dict(json, id=rid) if r["id"] == rid else r for r in rs["rules"]]
                    return Answer(rs)
                if method == "DELETE" and rid:
                    rs["rules"] = [r for r in rs["rules"] if r["id"] != rid]
                    return Answer(rs)
        if path == acct + "/cfd_tunnel" and method == "GET":
            return Answer([t for t in self.tunnels.values() if params.get("name") in (None, t["name"])])
        if path == acct + "/cfd_tunnel" and method == "POST":
            t = {"id": "11111111-2222-3333-4444-%012d" % (len(self.tunnels) + 1), "name": json["name"],
                 "config_src": json["config_src"], "status": "inactive", "connections": []}
            self.tunnels[t["id"]] = t
            return Answer(t)
        x = m(r"^%s/cfd_tunnel/([^/]+)(/token|/configurations|/connections)?$" % acct, path)
        if x:
            tid, what = x.group(1), x.group(2)
            if tid not in self.tunnels:
                return Answer(status=404, errors=[{"code": 1003, "message": "tunnel not found"}])
            if what == "/token":
                return Answer("token-for-" + tid)
            if what == "/configurations":
                if method == "PUT":
                    self.config[tid] = json["config"]
                return Answer({"tunnel_id": tid, "config": self.config.get(tid)})
            if what == "/connections":
                return Answer(None)
            if method == "DELETE":
                del self.tunnels[tid]
                return Answer(None)
            return Answer(self.tunnels[tid])
        x = m(r"^/zones/([^/]+)/dns_records(?:/([^/]+))?$", path)
        if x:
            zone, rid = x.groups()
            if method == "GET":
                return Answer([r for r in self.records.values() if r["zone"] == zone
                               and params.get("name") in (None, r["name"]) and params.get("type") in (None, r["type"])])
            if method == "POST":
                r = dict(json, id=self._id("rec"), zone=zone)
                self.records[r["id"]] = r
                return Answer(r)
            if method == "DELETE":
                del self.records[rid]
                return Answer({"id": rid})
        x = m(r"^%s/access/apps(?:/([^/]+))?(?:/policies(?:/([^/]+))?)?$" % acct, path)
        if x:
            aid, pid = x.groups()
            if aid is None and method == "GET":
                return Answer(list(self.apps.values()))
            if aid is None and method == "POST":
                a = dict(json, id=self._id("app"), policies=[])
                self.apps[a["id"]] = a
                return Answer(a)
            a = self.apps[aid]
            if path.endswith("/policies") and method == "POST":
                p = dict(json, id=self._id("pol"))
                a["policies"].append(p)
                return Answer(p)
            if method == "DELETE":
                del self.apps[aid]
                return Answer({"id": aid})
        return Answer(status=404, errors=[{"code": 7003, "message": "no route for %s %s" % (method, path)}])


cf = Cloudflare()
cloudflare._requests = cf

ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "cfc-key"
save_config(cfg)
H = {"X-API-Key": "cfc-key"}


def publish(url, want=200, **kw):
    body = dict({"url": url, "target": "10.0.0.5:80", "certificate": False, "http_redirect": False,
                 "dry_run": False}, **kw)
    r = client.post("/api/wizard/publish", headers=H, json=body)
    ok(r.status_code == want, "publish %s -> %d %s" % (url, r.status_code, ((r.get_json() or {}).get("error") or "")[:110]))
    return r.get_json() or {}


def service(name):
    return next(s for s in client.get("/api/services", headers=H).get_json() if s.get("pool") == name)


def tell(force=False):
    steps, warnings = cloudflare.reconcile(load_config(), force=force)
    return steps, warnings


def ours(zone):
    return [r for r in (cf.rulesets.get(zone) or {}).get("rules", [])
            if re.match(r"^haproxy-manager-countries(-\d+)?$", r.get("ref") or "")]


def hosts_routed():
    return [i.get("hostname") for i in cf.config[tid]["ingress"] if i.get("hostname")]


def changes():
    """The calls that changed something, in order: (method, what)."""
    return [(meth, "rule" if "/rulesets" in p else "route" if p.endswith("/configurations")
             else "dns" if "/dns_records" in p else "access" if "/access/" in p else p)
            for meth, p, _ in cf.calls if meth != "GET"]


# ---- the codes ---------------------------------------------------------------------------------
ok(cloudflare.parse_countries("us, ca\nGB us") == (["US", "CA", "GB"], []), "codes are upper-cased, each once, in order")
ok(cloudflare.check_countries(" us  ") == "US", "the stored form is the codes, space-separated")
for bad, why in (("UK", "did you mean GB"), ("USA", "USA"), ("U$", "U$")):
    try:
        cloudflare.check_countries(bad)
        ok(False, "%r is refused" % bad)
    except ValueError as e:
        ok(why in str(e), "%r is refused, saying %r" % (bad, why))
ok(cloudflare.check_countries("T1 XX XK") == "T1 XX XK", "Cloudflare's own Tor, unknown and Kosovo codes are taken")
ok(cloudflare._route_countries("QQ") == ["ZZ"] and cloudflare._route_countries("US QQ") == ["US"],
   "a stored list with no code it knows admits nobody; one with some keeps those")

# ---- connecting, and services ---------------------------------------------------------------------
r = client.put("/api/cloudflare/settings", headers=H, json={"enabled": True, "api_token": "good-token"})
ok(r.status_code == 200, "connected to a tunnel")
tid = load_config()["cloudflare"]["tunnel_id"]

res = publish("http://shop.example.com", name="shop",
              cloudflare={"enabled": True, "countries": "us"})
ok(any("limited to US" in w and "Through Cloudflare only" in w for w in res.get("warnings") or []),
   "limited to countries but reachable on its own ports: the publish says so")
ok(service("shop")["cloudflare"]["countries"] == "US", "the service says which countries")
res = publish("http://shop.example.com", name="shop", service_id=service("shop")["id"],
              cloudflare={"enabled": True, "countries": "us", "only": True})
ok(not any("limited to" in w for w in res.get("warnings") or []), "with Through Cloudflare only, nothing to warn about")
publish("http://shop.example.com", 400, name="shop", service_id=service("shop")["id"],
        cloudflare={"enabled": True, "countries": "UK"})
pool = next(b for b in load_config()["haproxy"]["backends"] if b["name"] == "shop")
r = client.put("/api/haproxy/backends/%s" % pool["id"], headers=H, json=dict(pool, cf_countries="usa"))
ok(r.status_code == 400 and "country code" in (r.get_json() or {}).get("error", ""),
   "the Backend Pools editor refuses a code that is not one too")
publish("http://plain.example.com", name="plain", cloudflare={"enabled": True})

# ---- the rule: made before the route, in a zone that had none ----------------------------------------
cf.calls.clear()
steps, warnings = tell()
ok("cloudflare: country rule for example.com" in steps and not warnings, "Apply makes the zone's country rule: %s" % steps)
rule = ours("z1")
ok(len(rule) == 1 and rule[0]["action"] == "block" and rule[0]["enabled"] is True
   and rule[0]["expression"] == '(http.host eq "shop.example.com" and not ip.src.country in {"US"})',
   "one rule, blocking shop.example.com to anyone outside US: %s" % (rule[0]["expression"] if rule else None))
writes = [(meth, p) for meth, p, _ in cf.calls if meth != "GET"]
first_rule = next(i for i, (meth, p) in enumerate(writes) if "/rulesets" in p)
first_route = next(i for i, (meth, p) in enumerate(writes) if p.endswith("/configurations"))
ok(first_rule < first_route, "the rule is written before the route: never reachable from elsewhere for a moment")
ok("z2" not in cf.rulesets, "a zone with nothing limited is given nothing")
cf.calls.clear()
tell()
ok(not cf.calls, "unchanged, nothing is asked")

# ---- the zone's own rules stay ------------------------------------------------------------------------
cf.rulesets["z1"]["rules"].insert(0, {"id": "theirs", "description": "block bad bots", "expression": "cf.client.bot",
                                      "action": "block", "enabled": True})
publish("http://shop.example.com", name="shop", service_id=service("shop")["id"],
        cloudflare={"enabled": True, "countries": "US CA", "only": True})
cf.calls.clear()
steps, _w = tell()
ok("cloudflare: country rule for example.com updated" in steps
   and [meth for meth, p, _ in cf.calls if "/rulesets" in p and meth != "GET"] == ["PATCH", "PATCH"]
   and len(ours("z1")) == 1 and ours("z1")[0]["ref"] == cloudflare.WAF_REF,
   "a changed list changes this app's rule, by itself: widened to old and new, then narrowed to the new")
ok(cf.rulesets["z1"]["rules"][0] == {"id": "theirs", "description": "block bad bots", "expression": "cf.client.bot",
                                     "action": "block", "enabled": True},
   "the zone's own rule is untouched, and still first")
ok('in {"US" "CA"}' in ours("z1")[0]["expression"] and 'in {"US"}' not in ours("z1")[0]["expression"],
   "and the rule names both countries")

# ---- paths, deeper zones -------------------------------------------------------------------------------
publish("http://shop.example.com/admin", name="shopadmin", cloudflare={"enabled": True, "countries": "BE", "only": True})
publish("http://api.dev.example.com", name="api", cloudflare={"enabled": True, "countries": "US", "only": True})
steps, _w = tell()
expr = ours("z1")[0]["expression"]
ok('(http.host eq "shop.example.com" and not starts_with(http.request.uri.path, "/admin") '
   'and not ip.src.country in {"US" "CA"})' in expr
   and '(http.host eq "shop.example.com" and starts_with(http.request.uri.path, "/admin") '
       'and not ip.src.country in {"BE"})' in expr,
   "two services on one host: each its path, the shorter less the longer")
ok(len(ours("z2")) == 1 and "api.dev.example.com" in ours("z2")[0]["expression"]
   and "api.dev" not in expr, "a host in a deeper zone gets its rule in that zone, and only there")
ok(len(cf.rulesets["z1"]["rules"]) == 2, "still one rule of this app's in the zone, beside the zone's own")

# a wildcard, and the names it takes in: what the listener does, in the order
# of its rules, not what a reader of the names would expect
def route(host, path="", countries=(), port=7800):
    return {"host": host, "path": path, "valid": True, "countries": list(countries), "port": port}


wild, shop, xp = route("*.example.com", countries=["US"]), route("shop.example.com"), route("x.example.com", "/p")
e = cloudflare.firewall_expressions([shop, xp, wild], cf.zones)["z1"][1]
ok(e == ['(http.host wildcard "*.example.com" and not http.host eq "shop.example.com" and not '
         '(http.host eq "x.example.com" and starts_with(http.request.uri.path, "/p")) and not ip.src.country in {"US"})'],
   "the names before a wildcard take theirs, and the wildcard's rule leaves them out: %s" % e)
e = cloudflare.firewall_expressions([wild, shop, xp], cf.zones)["z1"][1]
ok(e == ['(http.host wildcard "*.example.com" and not ip.src.country in {"US"})'],
   "a wildcard before them takes them too -- as HAProxy does -- so its rule covers them: %s" % e)
ok(cloudflare.firewall_expressions([wild, route("shop.example.com", countries=["BE"])], cf.zones)["z1"][1]
   == ['(http.host wildcard "*.example.com" and not ip.src.country in {"US"})'],
   "and a limited name it takes whole gets no clause of its own: nothing reaches its pool")
ok(cloudflare.firewall_expressions([route("shop.example.com", countries=["BE"], port=7801), wild], cf.zones)["z1"][1]
   == ['(http.host eq "shop.example.com" and not ip.src.country in {"BE"}) or '
       '(http.host wildcard "*.example.com" and not ip.src.country in {"US"})'],
   "a rule on another listener takes nothing from it")
deep = route("a.b.example.com", countries=["BE"])
ok(cloudflare.firewall_expressions([wild, deep], cf.zones)["z1"][1]
   == ['(http.host wildcard "*.example.com" and not http.host eq "a.b.example.com" and not ip.src.country in {"US"}) or '
       '(http.host eq "a.b.example.com" and not ip.src.country in {"BE"})'],
   "a deeper name is not the wildcard's in HAProxy, so it is taken out of Cloudflare's wider wildcard whatever the order")
ok(cloudflare.firewall_expressions([route("shop.example.com", "/api", countries=["CA"]), route("shop.example.com", countries=["US"])],
                                   cf.zones)["z1"][1]
   == ['(http.host eq "shop.example.com" and starts_with(http.request.uri.path, "/api") and not ip.src.country in {"CA"}) or '
       '(http.host eq "shop.example.com" and not starts_with(http.request.uri.path, "/api") and not ip.src.country in {"US"})'],
   "a path before the host-only rule is taken out of the latter")
ok(cloudflare.firewall_expressions([route("shop.example.com", countries=["US"]), route("shop.example.com", "/api", countries=["CA"])],
                                   cf.zones)["z1"][1]
   == ['(http.host eq "shop.example.com" and not ip.src.country in {"US"})'],
   "a path after it never fires, and gets no clause")
ok(cloudflare._q('a"b\\c') == '"a\\"b\\\\c"', "a quote or backslash in a path cannot end the string")
ok(cloudflare._q("/a\x01b\x7f\n") == '"/ab"', "a control character is dropped, as the renderer drops it: Cloudflare would refuse the whole rule")

# ---- removed with the services -------------------------------------------------------------------------
publish("http://api.dev.example.com", name="api", service_id=service("api")["id"],
        cloudflare={"enabled": True, "countries": "", "only": True})
steps, _w = tell()
ok("cloudflare: country rule for dev.example.com removed" in steps and not ours("z2"),
   "the last limited service in a zone gone, the rule goes")
for name in ("shop", "shopadmin"):
    publish("http://%s" % ("shop.example.com" + ("/admin" if name == "shopadmin" else "")), name=name,
            service_id=service(name)["id"], cloudflare={"enabled": False})
steps, _w = tell()
ok("cloudflare: country rule for example.com removed" in steps and not ours("z1")
   and [r["id"] for r in cf.rulesets["z1"]["rules"]] == ["theirs"],
   "unpublished, this app's rule is removed and the zone's own stays")

# ---- a token without the right -------------------------------------------------------------------------
cf.waf_denied = True
publish("http://plain.example.com", name="plain", service_id=service("plain")["id"],
        cloudflare={"enabled": True, "access": "public"})
cf.calls.clear()
steps, warnings = tell(force=True)
ok(not warnings, "nothing limited: a token without Zone WAF changes nothing for anyone")
ok("plain.example.com" in hosts_routed() and any(r["name"] == "plain.example.com" for r in cf.records.values()),
   "published, with its route and its record")
publish("http://plain.example.com", name="plain", service_id=service("plain")["id"],
        cloudflare={"enabled": True, "countries": "US", "only": True})
cf.calls.clear()
steps, warnings = tell()
ok(any("Zone WAF: Edit" in w and "plain.example.com is not published" in w and "\"plain\" is limited" in w for w in warnings)
   and load_config()["cloudflare"]["told"] != cloudflare._fingerprint(load_config()),
   "a limit it may not write is a warning naming the service and the right it needs, asked again at the next Apply")
ok("plain.example.com" not in hosts_routed() and not any(r["name"] == "plain.example.com" for r in cf.records.values()),
   "and the service is not published: a limit on paper alone would leave it open to the world, so its route and record go")
steps, warnings = tell(force=True)
ok("plain.example.com" not in hosts_routed() and any("not published" in w for w in warnings),
   "told again, it stays unpublished, and says so again")
r = client.post("/api/cloudflare/test", headers=H, json={}).get_json()
ok("may not manage Firewall rules in any zone" in r["message"] and "Zone WAF: Edit" in r["message"],
   "and the test says the same")
cf.waf_denied = "z2"
r = client.post("/api/cloudflare/test", headers=H, json={}).get_json()
ok("in 1 of 2 zone(s)" in r["message"] and "not in dev.example.com" in r["message"],
   "a token with the right in some zones only is told which: %s" % r["message"][-90:])
cf.waf_denied = False
cf.calls.clear()
steps, warnings = tell()
ok("cloudflare: country rule for example.com" in steps and not warnings, "given the right, the next Apply writes it")
ok("plain.example.com" in hosts_routed() and any(r["name"] == "plain.example.com" for r in cf.records.values()),
   "and publishes the service again")
w = changes()
ok(w.index(("POST", "rule")) < w.index(("PUT", "route")) < w.index(("POST", "dns")),
   "the rule first, then the route, then the name: %s" % w)
r = client.post("/api/cloudflare/test", headers=H, json={}).get_json()
ok("may manage Firewall rules" in r["message"], "and the test says it may")

# ---- a zone the token does not see ------------------------------------------------------------------------
publish("http://far.example.org", name="far", cloudflare={"enabled": True, "countries": "US", "only": True})
steps, warnings = tell()
ok(any("far.example.org is not published" in w and "not one this API token sees" in w for w in warnings)
   and "far.example.org" not in hosts_routed(),
   "a limited service in a zone the token cannot see is not published, and the warning says why")
publish("http://far.example.org", name="far", service_id=service("far")["id"], cloudflare={"enabled": True, "only": True})
steps, warnings = tell()
ok("far.example.org" in hosts_routed() and any("no DNS record" in w for w in warnings),
   "unlimited, the same service is routed, and only its record is missing")
publish("http://far.example.org", name="far", service_id=service("far")["id"], cloudflare={"enabled": False})
tell()

# ---- too long for Cloudflare ----------------------------------------------------------------------------
many = [route("h%03d.example.com" % i, countries=["US"]) for i in range(80)]
_name, exprs, left = cloudflare.firewall_expressions(many, cf.zones)["z1"]
ok(len(exprs) > 1 and all(len(e) <= cloudflare.WAF_MAX_EXPRESSION for e in exprs) and not left
   and sum(len(cloudflare._clauses(e)) for e in exprs) == 80,
   "eighty limited services are more than one rule holds, so they are packed into %d, every service in one" % len(exprs))
cf.calls.clear()
s2, unmet, later = cloudflare._firewall("good-token", cf.zones, many, [])
later()
refs = sorted(r["ref"] for r in ours("z1"))
ok(not unmet and len(ours("z1")) == len(exprs)
   and all(cloudflare._WAF_REF.match(r) for r in refs) and len(set(refs)) == len(refs),
   "written as that many rules, each with its own ref: %s" % refs)
ok([x["id"] for x in cf.rulesets["z1"]["rules"]][0] == "theirs", "the zone's own rule still first")
s3, unmet3, later3 = cloudflare._firewall("good-token", cf.zones, [route("plain.example.com", countries=["US"])], [])
later3()
ok(len(ours("z1")) == 1 and not unmet3, "back to one service, the extra rules are removed and one remains")
huge = route("long.example.com", "/" + "p" * cloudflare.WAF_MAX_EXPRESSION, countries=["US"])
_name, exprs, left = cloudflare.firewall_expressions([huge, route("plain.example.com", countries=["US"])], cf.zones)["z1"]
ok(left == [huge] and len(exprs) == 1, "a service whose clause alone is too long is left out, by itself")
s4, unmet4, later4 = cloudflare._firewall("good-token", cf.zones, [huge, route("plain.example.com", countries=["US"])], [])
ok([r["host"] for r, _why in unmet4] == ["long.example.com"] and "more than Cloudflare's" in unmet4[0][1],
   "and named as one whose limit is not set, so it is not published")

# ---- a path condition that lists alternatives ------------------------------------------------------------------
publish("http://shop.example.com/admin", name="shopadmin", service_id=service("shopadmin")["id"],
        cloudflare={"enabled": True, "countries": "BE", "only": True, "access": "allow", "allow": "a@example.com"})
c = load_config()
pc = next(x for x in c["haproxy"]["conditions"] if x.get("type") == "path_starts_with" and x.get("value") == "/admin")
pc["value"] = "/admin /manage"
save_config(c)
paths = sorted(r["path"] for r in cloudflare.routes(load_config()) if r["host"] == "shop.example.com")
ok(paths == ["/admin", "/manage"], "a path condition with two values is two routes, as HAProxy takes either: %s" % paths)
tell()
expr = ours("z1")[0]["expression"]
ok('starts_with(http.request.uri.path, "/admin") and not ip.src.country in {"BE"}' in expr
   and 'starts_with(http.request.uri.path, "/manage") and not ip.src.country in {"BE"}' in expr
   and '"/admin /manage"' not in expr,
   "each is limited on its own; neither is a path nobody asks for")
ok(sorted(a["domain"] for a in cf.apps.values()) == ["shop.example.com/admin", "shop.example.com/manage"],
   "and each has its sign-in")

# ---- a control character in a path ----------------------------------------------------------------------------
r = publish("http://shop.example.com/ad\x01min", 400, name="shopadmin", service_id=service("shopadmin")["id"],
            cloudflare={"enabled": True, "countries": "BE", "only": True})
ok("control character" in (r.get("error") or "") and "shopadmin" in (r.get("error") or ""),
   "the publish wizard refuses it, naming the service")
try:
    cloudflare.check_values(["shop.example.com", "/a\x7fb"], "shop")
    ok(False, "check_values refuses a DEL")
except ValueError as e:
    ok("\"shop\"" in str(e), "check_values refuses a DEL, naming the service")
c = load_config()
pc = next(x for x in c["haproxy"]["conditions"] if x.get("type") == "path_starts_with" and x.get("value") == "/admin /manage")
pc["value"] = "/adm\x01in"
save_config(c)
ok([r["path"] for r in cloudflare.routes(load_config()) if r["host"] == "shop.example.com"] == ["/admin"],
   "one stored anyway is routed by what HAProxy will see, the character dropped")
steps, warnings = tell()
ok(not warnings and 'starts_with(http.request.uri.path, "/admin")' in ours("z1")[0]["expression"]
   and "\x01" not in ours("z1")[0]["expression"],
   "so Cloudflare is told a rule it takes, and no other service waits on this one")

# ---- taking a limit away: the route first, then the rule -------------------------------------------------------
publish("http://shop.example.com/admin", name="shopadmin", service_id=service("shopadmin")["id"], cloudflare={"enabled": False})
cf.calls.clear()
steps, warnings = tell()
w = changes()
ok(not warnings and ("PUT", "route") in w and ("PATCH", "rule") in w and w.index(("PUT", "route")) < w.index(("PATCH", "rule")),
   "unpublished, the route goes before the rule that limited it is narrowed: %s" % w)
ok("shop.example.com" not in hosts_routed() and "shop.example.com" not in ours("z1")[0]["expression"]
   and "plain.example.com" in ours("z1")[0]["expression"],
   "and the rule then names the one service still limited")
publish("http://plain.example.com", name="plain", service_id=service("plain")["id"], cloudflare={"enabled": False})
cf.calls.clear()
steps, warnings = tell()
w = changes()
ok(not ours("z1") and w.index(("PUT", "route")) < w.index(("DELETE", "rule")),
   "the last one unpublished, the route goes before the rule is removed: %s" % w)
publish("http://plain.example.com", name="plain", service_id=service("plain")["id"],
        cloudflare={"enabled": True, "countries": "US", "only": True})
tell()

# ---- an older configuration asks nothing new --------------------------------------------------------------
lens = {r[0]: len(r) for r in cloudflare.desired(load_config())["routes"]}
ok(lens == {"api.dev.example.com": 6, "plain.example.com": 7},
   "a route with no countries is described as before 2.5, so upgrading asks nothing of Cloudflare; "
   "one with countries carries them, so a change to them is told: %s" % lens)

# ---- Disconnect ---------------------------------------------------------------------------------------------
apply.do_apply = lambda *a, **k: {"ok": True, "steps": []}
r = client.post("/api/cloudflare/disconnect", headers=H, json={})
ok(r.status_code == 200 and not ours("z1") and [x["id"] for x in cf.rulesets["z1"]["rules"]] == ["theirs"],
   "Disconnect removes the country rule with the rest, and the zone's own stays")

print("\n%d failed" % len(fails) if fails else "\nonly from where you said")
sys.exit(1 if fails else 0)
