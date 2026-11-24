#!/usr/bin/env python3
"""Cloudflare: a service limited to countries, by a Firewall custom rule.

    HAM_DATA_DIR=/tmp/x python3 tools/test-cloudflare-countries.py

Checked against a Cloudflare that lives in this file: the codes a service
takes, the rule each zone is given and what it says, the zone's own rules left
as they are, the rule written before the route, changed and removed with the
services, a token without the right to it, and Disconnect.
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
    return [r for r in (cf.rulesets.get(zone) or {}).get("rules", []) if r.get("ref") == cloudflare.WAF_REF]


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
   and [meth for meth, p, _ in cf.calls if "/rulesets" in p and meth != "GET"] == ["PATCH"],
   "a changed list changes this app's rule, by itself")
ok(cf.rulesets["z1"]["rules"][0] == {"id": "theirs", "description": "block bad bots", "expression": "cf.client.bot",
                                     "action": "block", "enabled": True},
   "the zone's own rule is untouched, and still first")
ok('in {"US" "CA"}' in ours("z1")[0]["expression"], "and the rule names both countries")

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

# a wildcard, and the names it takes in
rs = [{"host": "*.example.com", "path": "", "valid": True, "countries": ["US"]},
      {"host": "shop.example.com", "path": "", "valid": True, "countries": []},
      {"host": "x.example.com", "path": "/p", "valid": True, "countries": []}]
e = cloudflare.firewall_expressions(rs, cf.zones)["z1"][1]
ok(e == '(http.host wildcard "*.example.com" and not http.host eq "shop.example.com" and not '
        '(http.host eq "x.example.com" and starts_with(http.request.uri.path, "/p")) and not ip.src.country in {"US"})',
   "a wildcard leaves out the names other services own: %s" % e)
ok(cloudflare._q('a"b\\c') == '"a\\"b\\\\c"', "a quote or backslash in a path cannot end the string")

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
publish("http://plain.example.com", name="plain", service_id=service("plain")["id"],
        cloudflare={"enabled": True, "countries": "US", "only": True})
steps, warnings = tell()
ok(any("Zone WAF: Edit" in w for w in warnings)
   and load_config()["cloudflare"]["told"] != cloudflare._fingerprint(load_config()),
   "a limit it may not write is a warning naming the right it needs, asked again at the next Apply")
r = client.post("/api/cloudflare/test", headers=H, json={}).get_json()
ok("may not manage Firewall rules in any zone" in r["message"] and "Zone WAF: Edit" in r["message"],
   "and the test says the same")
cf.waf_denied = "z2"
r = client.post("/api/cloudflare/test", headers=H, json={}).get_json()
ok("in 1 of 2 zone(s)" in r["message"] and "not in dev.example.com" in r["message"],
   "a token with the right in some zones only is told which: %s" % r["message"][-90:])
cf.waf_denied = False
steps, warnings = tell()
ok("cloudflare: country rule for example.com" in steps and not warnings, "given the right, the next Apply writes it")
r = client.post("/api/cloudflare/test", headers=H, json={}).get_json()
ok("may manage Firewall rules" in r["message"], "and the test says it may")

# ---- too long for Cloudflare ----------------------------------------------------------------------------
many = [{"host": "h%03d.example.com" % i, "path": "", "valid": True, "countries": ["US"]} for i in range(80)]
big = cloudflare.firewall_expressions(many, cf.zones)["z1"][1]
ok(len(big) > cloudflare.WAF_MAX_EXPRESSION, "eighty limited services make an expression too long")
s2, w2, p2 = cloudflare._firewall("good-token", cf.zones, many, [])
ok(p2 and any("more than Cloudflare's" in w for w in w2) and not s2, "which is not written, and is said")

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
