#!/usr/bin/env python3
"""Cloudflare Tunnel: what HAProxy is told, what Cloudflare is told, and in what order.

    HAM_DATA_DIR=/tmp/x python3 tools/test-cloudflare.py

Checked against a Cloudflare that lives in this file: the tunnel made at the
first save, the loopback port and the visitor's address on the listener that
carries a published service, the Access application before the route before
the DNS record, nothing asked twice, nothing touched that was not made here,
and all of it taken away again. Also: a telling that failed is not counted
as done, so the next Apply does ask again; a call Cloudflare rate-limits is
asked once more; the token file sources as one assignment whatever the token
holds; and the repository key is held to one fingerprint alone.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-cf-"))
D = os.environ["HAM_DATA_DIR"]
os.environ["HAM_CERT_DIR"] = os.path.join(D, "certs")
os.environ["HAM_ERROR_DIR"] = os.path.join(D, "error-pages")
os.environ["HAM_CLOUDFLARED_BIN"] = os.path.join(D, "cloudflared-bin")
os.environ["HAM_CLOUDFLARED_ENV"] = os.path.join(D, "run", "cloudflared.env")
os.environ["HAM_CLOUDFLARED_UNIT_FILE"] = os.path.join(D, "units", "ham-cloudflared.service")
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import apply, cloudflare, haproxy, sync   # noqa: E402
from ham.base import CLOUDFLARED_BIN, CLOUDFLARED_ENV, CLOUDFLARED_UNIT_FILE   # noqa: E402
from ham.config import config_hash, load_config, save_config, shared_view   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


class Answer:
    def __init__(self, result=None, status=200, errors=None, pages=1, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self._body = {"success": not errors, "errors": errors or [], "result": result,
                      "result_info": {"total_pages": pages}}

    def json(self):
        return self._body


class Cloudflare:
    """As much of Cloudflare's API as this app speaks, with a memory."""
    ACCOUNT = "a" * 32

    def __init__(self):
        self.tunnels, self.config, self.records, self.apps, self.calls = {}, {}, {}, {}, []
        self.zones = [{"id": "z1", "name": "example.com"}, {"id": "z2", "name": "dev.example.com"}]
        self.accounts = [{"id": self.ACCOUNT, "name": "home"}]
        self.n, self.broken, self.ratelimit, self.timeouts = 0, "", 0, []

    def _id(self, prefix):
        self.n += 1
        return "%s%04d" % (prefix, self.n)

    def request(self, method, url, json=None, params=None, timeout=None, headers=None):
        path = url.split("/client/v4", 1)[1]
        self.calls.append((method, path, json))
        self.timeouts.append(timeout)
        if headers.get("Authorization") != "Bearer good-token":
            return Answer(status=403, errors=[{"code": 9109, "message": "Invalid access token"}])
        if self.ratelimit:
            self.ratelimit -= 1
            return Answer(status=429, errors=[{"code": 10000, "message": "rate limited"}], headers={"Retry-After": "0"})
        if self.broken and self.broken in path:
            return Answer(status=500, errors=[{"code": 1000, "message": "it broke"}])
        params = params or {}
        acct = "/accounts/%s" % self.ACCOUNT
        m = re.match
        if path == "/accounts":
            return Answer(self.accounts)
        if path == "/zones":
            return Answer(self.zones)
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
            if pid and method == "PUT":
                a["policies"] = [dict(json, id=pid) if p["id"] == pid else p for p in a["policies"]]
                return Answer(json)
            if method == "PUT":
                a.update(json)
                return Answer(a)
            if method == "DELETE":
                del self.apps[aid]
                return Answer({"id": aid})
        return Answer(status=404, errors=[{"code": 7003, "message": "no route for %s %s" % (method, path)}])


cf = Cloudflare()
cloudflare._requests = cf

ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "cf-key"
save_config(cfg)
H = {"X-API-Key": "cf-key"}


def put(body, want=200):
    r = client.put("/api/cloudflare/settings", headers=H, json=body)
    ok(r.status_code == want, "PUT settings -> %d %s" % (r.status_code, ((r.get_json() or {}).get("error") or "")[-90:].replace("\n", " ")))
    return r.get_json()


def publish(url, want=200, **kw):
    body = dict({"url": url, "target": "10.0.0.5:80", "certificate": False, "http_redirect": False,
                 "dry_run": False}, **kw)
    r = client.post("/api/wizard/publish", headers=H, json=body)
    ok(r.status_code == want, "publish %s -> %d %s" % (url, r.status_code, ((r.get_json() or {}).get("error") or "")[:90]))
    return r.get_json()


def text():
    return haproxy.render_haproxy(load_config())


def block(start):
    out, inside = [], False
    for ln in text().splitlines():
        if ln.startswith(start):
            inside = True
        elif inside and not ln.strip():
            break
        if inside:
            out.append(ln.strip())
    return out


def tell():
    """What Apply does about Cloudflare, without the rest of an Apply: one
    real Apply below shows it is called; the others would each wait out
    HAProxy's restart check."""
    steps, warnings = cloudflare.reconcile(load_config())
    return {"ok": True, "steps": steps, "warnings": warnings}


def service(name):
    return next(s for s in client.get("/api/services", headers=H).get_json() if s.get("pool") == name)


# ---- off ---------------------------------------------------------------------------------
publish("http://shop.example.com", name="shop")
before = text()
ok("cf_tunnel" not in before and "127.0.0.1:78" not in before, "with Cloudflare off nothing of it is rendered")
st = client.get("/api/status", headers=H).get_json()
ok(st["cloudflare"] == {"on": False, "installed": False, "connector": "off"}, "the status says off")
s = client.get("/api/cloudflare/settings", headers=H).get_json()
ok(s["enabled"] is False and s["has_api_token"] is False and "api_token" not in s and "tunnel_token" not in s,
   "the settings hand back no secret")
h0 = config_hash(load_config())

# ---- a service marked for Cloudflare before Cloudflare is connected ---------------------------
r = publish("http://shop.example.com", name="shop", service_id=service("shop")["id"],
            cloudflare={"enabled": True, "access": "allow", "allow": "Me@Example.com\n@example.org", "only": True})
ok(any("not connected yet" in w and "refuses every request" in w for w in r.get("warnings") or []),
   "marking a service before Cloudflare is connected says nothing is published, and that it now refuses everyone")
ok("http-request deny deny_status 403" in block("backend be_shop") and "cf_tunnel" not in text(),
   "through Cloudflare only, with no tunnel: every request is refused, not let in")
sv = service("shop")["cloudflare"]
ok(sv == {"enabled": True, "access": "allow", "allow": "me@example.com\n@example.org", "only": True, "countries": ""},
   "the service says how it is published, the addresses lowercased")
publish("http://shop.example.com", 400, name="shop", service_id=service("shop")["id"],
        cloudflare={"enabled": True, "access": "allow", "allow": "not an address"})
publish("http://shop.example.com", 400, name="shop", service_id=service("shop")["id"],
        cloudflare={"enabled": True, "access": "allow", "allow": ""})
r = publish("tcp://0.0.0.0:5432", name="pg", target="10.0.0.9:5432", cloudflare={"enabled": True})
ok(any("tcp://" in w and "Cloudflare" in w for w in r.get("warnings") or []), "a tcp:// service is told the tunnel is not for it")

# ---- connecting --------------------------------------------------------------------------
put({"enabled": True}, 400)
put({"enabled": True, "api_token": "bad-token"}, 400)
ok(not cf.tunnels, "a refused token makes no tunnel")
put({"enabled": True, "api_token": "good-token", "origin_port": 80}, 400)
put({"enabled": True, "api_token": "good-token", "account_id": "nope"}, 400)
r = put({"enabled": True, "api_token": "good-token"})
c = load_config()["cloudflare"]
tid = c["tunnel_id"]
ok(len(cf.tunnels) == 1 and cf.tunnels[tid]["name"] == "haproxy-manager" and cf.tunnels[tid]["config_src"] == "cloudflare",
   "the first save makes a remotely managed tunnel, named haproxy-manager")
ok(c["account_id"] == cf.ACCOUNT and c["tunnel_token"] == "token-for-" + tid,
   "the account is found from the token, and the tunnel's token is kept")
ok(r["status"]["connected"] is True and r["status"]["hosts"] == ["shop.example.com"],
   "the status says connected, and which host names go through it")
s = client.get("/api/cloudflare/settings", headers=H).get_json()
ok(s["has_api_token"] is True and "token-for" not in str(s) and "good-token" not in str(s), "and still hands back no secret")
ok(config_hash(load_config()) != h0 and "cloudflare" in shared_view(load_config()),
   "the section is part of what Apply and the other nodes compare")
put({"enabled": True})
ok(len(cf.tunnels) == 1, "saving again makes no second tunnel")
put({"enabled": True, "tunnel_name": "another"}, 400)
r = client.post("/api/cloudflare/test", headers=H, json={}).get_json()
ok(r["ok"] is True and "2 zone(s)" in r["message"] and "tunnel \"haproxy-manager\" is inactive" in r["message"],
   "the test says what the token sees and how the tunnel is doing")
r = client.post("/api/cloudflare/test", headers=H, json={"api_token": "bad-token"}).get_json()
ok(r["ok"] is False and "Invalid access token" in r["message"], "and what Cloudflare said to a token it refuses")
ok(cf.timeouts and all(t == cloudflare.TIMEOUT for t in cf.timeouts) and isinstance(cloudflare.TIMEOUT, tuple),
   "every call gives Cloudflare a connect budget and a read budget of their own")
cf.ratelimit, n = 1, len(cf.calls)
ok(cloudflare._call("good-token", "GET", "/zones")["result"] == cf.zones and len(cf.calls) == n + 2,
   "a call Cloudflare rate-limits is asked once more, after the pause it names")
cf.ratelimit, n = 2, len(cf.calls)
try:
    cloudflare._call("good-token", "GET", "/zones")
    ok(False, "limited twice, it gives up")
except cloudflare.CloudflareError as e:
    ok("rate limited" in str(e) and len(cf.calls) == n + 2, "limited twice, it gives up with Cloudflare's words")
cf.ratelimit = 0

# ---- what HAProxy is told ------------------------------------------------------------------
fe = block("frontend fe_")
port = load_config()["cloudflare"]["origin_port"]
ok("bind 127.0.0.1:%d" % port in fe and "acl cf_tunnel dst_port %d" % port in fe,
   "the listener that carries the service gains a loopback port for cloudflared")
ok("http-request set-src req.hdr(CF-Connecting-IP) if cf_tunnel { req.hdr(CF-Connecting-IP) -m found }" in fe
   and "http-request set-header X-Forwarded-Proto https if cf_tunnel" in fe,
   "on that port alone the visitor's address is Cloudflare's word, and the scheme is https")
reqs = [ln for ln in fe if ln.startswith("http-request")]
ok(reqs and reqs[0].startswith("http-request set-src"), "before anything else the listener does")
ok("http-request deny deny_status 403 unless { dst_port %d }" % port in block("backend be_shop"),
   "a service reached through Cloudflare only refuses what did not come down the tunnel")
ok("cf_tunnel" not in "\n".join(block("frontend fe_pg")) and "dst_port" not in "\n".join(block("backend be_pg")),
   "a tcp:// listener gains nothing")
c = load_config()
web = [f for f in c["haproxy"]["frontends"] if f.get("mode") != "tcp"][0]
web["http_to_https"] = True
save_config(c)
ok(any(ln.startswith("http-request redirect scheme https code 301") and ln.endswith("!cf_tunnel") for ln in block("frontend fe_")),
   "a listener that sends plain HTTP to HTTPS does not send the tunnel's visitors round again")
c = load_config()
[f for f in c["haproxy"]["frontends"] if f.get("mode") != "tcp"][0]["http_to_https"] = False
save_config(c)
if shutil.which("haproxy"):
    fd, path = tempfile.mkstemp(suffix=".cfg")
    os.write(fd, text().encode())
    os.close(fd)
    p = subprocess.run(["haproxy", "-c", "-f", path], capture_output=True, text=True)
    ok(p.returncode == 0, "haproxy -c accepts it" + ("" if p.returncode == 0 else ": " + (p.stdout + p.stderr)[-300:]))
c = load_config()
c["haproxy"]["frontends"][0]["binds"] += "\n0.0.0.0:%d" % port
save_config(c)
put({"enabled": True}, 400)
c = load_config()
c["haproxy"]["frontends"][0]["binds"] = c["haproxy"]["frontends"][0]["binds"].rsplit("\n", 1)[0]
save_config(c)

# ---- cloudflared on this node ----------------------------------------------------------------
ok(cloudflare.write_files(load_config()) and not cloudflare.installed(), "the token file is written")
ok(oct(CLOUDFLARED_ENV.stat().st_mode & 0o777) == "0o600" and CLOUDFLARED_ENV.read_text() == "TUNNEL_TOKEN=token-for-%s\n" % tid,
   "readable by root alone, and it is all cloudflared is given")
unit = CLOUDFLARED_UNIT_FILE.read_text()
ok("EnvironmentFile=%s" % CLOUDFLARED_ENV in unit and "tunnel run" in unit and "token-for" not in unit and "DynamicUser=yes" in unit,
   "the unit names the file and never the token, and runs as nobody in particular")
ok(cloudflare.write_files(load_config()) == [], "written once; unchanged files are left alone")
# The file is sourced by a root shell in the container. A token is base64,
# but the file must not become a command should one ever not be.
odd = load_config()
odd["cloudflare"]["tunnel_token"] = "x'y;$(echo pwned >&2) `id` z"
cloudflare.write_files(odd)
p = subprocess.run(["sh", "-c", '. "$1"; printf %s "$TUNNEL_TOKEN"', "_", str(CLOUDFLARED_ENV)], capture_output=True, text=True)
ok(p.stdout == odd["cloudflare"]["tunnel_token"] and "pwned" not in p.stderr and CLOUDFLARED_ENV.read_text().startswith("TUNNEL_TOKEN='"),
   "a token with shell in it is quoted, so sourcing the file sets the token and runs nothing")
cloudflare.write_files(load_config())
ok(CLOUDFLARED_ENV.read_text() == "TUNNEL_TOKEN=token-for-%s\n" % tid, "a base64 token needs no quoting, and gets none")
real_install = cloudflare.install
cloudflare.install = lambda: (False, "no network here")
step, warning = cloudflare.ensure_service(load_config())
ok(not step and "not installed on this node" in warning, "on, without cloudflared: Apply says this node carries nothing")
cloudflare.TRIED.unlink()
CLOUDFLARED_BIN.write_text("#!/bin/sh\necho cloudflared version 2026.11.1\n")
CLOUDFLARED_BIN.chmod(0o755)
ok(cloudflare.ensure_installed(load_config()) == (True, "installed"), "with cloudflared there, ensure_installed runs nothing")
step, warning = cloudflare.ensure_service(load_config())
ok(step == "cloudflared started" and not warning, "with it, Apply starts it")
# The install script holds Cloudflare's repository key to one fingerprint: the
# only key in the file, not one among others.
LIST = ("pub:-:4096:1:8A682D308D4E5E73:1:::-:::scESC::::::23::0:\nfpr:::::::::%s:\nuid:-::::::::Cloudflare:\n"
        "sub:-:4096:1:AAAAAAAAAAAAAAAA:1::::::s::::::23:\nfpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:\n" % cloudflare.REPO_KEY_FPR)
fprs = lambda listing: subprocess.run(["sh", "-c", "printf '%s' \"$1\" | " + cloudflare.KEY_FPRS, "_", listing],
                                      capture_output=True, text=True).stdout.strip()
ok(fprs(LIST) == cloudflare.REPO_KEY_FPR, "the key's own fingerprint is read, and not its subkey's")
ok(fprs(LIST + LIST.replace(cloudflare.REPO_KEY_FPR, "C" * 40)) != cloudflare.REPO_KEY_FPR
   and ('| %s)" = "%s" ]' % (cloudflare.KEY_FPRS, cloudflare.REPO_KEY_FPR)) in cloudflare.APT_INSTALL,
   "a second key beside it fails the check, which asks for that one fingerprint alone")
ok(client.get("/api/cloudflare/settings", headers=H).get_json()["status"]["version"] == "2026.11.1", "and the page shows its version")

# ---- what Cloudflare is told, and in what order -------------------------------------------------
cf.calls.clear()
res = apply.do_apply()
steps = [s for s in res["steps"] if s.startswith("cloudflare:")]
ok(steps == ["cloudflare: Access application for shop.example.com", "cloudflare: tunnel routes for 1 host name(s)",
             "cloudflare: DNS record for shop.example.com"], "Apply tells Cloudflare: %s" % steps)
writes = [(m, p.split("/")[-1] if "dns_records" not in p else "dns_records") for m, p, _ in cf.calls if m != "GET"]
ok(writes == [("POST", "apps"), ("POST", "policies"), ("PUT", "configurations"), ("POST", "dns_records")],
   "the sign-in first, then the route, then the name -- never reachable without its sign-in")
app_made = list(cf.apps.values())[0]
ok(app_made["domain"] == "shop.example.com" and app_made["type"] == "self_hosted" and app_made["name"] == "shop",
   "the Access application is the service's, by name and host")
pol = app_made["policies"][0]
ok(pol["name"] == "haproxy-manager" and pol["decision"] == "allow"
   and pol["include"] == [{"email": {"email": "me@example.com"}}, {"email_domain": {"domain": "example.org"}}],
   "its policy lets in the addresses and the domain that were listed")
ok(cf.config[tid]["ingress"] == [{"hostname": "shop.example.com", "service": "http://127.0.0.1:%d" % port, "originRequest": {}},
                                {"service": "http_status:404"}],
   "the tunnel sends the host to HAProxy's loopback port, and everything else a 404")
rec = list(cf.records.values())[0]
ok(rec["type"] == "CNAME" and rec["name"] == "shop.example.com" and rec["content"] == tid + ".cfargotunnel.com"
   and rec["proxied"] is True and rec["zone"] == "z1", "the DNS record points the name at the tunnel, proxied")
cf.calls.clear()
res = tell()
ok(not cf.calls and not [s for s in res["steps"] if s.startswith("cloudflare:")], "an Apply that changes nothing there asks nothing of Cloudflare")
r = client.post("/api/cloudflare/sync", headers=H, json={}).get_json()
ok(r["ok"] is True and not r["steps"] and all(m == "GET" for m, _, _ in cf.calls) and cf.calls,
   "Sync now asks again, and finds nothing to change")

# changing who may sign in changes the policy alone
publish("http://shop.example.com", name="shop", service_id=service("shop")["id"],
        cloudflare={"enabled": True, "access": "allow", "allow": "*", "only": True})
cf.calls.clear()
res = tell()
ok([s for s in res["steps"] if s.startswith("cloudflare:")] == ["cloudflare: Access policy for shop.example.com updated"]
   and list(cf.apps.values())[0]["policies"][0]["include"] == [{"everyone": {}}]
   and [(m, p.rsplit("/", 2)[-2]) for m, p, _ in cf.calls if m != "GET"] == [("PUT", "policies")],
   "a changed list of people changes the policy, and nothing else")

# a second service: a DNS record that is somebody else's, a host in a deeper zone, an application made by hand
cf.records["mine"] = {"id": "mine", "zone": "z1", "type": "A", "name": "wiki.example.com", "content": "203.0.113.9"}
cf.apps["hand"] = {"id": "hand", "domain": "api.dev.example.com", "name": "by hand", "policies": [{"id": "p", "name": "staff"}]}
publish("http://wiki.example.com", name="wiki", cloudflare={"enabled": True, "access": "public"})
publish("http://api.dev.example.com", name="api", cloudflare={"enabled": True, "access": "allow", "allow": "a@example.com"})
publish("http://plain.example.com", name="plain")
res = tell()
warns = "\n".join(res.get("warnings") or [])
ok("wiki.example.com already has a DNS record (A 203.0.113.9)" in warns and cf.records["mine"]["content"] == "203.0.113.9",
   "a name that already has a record keeps it, and Apply says visitors still go there")
ok("api.dev.example.com already has an Access application that was not made here" in warns
   and cf.apps["hand"]["policies"] == [{"id": "p", "name": "staff"}] and len(cf.apps) == 2,
   "an Access application made by hand is left exactly as it is")
ok(any(r["name"] == "api.dev.example.com" and r["zone"] == "z2" for r in cf.records.values()),
   "a host is given its record in the deepest zone it belongs to")
hosts = [i.get("hostname") for i in cf.config[tid]["ingress"]]
ok(hosts == ["api.dev.example.com", "shop.example.com", "wiki.example.com", None],
   "every published host has its route, and a service not ticked has none")
ok(not any(a["domain"] == "wiki.example.com" for a in cf.apps.values()), "a public service gets no Access application")
ok("dst_port" not in "\n".join(block("backend be_wiki")), "and, not being Cloudflare-only, still answers on its own port")

# a failure is said, and tried again
publish("http://new.example.com", name="new", cloudflare={"enabled": True})
cf.broken = "/configurations"
res = tell()
ok(res["ok"] is True and any("was not brought in step" in w and "it broke" in w for w in res.get("warnings") or []),
   "Cloudflare failing does not fail the Apply; it is a warning that says what Cloudflare said")
ok(client.get("/api/cloudflare/settings", headers=H).get_json()["status"]["in_step"] is False, "and the page says it is behind")
cf.broken = ""
res = tell()
ok("new.example.com" in [i.get("hostname") for i in cf.config[tid]["ingress"]], "the next Apply tries again, and catches up")

# something left undone is asked about again: the record that was in the way, once it is gone
ok(client.get("/api/cloudflare/settings", headers=H).get_json()["status"]["in_step"] is False
   and load_config()["cloudflare"]["told"] == "",
   "while a name still has somebody's record, Cloudflare is not counted as in step")
cf.calls.clear()
res = tell()
ok(cf.calls and any("wiki.example.com already has a DNS record" in w for w in res["warnings"]),
   "so an Apply that changes nothing here still asks, and says so again")
kept = cf.records.pop("mine")
res = tell()
ok("cloudflare: DNS record for wiki.example.com" in res["steps"]
   and any(r["name"] == "wiki.example.com" and r["content"] == tid + ".cfargotunnel.com" for r in cf.records.values()),
   "with the record deleted in Cloudflare, the next Apply makes the one for the tunnel")
told = load_config()["cloudflare"]["told"]
ok(told and client.get("/api/cloudflare/settings", headers=H).get_json()["status"]["in_step"] is True,
   "and now it is in step -- noted in the shared configuration, for every node to read")
ok("told" not in shared_view(load_config())["cloudflare"]
   and sync.shared_payload(load_config()).get("cloudflare_told") == told,
   "the note travels with a push to the other nodes, beside what they compare: noting it is not a change")
c = load_config()
before_hash = config_hash(c)
c["cloudflare"]["told"] = "something else"
ok(config_hash(c) == before_hash, "and writing it down is not an unapplied change")
cf.calls.clear()
tell()
ok(not cf.calls, "in step, an Apply asks nothing of Cloudflare")

# a Sync now that fails is not forgotten: what was told before does not hold
cf.broken = "/configurations"
r = client.post("/api/cloudflare/sync", headers=H, json={}).get_json()
ok(r["ok"] is False and r["status"]["in_step"] is False and load_config()["cloudflare"]["told"] == ""
   and "it broke" in r["status"]["last_error"],
   "a Sync now that Cloudflare fails leaves it marked behind, with what Cloudflare said")
cf.broken = ""
cf.calls.clear()
tell()
ok(cf.calls and client.get("/api/cloudflare/settings", headers=H).get_json()["status"]["in_step"] is True
   and not client.get("/api/cloudflare/settings", headers=H).get_json()["status"]["last_error"],
   "so the next Apply does ask again, as the warning says, and catches up")
cf.records["mine"] = dict(kept, name="elsewhere.example.com")

# a route somebody added to the tunnel in the dashboard, and its record, are theirs
cf.config[tid]["ingress"].insert(0, {"hostname": "cam.example.com", "service": "http://192.168.1.9:80"})
cf.records["cam"] = {"id": "cam", "zone": "z1", "type": "CNAME", "name": "cam.example.com", "content": tid + ".cfargotunnel.com"}
publish("http://extra.example.com", name="extra", cloudflare={"enabled": True})
tell()
hosts = [i.get("hostname") for i in cf.config[tid]["ingress"]]
ok("cam.example.com" in hosts and "extra.example.com" in hosts and hosts.index("extra.example.com") < hosts.index("cam.example.com")
   and hosts[-1] is None and "cam" in cf.records,
   "a route added to the tunnel by hand stays, after this app's own, and so does its DNS record")

# a service on one path of a host: its sign-in is found again, and the rest of the host stays in
publish("http://shop.example.com/admin", name="shopadmin", cloudflare={"enabled": True, "access": "allow", "allow": "a@example.com"})
tell()
ok(any(a["domain"] == "shop.example.com/admin" for a in cf.apps.values()), "a service on a path gets its Access application for that path")
ok("http-request deny deny_status 403 if { dst_port %d }" % port in block("backend be_plain"),
   "a service that is not published refuses what comes down the tunnel: a path of its host being published does not publish it")
ok(not any("dst_port" in ln for ln in block("backend be_shopadmin")), "the published one takes it")
publish("http://shop.example.com/admin", name="shopadmin", service_id=service("shopadmin")["id"], cloudflare={"enabled": False})
res = tell()
ok("cloudflare: Access application for shop.example.com/admin removed" in res["steps"]
   and not any(a["domain"] == "shop.example.com/admin" for a in cf.apps.values()),
   "and unticked, the application for the path is removed, not left behind")

# unpublishing takes away what was made, and only that
publish("http://shop.example.com", name="shop", service_id=service("shop")["id"], cloudflare={"enabled": False})
cf.calls.clear()
res = tell()
steps = [s for s in res["steps"] if s.startswith("cloudflare:")]
ok("cloudflare: DNS record for shop.example.com removed" in steps and "cloudflare: Access application for shop.example.com removed" in steps
   and not any(r["name"] == "shop.example.com" for r in cf.records.values())
   and not any(a["domain"] == "shop.example.com" for a in cf.apps.values()),
   "unticking a service removes its record and its Access application")
writes = [p for m, p, _ in cf.calls if m != "GET"]
ok(writes.index(next(p for p in writes if p.endswith("/configurations"))) < writes.index(next(p for p in writes if "/access/apps/" in p)),
   "the route goes before the sign-in does")
ok(block("backend be_shop").count("http-request deny deny_status 403 if { dst_port %d }" % port) == 1
   and not any("unless" in ln for ln in block("backend be_shop")),
   "and the service answers on its own port again, and no longer through the tunnel")
ok(cf.records["mine"]["content"] == "203.0.113.9" and "hand" in cf.apps, "what was not made here is still there")

# ---- off, and gone ---------------------------------------------------------------------------
put({"enabled": False})
ok("cf_tunnel" not in text(), "switched off: HAProxy forgets the loopback port")
res = tell()
ok(cf.config[tid]["ingress"] == [{"hostname": "cam.example.com", "service": "http://192.168.1.9:80"}, {"service": "http_status:404"}]
   and [r["id"] for r in cf.records.values() if (r.get("content") or "").endswith("cfargotunnel.com")] == ["cam"]
   and list(cf.apps) == ["hand"],
   "and the next Apply empties the tunnel of what was made here: its routes, its records, its applications -- and nothing else")
step, _w = cloudflare.ensure_service(load_config())
ok(step == "cloudflared stopped: Cloudflare is off" and not CLOUDFLARED_ENV.exists(), "cloudflared is stopped, and its token file removed")
# Disconnect applies twice -- off, then forgotten -- and an Apply here waits out
# HAProxy's restart check each time; what an Apply does was shown above.
applied = []
apply.do_apply = lambda *a, **k: applied.append(1) or {"ok": True, "steps": []}
r = client.post("/api/cloudflare/disconnect", headers=H, json={})
c = load_config()["cloudflare"]
ok(len(applied) == 2 and c["told"] == "", "it is switched off and applied before Cloudflare is asked, and applied again once forgotten")
ok(r.status_code == 200 and not cf.tunnels and c["tunnel_id"] == "" and c["tunnel_token"] == "" and c["enabled"] is False,
   "Disconnect deletes the tunnel and forgets it")
ok(c["api_token"] == "good-token", "the API token stays, for connecting again")
ok(client.post("/api/cloudflare/disconnect", headers=H, json={}).status_code == 400, "there is nothing to disconnect twice")

# ---- a tunnel that is somebody's is not taken over ---------------------------------------------
nas = "99999999-0000-0000-0000-000000000001"
cf.tunnels[nas] = {"id": nas, "name": "nas", "config_src": "cloudflare", "connections": []}
cf.config[nas] = {"ingress": [{"hostname": "nas.example.com", "service": "http://192.168.1.2:5000"}, {"service": "http_status:404"}]}
r = put({"enabled": True, "tunnel_name": "nas"}, 400)
ok("already in use" in r["error"] and "nas.example.com" in r["error"] and load_config()["cloudflare"]["tunnel_id"] == ""
   and cf.config[nas]["ingress"][0]["hostname"] == "nas.example.com",
   "a tunnel of that name with routes is refused, by name, and left exactly as it was")
cf.config[nas] = {"ingress": [{"service": "http_status:404"}]}
cf.tunnels[nas]["connections"] = [{"id": "c1"}]
r = put({"enabled": True, "tunnel_name": "nas"}, 400)
ok("a connector is connected to it" in r["error"], "so is one with no routes that something is connected to")
cf.tunnels[nas]["connections"] = []
put({"enabled": True, "tunnel_name": "nas"})
ok(load_config()["cloudflare"]["tunnel_id"] == nas, "an empty one of that name is used")

# ---- Disconnect when Cloudflare will not have it -----------------------------------------------
publish("http://shop.example.com", name="shop", service_id=service("shop")["id"], cloudflare={"enabled": True, "access": "allow", "allow": "a@example.com"})
tell()
ok(any(a["domain"] == "shop.example.com" for a in cf.apps.values()) and any(r["name"] == "shop.example.com" for r in cf.records.values()),
   "published again, on the new tunnel")
cf.broken = "/cfd_tunnel/" + nas
r = client.post("/api/cloudflare/disconnect", headers=H, json={})
c = load_config()["cloudflare"]
ok(r.status_code == 502 and "forget the tunnel" in r.get_json()["error"] and c["tunnel_id"] == nas and c["enabled"] is False,
   "Cloudflare failing leaves it switched off but still known, and says how to get out")
del cf.tunnels[nas]                    # deleted in the dashboard, meanwhile
cf.broken = ""
r = client.post("/api/cloudflare/disconnect", headers=H, json={})
c = load_config()["cloudflare"]
ok(r.status_code == 200 and c["tunnel_id"] == "" and "already gone" in r.get_json()["message"],
   "a tunnel already gone from Cloudflare can still be disconnected")
ok(not any(a["domain"] == "shop.example.com" for a in cf.apps.values()) and not any(r["name"] == "shop.example.com" for r in cf.records.values()),
   "and what this configuration published on it is cleared, by name")
put({"enabled": True, "tunnel_name": "third"})
cf.calls.clear()
r = client.post("/api/cloudflare/disconnect", headers=H, json={"forget": True})
c = load_config()["cloudflare"]
ok(r.status_code == 200 and not cf.calls and c["tunnel_id"] == "" and len(cf.tunnels) == 1,
   "forgetting asks nothing of Cloudflare: the tunnel stays there, and is gone here")
cloudflare.install = real_install

print("\n%d failed" % len(fails) if fails else "\nall passed")
sys.exit(1 if fails else 0)
