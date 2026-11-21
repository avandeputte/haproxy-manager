#!/usr/bin/env python3
"""Cloudflare Tunnel: what HAProxy is told, what Cloudflare is told, and in what order.

    HAM_DATA_DIR=/tmp/x python3 tools/test-cloudflare.py

Checked against a Cloudflare that lives in this file: the tunnel made at the
first save, the loopback port and the visitor's address on the listener that
carries a published service, the Access application before the route before
the DNS record, nothing asked twice, nothing touched that was not made here,
and all of it taken away again.
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
from ham import apply, cloudflare, haproxy   # noqa: E402
from ham.base import CLOUDFLARED_BIN, CLOUDFLARED_ENV, CLOUDFLARED_UNIT_FILE   # noqa: E402
from ham.config import config_hash, load_config, save_config, shared_view   # noqa: E402

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


class Cloudflare:
    """As much of Cloudflare's API as this app speaks, with a memory."""
    ACCOUNT = "a" * 32

    def __init__(self):
        self.tunnels, self.config, self.records, self.apps, self.calls = {}, {}, {}, {}, []
        self.zones = [{"id": "z1", "name": "example.com"}, {"id": "z2", "name": "dev.example.com"}]
        self.accounts = [{"id": self.ACCOUNT, "name": "home"}]
        self.n, self.broken = 0, ""

    def _id(self, prefix):
        self.n += 1
        return "%s%04d" % (prefix, self.n)

    def request(self, method, url, json=None, params=None, timeout=None, headers=None):
        path = url.split("/client/v4", 1)[1]
        self.calls.append((method, path, json))
        if headers.get("Authorization") != "Bearer good-token":
            return Answer(status=403, errors=[{"code": 9109, "message": "Invalid access token"}])
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
ok(sv == {"enabled": True, "access": "allow", "allow": "me@example.com\n@example.org", "only": True},
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
real_install = cloudflare.install
cloudflare.install = lambda: (False, "no network here")
step, warning = cloudflare.ensure_service(load_config())
ok(not step and "not installed on this node" in warning, "on, without cloudflared: Apply says this node carries nothing")
cloudflare.TRIED.unlink()
CLOUDFLARED_BIN.write_text("#!/bin/sh\necho cloudflared version 2026.11.1\n")
CLOUDFLARED_BIN.chmod(0o755)
step, warning = cloudflare.ensure_service(load_config())
ok(step == "cloudflared started" and not warning, "with it, Apply starts it")
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
ok("new.example.com" in [i.get("hostname") for i in cf.config[tid]["ingress"]]
   and client.get("/api/cloudflare/settings", headers=H).get_json()["status"]["in_step"] is True,
   "the next Apply tries again, and catches up")

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
ok("dst_port" not in "\n".join(block("backend be_shop")) and "http-request deny" not in "\n".join(block("backend be_shop")),
   "and the service answers on its own port again")
ok(cf.records["mine"]["content"] == "203.0.113.9" and "hand" in cf.apps, "what was not made here is still there")

# ---- off, and gone ---------------------------------------------------------------------------
put({"enabled": False})
ok("cf_tunnel" not in text(), "switched off: HAProxy forgets the loopback port")
res = tell()
ok(cf.config[tid]["ingress"] == [{"service": "http_status:404"}]
   and not any((r.get("content") or "").endswith("cfargotunnel.com") for r in cf.records.values())
   and list(cf.apps) == ["hand"], "and the next Apply empties the tunnel: no routes, no records, no applications of its own")
step, _w = cloudflare.ensure_service(load_config())
ok(step == "cloudflared stopped: Cloudflare is off" and not CLOUDFLARED_ENV.exists(), "cloudflared is stopped, and its token file removed")
r = client.post("/api/cloudflare/disconnect", headers=H, json={})
c = load_config()["cloudflare"]
ok(r.status_code == 200 and not cf.tunnels and c["tunnel_id"] == "" and c["tunnel_token"] == "" and c["enabled"] is False,
   "Disconnect deletes the tunnel and forgets it")
ok(c["api_token"] == "good-token", "the API token stays, for connecting again")
ok(client.post("/api/cloudflare/disconnect", headers=H, json={}).status_code == 400, "there is nothing to disconnect twice")
cloudflare.install = real_install

print("\n%d failed" % len(fails) if fails else "\nall passed")
sys.exit(1 if fails else 0)
