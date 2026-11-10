#!/usr/bin/env python3
"""What Nginx Proxy Manager users expect on day one.

    HAM_DATA_DIR=/tmp/x python3 tools/test-npm-parity.py

Wildcard hosts that route, IPv6 listening, uploaded certificates and their
download, redirect services, HSTS, WebSockets kept open, a chosen answer for
unknown hosts, and X-Real-IP / X-Forwarded-Host. Each is checked as what is
stored and what is rendered, and the whole file is put to haproxy -c.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ["HAM_DATA_DIR"] = tempfile.mkdtemp(prefix="ham-npm-")
D = os.environ["HAM_DATA_DIR"]
os.environ["HAM_CERT_DIR"] = os.path.join(D, "certs")
os.environ["HAM_ERROR_DIR"] = os.path.join(D, "error-pages")
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import acme, apply, haproxy, probe, rules   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "npm-key"
save_config(cfg)
H = {"X-API-Key": "npm-key"}


def post(path, body, want=200):
    r = client.post("/api/" + path, headers=H, json=body)
    ok(r.status_code == want, "POST %s -> %d %s" % (path, r.status_code,
                                                     ((r.get_json() or {}).get("error") or "")[:90]))
    return r.get_json()


def publish(url, **kw):
    body = dict({"url": url, "target": "10.0.0.5:80", "certificate": False,
                 "http_redirect": False, "dry_run": False}, **kw)
    return post("wizard/publish", body)


def text():
    return haproxy.render_haproxy(load_config())


def lines(needle):
    return [ln.strip() for ln in text().splitlines() if needle in ln]


def have_haproxy():
    try:
        return subprocess.run(["haproxy", "-v"], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


# ---- 1. wildcard hosts ------------------------------------------------------------
publish("http://*.example.com")
publish("http://app.example.com", target="10.0.0.6:80")
acl = lines("acl_host-wildcard-example")
ok(acl and "-m reg -i ^[^.]+\\.example\\.com$" in acl[0],
   "a wildcard host routes by pattern, one label deep, as its certificate would cover")
routes = lines("use_backend be_")
ok(routes.index(next(r for r in routes if "be_app" in r)) < routes.index(next(r for r in routes if "wildcard" in r)),
   "a named host is routed before the wildcard that would also match it")
spec = {"type": "host_matches", "value": "*.example.com", "param": "", "list": "", "negate": False}
ok(rules.matches(load_config(), spec, {"host": "a.example.com"}) is True
   and rules.matches(load_config(), spec, {"host": "a.b.example.com"}) is False
   and rules.matches(load_config(), spec, {"host": "example.com"}) is False,
   "the condition wizard judges a wildcard the same way")
ok(not any(u["host"].startswith("*") for u in probe.published_urls(load_config())),
   "a wildcard is not probed: nobody can ask for it")
svc = client.get("/api/services", headers=H).get_json()
ok(any(s["url"] == "http://*.example.com" for s in svc), "and the Services page lists it as typed")

# ---- 2. IPv6 ----------------------------------------------------------------------------
haproxy.ipv6_available.cache_clear()
real = haproxy.ipv6_available
haproxy.ipv6_available = lambda: True
ok(lines("bind 0.0.0.0:80") and lines("bind :::80 v6only") and not lines("v4v6"),
   "a listener on every address answers over IPv6 too: a second bind, so an IPv4 client "
   "keeps its IPv4 address rather than becoming ::ffff:a.b.c.d")
c = load_config(); c["haproxy"]["settings"]["ipv6"] = False; save_config(c)
ok(lines("bind 0.0.0.0:80") and not lines(":::80"), "unless IPv6 is turned off")
c = load_config(); c["haproxy"]["settings"]["ipv6"] = True; save_config(c)
haproxy.ipv6_available = lambda: False
ok(lines("bind 0.0.0.0:80"), "and a node without IPv6 keeps IPv4 alone, so HAProxy still starts")
haproxy.ipv6_available = lambda: True
c = load_config(); c["haproxy"]["frontends"][0]["binds"] = "192.0.2.10:80"; save_config(c)
ok(lines("bind 192.0.2.10:80") and not lines(":::80"), "a specific address -- a virtual IP -- is left as it is")
c = load_config(); c["haproxy"]["frontends"][0]["binds"] = "0.0.0.0:80"; save_config(c)
haproxy.ipv6_available = real

# ---- 12. headers, 6. WebSockets -----------------------------------------------------------
ok(lines("http-request set-header X-Real-IP %[src]") and lines("http-request set-header X-Forwarded-Host %[req.hdr(host)]"),
   "X-Real-IP and X-Forwarded-Host are set beside X-Forwarded-For, overwriting any a client sent")
ok(lines("timeout tunnel 1h"), "an idle WebSocket is kept for an hour, not cut at the 50 s timeouts")


def block(start):
    """The lines of one section of the rendered file, from its first line to the next blank one."""
    out, inside = [], False
    for ln in text().splitlines():
        if ln.startswith(start):
            inside = True
        elif inside and not ln.strip():
            break
        if inside:
            out.append(ln.strip())
    return out


publish("tcp://0.0.0.0:5432", target="10.0.0.7:5432", name="pg")
ok(not any("timeout tunnel" in ln for ln in block("defaults"))
   and not any("timeout tunnel" in ln for ln in block("backend be_pg"))
   and any("timeout tunnel 1h" in ln for ln in block("backend be_app")),
   "the tunnel timeout is an HTTP pool's: a tcp:// service keeps its client and server timeouts")
r = client.put("/api/haproxy/settings", headers=H, json={"timeout_tunnel": "forever"})
ok(r.status_code == 400 and "timeout_tunnel" in r.get_json()["error"], "a tunnel timeout that is not a time is refused")

# ---- 4. redirect services ------------------------------------------------------------------
post("wizard/publish", {"url": "http://old.example.com", "redirect": {"to": "https://new.example.com/", "code": 308},
                        "certificate": False, "http_redirect": False, "dry_run": False})
pool = next(b for b in load_config()["haproxy"]["backends"] if b["name"] == "old")
ok(pool["servers"] == [] and pool["redirect_to"] == "https://new.example.com/" and pool["redirect_code"] == 308
   and pool["notify_mode"] == "off" and not pool["healthcheck_enabled"],
   "a redirect service has no servers, no check, and no server to lose")
ok(lines("http-request redirect prefix https://new.example.com code 308"),
   "it answers with the redirect, the path kept, without a doubled slash")
post("wizard/publish", {"url": "http://tcp.example.com", "redirect": {"to": "ftp://x", "code": 301},
                        "certificate": False, "dry_run": False}, want=400)
post("wizard/publish", {"url": "http://x.example.com", "redirect": {"to": "https://y", "code": 303},
                        "certificate": False, "dry_run": False}, want=400)
svc = next(s for s in client.get("/api/services", headers=H).get_json() if s["pool"] == "old")
ok(svc["redirect"] == {"to": "https://new.example.com/", "code": 308, "keep_path": True} and svc["targets"] == [],
   "the Services API reports it")
ok(not any(u["pool"] == "be_old" for u in probe.published_urls(load_config())), "and the probes leave it alone")
post("wizard/publish", {"url": "http://old.example.com", "redirect": {"to": "https://new.example.com", "keep_path": False},
                        "certificate": False, "http_redirect": False, "dry_run": False, "service_id": svc["id"]})
ok(lines("http-request redirect location https://new.example.com code 301"), "without the path: to the address as given")
post("wizard/publish", {"url": "http://old.example.com", "target": "10.0.0.9:80", "certificate": False,
                        "http_redirect": False, "dry_run": False, "service_id": svc["id"]})
pool = next(b for b in load_config()["haproxy"]["backends"] if b["name"] == "old")
ok(pool["redirect_to"] == "" and len(pool["servers"]) == 1 and not lines("redirect location https://new"),
   "turned back into a forward, it forwards again")

# ---- 5. HSTS ---------------------------------------------------------------------------------
publish("https://secure.example.com", hsts=True, hsts_subdomains=True)
ok(lines('http-response set-header Strict-Transport-Security "max-age=63072000; includeSubDomains" if { ssl_fc }'),
   "HSTS is sent, over TLS only, with subdomains when asked")
svc = next(s for s in client.get("/api/services", headers=H).get_json() if s["pool"] == "secure")
publish("https://secure.example.com", hsts=False, service_id=svc["id"])
ok(not lines("Strict-Transport-Security"), "and stops when turned off")

# ---- 7. unknown hosts -----------------------------------------------------------------------
ok(not lines("bk_default_site"), "by default an unknown host gets HAProxy's own 503, as before")
# An HTTPS listener with no certificate attached loads the whole directory,
# which HAProxy wants to hold something: the stand-in Apply would make.
certs = pathlib.Path(os.environ["HAM_CERT_DIR"])
certs.mkdir(parents=True, exist_ok=True)
apply._selfsigned_placeholder(certs / "stand-in.pem", ["stand-in"])
r = client.put("/api/haproxy/settings", headers=H, json={"default_site": "404"})
ok(r.status_code == 200 and lines("default_backend bk_default_site") and lines("http-request return status 404"),
   "404: every HTTP listener without a pool of its own answers not found")
client.put("/api/haproxy/settings", headers=H, json={"default_site": "drop"})
ok(lines("http-request silent-drop"), "drop: the connection is dropped without a word")
r = client.put("/api/haproxy/settings", headers=H, json={"default_site": "redirect", "default_site_url": "nowhere"})
ok(r.status_code == 400, "a redirect without an address is refused")
client.put("/api/haproxy/settings", headers=H, json={"default_site": "redirect", "default_site_url": "https://example.com/"})
ok(lines("http-request redirect location https://example.com/ code 302"), "redirect: to the address given")

# ---- 3 and 13. certificates brought here ------------------------------------------------------
tmp = tempfile.mkdtemp()


def make(name, cn, sans):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", "/CN=" + cn,
                    "-addext", "subjectAltName=" + ",".join("DNS:" + s for s in sans),
                    "-keyout", os.path.join(tmp, name + ".key"), "-out", os.path.join(tmp, name + ".crt")],
                   capture_output=True, check=True)
    return (open(os.path.join(tmp, name + ".crt")).read(), open(os.path.join(tmp, name + ".key")).read())


crt, key = make("shop", "shop.example.com", ["shop.example.com", "www.shop.example.com"])
crt2, key2 = make("other", "other.example.com", ["other.example.com"])
post("acme/certificates/upload", {"name": "mismatch", "cert": crt, "key": key2}, want=400)
post("acme/certificates/upload", {"name": "nokey", "cert": crt, "key": ""}, want=400)
post("acme/certificates/upload", {"name": "enc", "cert": crt,
                                  "key": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----"}, want=400)
up = post("acme/certificates/upload", {"name": "shop-custom", "cert": crt, "key": key})
cert = next(c for c in load_config()["acme"]["certificates"] if c["name"] == "shop-custom")
ok(up["names"] == ["shop.example.com", "www.shop.example.com"] and cert["source"] == "custom"
   and cert["domains"] == "shop.example.com www.shop.example.com" and cert["auto_renew"] is False,
   "an uploaded certificate is stored by its names, and never renewed here")
pem = (pathlib.Path(os.environ["HAM_CERT_DIR"]) / "shop-custom.pem")
ok(pem.exists() and oct(pem.stat().st_mode & 0o777) == "0o600" and "PRIVATE KEY" in pem.read_text(),
   "as one PEM in the certificate directory, readable by root alone")
post("acme/certificates/upload", {"name": "shop-custom", "cert": crt, "key": key}, want=400)
r = client.post("/api/acme/issue/" + cert["id"], headers=H, json={})
ok(r.status_code == 400 and "uploaded" in r.get_json()["error"], "Issue is refused: it was uploaded, not issued")
crt3, key3 = make("shop2", "shop.example.com", ["shop.example.com", "api.shop.example.com"])
up = post("acme/certificates/upload", {"id": cert["id"], "cert": crt3, "key": key3})
cert = next(c for c in load_config()["acme"]["certificates"] if c["id"] == cert["id"])
ok("api.shop.example.com" in cert["domains"] and crt3.strip() in pem.read_text(), "uploading again replaces it")
# A redirect target is a log-format string to HAProxy: a literal % is written %%.
post("wizard/publish", {"url": "http://pct.example.com", "redirect": {"to": "https://new.example.com/docs%20v2", "code": 301},
                        "certificate": False, "http_redirect": False, "dry_run": False})
ok(lines("http-request redirect prefix https://new.example.com/docs%%20v2 code 301"),
   "a % in a redirect address is escaped, so HAProxy takes it as a % and not as a variable")
# Outside the wizard a pool's redirect is checked too, and one stored anyway does not take the node down.
pct = next(b for b in load_config()["haproxy"]["backends"] if b["name"] == "pct")
r = client.put("/api/haproxy/backends/" + pct["id"], headers=H, json=dict(pct, redirect_code="permanent"))
ok(r.status_code == 400 and "301, 302, 307 or 308" in r.get_json()["error"], "a redirect code that is not one is refused")
r = client.put("/api/haproxy/backends/" + pct["id"], headers=H, json=dict(pct, redirect_to="new.example.com"))
ok(r.status_code == 400 and "http://" in r.get_json()["error"], "and so is a redirect address without a scheme")
c = load_config()
next(b for b in c["haproxy"]["backends"] if b["name"] == "pct")["redirect_code"] = "permanent"
save_config(c)
ok(lines("docs%%20v2 code 301") and client.get("/api/services", headers=H).status_code == 200,
   "a bad code already stored renders as 301 instead of failing every page and every Apply")
c = load_config()
next(b for b in c["haproxy"]["backends"] if b["name"] == "pct")["redirect_code"] = 301
save_config(c)

# ---- an uploaded certificate is not issued over --------------------------------------------------
up = next(x for x in load_config()["acme"]["certificates"] if x["name"] == "shop-custom")
made = r = post("wizard/certificate", {"domains": up["domains"], "issue": False,
                                "account": {"name": "le", "email": "", "ca": "letsencrypt"},
                                "challenge": {"name": "http", "method": "http01"}})
ok([a["action"] for a in r["actions"] if a["type"] == "Certificate"] == ["created"]
   and any("uploaded" in w for w in r["warnings"]),
   "the certificate wizard, asked for names an uploaded certificate covers, makes a new one beside it")
after = next(x for x in load_config()["acme"]["certificates"] if x["id"] == up["id"])
ok(after == up, "and leaves the uploaded one exactly as it was")
res = acme._acme_issue(load_config(), up)
ok(not res["ok"] and "uploaded" in res["error"], "whatever asks, an uploaded certificate is not issued over")
r = client.post("/api/wizard/certificate", headers=H, json={"domains": "s.example.com", "account": "le", "challenge": "http"})
ok(r.status_code == 400 and "{id}" in r.get_json()["error"], "an account given as a string is refused, not a crash")

# ---- a renewal that changes nothing reloads nothing ------------------------------------------------
new = next(x for x in load_config()["acme"]["certificates"] if x["id"] == made["certificate_id"])
pem_crt, pem_key = make("renewed", "renewed.example.com", ["renewed.example.com"])
runs, reloads, told = [], [], []


def fake_acme(args, env_extra=None):
    runs.append(args[0])
    if "--install-cert" in args:
        pathlib.Path(args[args.index("--fullchain-file") + 1]).write_text(pem_crt)
        pathlib.Path(args[args.index("--key-file") + 1]).write_text(pem_key)
        return 0, "installed"
    return (2, "Skipping. Next renewal time is later.") if args[0] == "--issue" else (0, "ok")


real_run, real_after, real_notify = acme.acme_run, acme.after_certificate_deployed, acme.notify.notify
acme.acme_run = fake_acme
acme.after_certificate_deployed = lambda cfg, cert: (reloads.append(cert["name"]), "reloaded HAProxy")[1]
acme.notify.notify = lambda *a, **k: told.append(a[1])
first = acme.acme_issue(load_config(), new)
second = acme.acme_issue(load_config(), new)
acme.acme_run, acme.after_certificate_deployed, acme.notify.notify = real_run, real_after, real_notify
ok(first["ok"] and first["changed"] and len(reloads) == 1 and len(told) == 1,
   "a certificate that arrives is deployed, HAProxy reloaded and the issue announced")
ok(second["ok"] and second["changed"] is False and len(reloads) == 1 and len(told) == 1,
   "one that is not due and already deployed is left alone: no reload, no announcement, nothing sent")

issued = {"id": "acme1", "name": "issued", "domains": "x.example.com", "auto_renew": True}
c = load_config(); c["acme"]["certificates"].append(issued); save_config(c)
post("acme/certificates/upload", {"id": "acme1", "cert": crt, "key": key}, want=400)
d = client.get("/api/acme/certificates/%s/download" % cert["id"], headers=H)
body = d.get_data(as_text=True)
ok(d.status_code == 200 and d.headers["Content-Disposition"].endswith('shop-custom.crt"')
   and "BEGIN CERTIFICATE" in body and "PRIVATE KEY" not in body,
   "download: the certificate and chain, without the key")
d = client.get("/api/acme/certificates/%s/download?part=key" % cert["id"], headers=H)
ok("PRIVATE KEY" in d.get_data(as_text=True) and "BEGIN CERTIFICATE" not in d.get_data(as_text=True)
   and d.headers.get("Cache-Control") == "no-store", "and the key on its own, when asked for by name")
ok(client.get("/api/acme/certificates/acme1/download", headers=H).status_code == 404,
   "a certificate with no file yet has nothing to download")
renewed = []
real_issue = acme.acme_issue
acme.acme_issue = lambda cfg, c, force=False: (renewed.append(c["name"]), {"ok": True})[1]
client.post("/api/acme/renew", headers=H)
acme.acme_issue = real_issue
ok("shop-custom" not in renewed and "issued" in renewed, "Renew all leaves an uploaded certificate alone")

# ---- the whole file -----------------------------------------------------------------------------
if have_haproxy():
    apply.ensure_cert_files(load_config())
    good, msg = apply.check_rendered(load_config())
    ok(good, "haproxy -c accepts all of it: " + msg.splitlines()[-1][:120])
else:
    print("  ....  no haproxy here; the text checks above stand")

print("\n" + ("%d failed" % len(fails) if fails else "what an NPM user expects, on day one"))
sys.exit(1 if fails else 0)
