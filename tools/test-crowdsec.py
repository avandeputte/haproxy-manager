#!/usr/bin/env python3
"""CrowdSec: what is written, what HAProxy says, and nothing of it when off.

    HAM_DATA_DIR=/tmp/x python3 tools/test-crowdsec.py

Issue #21. The bouncer is a separate daemon on every node; this app writes
its configuration and the SPOE engine HAProxy loads, wires the listeners to
ask it, and keeps it running while CrowdSec is on. Checked here without a
bouncer or a LAPI: the files, the directives, the settings refused, and that
a node with CrowdSec off renders exactly as before.
"""
import os
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-cs-"))
D = os.environ["HAM_DATA_DIR"]
os.environ["HAM_CERT_DIR"] = os.path.join(D, "certs")
os.environ["HAM_ERROR_DIR"] = os.path.join(D, "error-pages")
os.environ["HAM_CROWDSEC_SPOE"] = os.path.join(D, "crowdsec.cfg")
os.environ["HAM_CROWDSEC_BOUNCER_CFG"] = os.path.join(D, "bouncers", "crowdsec-spoa-bouncer.yaml")
os.environ["HAM_CROWDSEC_BIN"] = os.path.join(D, "bouncer-bin")
os.environ["HAM_CROWDSEC_HTML"] = os.path.join(D, "html")
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import apply, crowdsec, haproxy   # noqa: E402
from ham.base import CERT_DIR, CROWDSEC_BIN, CROWDSEC_BOUNCER_CFG, CROWDSEC_HTML, CROWDSEC_SPOE   # noqa: E402
from ham.config import config_hash, load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "cs-key"
save_config(cfg)
H = {"X-API-Key": "cs-key"}


def put(body, want=200):
    r = client.put("/api/crowdsec/settings", headers=H, json=body)
    ok(r.status_code == want, "PUT settings -> %d %s" % (r.status_code, ((r.get_json() or {}).get("error") or "")[-80:].replace("\n", " ")))
    return r.get_json()


client.post("/api/wizard/publish", headers=H, json={
    "url": "http://shop.example.com", "target": "10.0.0.5:80", "certificate": False,
    "http_redirect": False, "dry_run": False})
client.post("/api/wizard/publish", headers=H, json={
    "url": "tcp://0.0.0.0:5432", "target": "10.0.0.9:5432", "certificate": False, "dry_run": False})
CERT_DIR.mkdir(parents=True, exist_ok=True)
# A stand-in for the bouncer: its binary and the pages it ships, so haproxy -c
# finds what the rendered file names. It is never run.
CROWDSEC_HTML.mkdir(parents=True, exist_ok=True)
for name in ("ban.html", "ban-with-contact.html", "captcha.html"):
    (CROWDSEC_HTML / name).write_text("<p>%s</p>" % name)


def bouncer_present(yes):
    if yes:
        CROWDSEC_BIN.write_text("#!/bin/sh\necho version: v0.4.0\n")
        CROWDSEC_BIN.chmod(0o755)
    elif CROWDSEC_BIN.exists():
        CROWDSEC_BIN.unlink()


bouncer_present(False)
# The real install runs apt-get; here it is a stub whose answer the checks set.
installs = []


def fake_install():
    installs.append(1)
    return fake_install.result


fake_install.result = (False, "no network")
crowdsec.install = fake_install

# ---- off: nothing of it anywhere ------------------------------------------------------
s = client.get("/api/crowdsec/settings", headers=H).get_json()
ok(s["enabled"] is False and s["has_api_key"] is False and s["status"]["installed"] is False,
   "off by default, no key, and this node has no bouncer")
before = haproxy.render_haproxy(load_config())
ok("crowdsec" not in before and "spoe" not in before, "a node with CrowdSec off renders no trace of it")
ok(crowdsec.write_files(load_config()) == [] and not CROWDSEC_SPOE.exists(), "and writes nothing")
st = client.get("/api/status?brief=1", headers=H).get_json()
ok(st["crowdsec"] == {"on": False, "installed": False, "bouncer": "off"}, "the status says off")

# ---- what is refused ------------------------------------------------------------------
put({"enabled": True}, want=400)
put({"enabled": True, "api_url": "192.168.1.5:8080", "api_key": "k"}, want=400)
put({"enabled": True, "api_url": "http://192.168.1.5:8080/", "api_key": "k", "mode": "captcha"}, want=400)
put({"enabled": True, "api_url": "http://192.168.1.5:8080/", "api_key": "k", "mode": "captcha",
     "captcha_provider": "turnstile", "captcha_site_key": "s"}, want=400)
ok(len(fails) == 0, "a URL without a scheme, a missing key, a captcha without provider or keys: all refused")

# ---- on, on a node without the bouncer: saved, silent, and said ----------------------------
r = put({"enabled": True, "api_url": "http://192.168.1.5:8080", "api_key": "abc123", "mode": "ban"})
cfg = load_config()
ok(crowdsec.configured(cfg) and not crowdsec.active(cfg), "configured, but not active here: no bouncer")
ok("spoe" not in haproxy.render_haproxy(cfg), "a node without the bouncer renders no trace, so its Apply still works")
step, warning = crowdsec.ensure_service(cfg)
ok(step == "" and "not installed" in warning and installs == [1], "and Apply tries to fetch it, and warns when it cannot")
crowdsec.TRIED.unlink()
st = client.get("/api/status?brief=1", headers=H).get_json()
ok(st["crowdsec"] == {"on": True, "installed": False, "bouncer": "missing"}, "the status says on, and that the bouncer is missing here")
put({"enabled": False})
bouncer_present(True)

# ---- on: the files, and what HAProxy says --------------------------------------------
h = config_hash(load_config())
r = put({"enabled": True, "api_url": "http://192.168.1.5:8080", "api_key": "abc123", "mode": "ban"})
ok(config_hash(load_config()) != h, "switching it on is an unapplied change")
s = client.get("/api/crowdsec/settings", headers=H).get_json()
ok(s["has_api_key"] and "api_key" not in s, "the key is stored and never read back")
cfg = load_config()
ok(crowdsec.active(cfg), "on, with a URL, a key and a bouncer: active")
ok(not CROWDSEC_SPOE.exists() and not CROWDSEC_BOUNCER_CFG.exists(),
   "saving the settings writes nothing for real: the check reads staged copies")
written = crowdsec.write_files(cfg)
ok(sorted(written) == ["crowdsec-spoa-bouncer.yaml", "crowdsec.cfg"],
   "Apply writes the SPOE engine and the bouncer's configuration: %s" % written)
ok(oct(CROWDSEC_BOUNCER_CFG.stat().st_mode & 0o777) == "0o640", "the bouncer's file is never world-readable")
yml = CROWDSEC_BOUNCER_CFG.read_text()
ok('api_url: "http://192.168.1.5:8080/"' in yml and 'api_key: "abc123"' in yml and "listen_tcp: 127.0.0.1:9000" in yml
   and "log_mode: stdout" in yml and "hosts:" not in yml,
   "the bouncer's YAML is whole: URL with its slash, the key, a local listener, no placeholders")
ok("use-backend crowdsec-spoa" in CROWDSEC_SPOE.read_text() and "crowdsec-http-no-body" in CROWDSEC_SPOE.read_text(),
   "the SPOE engine names the backend and the one HTTP message")
ok(re.search(r"^\s+log\s+global\n\s+option\s+dontlog-normal$", CROWDSEC_SPOE.read_text(), re.M)
   and "dontlog-normal" in crowdsec.SPOE_APPSEC,
   "and logs its failures only, not two lines for every request that went well")
ok(crowdsec.write_files(cfg) == [], "written once; unchanged files are left alone")
text = haproxy.render_haproxy(cfg)
fe = text[text.index("frontend fe_http-80"):text.index("\n\n", text.index("frontend fe_http-80"))]
ok("filter spoe engine crowdsec config %s" % CROWDSEC_SPOE in fe and "unique-id-format %[uuid()]" in fe,
   "an HTTP listener loads the engine")
ok("http-request send-spoe-group crowdsec crowdsec-http-no-body\n" in fe, "and asks about every request")
ok("lf-file %s/ban.html if cs_ban cs_html !cs_nohtml" % CROWDSEC_HTML in fe
   and 'string "Forbidden\\n" if cs_ban' in fe, "a ban is the bouncer's page for a browser, a line for anything else")
ok("captcha.html" not in fe and "Captcha required" not in fe, "no captcha lines in ban mode")
ok(fe.index("send-spoe-group") < fe.index("use_backend be_shop"), "asked before any routing")
tcp = text[text.index("frontend fe_tcp-5432"):]
tcp = tcp[:tcp.index("\n\n")]
ok("spoe" not in tcp, "a TCP listener is left alone: the answer is a page")
ok("backend crowdsec-spoa\n    mode tcp" in text and "server spoa 127.0.0.1:9000" in text, "and the agent backend exists once")
ok("tune.bufsize" not in text, "no buffer tuning in ban mode")
st = client.get("/api/status?brief=1", headers=H).get_json()
ok(st["crowdsec"]["on"] is True and st["crowdsec"]["installed"] is True, "the status says on, with the bouncer here")
s = client.get("/api/crowdsec/settings", headers=H).get_json()
ok(s["status"]["version"] == "0.4.0", "and the bouncer's version is read off it")

# ---- the pages: this installation's own 403, and a contact link ------------------------
client.post("/api/haproxy/errorpages", headers=H, json={"name": "banned", "codes": "403", "everywhere": True, "html": "<h1>No.</h1>"})
fe = haproxy.render_haproxy(load_config())
ok("file %s if cs_ban cs_html !cs_nohtml" % (pathlib.Path(os.environ["HAM_ERROR_DIR"]) / "banned-403.html") in fe,
   "an Error Page for 403 is what a banned browser sees")
c = load_config(); c["haproxy"]["errorpages"] = []; save_config(c)
put({"contact_url": "https://example.com/contact"})
fe = haproxy.render_haproxy(load_config())
ok("ban-with-contact.html" in fe, "with a contact URL and no own page, the bouncer's page with the link")
ok('contact_us_url: "https://example.com/contact"' in crowdsec.bouncer_yaml(load_config()), "and the bouncer is told the URL")

# ---- trusted networks, captcha ---------------------------------------------------------
lst = client.post("/api/haproxy/addresslists", headers=H, json={"name": "lan", "networks": "192.168.0.0/16"}).get_json()
put({"skip_lists": [lst["id"], "gone"]})
fe = haproxy.render_haproxy(load_config())
ok("acl cs_trusted src 192.168.0.0/16" in fe and "send-spoe-group crowdsec crowdsec-http-no-body unless cs_trusted" in fe,
   "a trusted list is never asked about")
put({"mode": "captcha", "captcha_provider": "turnstile", "captcha_site_key": "site", "captcha_secret_key": "sec"})
cfg = load_config()
yml = crowdsec.bouncer_yaml(cfg)
ok('host: "*"' in yml and 'provider: "turnstile"' in yml and 'site_key: "site"' in yml and 'secret_key: "sec"' in yml
   and len(cfg["crowdsec"]["captcha_signing_key"]) == 64 and cfg["crowdsec"]["captcha_signing_key"] in yml,
   "captcha: a catch-all host with the provider's keys and a signing key made once")
text = haproxy.render_haproxy(cfg)
ok("tune.bufsize 65536" in text and "lf-file %s/captcha.html if cs_captcha" % CROWDSEC_HTML in text
   and "Set-Cookie %[var(txn.crowdsec.captcha_cookie)]" in text and "redirect code 302 location %[url]" in text,
   "and HAProxy serves the captcha, sets its cookie and sends the solver back")
s = client.get("/api/crowdsec/settings", headers=H).get_json()
ok(s["has_captcha_secret"] and "captcha_secret_key" not in s and "captcha_signing_key" not in s, "the captcha secrets are never read back")

# ---- AppSec: the request travels too, and only when told where to -------------------------
put({"mode": "ban"})
cfg = load_config()
text = haproxy.render_haproxy(cfg)
ok("tune.bufsize" not in text and "http-buffer-request" not in text and "req.body" not in text
   and "appsec" not in crowdsec.bouncer_yaml(cfg) and crowdsec.spoe_text(cfg) == crowdsec.SPOE
   and "req.body" not in crowdsec.SPOE,
   "without an AppSec URL nothing is buffered, no body is sent and the bouncer is told nothing of it")
put({"appsec_url": "192.168.1.5:7422"}, want=400)
put({"appsec_url": "http://192.168.1.5:7422"})
cfg = load_config()
ok(crowdsec.appsec_on(cfg) and client.get("/api/crowdsec/settings", headers=H).get_json()["status"]["appsec"] is True,
   "an AppSec URL is all it takes, and the status says so")
ok('appsec_url: "http://192.168.1.5:7422/"' in crowdsec.bouncer_yaml(cfg), "the bouncer is told where AppSec listens")
written = crowdsec.write_files(cfg)
spoe = CROWDSEC_SPOE.read_text()
ok(sorted(written) == ["crowdsec-spoa-bouncer.yaml", "crowdsec.cfg"], "both files are written again, so the bouncer restarts")
ok("groups      crowdsec-http-body crowdsec-http-no-body" in spoe and "body=req.body" in spoe
   and spoe.count("spoe-message") == 3 and spoe.count("spoe-group") == 2,
   "the SPOE engine gains the message that carries the body, and keeps the one that does not")
text = haproxy.render_haproxy(cfg)
fe = text[text.index("frontend fe_http-80"):text.index("\n\n", text.index("frontend fe_http-80"))]
ok("option http-buffer-request" in fe and "acl cs_body_fits req.body_size -m int le 51200" in fe,
   "an HTTP listener waits for the body and knows which ones fit a frame")
ok("send-spoe-group crowdsec crowdsec-http-body if !cs_trusted cs_body_fits || !cs_trusted !{ req.body_size -m found }\n" in fe
   and "send-spoe-group crowdsec crowdsec-http-no-body if !cs_trusted !cs_body_fits { req.body_size -m found }\n" in fe,
   "a body that fits goes with the question, a larger one stays behind, and the trusted are asked neither")
ok(fe.count("send-spoe-group") == 2 and "status 413" not in fe, "nothing is refused for its size unless asked")
ok("tune.bufsize 65536" in text, "the buffer is the size a frame with a body needs")
tcp = text[text.index("frontend fe_tcp-5432"):]
ok("http-buffer-request" not in tcp[:tcp.index("\n\n")], "a TCP listener is still left alone")
put({"appsec_reject_large": True})
fe = haproxy.render_haproxy(load_config())
fe = fe[fe.index("frontend fe_http-80"):]
ok('http-request return status 413 content-type text/plain string "Request body too large to inspect\\n" '
   'if !cs_trusted { req.body_size -m found } !cs_body_fits\n' in fe
   and fe.index("status 413") < fe.index("send-spoe-group"),
   "asked for, a body AppSec cannot read is refused with 413 before anything else -- but not from the trusted")
put({"skip_lists": []})
fe = haproxy.render_haproxy(load_config())
ok("cs_trusted" not in fe and "crowdsec-http-body if cs_body_fits || !{ req.body_size -m found }\n" in fe
   and "crowdsec-http-no-body if !cs_body_fits { req.body_size -m found }\n" in fe
   and "if { req.body_size -m found } !cs_body_fits\n" in fe, "with nobody trusted, the same without the exception")


class FakeRequests:
    """Stands in for the AppSec listener: says what it was asked, answers as told."""
    def __init__(self):
        self.calls, self.status = [], 200

    def get(self, url, **kw):
        self.calls.append((url, kw))
        return type("R", (), {"status_code": self.status})()


real_requests, fake = crowdsec._requests, FakeRequests()
crowdsec._requests = fake
post = lambda body: client.post("/api/crowdsec/test-appsec", headers=H, json=body).get_json()   # noqa: E731
r = post({})
url, kw = fake.calls[-1]
ok(r["ok"] is True and url == "http://192.168.1.5:7422/" and kw["headers"]["X-Crowdsec-Appsec-Api-Key"] == "abc123"
   and kw["headers"]["X-Crowdsec-Appsec-Uri"] == "/" and kw["headers"]["X-Crowdsec-Appsec-Verb"] == "GET"
   and kw.get("verify", True) is True,
   "the AppSec test asks the stored address the way the bouncer does, with the stored key")
r = post({"appsec_url": "http://192.168.1.5:9999/"})
ok(r["ok"] is True and fake.calls[-1][0] == "http://192.168.1.5:9999/", "another port on the LAPI's own host may have the stored key")
n = len(fake.calls)
r = post({"appsec_url": "http://203.0.113.9:7422/"})
ok(r["ok"] is False and "needed first" in r["message"] and len(fake.calls) == n, "any other host is not sent the stored key")
r = post({"appsec_url": "http://203.0.113.9:7422/", "api_key": "typed"})
ok(r["ok"] is True and fake.calls[-1][1]["headers"]["X-Crowdsec-Appsec-Api-Key"] == "typed", "but is asked with a key typed for it")
r = post({"appsec_url": "203.0.113.9:7422", "api_key": "typed"})
ok(r["ok"] is False and "must start with" in r["message"], "an address without a scheme is not asked at all")
fake.status = 401
r = post({})
ok(r["ok"] is False and "refused the API key" in r["message"], "a key AppSec refuses is reported as that")
fake.status = 403
ok(post({})["ok"] is True, "AppSec blocking the test request is still AppSec answering")
fake.status = 500
ok(post({})["ok"] is False, "anything else is reported as it came")
crowdsec._requests = real_requests
r = post({"appsec_url": "http://127.0.0.1:1", "api_key": "x"})
ok(r["ok"] is False and "did not answer" in r["message"], "an AppSec that is not there is reported as such")
put({"appsec_url": ""})
r = post({})
ok(r["ok"] is False and "needed first" in r["message"] and not crowdsec.appsec_on(load_config()), "emptied, AppSec is off again")
put({"appsec_url": "http://192.168.1.5:7422/", "skip_lists": [lst["id"]], "mode": "captcha"})

# ---- the install: only when wanted, only when missing, not again and again ---------------
bouncer_present(False)
installs.clear()
fake_install.result = (True, "installed")
put({"enabled": False})
crowdsec.startup()
ok(not installs, "a node with CrowdSec off is never given a third-party repository")
put({"enabled": True})
crowdsec.NOT_WANTED.parent.mkdir(parents=True, exist_ok=True)
crowdsec.NOT_WANTED.write_text("")
crowdsec.startup()
ok(not installs, "nor a node marked as not wanting the bouncer")
crowdsec.NOT_WANTED.unlink()
crowdsec.startup()
ok(installs == [1], "a node with CrowdSec on and no bouncer gets it at startup")
fake_install.result = (False, "no network")
crowdsec.startup()
ok(installs == [1, 1] and crowdsec.TRIED.exists(), "a failed install is remembered")
crowdsec.startup()
ok(installs == [1, 1], "and not retried at the next start")
crowdsec.TRIED.unlink()
bouncer_present(True)
crowdsec.startup()
ok(installs == [1, 1], "a node that has it is left alone")
bouncer_present(False)
step, warning = crowdsec.ensure_service(load_config())
ok(installs == [1, 1, 1] and "not installed" in warning, "Apply tries once more, and says so when it fails")
crowdsec.NOT_WANTED.write_text("")
r = client.post("/api/crowdsec/install", headers=H, json={}).get_json()
ok(r["ok"] is False and "no network" in r["message"], "asked for by hand, the button says why it failed")
fake_install.result = (True, "installed")
bouncer_present(True)
r = client.post("/api/crowdsec/install", headers=H, json={}).get_json()
ok(r["ok"] is True and not crowdsec.NOT_WANTED.exists() and not crowdsec.TRIED.exists(),
   "asked for by hand, the node is wanted after all")
r = client.post("/api/crowdsec/test", headers=H, json={"api_url": "http://127.0.0.1:1/"}).get_json()
ok(r["ok"] is False and "needed first" in r["message"], "the stored key is not sent to an address that is not the stored one")

# ---- the LAPI test ----------------------------------------------------------------------
r = client.post("/api/crowdsec/test", headers=H, json={"api_url": "http://127.0.0.1:1", "api_key": "x"}).get_json()
ok(r["ok"] is False and "did not answer" in r["message"], "a LAPI that is not there is reported as such")

crowdsec._requests = fake
lapi = lambda url: client.post("/api/crowdsec/test", headers=H, json={"api_url": url, "api_key": "x"}).get_json()   # noqa: E731
fake.status = 404
r = lapi("http://127.0.0.1:%d" % crowdsec.PORT)
ok(r["ok"] is False and "own interface" in r["message"] and "listen_uri" in r["message"],
   "a LAPI URL that leads to this interface is called that, with the way out: %s" % r["message"][:60])
r = lapi("http://localhost:%d/" % crowdsec.PORT)
ok(r["ok"] is False and "own interface" in r["message"], "by name as well")
r = lapi("http://127.0.0.1:%d" % (crowdsec.PORT + 1))
ok(r["ok"] is False and "own interface" not in r["message"] and "answered 404" in r["message"] and "not a CrowdSec LAPI" in r["message"],
   "a 404 from anywhere else is something that is not a LAPI")
r = lapi("http://192.0.2.7:%d" % crowdsec.PORT)
ok(r["ok"] is False and "own interface" not in r["message"], "the same port on another machine is not this interface")
fake.status = 500
r = lapi("http://127.0.0.1:%d" % (crowdsec.PORT + 1))
ok(r["ok"] is False and r["message"] == "the LAPI answered 500", "any other answer is reported as it came")
fake.status = 403
r = lapi("http://127.0.0.1:%d" % crowdsec.PORT)
ok(r["ok"] is False and "refused the API key" in r["message"], "a refused key is still a refused key")
fake.status = 200
ok(lapi("http://127.0.0.1:%d" % crowdsec.PORT)["ok"] is True, "and a LAPI that answers is a LAPI, whatever its port")
crowdsec._requests = real_requests

# ---- off again ---------------------------------------------------------------------------
put({"enabled": False})
text = haproxy.render_haproxy(load_config())
ok("spoe" not in text and "crowdsec" not in text and "http-buffer-request" not in text and "bufsize" not in text,
   "off again: no trace in the file, AppSec URL or not")
bouncer_present(False)
step, warning = crowdsec.ensure_service(load_config())
ok(step == "" and warning == "", "and nothing to stop on a node without the bouncer")
bouncer_present(True)

# ---- the rendered file is one HAProxy accepts, engine and all -----------------------------
put({"enabled": True})

# ---- gRPC beside AppSec (#37) ------------------------------------------------------------
# A stream is a request whose body never ends, and a listener that waits for
# whole bodies never lets one through. A service marked as speaking gRPC --
# HTTP/2 to its servers -- has its gRPC requests let through unwaited, and
# asked about without their body. Nothing else is, whatever it claims to be.
fe = haproxy.render_haproxy(load_config())
fe = fe[fe.index("frontend fe_http-80"):fe.index("\n\n", fe.index("frontend fe_http-80"))]
ok("option http-buffer-request" in fe and "wait-for-body" not in fe and "cs_stream" not in fe,
   "with no gRPC service on the listener, it waits for bodies the way it always did")
r = client.post("/api/wizard/publish", headers=H, json={
    "url": "http://grpc.example.com", "target": "https://10.0.0.7:443", "certificate": False,
    "http_redirect": False, "server_http2": True, "dry_run": False})
ok(r.status_code == 200, "a gRPC service is published: HTTP/2 to its servers")
fe = haproxy.render_haproxy(load_config())
fe = fe[fe.index("frontend fe_http-80"):fe.index("\n\n", fe.index("frontend fe_http-80"))]
ok("option http-buffer-request" not in fe
   and "http-request wait-for-body time 24h unless cs_stream || cs_trusted\n" in fe,
   "the listener then waits per request, and not for a stream or the trusted")
marks = [ln.strip() for ln in fe.splitlines() if "set-var(txn.cs_stream)" in ln]
ok(len(marks) == 1 and marks[0].startswith("http-request set-var(txn.cs_stream) bool(1) if acl_host-") and marks[0].endswith(" cs_grpc")
   and "acl cs_grpc req.hdr(content-type) -m beg application/grpc" in fe,
   "a stream is a gRPC request for that service, and no other: %s" % marks)
ok("crowdsec-http-body if !cs_trusted !cs_stream cs_body_fits || !cs_trusted !cs_stream !{ req.body_size -m found }\n" in fe
   and "crowdsec-http-no-body if !cs_trusted !cs_body_fits { req.body_size -m found } || !cs_trusted cs_stream\n" in fe,
   "it is asked about without its body, and everything else as before")
ok("if !cs_trusted !cs_stream { req.body_size -m found } !cs_body_fits\n" in fe, "and is not refused for a size it does not have")
ok(fe.index("set-var(txn.cs_stream)") < fe.index("wait-for-body") < fe.index("status 413") < fe.index("send-spoe-group"),
   "in that order: what it is, whether to wait, then the questions")
ok(crowdsec._and(" if a b || c", "x") == " if a b x || c x" and crowdsec._and("", "x") == " if x",
   "a rule with alternatives marks a stream in each of them")
apply._selfsigned_placeholder(CERT_DIR / "stand-in.pem", ["stand-in"])
crowdsec.write_files(load_config())
text = haproxy.render_haproxy(load_config())
ok("crowdsec-http-body" in text and "status 413" in text and "captcha.html" in text and "cs_trusted" in text,
   "what is checked next has all of it: AppSec, the size limit, the captcha and a trusted list")
fd, path = tempfile.mkstemp(suffix=".cfg")
with os.fdopen(fd, "w") as f:
    f.write(text)
try:
    r = subprocess.run(["haproxy", "-c", "-f", path], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        ok(True, "haproxy -c accepts the configuration with the SPOE engine, the captcha and AppSec")
    else:
        ok(False, "haproxy -c: " + (r.stderr or r.stdout).strip()[-400:])
except FileNotFoundError:
    print("  ....  no haproxy here; the text checks above stand")
finally:
    os.unlink(path)

print("\n" + ("%d failed" % len(fails) if fails else "asked about everyone, answered for the banned, silent when off"))
sys.exit(1 if fails else 0)
