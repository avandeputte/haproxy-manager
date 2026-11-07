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

# ---- off again ---------------------------------------------------------------------------
put({"enabled": False})
text = haproxy.render_haproxy(load_config())
ok("spoe" not in text and "crowdsec" not in text, "off again: no trace in the file")
bouncer_present(False)
step, warning = crowdsec.ensure_service(load_config())
ok(step == "" and warning == "", "and nothing to stop on a node without the bouncer")
bouncer_present(True)

# ---- the rendered file is one HAProxy accepts, engine and all -----------------------------
put({"enabled": True})
apply._selfsigned_placeholder(CERT_DIR / "stand-in.pem", ["stand-in"])
crowdsec.write_files(load_config())
text = haproxy.render_haproxy(load_config())
fd, path = tempfile.mkstemp(suffix=".cfg")
with os.fdopen(fd, "w") as f:
    f.write(text)
try:
    r = subprocess.run(["haproxy", "-c", "-f", path], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        ok(True, "haproxy -c accepts the configuration with the SPOE engine")
    else:
        ok(False, "haproxy -c: " + (r.stderr or r.stdout).strip()[-400:])
except FileNotFoundError:
    print("  ....  no haproxy here; the text checks above stand")
finally:
    os.unlink(path)

print("\n" + ("%d failed" % len(fails) if fails else "asked about everyone, answered for the banned, silent when off"))
sys.exit(1 if fails else 0)
