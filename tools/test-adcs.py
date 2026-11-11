#!/usr/bin/env python3
"""Certificates from Active Directory Certificate Services, through the
acme2certifier the node runs for an issuance.

    python3 tools/test-adcs.py

An ACME account with "adcs" as its CA names the CA's server, template and a
service account. What such an account refuses before it is stored, what
acme2certifier is given (its acme_srv.cfg), and what happens at an issuance:
acme2certifier is started on localhost, acme.sh is pointed at it, and it is
stopped and its configuration -- it holds the password -- removed afterwards.
A stand-in acme2certifier answers the directory; a stand-in acme.sh records
what it was given and what it found running.
"""
import configparser
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ["HAM_DATA_DIR"] = tempfile.mkdtemp(prefix="ham-adcs-")
D = os.environ["HAM_DATA_DIR"]
os.environ["HAM_CERT_DIR"] = os.path.join(D, "certs")
os.environ["HAM_ERROR_DIR"] = os.path.join(D, "error-pages")
os.environ["HAM_ACME_HOME"] = os.path.join(D, "acme")
os.environ["HAM_ACME_SH"] = os.path.join(D, "acme.sh")
os.environ["HAM_A2C_DIR"] = os.path.join(D, "a2c-dir")
os.environ["HAM_A2C_STATE"] = os.path.join(D, "a2c-state")
os.environ["HAM_DRY_RUN"] = "1"
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    os.environ["HAM_A2C_PORT"] = str(s.getsockname()[1])
PORT = int(os.environ["HAM_A2C_PORT"])

# The stand-in acme2certifier: the WSGI application acme2certifier's entry
# point exports, served by the same waitress the real one is, answering a
# directory. It checks that it was given a configuration and where.
A2C_DIR = pathlib.Path(os.environ["HAM_A2C_DIR"])
A2C_DIR.mkdir()
(A2C_DIR / "acme2certifier_wsgi.py").write_text(r'''
import json, os, pathlib
print("stand-in acme2certifier loaded", flush=True)
seen = {"cfg": os.environ.get("ACME_SRV_CONFIGFILE", ""), "cwd": os.getcwd(),
        "cfg_text": pathlib.Path(os.environ.get("ACME_SRV_CONFIGFILE", "/nonexistent")).read_text()
                    if os.path.exists(os.environ.get("ACME_SRV_CONFIGFILE", "/nonexistent")) else ""}
def application(environ, start_response):
    if environ.get("PATH_INFO") == "/directory":
        body = {"newNonce": "n", "newAccount": "a", "newOrder": "o", "seen": seen}
        start_response("200 OK", [("Content-Type", "application/json")])
        return [json.dumps(body).encode()]
    start_response("404 Not Found", [])
    return [b""]
''')

# The stand-in acme.sh: records its arguments, whether acme2certifier's
# directory answered while it ran, and the configuration file's mode.
RUNS = os.path.join(D, "runs.txt")
os.makedirs(os.environ["HAM_ACME_HOME"], exist_ok=True)
pathlib.Path(os.environ["HAM_ACME_SH"]).write_text(r'''#!/bin/sh
up=no; python3 -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:%d/directory', timeout=3)" 2>/dev/null && up=yes
mode=none; [ -f "$HAM_A2C_STATE/acme_srv.cfg" ] && mode=$(stat -c %%a "$HAM_A2C_STATE/acme_srv.cfg")
echo "up=$up cfg=$mode $*" >> "%s"
case "$*" in *--issue*) exit 1;; esac
exit 0
''' % (PORT, RUNS))
os.chmod(os.environ["HAM_ACME_SH"], 0o755)

import ham; ham   # noqa: E402  (route registration)
from ham import acme, adcs, mcp   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "ad-key"
save_config(cfg)
H = {"X-API-Key": "ad-key"}

GOOD = {"name": "corp", "ca": "adcs", "adcs_method": "msicpr", "adcs_host": "ca01.corp.example.lan",
        "adcs_ca_name": "Corp Issuing CA", "adcs_template": "WebServer", "adcs_auth": "kerberos",
        "adcs_domain": "corp.example.lan", "adcs_dc": "", "adcs_user": "svc-acme",
        "adcs_password": 'p%ss"w#d=x'}


def add_account(body, want):
    r = client.post("/api/acme/accounts", headers=H, json=body)
    err = (r.get_json() or {}).get("error") or ""
    ok(r.status_code == want, "account %s -> %d %s" % (body.get("name"), r.status_code, err[:110]))
    return r.get_json() or {}, err


print("what an account refuses")
_, err = add_account(dict(GOOD, name="no-host", adcs_host=""), 400)
ok("certification authority's server" in err, "without the CA server it says it needs one")
add_account(dict(GOOD, name="bad-host", adcs_host="ca01.corp example"), 400)
add_account(dict(GOOD, name="url-host", adcs_host="https://ca01.corp.example.lan"), 400)
_, err = add_account(dict(GOOD, name="no-template", adcs_template=""), 400)
ok("template" in err, "without a template it says so")
_, err = add_account(dict(GOOD, name="no-user", adcs_user=""), 400)
ok("service account" in err, "without a user it says so")
_, err = add_account(dict(GOOD, name="no-pw", adcs_password=""), 400)
ok("password" in err, "without a password it says so")
_, err = add_account(dict(GOOD, name="no-ca-name", adcs_ca_name=""), 400)
ok("certification authority's name" in err and "certutil" in err, "MS-ICPR without the CA name says so")
_, err = add_account(dict(GOOD, name="no-domain", adcs_domain=""), 400)
ok("Kerberos needs the Active Directory domain" in err, "Kerberos without the domain says so")
_, err = add_account(dict(GOOD, name="basic-rpc", adcs_auth="basic"), 400)
ok("MS-ICPR" in err and "kerberos or ntlm" in err, "MS-ICPR with basic authentication is refused")
_, err = add_account(dict(GOOD, name="web-krb", adcs_method="certsrv", adcs_auth="kerberos"), 400)
ok("ntlm or basic" in err, "web enrollment with Kerberos is refused")
_, err = add_account(dict(GOOD, name="multiline", adcs_password="a\nb"), 400)
ok("one line" in err, "a password over two lines is refused: " + err[:60])
_, err = add_account(dict(GOOD, name="bad-pem", adcs_method="certsrv", adcs_auth="ntlm", ca_bundle="nope"), 400)
ok("PEM" in err, "web enrollment with a CA certificate that is not PEM is refused")
add_account(dict(GOOD, name="odd-method", adcs_method="ldap"), 400)
add_account(GOOD, 200)
add_account(dict(GOOD, name="ntlm-no-domain", adcs_auth="ntlm", adcs_domain=""), 200)
add_account(dict(GOOD, name="web", adcs_method="certsrv", adcs_auth="ntlm", adcs_ca_name="", adcs_domain=""), 200)
add_account({"name": "le", "ca": "letsencrypt"}, 200)
accs = {a["name"]: a for a in load_config()["acme"]["accounts"]}
ok(set(accs) == {"corp", "ntlm-no-domain", "web", "le"}, "only the valid accounts were stored: %s" % sorted(accs))
ok(mcp.redact(dict(accs["corp"], adcs_extra="[CAhandler]\npassword: x"))["adcs_extra"] == "[redacted]",
   "and so are the extra settings, which can hold one")
ok(mcp.redact(accs["corp"])["adcs_password"] == "[redacted]", "the password is a secret to MCP")

print("what acme2certifier is given")
text = adcs.config_text(accs["corp"])
cp = configparser.ConfigParser(interpolation=None)
cp.read_string(text)
ca = cp["CAhandler"]
ok(ca["handler_module"].endswith("msicpr_ca_handler"), "MS-ICPR: acme2certifier's msicpr handler")
ok(ca["host"] == "ca01.corp.example.lan" and ca["ca_name"] == "Corp Issuing CA" and ca["template"] == "WebServer",
   "with the CA server, its name and the template")
ok(ca["user"] == "svc-acme" and ca["password"] == 'p%ss"w#d=x', "the service account, the password as typed")
ok(ca["use_kerberos"] == "True" and ca["target_domain"] == "corp.example.lan" and "domain_controller" not in ca,
   "Kerberos with the domain, and no domain controller when none was given")
ok(cp["DBhandler"]["dbfile"].startswith(os.environ["HAM_A2C_STATE"]), "its database lives in the state directory")
ok(cp["Challenge"]["challenge_validation_disable"] == "False" and cp["Nonce"]["nonce_check_disable"] == "False",
   "nothing is switched off")
ok(cp["Account"]["contact_check_disable"] == "True" and cp["Account"]["tos_check_disable"] == "True",
   "except the contact and the terms, which acme.sh here has neither of")
cp = configparser.ConfigParser(interpolation=None)
cp.read_string(adcs.config_text(dict(accs["corp"], adcs_auth="ntlm", adcs_dc="10.0.0.5")))
ok(cp["CAhandler"]["use_kerberos"] == "False" and cp["CAhandler"]["domain_controller"] == "10.0.0.5",
   "NTLM, with the domain controller given")
cp = configparser.ConfigParser(interpolation=None)
cp.read_string(adcs.config_text(accs["web"], "/state/ca-bundle.pem"))
ca = cp["CAhandler"]
ok(ca["handler_module"].endswith("mscertsrv_ca_handler") and ca["auth_method"] == "ntlm"
   and ca["ca_bundle"] == "/state/ca-bundle.pem" and "ca_name" not in ca and "use_kerberos" not in ca,
   "web enrollment: the mscertsrv handler, NTLM, the CA certificate to trust")
extra = ('[CAhandler]\ntimeout: 30\nkrb5_keytab: /etc/ham/svc.keytab\n[Challenge]\ndns_server_list: ["10.0.0.53"]\n'
         '[Order]\nallowed_domainlist: ["*.corp.example.lan"]\n[DEFAULT]\ndebug: True\n')
cp = configparser.ConfigParser(interpolation=None)
cp.read_string(adcs.config_text(dict(accs["corp"], adcs_extra=extra)))
ok(cp["CAhandler"]["timeout"] == "30" and cp["CAhandler"]["host"] == "ca01.corp.example.lan",
   "an extra setting replaces the generated one, the rest stays")
ok(cp["CAhandler"]["krb5_keytab"] == "/etc/ham/svc.keytab" and cp["Challenge"]["dns_server_list"] == '["10.0.0.53"]'
   and cp["Order"]["allowed_domainlist"] == '["*.corp.example.lan"]', "new settings are added, in their sections")
ok(cp["DEFAULT"]["debug"] == "True", "a [DEFAULT] of the account's own is taken too")
ok(cp["DBhandler"]["dbfile"].startswith(os.environ["HAM_A2C_STATE"]) and cp["Challenge"]["challenge_validation_disable"] == "False",
   "the database and the untouched settings are as before")
_, err = add_account(dict(GOOD, name="extra-db", adcs_extra="[DBhandler]\ndbfile: /tmp/x.db\n"), 400)
ok("[DBhandler]" in err, "extra settings may not move the database")
for bad, what in (("[CAhandler]\nhandler_module: /tmp/evil.py\n", "a handler by file path"),
                  ("[CAhandler]\nhandler_module: os\n", "a module that is not acme2certifier's"),
                  ("[Hooks]\nhooks_file: /tmp/evil.py\n", "a hooks file"),
                  ("[EABhandler]\neab_handler_module: ../x.py\n", "an EAB handler by path"),
                  ("[CAhandler:two]\nhandler_file: /tmp/evil.py\n", "a handler file in a second handler"),
                  ("[Helper]\nlog_file: /etc/cron.d/x\n", "a log file of its choosing"),
                  ("[CAhandler]\nkrb5_kinit_path: /tmp/kinit\n", "a kinit outside the system's")):
    _, err = add_account(dict(GOOD, name="extra-code", adcs_extra=bad), 400)
    ok("extra acme2certifier settings" in err or "kinit" in err, "extra settings may not name %s: %s" % (what, err[:60]))
add_account(dict(GOOD, name="extra-builtin", adcs_extra="[EABhandler]\neab_handler_module: acme2certifier.eabhandlers.kid_profile_handler\n"
                                                       "[CAhandler]\nkrb5_kinit_path: /usr/bin/kinit\n"), 200)
_, err = add_account(dict(GOOD, name="extra-nosec", adcs_extra="timeout: 30\n"), 400)
ok("section headers" in err, "extra settings without a section header say so")
_, err = add_account(dict(GOOD, name="extra-broken", adcs_extra="[CAhandler]\nthis is not a setting\n"), 400)
ok("acme_srv.cfg lines" in err, "extra settings that do not parse say so: " + err[:70])
r = client.post("/api/acme/adcs/config", headers=H, json=dict(GOOD, adcs_extra="[CAhandler]\ntimeout: 30\n")).get_json()
ok(r["ok"] and "timeout = 30" in r["config"] and "msicpr_ca_handler" in r["config"],
   "the configuration is shown with the extra settings laid over")
ok(GOOD["adcs_password"] not in r["config"] and "password = ********" in r["config"], "with the password masked")
r = client.post("/api/acme/adcs/config", headers=H,
                json=dict(GOOD, adcs_password="e", adcs_extra="[EABhandler]\nhmac_key: other-sekrit\n")).get_json()
ok(r["ok"] and "other-sekrit" not in r["config"] and "hmac_key = ********" in r["config"]
   and "handler_module = acme2certifier" in r["config"],
   "masked by setting, not by text: a one-letter password leaves the rest readable, a credential in the extras is hidden")
r = client.post("/api/acme/adcs/config", headers=H, json=dict(GOOD, adcs_host="")).get_json()
ok(not r["ok"] and "certification authority's server" in r["error"], "or the reason an incomplete account is refused")
ok(acme.server_args(accs["corp"]) == ["--server", "http://127.0.0.1:%d/directory" % PORT],
   "acme.sh is pointed at acme2certifier on localhost")
ok(acme.check_directory(accs["corp"]) == "", "the directory is not read ahead: nothing is running yet")

print("where acme2certifier is installed")
ok(not adcs.installed() or adcs._module("acme2certifier"), "an entry point without its package is not an install")
(A2C_DIR / "acme2certifier" / "acme_srv").mkdir(parents=True)
(A2C_DIR / "acme2certifier" / "__init__.py").write_text("")
(A2C_DIR / "acme2certifier" / "acme_srv" / "version.py").write_text('__version__ = "9.9.9"\n')
ok(adcs.installed() and adcs.a2c_dir() == A2C_DIR, "the package beside the entry point counts, as the .rpm lays it out")
ok(adcs.version() in ("9.9.9", adcs.A2C_VERSION), "its version is read from the package when there is no metadata: %s" % adcs.version())
import email.message   # noqa: E402
hdrs = email.message.Message()
hdrs["WWW-Authenticate"] = "Negotiate"
hdrs["WWW-Authenticate"] = "NTLM"
ok(adcs.offers_ntlm(hdrs), "a 401 that offers Negotiate before NTLM, as IIS does, offers NTLM")
basic = email.message.Message()
basic["WWW-Authenticate"] = 'Basic realm="x"'
ok(not adcs.offers_ntlm(basic), "one that offers only basic does not")

print("issuing")
REAL = {k: getattr(adcs, k) for k in ("installed", "missing_for", "ensure_installed", "install")}
# The stand-in stands in: acme2certifier counts as installed, Impacket too.
adcs.installed = lambda: True
adcs.missing_for = lambda acc: ""
cfg = load_config()
cfg["acme"]["challenges"].append({"id": "ch1", "name": "http", "method": "http01"})
cfg["acme"]["certificates"].append({"id": "c-corp", "name": "c-corp", "domains": "web.corp.example.lan",
                                    "account": accs["corp"]["id"], "challenge": "ch1"})
cfg["acme"]["certificates"].append({"id": "c-le", "name": "c-le", "domains": "le.example.lan",
                                    "account": accs["le"]["id"], "challenge": "ch1"})
save_config(cfg)
cfg = load_config()
certs = {c["id"]: c for c in cfg["acme"]["certificates"]}
t0 = time.time()
res = acme.acme_issue(cfg, certs["c-corp"])
took = time.time() - t0
runs = pathlib.Path(RUNS).read_text().splitlines()
ok(len(runs) == 2, "register and issue: %d runs, in %.1fs" % (len(runs), took))
reg, iss = (runs + ["", ""])[:2]
ok(reg.startswith("up=yes") and iss.startswith("up=yes"), "acme2certifier answered its directory while acme.sh ran")
ok(" cfg=600 " in reg and " cfg=600 " in iss, "its configuration was on disk, mode 0600: %s" % reg.split()[1])
ok("--register-account" in reg and "--server http://127.0.0.1:%d/directory" % PORT in reg,
   "the account is registered with it")
ok("--issue --server http://127.0.0.1:%d/directory" % PORT in iss and "--ca-bundle" not in iss,
   "the certificate is requested from it, over plain HTTP on localhost")
state = pathlib.Path(os.environ["HAM_A2C_STATE"])
ok(not (state / "acme_srv.cfg").exists(), "the configuration, which holds the password, is gone afterwards")
try:
    urllib.request.urlopen("http://127.0.0.1:%d/directory" % PORT, timeout=2)
    still = True
except Exception:
    still = False
ok(not still, "acme2certifier is stopped afterwards")
log_text = res.get("log") or ""
ok("--- acme2certifier ---" in log_text and "stand-in acme2certifier loaded" in log_text.split("--- acme2certifier ---")[1],
   "its output is kept with the issue log, under acme.sh's")
ok(not res["ok"] and "issuance failed" in res["error"], "the stand-in's refusal is reported: %s" % res["error"][:80])
# What the stand-in saw: the configuration named by ACME_SRV_CONFIGFILE, in
# the directory acme2certifier's entry point lives in.
seen = None
# (the stand-in's view travelled in the directory the stand-in acme.sh fetched; read it again live)
with adcs.serving(accs["corp"], []) as why:
    ok(why == "", "started again for a look: %s" % why)
    body = json.loads(urllib.request.urlopen("http://127.0.0.1:%d/directory" % PORT, timeout=3).read())
    seen = body["seen"]
ok(seen and seen["cfg"] == str(state / "acme_srv.cfg") and seen["cwd"] == str(A2C_DIR),
   "ACME_SRV_CONFIGFILE names the configuration, and it runs from acme2certifier's directory")
ok(seen and "handler_module = acme2certifier.cahandlers.msicpr_ca_handler" in seen["cfg_text"],
   "and the configuration it read is the account's")

before = len(pathlib.Path(RUNS).read_text().splitlines())
acme.acme_issue(cfg, certs["c-le"])
runs = pathlib.Path(RUNS).read_text().splitlines()
ok(len(runs) == before + 2 and runs[-1].startswith("up=no") and "--server letsencrypt" in runs[-1],
   "a Let's Encrypt certificate runs without acme2certifier")

print("when acme2certifier will not start")
good_command = adcs.command
adcs.command = lambda: [sys.executable, "-c", "import sys; print('boom: no such handler'); sys.exit(3)"]
adcs.READY_WAIT = 5
before = len(pathlib.Path(RUNS).read_text().splitlines())
res = acme.acme_issue(cfg, certs["c-corp"])
ok(not res["ok"] and "did not start" in res["error"] and "boom" in res["error"],
   "a start that fails says so, with its last words: %s" % res["error"][:100])
ok(len(pathlib.Path(RUNS).read_text().splitlines()) == before, "and acme.sh was not run")
adcs.command = good_command

print("when it is not installed")
adcs.installed = lambda: False
adcs.ensure_installed = lambda: (False, "the install did not finish: no apt here")
before = len(pathlib.Path(RUNS).read_text().splitlines())
res = acme.acme_issue(cfg, certs["c-corp"])
ok(not res["ok"] and "could not be installed" in res["error"] and "no apt here" in res["error"],
   "a node without it that cannot get it says so: %s" % res["error"][:100])
ok(len(pathlib.Path(RUNS).read_text().splitlines()) == before, "and acme.sh was not run")
r = client.get("/api/acme/health", headers=H).get_json()
ok(r.get("adcs", {}).get("wanted") is True and r["adcs"]["installed"] is False and r["adcs"]["port"] == PORT,
   "the health check says AD CS is wanted and acme2certifier missing")
adcs.installed = lambda: True

print("what acme2certifier's output explains")
ok(adcs.explain("x\nCAhandler.enroll() Could not get certificate from CA server\ny").startswith("Could not get certificate"),
   "the CA's refusal")
ok("Failed to connect to endpoint mapper" in adcs.explain("Trying\nFailed to connect to endpoint mapper: [Errno -2] Name or service not known\n"),
   "a connection that failed")
ok(adcs.explain("Failed to connect to endpoint mapper: refused\nCould not get certificate from CA server\n")
   .startswith("Failed to connect"), "the specific line before the handler's summary")
ok(adcs.explain("all fine") == "", "nothing when nothing went wrong")

print("testing the connection")
r = client.post("/api/acme/adcs/test", headers=H, json=dict(GOOD, adcs_host="")).get_json()
ok(r["ok"] is False and "certification authority's server" in r["message"], "an incomplete account is refused with why")
adcs._serving.acquire()
t0 = time.time()
r = client.post("/api/acme/adcs/test", headers=H, json=GOOD).get_json()
adcs._serving.release()
ok(r["ok"] is False and "being requested" in r["message"] and time.time() - t0 < 10,
   "while an issuance has acme2certifier, the test says so instead of waiting for it")
r = client.post("/api/acme/adcs/test", headers=H,
                json=dict(GOOD, adcs_method="certsrv", adcs_auth="basic", adcs_host="localhost")).get_json()
ok(r["ok"] is False and "could not reach" in r["message"], "web enrollment nobody answers for: %s" % r["message"][:70])

print("the certificate wizard")
r = client.post("/api/wizard/certificate", headers=H, json={
    "domains": "app.corp.example.lan", "issue": False, "dry_run": True,
    "account": dict(GOOD, name="wiz", adcs_host=""), "challenge": {"id": "ch1"}})
ok(r.status_code == 400 and "certification authority's server" in (r.get_json() or {}).get("error", ""),
   "a new AD CS account without the CA server is refused (%d)" % r.status_code)
r = client.post("/api/wizard/certificate", headers=H, json={
    "domains": "app.corp.example.lan", "issue": False,
    "account": dict(GOOD, name="wiz"), "challenge": {"id": "ch1"}})
ok(r.status_code == 200, "a complete one is created (%d %s)" % (r.status_code, ((r.get_json() or {}).get("error") or "")[:80]))
new = [a for a in load_config()["acme"]["accounts"] if a["name"] == "wiz"]
ok(new and new[0]["adcs_host"] == "ca01.corp.example.lan" and new[0]["adcs_password"] == GOOD["adcs_password"]
   and new[0]["adcs_template"] == "WebServer", "with the CA server, template and credentials stored")

print("getting it onto a node")
# Every node gets it when the service starts, whether or not an account uses
# it; nobody presses anything. The install itself is stood in for.
import threading   # noqa: E402
adcs.ensure_installed = REAL["ensure_installed"]
adcs.STARTUP_TRIES = (0, 0, 0)
state = {"there": False, "works": False, "runs": 0}
adcs.installed = lambda: state["there"]


def fake_install():
    state["runs"] += 1
    if state["works"]:
        state["there"] = True
        return True, "installed acme2certifier"
    return False, "the install did not finish: could not resolve github.com"


adcs.install = fake_install
cfg = load_config()
kept = cfg["acme"]["accounts"]
cfg["acme"]["accounts"] = [a for a in kept if a.get("ca") != "adcs"]
save_config(cfg)
ok(not adcs.wanted(load_config()), "(no account uses AD CS)")
adcs.startup()
ok(state["runs"] == 3 and not state["there"],
   "startup tries on a node no account needs it on, and again when it fails (%d tries)" % state["runs"])
ok(adcs.TRIED.exists() and "github.com" in adcs.last_failure(), "what stopped it is kept")
ok(adcs.ensure_installed()[0] is False and state["runs"] == 3,
   "an issuance does not try again so soon after a failure")
r = client.post("/api/acme/adcs/test", headers=H, json=GOOD).get_json()
ok(r["ok"] is False and state["runs"] == 4 and "could not be installed" in r["message"]
   and "github.com" in r["message"], "testing the connection does, and says why it could not: %s" % r["message"][:90])
state["works"] = True
state["runs"] = 0
adcs.startup()
ok(state["runs"] == 1 and state["there"] and not adcs.TRIED.exists(),
   "the next start installs it, once, and forgets the failure")
adcs.startup()
ok(state["runs"] == 1, "a node that has it is left alone")
# while one install runs, whoever else needs it waits for that one
state.update(there=False, runs=0)
gate = threading.Event()


def slow_install():
    state["runs"] += 1
    gate.wait(10)
    state["there"] = True
    return True, "installed acme2certifier"


adcs.install = slow_install
first = threading.Thread(target=adcs.startup)
first.start()
for _ in range(100):
    if adcs._installing.locked():
        break
    time.sleep(0.05)
r = client.get("/api/acme/health", headers=H).get_json()
ok(r["adcs"]["installing"] is True and r["adcs"]["installed"] is False, "the health check says an install is running")
got = []
second = threading.Thread(target=lambda: got.append(adcs.ensure_installed(force=True)))
second.start()
time.sleep(0.3)
ok(not got, "a second caller waits for the install that is running")
gate.set()
first.join(10)
second.join(10)
ok(got and got[0][0] is True and state["runs"] == 1, "and finds it installed, without a second install")
cfg = load_config()
cfg["acme"]["accounts"] = kept
save_config(cfg)

print()
print("FAILED: %d" % len(fails) if fails else "all passed")
sys.exit(1 if fails else 0)
