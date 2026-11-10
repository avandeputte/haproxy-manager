#!/usr/bin/env python3
"""A certificate authority of your own: an ACME account with "custom" as its CA.

    python3 tools/test-custom-ca.py

The account names the server's ACME directory and, optionally, a CA
certificate to trust for that server's HTTPS. What is refused before it is
stored, what acme.sh is given (with a stand-in acme.sh that records its
arguments), and that a CA_BUNDLE acme.sh saved into account.conf is gone
before the next run -- acme.sh reads that file after its command line, so a
saved bundle would otherwise replace the system's trust for every CA after it.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ["HAM_DATA_DIR"] = tempfile.mkdtemp(prefix="ham-customca-")
D = os.environ["HAM_DATA_DIR"]
os.environ["HAM_CERT_DIR"] = os.path.join(D, "certs")
os.environ["HAM_ERROR_DIR"] = os.path.join(D, "error-pages")
os.environ["HAM_ACME_HOME"] = os.path.join(D, "acme")
os.environ["HAM_ACME_SH"] = os.path.join(D, "acme.sh")
os.environ["HAM_DRY_RUN"] = "1"

# The stand-in: one line per run with its arguments, and whether account.conf
# held a CA_BUNDLE when it started. Like acme.sh after an issue, it then saves
# the bundle it was given into account.conf.
RUNS = os.path.join(D, "runs.txt")
os.makedirs(os.environ["HAM_ACME_HOME"], exist_ok=True)
pathlib.Path(os.environ["HAM_ACME_SH"]).write_text(r'''#!/bin/sh
conf="$HAM_ACME_HOME/account.conf"
saved=no; grep -q '^CA_BUNDLE=' "$conf" 2>/dev/null && saved=yes
echo "saved=$saved $*" >> "%s"
prev=""; for a in "$@"; do
  if [ "$prev" = "--ca-bundle" ]; then echo "CA_BUNDLE='$a'" >> "$conf"; fi
  prev="$a"
done
case "$*" in *--issue*) exit 1;; esac
exit 0
''' % RUNS)
os.chmod(os.environ["HAM_ACME_SH"], 0o755)
pathlib.Path(os.environ["HAM_ACME_HOME"], "account.conf").write_text(
    "ACCOUNT_EMAIL='a@example.com'\nCA_BUNDLE='/somewhere/old.pem'\nAUTO_UPGRADE='0'\n")

import ham; ham   # noqa: E402  (route registration)
from ham import acme   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "ca-key"
save_config(cfg)
H = {"X-API-Key": "ca-key"}

# a CA certificate, as an internal CA would hand out
k = os.path.join(D, "ca.key")
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-keyout", k, "-out", os.path.join(D, "ca.pem"), "-days", "30",
                "-subj", "/CN=Test Internal CA"], check=True, capture_output=True)
CA_PEM = pathlib.Path(D, "ca.pem").read_text()


def add_account(body, want):
    r = client.post("/api/acme/accounts", headers=H, json=body)
    err = (r.get_json() or {}).get("error") or ""
    ok(r.status_code == want, "account %s -> %d %s" % (body.get("name"), r.status_code, err[:100]))
    return r.get_json() or {}, err


print("what an account refuses")
_, err = add_account({"name": "no-url", "ca": "custom", "server": ""}, 400)
ok("ACME directory" in err, "a custom CA without an address says it needs one")
add_account({"name": "ftp", "ca": "custom", "server": "ftp://ca.example.lan/directory"}, 400)
add_account({"name": "spaces", "ca": "custom", "server": "https://ca example/directory"}, 400)
_, err = add_account({"name": "bad-pem", "ca": "custom", "server": "https://ca.example.lan/directory",
                      "ca_bundle": "not a certificate"}, 400)
ok("PEM" in err, "a CA certificate that is not PEM is refused")
_, err = add_account({"name": "key-pem", "ca": "custom", "server": "https://ca.example.lan/directory",
                      "ca_bundle": pathlib.Path(k).read_text()}, 400)
ok("PEM" in err, "a private key in place of the CA certificate is refused")
broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
_, err = add_account({"name": "broken", "ca": "custom", "server": "https://ca.example.lan/directory",
                      "ca_bundle": broken}, 400)
ok("openssl" in err, "a certificate openssl cannot read is refused")
add_account({"name": "le", "ca": "letsencrypt", "server": ""}, 200)
add_account({"name": "internal", "ca": "custom", "server": "https://ca.example.lan/directory",
             "ca_bundle": CA_PEM, "email": "ops@example.lan"}, 200)
add_account({"name": "plain", "ca": "custom", "server": "http://a2c.example.lan/directory"}, 200)
accs = {a["name"]: a for a in load_config()["acme"]["accounts"]}
ok(set(accs) == {"le", "internal", "plain"}, "only the valid accounts were stored: %s" % sorted(accs))

r = client.put("/api/acme/accounts/" + accs["internal"]["id"], headers=H,
               json=dict(accs["internal"], server=""))
ok(r.status_code == 400, "editing away the address is refused (%d)" % r.status_code)

print("the public CAs")
_, err = add_account({"name": "old-buypass", "ca": "buypass"}, 400)
ok("31 October 2025" in err, "Buypass, which stopped issuing, is refused with why")
_, err = add_account({"name": "typo", "ca": "letsencrypt-prod"}, 400)
ok("unknown certificate authority" in err, "a CA name acme.sh does not know is refused")
for ca, who in (("google", "Google"), ("google_test", "Google"), ("sslcom", "SSL.com"), ("actalis", "Actalis")):
    _, err = add_account({"name": "no-eab-" + ca, "ca": ca}, 400)
    ok(who + " needs External Account Binding" in err, "%s without EAB says it needs it" % ca)
add_account({"name": "gts", "ca": "google", "eab_kid": "kid", "eab_hmac": "hmac"}, 200)
add_account({"name": "zero", "ca": "zerossl", "email": "z@example.com"}, 200)
for ca in ("letsencrypt", "letsencrypt_test"):
    acc, _ = add_account({"name": "left-" + ca, "ca": ca, "eab_kid": "left-over", "eab_hmac": "left-over-key"}, 200)
    ok(acc.get("eab_kid") == "" and acc.get("eab_hmac") == "",
       "%s has no EAB: what was typed for another CA is not stored with it" % ca)
acc, _ = add_account({"name": "zero-eab", "ca": "zerossl", "eab_kid": "kid", "eab_hmac": "hmac"}, 200)
ok(acc.get("eab_kid") == "kid" and acc.get("eab_hmac") == "hmac", "ZeroSSL keeps EAB credentials that were given")
_real_run, _reg = acme.acme_run, []
acme.acme_run = lambda args, env_extra=None: (_reg.append(args) or (0, ""))
acme.ensure_account({"ca": "letsencrypt", "email": "", "eab_kid": "old", "eab_hmac": "old-key"})
ok("--eab-kid" not in _reg[-1], "an older Let's Encrypt account still carrying EAB registers without it")
acme.ensure_account({"ca": "google", "email": "", "eab_kid": "kid", "eab_hmac": "key"})
ok(_reg[-1][_reg[-1].index("--eab-kid") + 1] == "kid", "a CA that has EAB is still given it")
acme.acme_run = _real_run
for ca in ("google", "google_test", "sslcom", "actalis", "zerossl", "letsencrypt_test"):
    ok(acme.server_args({"ca": ca}) == ["--server", ca], "%s is passed to acme.sh by its short name" % ca)
known = subprocess.run(["sh", "-c", "sed -n '/^CA_NAMES=/,/^\"/p' /opt/acme.sh/acme.sh"],
                       capture_output=True, text=True).stdout.lower()
if known:
    names = {n for line in known.splitlines() for n in line.split(",")[1:]}
    ok(set(acme.CA_SERVERS) <= names, "every CA offered is one this acme.sh knows: %s"
       % sorted(set(acme.CA_SERVERS) - names))
else:
    print("  SKIP  no acme.sh at /opt/acme.sh to compare the names with")

print("what acme.sh is given")
ok(acme.server_args(accs["le"]) == ["--server", "letsencrypt"], "Let's Encrypt keeps its short name")
ok(acme.server_args(accs["plain"]) == ["--server", "http://a2c.example.lan/directory"],
   "a custom CA without a certificate to trust: its address, and no --ca-bundle")
args = acme.server_args(accs["internal"])
ok(args[:2] == ["--server", "https://ca.example.lan/directory"] and args[2] == "--ca-bundle",
   "a custom CA with a certificate to trust: its address and --ca-bundle")
bundle = pathlib.Path(args[3]).read_text()
ok(CA_PEM.strip() in bundle, "the bundle holds the account's CA certificate")
system = next((p for p in acme.SYSTEM_BUNDLES if os.path.isfile(p)), None)
if system:
    first = pathlib.Path(system).read_text().strip().splitlines()[0]
    ok(bundle.startswith(first) and bundle.count("BEGIN CERTIFICATE") > 1,
       "and the system's trusted CAs before it, for a DNS hook's public API")
else:
    print("  SKIP  no system CA bundle on this machine")

print("reading the directory first")
# A local HTTPS server with a certificate from the test CA, answering a
# directory at /directory and something else at /other.
import http.server, json, ssl, threading   # noqa: E401,E402
srv_key, srv_csr, srv_crt = (os.path.join(D, n) for n in ("srv.key", "srv.csr", "srv.pem"))
subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", srv_key, "-out", srv_csr, "-subj", "/CN=localhost"], check=True, capture_output=True)
pathlib.Path(D, "ext").write_text("subjectAltName=DNS:localhost\n")
subprocess.run(["openssl", "x509", "-req", "-in", srv_csr, "-CA", os.path.join(D, "ca.pem"), "-CAkey", k,
                "-CAcreateserial", "-out", srv_crt, "-days", "5", "-extfile", os.path.join(D, "ext")],
               check=True, capture_output=True)


class Dir(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = {"/directory": {"newNonce": "x", "newAccount": "y", "newOrder": "z"},
                "/other": {"hello": 1}}.get(self.path)
        self.send_response(200 if body else 404)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode() if body else b"no")

    def log_message(self, *a):
        pass


httpd = http.server.HTTPServer(("127.0.0.1", 0), Dir)
sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
sctx.load_cert_chain(srv_crt, srv_key)
httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
base = "https://localhost:%d" % httpd.server_address[1]
acc = {"ca": "custom", "server": base + "/directory", "ca_bundle": CA_PEM}
ok(acme.check_directory(acc) == "", "a directory served with a trusted certificate is read")
why = acme.check_directory(dict(acc, ca_bundle=""))
ok("does not trust" in why and "CA certificate to trust" in why, "an untrusted certificate says what to do: " + why[:90])
why = acme.check_directory(dict(acc, server=base + "/other"))
ok("not an ACME directory" in why, "a page that is not a directory says so: " + why[:80])
why = acme.check_directory(dict(acc, server=base + "/missing"))
ok("HTTP 404" in why, "a missing page gives its status: " + why[:80])
why = acme.check_directory(dict(acc, server="https://localhost:1/directory"))
ok("could not reach" in why, "an unreachable server says so: " + why[:80])
ok(acme.check_directory({"ca": "letsencrypt"}) == "", "a public CA is not read first")

# From here the stand-in acme.sh stands in for the CA as well.
acme.check_directory = lambda acc: ""

print("issuing, and the CA_BUNDLE acme.sh saves")
cfg = load_config()
cfg["acme"]["challenges"].append({"id": "ch1", "name": "http", "method": "http01"})
for n in ("internal", "le"):
    cfg["acme"]["certificates"].append({"id": "c-" + n, "name": "c-" + n, "domains": n + ".example.lan",
                                        "account": accs[n]["id"], "challenge": "ch1"})
save_config(cfg)
cfg = load_config()
certs = {c["id"]: c for c in cfg["acme"]["certificates"]}
acme.acme_issue(cfg, certs["c-internal"])
acme.acme_issue(cfg, certs["c-le"])
runs = pathlib.Path(RUNS).read_text().splitlines()
ok(len(runs) == 4, "register and issue for each account: %d runs" % len(runs))
reg_i, iss_i, reg_le, iss_le = runs
ok(reg_i.startswith("saved=no") and iss_i.startswith("saved=no"),
   "the CA_BUNDLE already in account.conf was gone before the first run")
ok("--register-account" in reg_i and "--server https://ca.example.lan/directory --ca-bundle" in reg_i,
   "the account is registered with the custom CA, trusting its certificate")
ok("--issue --server https://ca.example.lan/directory --ca-bundle" in iss_i,
   "the certificate is requested from the custom CA, trusting its certificate")
ok(reg_le.startswith("saved=no") and iss_le.startswith("saved=no"),
   "the bundle acme.sh saved for the custom CA was gone before the Let's Encrypt runs")
ok("--server letsencrypt" in iss_le and "--ca-bundle" not in iss_le,
   "Let's Encrypt is asked with the system's trust only")
conf = pathlib.Path(os.environ["HAM_ACME_HOME"], "account.conf").read_text()
ok("ACCOUNT_EMAIL='a@example.com'" in conf and "AUTO_UPGRADE='0'" in conf,
   "the rest of account.conf is left as it was")

# a stored account broken by hand is refused at issue time, before acme.sh runs
cfg = load_config()
for a in cfg["acme"]["accounts"]:
    if a["name"] == "plain":
        a["server"] = ""
        certs["c-internal"]["account"] = a["id"]
before = len(pathlib.Path(RUNS).read_text().splitlines())
res = acme.acme_issue(cfg, certs["c-internal"])
ok(not res["ok"] and "ACME directory" in res["error"], "issuing with no address says why: %s" % res["error"][:80])
ok(len(pathlib.Path(RUNS).read_text().splitlines()) == before, "and acme.sh was not run")

print("renewing on acme.sh's schedule between rounds")
import time   # noqa: E402
from datetime import datetime, timezone   # noqa: E402
home = pathlib.Path(os.environ["HAM_ACME_HOME"])
now = time.time()


def plan(main, when, ecc=True):
    d = home / (main + ("_ecc" if ecc else ""))
    d.mkdir(parents=True, exist_ok=True)
    (d / (main + ".conf")).write_text("Le_Domain='%s'\nLe_NextRenewTime='%d'\nLe_NextRenewTimeStr='x'\n" % (main, when))


def at(seconds_ago):
    return datetime.fromtimestamp(now - seconds_ago, timezone.utc).isoformat(timespec="seconds")


plan("day.example.lan", now - 60)
plan("later.example.lan", now + 3600)
plan("rsa.example.lan", now - 60, ecc=False)
c = lambda cid, dom: {"id": cid, "domains": dom}   # noqa: E731
meta = {"_meta": {"issue_log": {}}}
ok(acme.renewal_due(meta, c("d", "day.example.lan"), now), "a certificate acme.sh planned to renew by now is due")
ok(not acme.renewal_due(meta, c("l", "later.example.lan"), now), "one planned for later is not")
ok(acme.renewal_due(meta, dict(c("r", "rsa.example.lan"), key_type="rsa-2048"), now),
   "an RSA certificate's plan is read from its own folder (no _ecc)")
plan("switched.example.lan", now - 86400)                  # issued as EC once: the folder stays
plan("switched.example.lan", now + 3600, ecc=False)        # RSA now, and not due
ok(not acme.renewal_due(meta, dict(c("s", "switched.example.lan"), key_type="rsa-2048"), now),
   "a certificate switched from EC to RSA is judged by its RSA plan, not the _ecc folder left behind")
ok(acme.renewal_due(meta, dict(c("s", "switched.example.lan"), key_type="ec-256"), now),
   "and by the EC one while it is an EC certificate")
ok(not acme.renewal_due(meta, c("n", "never.example.lan"), now), "one acme.sh has no plan for is left to the rounds")
meta["_meta"]["issue_log"]["d"] = {"time": at(600), "ok": False}
ok(not acme.renewal_due(meta, c("d", "day.example.lan"), now), "a failure ten minutes ago waits an hour before trying again")
meta["_meta"]["issue_log"]["d"] = {"time": at(3700), "ok": False}
ok(acme.renewal_due(meta, c("d", "day.example.lan"), now), "after an hour it is tried again")
meta["_meta"]["issue_log"]["d"] = {"time": at(600), "ok": True}
ok(acme.renewal_due(meta, c("d", "day.example.lan"), now), "a success does not hold the next renewal back")

print("the certificate wizard")
r = client.post("/api/wizard/certificate", headers=H, json={
    "domains": "app.example.lan", "issue": False, "dry_run": True,
    "account": {"name": "new-internal", "ca": "custom", "server": ""},
    "challenge": {"id": "ch1"}})
ok(r.status_code == 400 and "ACME directory" in (r.get_json() or {}).get("error", ""),
   "a new custom account without an address is refused (%d)" % r.status_code)
r = client.post("/api/wizard/certificate", headers=H, json={
    "domains": "app.example.lan", "issue": False,
    "account": {"name": "new-internal", "ca": "custom", "server": "https://ca2.example.lan/acme/directory",
                "ca_bundle": CA_PEM},
    "challenge": {"id": "ch1"}})
ok(r.status_code == 200, "a new custom account with an address is created (%d %s)"
   % (r.status_code, ((r.get_json() or {}).get("error") or "")[:80]))
new = [a for a in load_config()["acme"]["accounts"] if a["name"] == "new-internal"]
ok(new and new[0]["server"] == "https://ca2.example.lan/acme/directory" and "BEGIN CERTIFICATE" in new[0]["ca_bundle"],
   "with its address and CA certificate stored")

print()
print("FAILED: %d" % len(fails) if fails else "all passed")
sys.exit(1 if fails else 0)
