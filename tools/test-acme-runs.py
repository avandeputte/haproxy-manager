#!/usr/bin/env python3
"""How acme.sh is run, and what an issuance leaves on disk.

    python3 tools/test-acme-runs.py

Pinned here: acme.sh logs at level 1, where the DNS hook's API calls -- and
the credentials in them -- are not traced into the log the Logs page shows;
an account is registered once per process, not once per certificate per
round; one certificate is issued by one run at a time, and a second caller
is told so rather than queued; a renewal round goes on past a certificate
that raises; a PEM with a private key is never world-readable, not even for
a moment, and never half written; every block of an uploaded chain is read
by openssl before the upload is accepted; two certificate names that would
share one file are refused, as is the UI certificate's name; the file a
download is given is named as it is on disk; and the node's own UI
certificate counts when a host asks what covers it.
"""
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ["HAM_DATA_DIR"] = tempfile.mkdtemp(prefix="ham-acmeruns-")
D = os.environ["HAM_DATA_DIR"]
os.environ["HAM_CERT_DIR"] = os.path.join(D, "certs")
os.environ["HAM_ERROR_DIR"] = os.path.join(D, "error-pages")
os.environ["HAM_ACME_HOME"] = os.path.join(D, "acme")
os.environ["HAM_ACME_SH"] = os.path.join(D, "acme.sh")
os.environ["HAM_DRY_RUN"] = "1"

# The stand-in acme.sh: one line per run with its arguments.
RUNS = os.path.join(D, "runs.txt")
os.makedirs(os.environ["HAM_ACME_HOME"], exist_ok=True)
pathlib.Path(os.environ["HAM_ACME_SH"]).write_text('#!/bin/sh\necho "$*" >> "%s"\nexit 0\n' % RUNS)
os.chmod(os.environ["HAM_ACME_SH"], 0o755)

import ham; ham   # noqa: E402  (route registration)
from ham import acme   # noqa: E402
from ham.base import CERT_DIR   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402
from ham.util import cert_path   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


def runs():
    try:
        return pathlib.Path(RUNS).read_text().splitlines()
    except OSError:
        return []


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "runs-key"
save_config(cfg)
H = {"X-API-Key": "runs-key"}

print("how acme.sh is run")
acme.acme_run(["--version"])
last = runs()[-1].split()
ok("--log" in last and last[last.index("--log-level") + 1] == "1" if "--log-level" in last else False,
   "every run carries --log --log-level 1: %s" % " ".join(last))

acc = {"id": "a1", "name": "le", "email": "me@example.com", "ca": "letsencrypt"}
before = len(runs())
acme.ensure_account(acc)
acme.ensure_account(acc)
ok(len(runs()) - before == 1 and "--register-account" in runs()[-1],
   "the same account is registered once per process, not once per issue")
acme.ensure_account(dict(acc, email="other@example.com"))
ok(len(runs()) - before == 2, "an account whose details changed is registered again")
acme._registered.discard(acme._account_signature(acc))
acme.ensure_account(acc)
ok(len(runs()) - before == 3, "and so is one forgotten after a failed issue")

print("one run per certificate at a time")
inside, release = threading.Event(), threading.Event()
real_issue = acme._acme_issue


def slow_issue(cfg, cert, force=False):
    inside.set()
    release.wait(10)
    return {"ok": True, "changed": False, "log": ""}


acme._acme_issue = slow_issue
c = load_config()
c["acme"]["accounts"] = [acc]
c["acme"]["challenges"] = [{"id": "c1", "name": "http", "method": "http01"}]
c["acme"]["certificates"] = [{"id": "k1", "name": "one", "domains": "one.example.com", "account": "a1",
                              "challenge": "c1", "key_type": "ec-256"},
                             {"id": "k2", "name": "two", "domains": "two.example.com", "account": "a1",
                              "challenge": "c1", "key_type": "ec-256"}]
save_config(c)
first = {}
t = threading.Thread(target=lambda: first.update(acme.acme_issue(c, c["acme"]["certificates"][0])))
t.start()
ok(inside.wait(5), "the first issue of 'one' is running")
second = acme.acme_issue(c, c["acme"]["certificates"][0])
ok(not second.get("ok") and second.get("busy") and "already being issued" in second.get("error", ""),
   "a second issue of 'one' meanwhile is told it is already being issued, without waiting")
r = client.post("/api/acme/issue/k1", headers=H, json={})
ok(r.status_code == 409 and r.get_json().get("busy"), "and the Issue button gets 409 for it")
other = acme.acme_issue(c, c["acme"]["certificates"][1])
ok(other.get("ok"), "an issue of 'two' at the same time goes ahead")
release.set()
t.join(5)
ok(first.get("ok") is True, "the first run finished normally")
again = acme.acme_issue(c, c["acme"]["certificates"][0])
ok(again.get("ok"), "and 'one' can be issued again once it has")
acme._acme_issue = real_issue

print("a renewal round goes on past a certificate that raises")
tried = []


def flaky(cfg, cert, force=False):
    tried.append(cert["name"])
    if cert["name"] == "one":
        raise RuntimeError("the first certificate is broken")
    return {"ok": True}


real_acme_issue = acme.acme_issue
acme.acme_issue = flaky
c = load_config()
c["acme"]["settings"].update({"enabled": True, "auto_renew": True, "renew_hours": 1})
save_config(c)
acme._last_renew = 0
acme._renew_tick()
ok(tried == ["one", "two"], "the round tried both certificates although the first raised: %s" % tried)
acme.acme_issue = real_acme_issue

print("a private key on disk")
p = CERT_DIR / "perm-test.pem"
acme.write_private(p, "secret\n")
ok(stat.S_IMODE(p.stat().st_mode) == 0o600, "write_private leaves the file 0600")
ok(p.read_text() == "secret\n", "with its content")
acme.write_private(p, "second\n")
ok(p.read_text() == "second\n" and stat.S_IMODE(p.stat().st_mode) == 0o600, "and replaces it the same way")
ok(not [f for f in os.listdir(str(CERT_DIR)) if f.startswith(".perm-test")],
   "no temporary file is left beside it")
conf = pathlib.Path(os.environ["HAM_ACME_HOME"]) / "account.conf"
conf.write_text("ACCOUNT_EMAIL='a@example.com'\nCA_BUNDLE='/old.pem'\n")
acme._forget_ca_bundle()
ok(conf.read_text() == "ACCOUNT_EMAIL='a@example.com'\n" and stat.S_IMODE(conf.stat().st_mode) == 0o600,
   "account.conf is rewritten whole, and closed to others")

print("an uploaded chain")


def openssl(*args):
    return subprocess.run(["openssl"] + list(args), capture_output=True, text=True, check=True).stdout


work = tempfile.mkdtemp(prefix="ham-pem-")
ca_key, ca_crt = os.path.join(work, "ca.key"), os.path.join(work, "ca.crt")
openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", ca_key,
        "-out", ca_crt, "-days", "2", "-subj", "/CN=Test Root")
leaf_key, leaf_csr, leaf_crt = (os.path.join(work, n) for n in ("leaf.key", "leaf.csr", "leaf.crt"))
openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", leaf_key,
        "-out", leaf_csr, "-subj", "/CN=up.example.com")
ext = os.path.join(work, "ext.cnf")
pathlib.Path(ext).write_text("subjectAltName=DNS:up.example.com,DNS:www.up.example.com\n")
openssl("x509", "-req", "-in", leaf_csr, "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial", "-days", "2",
        "-out", leaf_crt, "-extfile", ext)
leaf, key, ca = (pathlib.Path(f).read_text() for f in (leaf_crt, leaf_key, ca_crt))
GARBAGE = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGUgYXQgYWxs\n-----END CERTIFICATE-----\n"


def upload(name, cert, key, chain, **more):
    body = dict({"name": name, "cert": cert, "key": key, "chain": chain}, **more)
    r = client.post("/api/acme/certificates/upload", headers=H, json=body)
    return r.status_code, (r.get_json() or {})


code, body = upload("good", leaf, key, ca)
ok(code == 200 and body.get("names") == ["up.example.com", "www.up.example.com"],
   "a real certificate with a real chain is accepted: %s" % body.get("names"))
pem = cert_path({"name": "good"})
ok(stat.S_IMODE(pem.stat().st_mode) == 0o600 and pem.read_text().count("BEGIN CERTIFICATE") == 2,
   "its file is 0600 and holds the leaf and the chain")
code, body = upload("bad-chain", leaf, key, ca + GARBAGE)
ok(code == 400 and "certificate 2 of the chain could not be read" in body.get("error", ""),
   "a chain whose second block is not a certificate is refused, naming the block: %s" % body.get("error", "")[:80])
code, body = upload("bad-chain", leaf + GARBAGE, key, "")
ok(code == 400 and "certificate 1 of the chain" in body.get("error", ""),
   "a bad block pasted after the certificate is refused the same way")
ok(not cert_path({"name": "bad-chain"}).exists(), "and nothing was written for it")
code, body = upload("half", leaf, key, ca.replace("-----END CERTIFICATE-----", ""))
ok(code == 400 and "PEM marker outside a complete block" in body.get("error", ""),
   "a chain certificate missing its END line is refused rather than dropped: %s" % body.get("error", "")[:70])
code, body = upload("noted", leaf, key, "subject=CN = Test Root\nissuer=CN = Test Root\n" + ca)
ok(code == 200, "the subject= and issuer= lines openssl prints around a block are fine")

print("names that share a file")
c = load_config()
aid = c["acme"]["accounts"][0]["id"]
cid = c["acme"]["challenges"][0]["id"]
base = {"account": aid, "challenge": cid, "key_type": "ec-256", "domains": "n.example.com"}
r = client.post("/api/acme/certificates", headers=H, json=dict(base, name="my cert"))
ok(r.status_code == 200, "a certificate named 'my cert' is stored")
mine = r.get_json().get("id")
r = client.post("/api/acme/certificates", headers=H, json=dict(base, name="my_cert"))
ok(r.status_code == 400 and "same file" in r.get_json().get("error", "") and "my_cert.pem" in r.get_json().get("error", ""),
   "'my_cert' is refused: it would be the same file, and the message names it")
r = client.post("/api/acme/certificates", headers=H, json=dict(base, name="my cert"))
ok(r.status_code == 400 and "same file" in r.get_json().get("error", ""), "and so is a second 'my cert'")
r = client.put("/api/acme/certificates/%s" % mine, headers=H, json=dict(base, name="my cert", domains="m.example.com"))
ok(r.status_code == 200, "editing 'my cert' itself is not a collision with itself")
r = client.post("/api/acme/certificates", headers=H, json=dict(base, name="good"))
ok(r.status_code == 400 and "same file" in r.get_json().get("error", ""),
   "a name an uploaded certificate has is refused too")
code, body = upload("my_cert", leaf, key, ca)
ok(code == 400 and "same file" in body.get("error", ""), "an upload under a colliding name is refused: %s"
   % body.get("error", "")[:60])
for bad in ("haproxy-manager-ui", "haproxy-manager-ui-2"):
    r = client.post("/api/acme/certificates", headers=H, json=dict(base, name=bad))
    ok(r.status_code == 400 and "web UI" in r.get_json().get("error", ""),
       "the UI certificate's name %r is refused" % bad)
r = client.post("/api/acme/certificates", headers=H, json=dict(base, name="  "))
ok(r.status_code == 400, "a name of spaces only is refused")
code, body = upload("", leaf, key, ca)
ok(code == 400 and "needs a name" in body.get("error", ""), "an upload without a name is refused")
# a node's own UI certificate holds its file too, and covers its host
c = load_config()
c["local"].setdefault("acme", {}).setdefault("certificates", []).append(
    {"id": "ui1", "name": "haproxy-manager-ui", "domains": "ham.example.com", "account": aid, "challenge": cid,
     "key_type": "ec-256"})
save_config(c)
r = client.post("/api/acme/certificates", headers=H, json=dict(base, name=" haproxy-manager-ui "))
ok(r.status_code == 400 and "same file" in r.get_json().get("error", ""),
   "a shared certificate cannot take the UI certificate's file: %s" % r.get_json().get("error", "")[:60])
r = client.get("/api/acme/cover?host=ham.example.com", headers=H)
ok(r.status_code == 200 and r.get_json().get("covered") and r.get_json().get("name") == "haproxy-manager-ui",
   "the node's own UI certificate is reported as covering its host")
# the wizard picks a name that is not another certificate's file either
r = client.post("/api/wizard/certificate", headers=H,
                json={"domains": "w.example.com", "name": "my cert", "account": {"id": aid},
                      "challenge": {"id": cid}, "dry_run": True})
ok(r.status_code == 200 and r.get_json().get("certificate") == "my_cert-2",
   "the wizard, asked for 'my cert' while that exists, names the new one my_cert-2, not my cert's file: %s"
   % r.get_json().get("certificate"))

print("a download's file name")
c = load_config()
c["acme"]["certificates"].append({"id": "odd", "name": 'odd"name\r\nX', "source": "custom",
                                  "domains": "odd.example.com"})
save_config(c)
acme.write_private(cert_path(c["acme"]["certificates"][-1]), leaf + key)
r = client.get("/api/acme/certificates/odd/download", headers=H)
ok(r.status_code == 200 and r.headers.get("Content-Disposition") == 'attachment; filename="odd_name__X.crt"',
   "the file is named as on disk, with no quote or line break: %s" % r.headers.get("Content-Disposition"))

print("a backup and the AD CS password")
c = load_config()
c["acme"]["accounts"].append({"id": "ad1", "name": "corp", "ca": "adcs", "adcs_method": "msicpr",
                              "adcs_host": "ca01.corp.example.lan", "adcs_ca_name": "Corp CA",
                              "adcs_template": "WebServer", "adcs_user": "svc", "adcs_password": "AD-PASS-1"})
save_config(c)
r = client.get("/api/export/config", headers=H)
ok(r.status_code == 200 and "AD-PASS-1" not in r.get_data(as_text=True), "the export carries no AD CS password")
r = client.post("/api/import/config", headers=H, json=r.get_json())
ok(r.status_code == 200, "the export restores")
kept = next(a for a in load_config()["acme"]["accounts"] if a.get("id") == "ad1")
ok(kept.get("adcs_password") == "AD-PASS-1", "and the same node keeps the password it had")

print()
print("FAILED: %d" % len(fails) if fails else "all passed")
sys.exit(1 if fails else 0)
