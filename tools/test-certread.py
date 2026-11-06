#!/usr/bin/env python3
"""A certificate file is read by openssl once, not once per service using it.

    HAM_DATA_DIR=/tmp/x python3 tools/test-certread.py

The Services page asked about each service's certificate file, two openssl
runs a time: 62 services behind one wildcard took 5.7 seconds on a small
machine (#16). Now a file is read once and again only when it changes, so what
is checked here is that nothing it said is lost on the way -- the names, the
placeholder, the expiry -- that a renewed file is read afresh, that the days
left still count down, and that the page asks openssl nothing the second time.
Needs openssl, which the image has.
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-cert-"))
os.environ.setdefault("HAM_CERT_DIR", tempfile.mkdtemp(prefix="ham-certs-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import util   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402
from ham.util import cert_details, cert_path   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


WORK = pathlib.Path(tempfile.mkdtemp(prefix="ham-ca-"))


def sh(*cmd):
    subprocess.run(cmd, check=True, capture_output=True)


sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
   "-subj", "/CN=Test CA", "-keyout", str(WORK / "ca.key"), "-out", str(WORK / "ca.crt"))


def issue(p, cn, sans=(), days=90, self_signed=False):
    """A PEM at p, as Apply deploys it: certificate, then key."""
    key, csr, crt = WORK / "k", WORK / "csr", WORK / "crt"
    ext = WORK / "ext"
    ext.write_text("subjectAltName=" + ",".join("DNS:" + s for s in sans) + "\n" if sans else "")
    if self_signed:
        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", str(days),
           "-subj", "/CN=" + cn, "-keyout", str(key), "-out", str(crt))
    else:
        sh("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + cn,
           "-keyout", str(key), "-out", str(csr))
        sh("openssl", "x509", "-req", "-in", str(csr), "-CA", str(WORK / "ca.crt"),
           "-CAkey", str(WORK / "ca.key"), "-CAcreateserial", "-days", str(days),
           "-out", str(crt), *(["-extfile", str(ext)] if sans else []))
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_bytes(crt.read_bytes() + key.read_bytes())
    tmp.replace(p)


runs = []
real_run = util.run


def counting_run(cmd, *a, **kw):
    if cmd[0] == "openssl":
        runs.append(cmd)
    return real_run(cmd, *a, **kw)


util.run = counting_run

# ---- what a file says ---------------------------------------------------------
wild = cert_path({"name": "wildcard"})
issue(wild, "*.example.com", sans=("*.example.com", "example.com"))
info = cert_details(wild)
ok(info["deployed"] and info["status"] == "valid", "an issued certificate is valid: %s" % info["status"])
ok(info["names"] == ["*.example.com", "example.com"], "its names come from the SAN: %r" % info["names"])
ok(info["issuer"] == "CN=Test CA" and info["subject"] == "CN=*.example.com",
   "issuer and subject: %r %r" % (info["issuer"], info["subject"]))
ok(info["days_left"] in (88, 89) and info["expires_iso"].endswith("+00:00"),
   "and it expires when it was issued to: %r days" % info["days_left"])
ok(len(runs) == 1, "one openssl run reads all of it: %d" % len(runs))

nosan = cert_path({"name": "old-style"})
issue(nosan, "legacy.example.com")
ok(cert_details(nosan)["names"] == ["legacy.example.com"],
   "a certificate without a SAN covers its common name")

placeholder = cert_path({"name": "placeholder"})
issue(placeholder, "new.example.com", self_signed=True)
ok(cert_details(placeholder)["status"] == "placeholder",
   "the self-signed placeholder Apply puts in is still told apart")

soon = cert_path({"name": "soon"})
issue(soon, "soon.example.com", sans=("soon.example.com",), days=5)
ok(cert_details(soon)["status"] == "expiring", "one with days left is expiring")

junk = cert_path({"name": "junk"})
junk.write_text("not a certificate\n")
ok(cert_details(junk)["status"] == "unreadable", "a file openssl cannot read is unreadable")
ok(cert_details(cert_path({"name": "absent"}))["status"] == "missing", "and a missing one missing")

# ---- read once ----------------------------------------------------------------
before = len(runs)
again = cert_details(wild)
ok(len(runs) == before, "asking about the same file again runs nothing")
ok(again == info, "and says the same")
again["names"].append("tampered.example.com")
ok(cert_details(wild)["names"] == ["*.example.com", "example.com"],
   "a caller changing the answer it got does not change the next one")

future = datetime.now() + timedelta(days=30)


class Later(datetime):
    @classmethod
    def now(cls, tz=None):
        return future.astimezone(tz) if tz else future


util.datetime = Later
later = cert_details(wild)
util.datetime = datetime
ok(later["days_left"] == info["days_left"] - 30 and len(runs) == before,
   "the days left are worked out on each call, not kept: %r" % later["days_left"])

time.sleep(0.01)
issue(wild, "*.example.com", sans=("*.example.com", "example.com", "*.example.org"), days=60)
renewed = cert_details(wild)
ok(len(runs) == before + 1 and "*.example.org" in renewed["names"],
   "a renewed file is read again: %r" % renewed["names"])
ok(renewed["days_left"] in (58, 59), "with its own expiry: %r" % renewed["days_left"])

time.sleep(0.01)
issue(junk, "fixed.example.com", sans=("fixed.example.com",))
ok(cert_details(junk)["status"] == "valid", "an unreadable file that is replaced is read again")

# ---- the Services page -----------------------------------------------------------
ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "cert-key"
save_config(cfg)
H = {"X-API-Key": "cert-key"}
N = 180
for i in range(N):
    r = client.post("/api/wizard/publish", headers=H, json={
        "url": "https://svc%d.example.com" % i, "target": "10.0.%d.%d:80" % (i // 250, i % 250 + 1),
        "certificate": False, "dry_run": False})
    if r.status_code != 200:
        ok(False, "publishing svc%d: %s" % (i, r.get_json()))
        break
cfg = load_config()
cfg["acme"]["certificates"].append({"id": "wildcert", "name": "wildcard",
                                    "domains": "*.example.com", "enabled": True})
for fe in cfg["haproxy"]["frontends"]:
    if fe.get("ssl_enabled"):
        fe["certificates"] = ["wildcert"]
save_config(cfg)

util._CERT_READS.clear()
before = len(runs)
t = time.perf_counter()
svcs = client.get("/api/services", headers=H).get_json()
cold = time.perf_counter() - t
ok(len(svcs) == N and all(s["certificate"] == "wildcard" and s["certificate_status"] == "valid"
                          for s in svcs),
   "%d services, each shown on the wildcard and valid" % len(svcs))
ok(len(runs) - before == 1, "%d services behind one certificate read it once: %d openssl run(s)"
   % (N, len(runs) - before))
before = len(runs)
t = time.perf_counter()
client.get("/api/services", headers=H)
warm = time.perf_counter() - t
ok(len(runs) == before, "and the next visit reads nothing")
print("        /api/services with %d services: %.0f ms first, %.0f ms after" % (N, cold * 1000, warm * 1000))

print("\n" + ("%d failed" % len(fails) if fails else "each certificate file is read once"))
sys.exit(1 if fails else 0)
