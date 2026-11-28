#!/usr/bin/env python3
"""The optional second factor: the arithmetic, and the doors it guards.

The TOTP arithmetic is pinned to the RFC 4226 test vectors -- a code that
computes anything else locks the person out at the door. The flow is pinned
too: nothing stored until the phone proves it holds the secret, enrolment
asking for the password and never replacing a phone already enrolled, a code
never working twice, recovery codes burning on use, a password change keeping
the second factor, and the pushed administrator record carrying it all so a
failover node asks the same question. The otpauth URI is pinned to encode
what it carries, and to shrink its label rather than fail when a long name
and a long host name would not fit the QR code.

    HAM_DATA_DIR=/tmp/x python3 tools/test-twofactor.py
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-2fa-"))
os.environ["HAM_DRY_RUN"] = "1"

import base64   # noqa: E402
import ham; ham   # noqa: E402  (route registration)
from ham import twofactor   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


# -- RFC 4226 appendix D: secret "12345678901234567890", counters 0..9 -------
SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
VECTORS = ["755224", "287082", "359152", "969429", "338314",
           "254676", "287922", "162583", "399871", "520489"]
ok(all(twofactor.hotp(SECRET, i) == v for i, v in enumerate(VECTORS)),
   "the HOTP arithmetic matches every RFC 4226 test vector")

now = 59                                 # RFC 6238: T=59 -> counter 1
ok(twofactor.verify_totp(SECRET, VECTORS[1], now=now) == 1,
   "a TOTP is the HOTP of the time step")
ok(twofactor.verify_totp(SECRET, VECTORS[0], now=now) == 0,
   "a code from the previous step still verifies -- phones drift")
ok(twofactor.verify_totp(SECRET, VECTORS[3], now=now) is None,
   "one from further away does not")
ok(twofactor.verify_totp(SECRET, VECTORS[1], now=now, last_counter=1) is None,
   "a one-time password is one-time: the same code is refused the second time")
ok(twofactor.verify_totp(SECRET, "12345", now=now) is None and
   twofactor.verify_totp(SECRET, "boop12", now=now) is None,
   "five digits or letters are not a code")

# -- the flow ----------------------------------------------------------------
import time   # noqa: E402
ham.app.config["TESTING"] = True
client = ham.app.test_client()
client.post("/api/setup", json={"username": "alex", "password": "twofactor-pw1"})

r = client.post("/api/2fa/setup")
ok(r.status_code == 403, "a change asked on a session without a JSON body is turned away "
                         "as a form post would be")
r = client.post("/api/2fa/setup", json={}).get_json()       # as the UI sends it
ok(r["ok"] and r["secret"] and r["uri"].startswith("otpauth://totp/"),
   "setup hands back a secret and its otpauth URI")
ok(isinstance(r["matrix"], list) and len(r["matrix"]) >= 21,
   "and the QR code as a matrix, drawn by the browser")
ok(not (load_config()["local"]["admin"].get("totp_secret")),
   "nothing is stored yet: an unscanned secret must not lock the account")

secret = r["secret"]
PW = "twofactor-pw1"
good = twofactor.hotp(secret, int(time.time() // 30))
r = client.post("/api/2fa/enable", json={"secret": secret, "code": good})
ok(r.status_code == 401 and not load_config()["local"]["admin"].get("totp_secret"),
   "a session alone cannot enrol a phone: the password is asked for, as it is to turn it off")
r = client.post("/api/2fa/enable", json={"secret": secret, "code": good, "password": "wrong"})
ok(r.status_code == 401, "and the wrong password does not do")
r = client.post("/api/2fa/enable", json={"secret": secret, "code": "000000", "password": PW}).get_json()
ok(not r["ok"], "a wrong code refuses to enable it")

r = client.post("/api/2fa/enable", json={"secret": secret, "code": good, "password": PW}).get_json()
ok(r["ok"] and len(r["recovery"]) == 8, "the right code and password enable it, with recovery codes")
recovery = r["recovery"]
admin = load_config()["local"]["admin"]
ok(admin.get("totp_enabled") and admin.get("totp_secret") == secret, "and it is stored")
ok(all(len(h) == 64 for h in admin["totp_recovery"]) and
   not any(c.replace("-", "") in str(admin["totp_recovery"]) for c in recovery),
   "recovery codes are stored only as hashes")

other = twofactor.new_secret()
r = client.post("/api/2fa/enable", json={"secret": other, "password": PW,
                                         "code": twofactor.hotp(other, int(time.time() // 30))})
ok(r.status_code == 409 and load_config()["local"]["admin"].get("totp_secret") == secret,
   "a second enrolment does not replace the first: the phone in use is turned off first")

# -- signing in --------------------------------------------------------------
fresh = ham.app.test_client()
r = fresh.post("/api/login", json={"username": "alex", "password": "twofactor-pw1"})
ok(r.status_code == 401 and r.get_json().get("totp_required"),
   "the right password alone is no longer enough -- and says a code is wanted")

# the code minted at enable was consumed by enable's verification bookkeeping?
# enable does not touch totp_last, so the current code works:
code = twofactor.hotp(secret, int(time.time() // 30) + 1)
# +1 keeps this test off the counter any earlier verification may have burned
r = fresh.post("/api/login", json={"username": "alex", "password": "twofactor-pw1",
                                   "code": code})
ok(r.status_code == 200, "password plus code signs in")
r2 = ham.app.test_client().post("/api/login",
    json={"username": "alex", "password": "twofactor-pw1", "code": code})
ok(r2.status_code == 401, "the same code cannot sign in twice")

r = ham.app.test_client().post("/api/login",
    json={"username": "alex", "password": "twofactor-pw1", "code": recovery[0]})
ok(r.status_code == 200, "a recovery code works in place of a code")
r = ham.app.test_client().post("/api/login",
    json={"username": "alex", "password": "twofactor-pw1", "code": recovery[0]})
ok(r.status_code == 401, "and burns on use")
ok(len(load_config()["local"]["admin"]["totp_recovery"]) == 7, "seven remain")

# -- the pushed record carries it --------------------------------------------
cfg = load_config()
cfg["local"]["api_key"] = "push-test-key"
save_config(cfg)
rec = dict(load_config()["local"]["admin"])
r = client.post("/api/admin/receive", json={"admin": rec},
                headers={"X-API-Key": "push-test-key"}).get_json()
ok(r["ok"], "the record is accepted")
after = load_config()["local"]["admin"]
ok(after.get("totp_enabled") and after.get("totp_secret") == secret,
   "a failover node asks for the same code the active one would")

# -- a password change keeps the second factor, and so does the push ---------
from ham import sync   # noqa: E402
cfg = load_config()
cfg["local"]["sync"]["peers"] = [{"id": "p1", "name": "node-2", "url": "https://node-2.example",
                                  "api_key": "k2", "enabled": True, "verify_tls": True}]
save_config(cfg)
pushed = []


class _Reply:
    status_code = 200

    def json(self):
        return {"ok": True}


class _Requests:
    def post(self, url, json=None, **kw):
        pushed.append((url, json))
        return _Reply()


authed = ham.app.test_client()
authed.post("/api/login", json={"username": "alex", "password": PW, "code": recovery[1]})
real_requests, sync._requests = sync._requests, _Requests()
try:
    r = authed.post("/api/password", json={"current": PW, "new": "twofactor-pw2", "propagate": True})
finally:
    sync._requests = real_requests
PW = "twofactor-pw2"
admin = load_config()["local"]["admin"]
ok(r.status_code == 200 and twofactor.enabled(admin) and admin.get("totp_secret") == secret,
   "changing the password leaves the second factor in place")
ok(len(admin.get("totp_recovery") or []) == 6, "with the recovery codes not yet used")
sent = (pushed[0][1] if pushed else {}).get("admin") or {}
ok(pushed and pushed[0][0].endswith("/api/admin/receive")
   and sent.get("totp_enabled") and sent.get("totp_secret") == secret and sent.get("totp_recovery"),
   "and the record pushed to the other nodes carries it, so none of them stops asking")
ok(sent.get("hash") == admin["hash"] and sent.get("hash") != rec["hash"],
   "along with the new password digest")

# -- turning it off ----------------------------------------------------------
authed = ham.app.test_client()
authed.post("/api/login", json={"username": "alex", "password": PW, "code": recovery[2]})
r = authed.post("/api/2fa/disable", json={"password": "wrong"}).get_json()
ok(not r["ok"], "the wrong password does not turn it off")
r = authed.post("/api/2fa/disable", json={"password": PW}).get_json()
ok(r["ok"] and not load_config()["local"]["admin"].get("totp_secret"),
   "the right one does, and the secret is gone")
r = ham.app.test_client().post("/api/login", json={"username": "alex", "password": PW})
ok(r.status_code == 200, "and the password alone signs in again")

# -- the URI the phone scans -------------------------------------------------
cfg = load_config()
cfg["local"]["admin"]["username"] = "ops team/alex"
uri = twofactor.otpauth_uri(cfg, "ABC234", host="node 1.example.org")
ok(uri == "otpauth://totp/haproxy-manager:ops%20team%2Falex%40node%201.example.org"
          "?secret=ABC234&issuer=haproxy-manager&digits=6&period=30",
   "the account label is percent-encoded: a space or a slash in a name does not break the URI")
real_host = twofactor.socket.gethostname
try:
    cfg["local"]["admin"]["username"] = "a" * 40
    twofactor.socket.gethostname = lambda: "node-" + "x" * 40 + ".very.long.example.org"
    uri, matrix = twofactor.enrolment(cfg, twofactor.new_secret())
    ok(uri and isinstance(matrix, list) and ".very.long" not in uri and "%40node-" in uri,
       "a label too long for the QR code with the full host name keeps the short one")
    twofactor.socket.gethostname = lambda: "x" * 300
    uri, matrix = twofactor.enrolment(cfg, twofactor.new_secret())
    ok(uri and isinstance(matrix, list) and "%40" not in uri,
       "a host name that will not fit at all is left out of the label")
    cfg["local"]["admin"]["username"] = "a" * 400
    uri, why = twofactor.enrolment(cfg, twofactor.new_secret())
    ok(uri is None and "too long" in why,
       "and a name that fits nowhere is refused with a reason rather than a crash")
finally:
    twofactor.socket.gethostname = real_host

print("\n" + ("%d failed" % len(fails) if fails
              else "the second factor guards the door it should"))
sys.exit(1 if fails else 0)
