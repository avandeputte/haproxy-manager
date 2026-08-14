#!/usr/bin/env python3
"""The optional second factor: the arithmetic, and the doors it guards.

The TOTP arithmetic is pinned to the RFC 4226 test vectors -- a code that
computes anything else locks the person out at the door. The flow is pinned
too: nothing stored until the phone proves it holds the secret, a code never
working twice, recovery codes burning on use, and the pushed administrator
record carrying it all so a failover node asks the same question.

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

r = client.post("/api/2fa/setup").get_json()
ok(r["ok"] and r["secret"] and r["uri"].startswith("otpauth://totp/"),
   "setup hands back a secret and its otpauth URI")
ok(isinstance(r["matrix"], list) and len(r["matrix"]) >= 21,
   "and the QR code as a matrix, drawn by the browser")
ok(not (load_config()["local"]["admin"].get("totp_secret")),
   "nothing is stored yet: an unscanned secret must not lock the account")

secret = r["secret"]
r = client.post("/api/2fa/enable", json={"secret": secret, "code": "000000"}).get_json()
ok(not r["ok"], "a wrong code refuses to enable it")

good = twofactor.hotp(secret, int(time.time() // 30))
r = client.post("/api/2fa/enable", json={"secret": secret, "code": good}).get_json()
ok(r["ok"] and len(r["recovery"]) == 8, "the right code enables it, with recovery codes")
recovery = r["recovery"]
admin = load_config()["local"]["admin"]
ok(admin.get("totp_enabled") and admin.get("totp_secret") == secret, "and it is stored")
ok(all(len(h) == 64 for h in admin["totp_recovery"]) and
   not any(c.replace("-", "") in str(admin["totp_recovery"]) for c in recovery),
   "recovery codes are stored only as hashes")

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

# -- turning it off ----------------------------------------------------------
authed = ham.app.test_client()
authed.post("/api/login", json={"username": "alex", "password": "twofactor-pw1",
                                "code": recovery[1]})
r = authed.post("/api/2fa/disable", json={"password": "wrong"}).get_json()
ok(not r["ok"], "the wrong password does not turn it off")
r = authed.post("/api/2fa/disable", json={"password": "twofactor-pw1"}).get_json()
ok(r["ok"] and not load_config()["local"]["admin"].get("totp_secret"),
   "the right one does, and the secret is gone")
r = ham.app.test_client().post("/api/login",
    json={"username": "alex", "password": "twofactor-pw1"})
ok(r.status_code == 200, "and the password alone signs in again")

print("\n" + ("%d failed" % len(fails) if fails
              else "the second factor guards the door it should"))
sys.exit(1 if fails else 0)
