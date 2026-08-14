"""A second factor for the sign-in, for whoever wants one.

Time-based one-time passwords, RFC 6238: the standard six digits every
thirty seconds that any authenticator app produces. Optional, per
administrator, enabled from the account dialog -- and the escape hatch for a
lost phone is deliberate and physical: `app.py disable-2fa` on the node's own
shell, because whoever can run that already owns the machine.

hashlib and hmac are the whole implementation, like the password hashing:
a dependency would be larger than the code.
"""

from flask import jsonify, request
import base64
import hashlib
import hmac
import os
import socket
import time

from .base import _lock, app, log
from .config import load_config, save_config
from . import auth, qr

DIGITS = 6
STEP = 30
# Codes one step either side still verify: phones drift, people type slowly.
DRIFT = 1
RECOVERY_CODES = 8


def new_secret():
    """A 160-bit secret, base32 without padding -- what the apps expect."""
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def hotp(secret_b32, counter):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF
    return "%0*d" % (DIGITS, code % (10 ** DIGITS))


def verify_totp(secret_b32, code, now=None, last_counter=-1):
    """The matching counter when the code is good, else None.

    The counter is handed back so the caller can remember it: a TOTP is a
    one-time password, and accepting the same code twice inside its window
    would let anyone who watched it typed use it right behind you.
    """
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != DIGITS:
        return None
    counter = int((now if now is not None else time.time()) // STEP)
    for c in range(counter - DRIFT, counter + DRIFT + 1):
        if c > last_counter and hmac.compare_digest(hotp(secret_b32, c), code):
            return c
    return None


def _hash_recovery(code):
    return hashlib.sha256(code.strip().replace("-", "").lower().encode()).hexdigest()


def make_recovery_codes():
    """Eight codes, shown once; only their hashes are stored."""
    plain = []
    for _ in range(RECOVERY_CODES):
        raw = base64.b32encode(os.urandom(5)).decode().lower().rstrip("=")
        plain.append(raw[:4] + "-" + raw[4:8])
    return plain, [_hash_recovery(p) for p in plain]


def use_recovery(admin, code):
    """Burn a recovery code. True if it matched (the caller saves)."""
    want = _hash_recovery(code or "")
    hashes = admin.get("totp_recovery") or []
    if want in hashes:
        admin["totp_recovery"] = [h for h in hashes if h != want]
        return True
    return False


def enabled(admin):
    return bool(admin.get("totp_secret")) and bool(admin.get("totp_enabled"))


def otpauth_uri(cfg, secret):
    user = (cfg["local"].get("admin") or {}).get("username") or "admin"
    issuer = "haproxy-manager"
    label = "%s:%s@%s" % (issuer, user, socket.gethostname())
    return "otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d" % (
        label, secret, issuer, DIGITS, STEP)


# --------------------------------------------------------------------------

@app.post("/api/2fa/setup")
def api_2fa_setup():
    """Start enrolment: a fresh secret and its QR code. Nothing is stored yet.

    The secret only takes effect when /api/2fa/enable proves the authenticator
    produces the right codes -- enabling 2FA against a secret that was never
    scanned locks the account, which is the one outcome worse than no 2FA.
    """
    cfg = load_config()
    if not auth.current_user(cfg):
        return jsonify({"ok": False, "error": "sign in first"}), 401
    secret = new_secret()
    uri = otpauth_uri(cfg, secret)
    return jsonify({"ok": True, "secret": secret, "uri": uri,
                    "matrix": qr.encode(uri)})


@app.post("/api/2fa/enable")
def api_2fa_enable():
    """Turn it on, once the phone has proven it holds the secret."""
    cfg = load_config()
    if not auth.current_user(cfg):
        return jsonify({"ok": False, "error": "sign in first"}), 401
    body = request.get_json(force=True, silent=True) or {}
    secret = (body.get("secret") or "").strip()
    if not secret:
        return jsonify({"ok": False, "error": "run setup first"}), 400
    if verify_totp(secret, body.get("code")) is None:
        return jsonify({"ok": False, "error":
                        "that code does not match -- scan the QR code again and "
                        "enter the current six digits"}), 400
    plain, hashes = make_recovery_codes()
    with _lock:
        cfg = load_config()
        admin = cfg["local"].setdefault("admin", {})
        admin["totp_secret"] = secret
        admin["totp_enabled"] = True
        admin["totp_recovery"] = hashes
        admin["totp_last"] = 0
        save_config(cfg)
    log.info("two-factor authentication enabled for %s", admin.get("username"))
    return jsonify({"ok": True, "recovery": plain,
                    "note": "Keep these somewhere that is not the phone: each works "
                            "once, in place of a code, if the phone is gone."})


@app.post("/api/2fa/disable")
def api_2fa_disable():
    """Turn it off. The password proves it is still you at the keyboard."""
    cfg = load_config()
    if not auth.current_user(cfg):
        return jsonify({"ok": False, "error": "sign in first"}), 401
    body = request.get_json(force=True, silent=True) or {}
    if not auth.verify_password(body.get("password") or "",
                                cfg["local"].get("admin") or {}):
        time.sleep(0.5)
        return jsonify({"ok": False, "error": "the password is not correct"}), 401
    with _lock:
        cfg = load_config()
        admin = cfg["local"].setdefault("admin", {})
        for key in ("totp_secret", "totp_enabled", "totp_recovery", "totp_last"):
            admin.pop(key, None)
        save_config(cfg)
    log.info("two-factor authentication disabled for %s", admin.get("username"))
    return jsonify({"ok": True})
