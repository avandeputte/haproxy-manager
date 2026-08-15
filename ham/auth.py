"""Sessions for people, an API key for peers and scripts."""

from datetime import datetime
from datetime import timezone
from flask import jsonify
from flask import request
import base64
import hashlib
import hmac
import os
import re
import socket
import time

from .base import PORT, VERSION, _lock, app, log
from .config import load_config, save_config
from .util import run
from . import sync, twofactor, vrrp

# --------------------------------------------------------------------------
# authentication: interactive login for people, API key for the peer/scripts
# --------------------------------------------------------------------------

PBKDF2_ITERATIONS = 240000
SESSION_COOKIE = "ham_session_" + hashlib.sha256(
    ("%s:%s" % (socket.gethostname(), PORT)).encode()).hexdigest()[:8]
_login_fails = {}       # remote address -> [failure count, locked-until timestamp]
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SECONDS = 60


def hash_password(password, salt=None, iterations=PBKDF2_ITERATIONS):
    salt = salt or os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations)
    return {"salt": salt, "hash": dk.hex(), "iterations": iterations}


def verify_password(password, admin):
    if not (admin.get("hash") and admin.get("salt")):
        return False
    got = hash_password(password, admin["salt"], admin.get("iterations") or PBKDF2_ITERATIONS)
    return hmac.compare_digest(got["hash"], admin["hash"])


def bad_username(username):
    """A complaint if this cannot be an administrator name, else "".

    The name is written into the session payload as `username|exp|unlocked`
    and split back on "|", so a "|" in it would shift the expiry out of
    position -- a login that succeeds but can never be read back, a permanent
    401 loop repairable only through the API key. Control characters have no
    business in a login name either.
    """
    username = (username or "").strip()
    if not username:
        return "a username is required"
    if len(username) > 64:
        return "the username is too long"
    if "|" in username or any(ord(c) < 0x20 for c in username):
        return "the username cannot contain '|' or control characters"
    return ""


def set_admin(cfg, username, password):
    rec = hash_password(password)
    rec["username"] = (username or "admin").strip() or "admin"
    rec["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cfg["local"]["admin"] = rec
    # The password just changed, so every cookie signed with the old secret
    # must stop verifying: rotate the signing secret here, where the password
    # is set, so no caller can change the login and leave a stolen session
    # alive behind it. A cookie that outlived a password change could be
    # traded for the API key and session secret at /api/local -- permanent
    # credentials from a transient theft.
    cfg["local"]["session_secret"] = os.urandom(32).hex()
    return cfg


def key_fingerprint(key):
    """A short, stable tag for a key, so two nodes can be compared by eye."""
    key = (key or "").strip()
    return hashlib.sha256(key.encode()).hexdigest()[:8] if key else ""


def key_matches(stored, presented):
    """Compare API keys, ignoring whitespace a copy-and-paste picked up.

    A key pasted with a trailing newline looks identical on screen but fails a
    byte comparison, which surfaces only as an unexplained 401.
    """
    stored = (stored or "").strip()
    presented = (presented or "").strip()
    if not stored or not presented:
        return False
    try:
        return hmac.compare_digest(stored.encode(), presented.encode())
    except (UnicodeEncodeError, TypeError):
        return False


def needs_setup(cfg):
    """True while no administrator exists -- the UI then offers to create one.

    A configuration that would not parse is never first-run: treating a
    corrupt file as "no admin yet" would open setup to anyone. It reads as
    already-set-up, so setup refuses and the broken file can be repaired
    rather than silently replaced.
    """
    if (cfg.get("_meta") or {}).get("unreadable"):
        return False
    return not (cfg["local"].get("admin") or {}).get("hash")


def session_secret(cfg):
    secret = cfg["local"].get("session_secret") or ""
    if not secret:
        secret = os.urandom(32).hex()
        cfg["local"]["session_secret"] = secret
        save_config(cfg)
    return secret


def make_session(cfg, username, unlocked=False):
    exp = int(time.time()) + max(1, int(cfg["local"].get("session_hours") or 12)) * 3600
    payload = "%s|%d|%d" % (username, exp, 1 if unlocked else 0)
    sig = hmac.new(session_secret(cfg).encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(("%s|%s" % (payload, sig)).encode()).decode()


def read_session(cfg, token):
    """Return the username carried by a valid, unexpired token, else None."""
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        body, sig = raw.rsplit("|", 1)
        parts = body.split("|")
        username, exp = parts[0], parts[1]
        unlocked = len(parts) > 2 and parts[2] == "1"
    except Exception:
        return None
    payload = body
    want = hmac.new(session_secret(cfg).encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, sig):
        return None
    try:
        if int(exp) < time.time():
            return None
    except ValueError:
        return None
    return {"user": username, "unlocked": unlocked}


def current_session(cfg=None):
    cfg = cfg or load_config()
    token = request.cookies.get(SESSION_COOKIE, "")
    return (read_session(cfg, token) if token else None) or {}


def current_user(cfg=None):
    return current_session(cfg).get("user")


def session_unlocked(cfg=None):
    """Has this session lifted the passive-node lock? It cannot outlive it."""
    try:
        return bool(current_session(cfg).get("unlocked"))
    except RuntimeError:            # no request context: background threads
        return False


PUBLIC_PATHS = {"/api/login", "/api/whoami", "/api/setup"}   # /api/setup creates the first admin

# Shared configuration is edited on the node that holds the virtual IP and
# pushed out from there. Everything a passive node needs to fix ITSELF -- its
# interface, priority, login, API key, peer list, updates -- stays editable,
# otherwise a node that cannot take the VIP could never be repaired.
LOCAL_WRITE_PREFIXES = (
    "/api/local", "/api/password", "/api/logout", "/api/peers",
    "/api/update", "/api/version", "/api/apply", "/api/sync/receive", "/api/setup",
    "/api/admin",          # the administrator record, pushed from another node
    "/api/webui",          # this node's own UI address, not shared
    "/api/unlock",         # lifting the lock cannot itself be blocked by it
)


def node_role(cfg):
    vips = vrrp.cluster_vips(cfg)
    if not vips:
        return "standalone", []
    rc, out = run(["ip", "-o", "addr"])
    held = [v for v in vips if rc == 0 and re.search(r"\binet6? %s/" % re.escape(v), out)]
    return ("active" if held else "passive"), held


def readonly_state(cfg):
    """(read_only, reason). Only a passive node is read-only, and only if asked."""
    if session_unlocked(cfg):
        return False, ""
    role, _ = node_role(cfg)
    if role != "passive":
        return False, ""
    if not sync.enabled_peers(cfg):
        # Nothing to defer to. A lone node that has not won the virtual IP --
        # during bring-up, or because VRRP is broken -- must stay usable.
        return False, ""
    return True, ("This node is passive: another node holds the virtual IP and serves traffic. "
                  "Change the shared configuration there and push it here, so the two cannot "
                  "diverge. This node's own settings stay editable.")


@app.after_request
def _audit(resp):
    """One line per change, so the log says who did what from where."""
    if request.path.startswith("/api/") and request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if request.path not in ("/api/login", "/api/whoami"):
            try:
                who = current_user() or ("api-key" if request.headers.get("X-API-Key") else "anonymous")
            except Exception:
                who = "?"
            what = ""
            if request.is_json:
                # the name only -- request bodies carry passwords and API keys
                try:
                    name = (request.get_json(silent=True) or {}).get("name")
                    what = " '%s'" % str(name)[:80] if name else ""
                except Exception:
                    what = ""
            level = log.info if resp.status_code < 400 else log.warning
            level("%s %s %s%s -> %s (%s)", who, request.method, request.path,
                  what, resp.status_code, request.remote_addr)
    return resp


@app.before_request
def _auth():
    if not request.path.startswith("/api/"):
        return

    # Flask's MAX_CONTENT_LENGTH is only applied by the form parser on the
    # Werkzeug that ships with Debian, so a JSON body of any size is read into
    # memory. Check it here, before anything reads the stream.
    limit = app.config.get("MAX_CONTENT_LENGTH") or 0
    if limit and (request.content_length or 0) > limit:
        return jsonify({"ok": False, "error":
                        "the request body is too large (%d bytes, limit %d)"
                        % (request.content_length, limit)}), 413
    if request.path in PUBLIC_PATHS:
        return
    if request.path == "/api/sync/receive":
        return  # enforced inside the handler (always requires the API key)

    cfg = load_config()
    if needs_setup(cfg) and not cfg["local"].get("api_key"):
        # First run. Only the calls that create the administrator are open;
        # everything else stays shut, so a node waiting to be set up does not
        # hand its configuration to whoever reaches it first.
        if request.path == "/api/setup/state":
            return
        return jsonify({"ok": False, "needs_setup": True, "error":
                        "This node has no administrator yet. Open it in a browser and create "
                        "one; until then only setup is available."}), 401

    authorised = bool(current_user(cfg))
    if not authorised:
        authorised = key_matches(cfg["local"].get("api_key"), request.headers.get("X-API-Key"))
    if not authorised:
        presented = request.headers.get("X-API-Key")
        # header_seen is always reported: a request that arrives with no key at
        # all is the signature of something stripping it in transit.
        body = {"ok": False, "hostname": socket.gethostname(), "version": VERSION,
                "header_seen": presented is not None,
                "error": "not authorised: sign in, or present this node's API key as X-API-Key"}
        if presented is not None:          # a machine tried a key: help it compare
            body.update({"presented_fp": key_fingerprint(presented),
                         "expected_fp": key_fingerprint(cfg["local"].get("api_key"))})
        return jsonify(body), 401

    if request.method in ("POST", "PUT", "DELETE", "PATCH") and \
            not request.path.startswith(LOCAL_WRITE_PREFIXES):
        ro, why = readonly_state(cfg)
        if ro:
            return jsonify({"ok": False, "error": why, "read_only": True}), 409


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(413)
@app.errorhandler(500)
def _json_errors(e):
    """API callers get JSON, not Werkzeug's HTML page."""
    if not request.path.startswith("/api/"):
        return e
    code = getattr(e, "code", 500)
    limit = app.config.get("MAX_CONTENT_LENGTH") or 0
    if code == 400 and limit and (request.content_length or 0) > limit:
        code = 413                       # Werkzeug reports the parse failure, not the size
    text = {400: "the request body was not valid JSON",
            404: "no such endpoint or object",
            405: "that method is not allowed here",
            413: "the request body is too large",
            500: "the node hit an unexpected error"}.get(code, str(e))
    return jsonify({"ok": False, "error": text}), code


@app.get("/api/whoami")
def api_whoami():
    cfg = load_config()
    user = current_user(cfg)
    if not user:
        # Unauthenticated: only what the sign-in screen has to know. The
        # administrator's name, the hostname and the version are not for
        # anyone who can merely reach the port.
        return jsonify({"authenticated": False, "needs_setup": needs_setup(cfg)})
    return jsonify({
        "authenticated": True,
        "username": user,
        "email": (cfg["local"].get("admin") or {}).get("email", ""),
        "theme": (cfg["local"].get("admin") or {}).get("theme", "system"),
        "totp_enabled": twofactor.enabled(cfg["local"].get("admin") or {}),
        "version": VERSION,
        "hostname": socket.gethostname(),
        "needs_setup": False,
        "admin_username": (cfg["local"].get("admin") or {}).get("username", "admin"),
        # How many other nodes there are, so the account dialog knows whether
        # offering to copy the login anywhere makes sense.
        "peers": len(sync.enabled_peers(cfg)),
    })


def _prune_login_fails():
    """Drop finished entries: one per source address would otherwise accumulate."""
    now = time.time()
    for addr in [a for a, (fails, until) in _login_fails.items() if until and until < now]:
        _login_fails.pop(addr, None)
    if len(_login_fails) > 5000:            # a flood from many addresses
        _login_fails.clear()


def _login_ok(cfg, username, resp_body):
    resp = jsonify(resp_body)
    resp.set_cookie(
        SESSION_COOKIE, make_session(cfg, username),
        max_age=max(1, int(cfg["local"].get("session_hours") or 12)) * 3600,
        httponly=True, samesite="Strict", secure=request.is_secure, path="/",
    )
    return resp


@app.post("/api/setup")
def api_setup():
    """Create the first administrator. Only possible while none exists."""
    cfg = load_config()
    if not needs_setup(cfg):
        return jsonify({"ok": False, "error": "an administrator already exists"}), 409
    body = request.get_json(force=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    bad = bad_username(username)
    if bad:
        return jsonify({"ok": False, "error": bad}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "error": "the password must be at least 8 characters"}), 400
    with _lock:
        cfg = load_config()
        if not needs_setup(cfg):        # someone else got there first
            return jsonify({"ok": False, "error": "an administrator already exists"}), 409
        set_admin(cfg, username, password)
        save_config(cfg)
    return _login_ok(cfg, username, {"ok": True, "username": username})


@app.post("/api/login")
def api_login():
    cfg = load_config()
    ip = request.remote_addr or "?"
    fails, until = _login_fails.get(ip, [0, 0])
    if until > time.time():
        return jsonify({"ok": False, "error": "too many failed attempts -- try again in %d seconds"
                                              % int(until - time.time())}), 429

    body = request.get_json(force=True) or {}
    admin = cfg["local"].get("admin") or {}
    username = (body.get("username") or "").strip()
    ok = (hmac.compare_digest(username.encode(), admin.get("username", "").encode()) and
          verify_password(body.get("password") or "", admin))

    def failed(message, status=401):
        nonlocal fails
        fails += 1
        if fails >= LOGIN_MAX_FAILS:
            _login_fails[ip] = [0, time.time() + LOGIN_LOCK_SECONDS]   # locked; counter restarts
        else:
            _login_fails[ip] = [fails, 0]
        _prune_login_fails()
        log.warning("failed sign-in for %r from %s (%d in a row)", username, ip, fails)
        time.sleep(0.5)  # blunt the rate of online guessing
        return jsonify({"ok": False, "error": message}), status

    if not ok:
        return failed("invalid username or password")

    # The second factor, for accounts that carry one. The password was right,
    # so asking for the code is not a failure -- and does not count as one.
    if twofactor.enabled(admin):
        code = (body.get("code") or "").strip()
        if not code:
            return jsonify({"ok": False, "totp_required": True,
                            "error": "enter the six-digit code from your "
                                     "authenticator app"}), 401
        # Verify the code and consume it in one held lock, against the counter
        # and recovery list read inside that lock. Checking a lock-free copy
        # and storing the result later left a window where two logins racing
        # with the same shoulder-surfed code both read the old counter, both
        # passed the replay check, and both got in -- and two concurrent
        # recovery-code uses could burn the same code twice.
        accepted = False
        recovery_left = None
        with _lock:
            cur = load_config()
            cur_admin = cur["local"].setdefault("admin", {})
            counter = twofactor.verify_totp(cur_admin.get("totp_secret"), code,
                                            last_counter=int(cur_admin.get("totp_last") or 0))
            if counter is not None:
                cur_admin["totp_last"] = counter
                save_config(cur)
                accepted = True
            elif twofactor.use_recovery(cur_admin, code):
                save_config(cur)
                accepted = True
                recovery_left = len(cur_admin.get("totp_recovery") or [])
        if recovery_left is not None:
            log.warning("a recovery code was used to sign in as %s; %d remain%s",
                        username, recovery_left, "" if recovery_left != 1 else "s")
        if not accepted:
            return failed("that code is not right, or was already used")

    _login_fails.pop(ip, None)
    log.info("signed in: %s from %s", username, ip)
    return _login_ok(cfg, username, {"ok": True, "username": username})


@app.post("/api/unlock")
def api_unlock():
    """Lift or restore the passive-node lock for this session only.

    Kept in the session rather than the configuration so it cannot outlive the
    person who set it: signing out or back in restores the lock.
    """
    cfg = load_config()
    user = current_user(cfg)
    if not user:
        return jsonify({"ok": False, "error": "sign in first"}), 401
    on = bool((request.get_json(silent=True) or {}).get("on"))
    resp = jsonify({"ok": True, "unlocked": on})
    resp.set_cookie(SESSION_COOKIE, make_session(cfg, user, unlocked=on),
                    max_age=max(1, int(cfg["local"].get("session_hours") or 12)) * 3600,
                    httponly=True, samesite="Strict", secure=request.is_secure, path="/")
    return resp


@app.post("/api/logout")
def api_logout():
    resp = jsonify({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.post("/api/admin/receive")
def api_admin_receive():
    """Take the administrator record from another node.

    Node-local settings are never synced as a rule, and this is the deliberate
    exception: it only runs because someone ticked the box on another node.
    The API key is required -- a session on this node is not enough -- so it
    cannot be reached from a browser.

    What arrives is the salt and digest, not a password: this node can verify
    the same password afterwards, and still cannot tell you what it is.
    """
    cfg = load_config()
    if not key_matches(cfg["local"].get("api_key"), request.headers.get("X-API-Key")):
        return jsonify({"ok": False, "hostname": socket.gethostname(),
                        "error": "the administrator can only be set by a node presenting "
                                 "this node's API key",
                        "presented_fp": key_fingerprint(request.headers.get("X-API-Key")),
                        "expected_fp": key_fingerprint(cfg["local"].get("api_key"))}), 401
    rec = (request.get_json(force=True) or {}).get("admin") or {}
    if not (rec.get("hash") and rec.get("salt") and rec.get("username")):
        return jsonify({"ok": False, "error": "that is not an administrator record"}), 400
    with _lock:
        cfg = load_config()
        cfg["local"]["admin"] = {
            "username": str(rec["username"]).strip() or "admin",
            "salt": str(rec["salt"]), "hash": str(rec["hash"]),
            "iterations": int(rec.get("iterations") or PBKDF2_ITERATIONS),
            "email": str(rec.get("email") or ""),
            "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        # The same login everywhere means the same second factor everywhere:
        # a failover node that suddenly stopped asking for the code would be
        # the door left open exactly when nobody is watching.
        if rec.get("totp_secret") and rec.get("totp_enabled"):
            cfg["local"]["admin"].update({
                "totp_secret": str(rec["totp_secret"]),
                "totp_enabled": True,
                "totp_recovery": [str(h) for h in rec.get("totp_recovery") or []],
                "totp_last": int(rec.get("totp_last") or 0),
            })
        # Rotate the session secret, which is what signs the cookies: every
        # session on this node is now invalid. That is correct -- the
        # credential changed, and anyone signed in here was signed in with the
        # old one. Without this a stolen cookie would outlive the password
        # change that was meant to shut it out.
        cfg["local"]["session_secret"] = os.urandom(32).hex()
        save_config(cfg)
    log.info("administrator record accepted from %s", request.remote_addr)
    return jsonify({"ok": True, "hostname": socket.gethostname(),
                    "username": cfg["local"]["admin"]["username"]})


@app.post("/api/password")
def api_password():
    """Change the administrator username and/or password (session required)."""
    cfg = load_config()
    user = current_user(cfg)
    if not user:
        return jsonify({"ok": False, "error": "log in first"}), 401
    body = request.get_json(force=True) or {}
    admin = cfg["local"].get("admin") or {}
    new = body.get("new") or ""
    wants_name = (body.get("username") or admin.get("username") or "admin").strip() \
        != (admin.get("username") or "admin")
    # The current password is what proves it is still you at the keyboard, so
    # anything that changes how you sign in requires it. The email is not a
    # credential and there is no reset-by-email here, so a session is enough.
    if new or wants_name:
        if not verify_password(body.get("current") or "", admin):
            time.sleep(0.5)
            return jsonify({"ok": False, "error":
                            "the current password is not correct"}), 401
    # Appearance is a preference, not a credential: it needs a session and
    # nothing more, and it travels with the account so it follows the person to
    # another browser.
    theme = body.get("theme")
    if theme is not None and theme not in ("system", "light", "dark"):
        return jsonify({"ok": False, "error": "unknown appearance %r" % theme}), 400
    # The email can be changed on its own; a password only when one is given.
    email = body.get("email")
    if email is not None:
        email = str(email).strip()
        if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return jsonify({"ok": False, "error": "that does not look like an email address"}), 400
    if new and len(new) < 8:
        return jsonify({"ok": False, "error": "the new password must be at least 8 characters"}), 400
    username = (body.get("username") or admin.get("username") or "admin").strip()
    bad = bad_username(username)
    if bad:
        return jsonify({"ok": False, "error": bad}), 400
    with _lock:
        cfg = load_config()
        if new:
            set_admin(cfg, username, new)
        else:
            cfg["local"]["admin"]["username"] = username
        if email is not None:
            cfg["local"]["admin"]["email"] = email
        if theme is not None:
            cfg["local"]["admin"]["theme"] = theme
        save_config(cfg)
    # Offered rather than automatic: the login is node-local, and wanting a
    # different administrator on one node is legitimate.
    pushed = sync.push_admin(cfg) if body.get("propagate") else None
    for r in (pushed or []):
        (log.info if r.get("ok") else log.warning)(
            "administrator %s on %s%s", "updated" if r.get("ok") else "NOT updated",
            r.get("name"), "" if r.get("ok") else ": " + r.get("error", ""))
    out = {"ok": True, "username": username,
           "email": cfg["local"]["admin"].get("email", ""),
           "theme": cfg["local"]["admin"].get("theme", "system")}
    if pushed is not None:
        out["nodes"] = pushed
    if new or wants_name:
        return _login_ok(cfg, username, out)
    return jsonify(out)


# --------------------------------------------------------------------------
# settings validation
