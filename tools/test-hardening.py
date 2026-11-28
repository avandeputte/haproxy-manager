#!/usr/bin/env python3
"""The fixes from the code reviews, pinned so they cannot quietly regress.

Each of these was a real defect: a password change that left stolen sessions
alive, a backup that carried DNS credentials, a corrupt file that reopened
setup, a mesh push that undid TLS verification, an operator field that could
inject a directive. The second review added the door itself: a node-settings
read that handed out every credential, a session cookie never marked Secure
behind the UI's own listener, a sign-in throttle that saw every visitor as
127.0.0.1, a change accepted from any sibling site's form, and answers with
no security headers at all. One assertion each, at the seam where the fix
lives, driven through the real request path where there is one.

    HAM_DATA_DIR=/tmp/x python3 tools/test-hardening.py
"""
import base64
import copy
import hashlib
import os
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
_tmp = tempfile.mkdtemp(prefix="ham-harden-")
os.environ.setdefault("HAM_DATA_DIR", _tmp)
os.environ.setdefault("HAM_CERT_DIR", os.path.join(_tmp, "certs"))
os.environ.setdefault("HAM_HAPROXY_CFG", os.path.join(_tmp, "haproxy.cfg"))
os.environ.setdefault("HAM_KEEPALIVED_CFG", os.path.join(_tmp, "keepalived.conf"))
os.environ["HAM_DRY_RUN"] = "1"

import ham   # noqa: E402
from ham import auth, backup, haproxy, oauth   # noqa: E402
from ham.config import CONF_PATH, DEFAULT_CONFIG, load_config, save_config   # noqa: E402
from ham.auth import needs_setup   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


# -- a password change rotates the signing secret ----------------------------
cfg = copy.deepcopy(DEFAULT_CONFIG)
auth.set_admin(cfg, "alex", "first-password")
first_secret = cfg["local"]["session_secret"]
token = auth.make_session(cfg, "alex")
ok(auth.read_session(cfg, token) is not None, "a fresh session verifies")
cfg["local"]["admin"].update({"email": "alex@example.org", "theme": "dark",
                              "totp_secret": "ABCDEFGH", "totp_enabled": True})
auth.set_admin(cfg, "alex", "second-password")
ok(cfg["local"]["session_secret"] != first_secret,
   "changing the password rotates the session secret")
ok(auth.read_session(cfg, token) is None,
   "so a session signed with the old secret -- a stolen cookie -- stops verifying")
ok(cfg["local"]["admin"].get("email") == "alex@example.org"
   and cfg["local"]["admin"].get("theme") == "dark"
   and cfg["local"]["admin"].get("totp_enabled") is True
   and cfg["local"]["admin"].get("totp_secret") == "ABCDEFGH",
   "and the email, appearance and second factor survive the change -- only the credential is replaced")
ok(auth.verify_password("second-password", cfg["local"]["admin"])
   and not auth.verify_password("first-password", cfg["local"]["admin"]),
   "which is the new password, not the old")

# -- the username cannot break the session payload ---------------------------
ok(auth.bad_username("ops|admin"), "a '|' in the username is refused (it delimits the payload)")
ok(auth.bad_username("a\x00b"), "and a control character")
ok(not auth.bad_username("alex@corp"), "an ordinary name is fine")

# -- the config export carries no DNS or EAB secrets -------------------------
acme = {"accounts": [{"id": "a1", "name": "le", "eab_hmac": "SUPER-SECRET-HMAC"}],
        "challenges": [{"id": "c1", "name": "cf", "dns_credentials": "CF_Token=leaky"}],
        "certificates": []}
clean = backup._acme_without_secrets(acme)
ok(clean["challenges"][0]["dns_credentials"] == ""
   and clean["accounts"][0]["eab_hmac"] == "",
   "the export blanks DNS credentials and EAB keys")
ok(acme["challenges"][0]["dns_credentials"] == "CF_Token=leaky",
   "without mutating the stored config")

# -- a corrupt config file does not reopen setup -----------------------------
save_config(copy.deepcopy(DEFAULT_CONFIG))       # a real file exists
CONF_PATH.write_text("{ this is not json")
broken = load_config()
ok(broken["_meta"].get("unreadable") is True, "an unparseable config is flagged")
ok(needs_setup(broken) is False,
   "and never reads as first-run, so /api/setup stays shut")
raised = False
try:
    save_config(broken)
except RuntimeError:
    raised = True
ok(raised, "and a writer refuses to overwrite it rather than losing the real file")
CONF_PATH.unlink()

# -- mesh sync does not reset a peer's verify_tls ----------------------------
# Driven through the real receive endpoint: an admin turned Verify TLS on for
# node A, and node A's push (which carries verify_tls False for itself) must
# not turn it back off.
ham.app.config["TESTING"] = True
_client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "recv-key"
cfg["local"]["sync"]["peers"] = [
    {"id": "p1", "name": "node-a", "url": "https://a.example", "api_key": "akey",
     "verify_tls": True, "enabled": True}]
save_config(cfg)
_client.environ_base["HTTP_X_API_KEY"] = "recv-key"
_client.post("/api/sync/receive", json={
    "rev": 1, "fp": "x", "config": {},
    "peers": [{"id": "self-x", "name": "node-a", "url": "https://a.example",
               "api_key": "akey", "self": True, "verify_tls": False, "enabled": True}]})
peer = next((p for p in load_config()["local"]["sync"]["peers"]
             if p["url"] == "https://a.example"), {})
ok(peer.get("verify_tls") is True,
   "an inbound mesh list keeps this node's verify_tls, not the sender's False")

# -- a newline in a server address cannot inject a directive -----------------
cfg = copy.deepcopy(DEFAULT_CONFIG)
cfg["acme"]["settings"]["haproxy_integration"] = False
cfg["haproxy"]["servers"] = [{"id": "s1", "name": "web", "enabled": True,
                              "address": "10.0.0.1\n    http-request deny\n    #",
                              "port": "80"}]
cfg["haproxy"]["backends"] = [{"id": "b1", "name": "shop", "mode": "http",
                               "servers": ["s1"]}]
cfg["haproxy"]["frontends"] = [{"id": "f1", "name": "https", "mode": "http",
                                "binds": "0.0.0.0:443", "rules": [],
                                "default_backend": "b1", "enabled": True}]
out = haproxy.render_haproxy(cfg)
server_lines = [ln for ln in out.splitlines() if ln.strip().startswith("server web")]
injected = [ln for ln in out.splitlines() if ln.strip().startswith("http-request deny")]
ok(len(server_lines) == 1 and not injected,
   "a newline in an address is stripped, so it never becomes a standalone directive")

# -- the nonce claim is enforced ---------------------------------------------
now = __import__("time").time()
base = {"issuer": "https://idp", "client_id": "ham"}
good = {"iss": "https://idp", "aud": "ham", "exp": now + 60, "email_verified": True}
ok(oauth._vet_claims(base, dict(good, nonce="N"), "N") == "",
   "a token whose nonce matches the request passes")
ok("different sign-in" in oauth._vet_claims(base, dict(good, nonce="OTHER"), "N"),
   "and one minted for a different request is refused on its nonce")

# ===========================================================================
# The second review, through the real request path. The stored configuration
# still carries the API key "recv-key" and the peer "akey" from above; an
# administrator is created here so a browser session exists to test with.
# ===========================================================================
import time   # noqa: E402

PW = "hardening-pw-1"
anon = ham.app.test_client()
r = anon.post("/api/setup", json={"username": "alex", "password": PW})
assert r.status_code == 200, r.get_json()
keyed = ham.app.test_client()
keyed.environ_base["HTTP_X_API_KEY"] = "recv-key"


def signed_in(**environ):
    c = ham.app.test_client()
    c.environ_base.update(environ)
    r = c.post("/api/login", json={"username": "alex", "password": PW})
    assert r.status_code == 200, r.get_json()
    return c


# -- the node's own settings go out without their secrets --------------------
cfg = load_config()
cfg["local"]["session_secret"] = "sess-secret-0123456789abcdef"
cfg["local"]["mcp"].update({"token": "ham_mcp_tokentoken", "token_hash": "cafe" * 16})
cfg["local"]["admin"].update({"totp_secret": "TOTPSECRETBASE32", "totp_recovery": ["r" * 64]})
cfg["local"]["keepalived"]["auth_pass"] = "vrrp-pass"
save_config(cfg)
stored_hash, stored_salt = cfg["local"]["admin"]["hash"], cfg["local"]["admin"]["salt"]
sess = signed_in()
r = sess.get("/api/local")
text = r.get_data(as_text=True)
leaks = [s for s in ("recv-key", "akey", "sess-secret", "ham_mcp_token", "cafe" * 16,
                     "TOTPSECRETBASE32", "r" * 64, "vrrp-pass", stored_hash, stored_salt)
         if s in text]
ok(r.status_code == 200 and not leaks,
   "GET /api/local carries no API key, peer key, session secret, password digest, "
   "second factor, MCP token or VRRP password (leaked: %s)" % (leaks or "none"))
body = r.get_json()
ok(body["api_key"] == "[redacted]" and body["sync"]["peers"][0]["api_key"] == "[redacted]",
   "the secrets are marked [redacted], the way the MCP server marks them")
body.pop("updates", None)
body["sync"]["peers"].insert(0, {"id": "p0", "name": "node-0", "url": "https://z.example",
                                 "api_key": "zkey", "enabled": True})
r = keyed.put("/api/local", json=body)
after = load_config()["local"]
ok(r.status_code == 200 and after["api_key"] == "recv-key"
   and after["session_secret"] == "sess-secret-0123456789abcdef"
   and after["keepalived"]["auth_pass"] == "vrrp-pass",
   "sent back as it came, [redacted] keeps every stored value")
keys = {p["id"]: p["api_key"] for p in after["sync"]["peers"]}
ok(keys == {"p0": "zkey", "p1": "akey"},
   "and a peer's key is restored by its id, not its position in the list")
ok("recv-key" not in r.get_data(as_text=True), "the PUT's answer is redacted too")

# -- the cookie is Secure when the visitor came over TLS ----------------------
def cookie_flags(resp):
    return [h for h in resp.headers.getlist("Set-Cookie") if h.startswith(auth.SESSION_COOKIE)]


c = ham.app.test_client()
r = c.post("/api/login", json={"username": "alex", "password": PW},
           headers={"X-Forwarded-Proto": "https"})
ok(cookie_flags(r) and "Secure" in cookie_flags(r)[0],
   "behind the UI's own listener -- loopback, X-Forwarded-Proto https -- the cookie is Secure")
r = ham.app.test_client().post("/api/login", json={"username": "alex", "password": PW})
ok(cookie_flags(r) and "Secure" not in cookie_flags(r)[0],
   "over plain HTTP it is not, or the browser would never send it back")
c = ham.app.test_client()
c.environ_base["REMOTE_ADDR"] = "10.0.0.9"
r = c.post("/api/login", json={"username": "alex", "password": PW},
           headers={"X-Forwarded-Proto": "https"})
ok(cookie_flags(r) and "Secure" not in cookie_flags(r)[0],
   "and the header is not believed from anywhere but loopback")
c = ham.app.test_client()
c.set_cookie(auth.SESSION_COOKIE, "expired-or-garbage")
r = c.post("/api/logout")
ok(r.status_code == 200 and cookie_flags(r)
   and re.search(r"Max-Age=0|Expires=Thu, 01 Jan 1970", cookie_flags(r)[0]),
   "signing out deletes the cookie even when it no longer verifies")

# -- the sign-in throttle sees the visitor, not the listener ------------------
auth._login_fails.clear()


def attempt(addr, username, password):
    c = ham.app.test_client()
    return c.post("/api/login", json={"username": username, "password": password},
                  headers={"X-Forwarded-For": addr}).status_code


codes = [attempt("203.0.113.1", "guesser-%d" % i, "wrong") for i in range(auth.LOGIN_MAX_FAILS)]
ok(codes == [401] * auth.LOGIN_MAX_FAILS and attempt("203.0.113.1", "alex", PW) == 429,
   "five failures from one forwarded address lock that address out")
ok(attempt("203.0.113.2", "alex", PW) == 200,
   "and nobody else: the counter is the visitor's, not 127.0.0.1's")
auth._login_fails.clear()
for i in range(auth.LOGIN_MAX_FAILS):
    attempt("198.51.100.%d" % (i + 1), "alex", "wrong")
ok(attempt("198.51.100.200", "alex", PW) == 429,
   "five failures for one name from five addresses lock the name")
ok(attempt("198.51.100.200", "nobody", "wrong") == 401,
   "while another name from that address is merely refused")
auth._login_fails.clear()
c = ham.app.test_client()
c.environ_base["REMOTE_ADDR"] = "10.0.0.9"
for i in range(auth.LOGIN_MAX_FAILS):
    c.post("/api/login", json={"username": "u%d" % i, "password": "wrong"},
           headers={"X-Forwarded-For": "203.0.113.%d" % (i + 1)})
r = c.post("/api/login", json={"username": "alex", "password": PW},
           headers={"X-Forwarded-For": "203.0.113.99"})
ok(r.status_code == 429,
   "a direct visitor cannot dodge the throttle by writing X-Forwarded-For itself")
auth._login_fails.clear()

# -- a change on a session must come from this node's own page ---------------
sess = signed_in()
r = sess.put("/api/local", json={}, headers={"Origin": "https://evil.example.org"})
ok(r.status_code == 403, "a form on another site, cookie attached, is refused")
r = sess.put("/api/local", json={}, headers={"Origin": "http://localhost"})
ok(r.status_code == 200, "the UI's own page, which names itself in Origin, is not")
r = sess.put("/api/local", json={}, headers={"Referer": "http://localhost/#/p:cluster"})
ok(r.status_code == 200, "nor is one that only names itself in Referer")
r = sess.put("/api/local", data="x=1", content_type="text/plain")
ok(r.status_code == 403, "with neither header, a body that is not JSON -- what a form sends -- is refused")
r = sess.put("/api/local", json={})
ok(r.status_code == 200, "and a JSON body, which no form can send, goes through")
r = sess.get("/api/local", headers={"Origin": "https://evil.example.org"})
ok(r.status_code == 200, "reads are not gated: the cookie's SameSite already covers them")
r = keyed.put("/api/local", json={}, headers={"Origin": "https://evil.example.org"})
ok(r.status_code == 200, "a peer presenting the API key is not asked where it came from")
r = sess.put("/api/local", json={}, headers={"Origin": "null"})
ok(r.status_code == 403, "an opaque origin is another site, not this one")

# -- every answer carries the hardening headers ------------------------------
r = anon.get("/")
want = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "Referrer-Policy": "same-origin"}
ok(all(r.headers.get(k) == v for k, v in want.items()) and r.status_code == 200,
   "the page says nosniff, DENY and same-origin")
csp = r.headers.get("Content-Security-Policy", "")
inline = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
                    (pathlib.Path(__file__).resolve().parent.parent / "static" / "index.html").read_text(), re.S)
digest = base64.b64encode(hashlib.sha256(inline[0].encode()).digest()).decode()
ok(len(inline) == 1 and ("'sha256-%s'" % digest) in csp,
   "its policy allows the one inline script by hash")
scripts = re.search(r"script-src ([^;]*)", csp).group(1)
ok("'unsafe-inline'" not in scripts and "'unsafe-eval'" not in scripts,
   "and no other inline or evaluated script")
ok("frame-ancestors 'none'" in csp and "object-src 'none'" in csp and "default-src 'self'" in csp,
   "nothing from elsewhere, no plugins, no framing")
r = anon.get("/api/whoami")
ok(r.headers.get("X-Content-Type-Options") == "nosniff"
   and r.headers.get("Content-Security-Policy") == csp,
   "API answers carry the same headers")

# -- the anonymous 401 says less -------------------------------------------
r = anon.get("/api/status")
body = r.get_json()
ok(r.status_code == 401 and "version" not in body and "expected_fp" not in body
   and body.get("header_seen") is False,
   "a request with no key learns neither the version nor the key's fingerprint")
r = anon.get("/api/status", headers={"X-API-Key": "not-the-key"})
body = r.get_json()
ok(r.status_code == 401 and body.get("expected_fp") and body.get("presented_fp")
   and body.get("header_seen") is True,
   "one that presents a key -- a peer being set up -- still gets the fingerprints to compare")

# -- the pushed administrator name obeys the same rule -----------------------
r = keyed.post("/api/admin/receive", json={"admin": {"username": "ops|admin", "salt": "ab",
                                                     "hash": "cd"}})
ok(r.status_code == 400 and "|" in (r.get_json().get("error") or ""),
   "a '|' in a pushed administrator name is refused, not stored into an unreadable cookie")
ok(load_config()["local"]["admin"]["username"] == "alex", "and the administrator is unchanged")

# -- a passive node may retry its own acme2certifier install -----------------
ok("/api/acme/adcs/install".startswith(auth.LOCAL_WRITE_PREFIXES),
   "the acme2certifier retry counts as this node's own, so the lock does not block it")

print("\n" + ("%d failed" % len(fails) if fails
              else "the review's fixes hold"))
sys.exit(1 if fails else 0)
