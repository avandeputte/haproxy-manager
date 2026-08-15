#!/usr/bin/env python3
"""Single sign-on: the cookie, the flow's guards, and what gets rendered.

The enforcement lives in haproxy.cfg, so the renderer's output is the
feature; the Flask side is guards around an HTTP dance with the provider.
Both are pinned here with the attacks the design review found: the
open-redirect bounce, the ambiguous return address, the login started in
somebody else's browser, the half-configured pool serving openly.

    HAM_DATA_DIR=/tmp/x python3 tools/test-oauth.py
"""
import copy
import json
import os
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-oauth-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham   # noqa: E402
from ham import haproxy, oauth   # noqa: E402
from ham.config import DEFAULT_CONFIG, load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


SECRET = "a" * 64

# -- the cookie --------------------------------------------------------------
c = oauth.issue_cookie(SECRET, "Alice@Example.COM", 12)
exp, who, sig = c.split(".")
ok(who == b"alice@example.com".hex(), "the address travels lowercased and hex-encoded")
ok(oauth.read_cookie(SECRET, c) == "alice@example.com", "and reads back")
ok(oauth.read_cookie("b" * 64, c) is None, "a different secret verifies nothing")
ok(oauth.read_cookie(SECRET, "%s.%s.%s" % (int(time.time()) - 10, who, sig)) is None,
   "tampering with the expiry breaks the signature")
old = "%d.%s" % (int(time.time()) - 10, who)
import hmac as _hmac, hashlib as _hashlib   # noqa: E401,E402
oldsig = _hmac.new(SECRET.encode(), old.encode(), _hashlib.sha256).hexdigest()
ok(oauth.read_cookie(SECRET, "%s.%s" % (old, oldsig)) is None,
   "a genuinely signed but expired cookie is refused")

# -- the allow-list ----------------------------------------------------------
entries, bad = oauth.parse_allow("Alice@Example.com\n@corp.example.com\n*\n\nnot an email\n")
ok(entries == ["alice@example.com", "@corp.example.com", "*"] and bad == ["not an email"],
   "emails, @domains and * parse; garbage is named, not dropped")

# -- the return address ------------------------------------------------------
S = {"cookie_domain": "example.com", "auth_host": "auth.example.com"}
rd = lambda h, p="/x": oauth._valid_rd(S, h.encode().hex(), p.encode().hex())  # noqa: E731
ok(rd("shop.example.com") == "https://shop.example.com/x", "a host under the domain comes back")
ok(rd("example.com") == "https://example.com/x", "the bare domain too")
ok(rd("evil-example.com") is None, "a suffix that is not a dot-suffix does not")
ok(rd("shop.example.com.evil.net") is None, "nor the domain buried in the middle")
ok(rd("shop.example.com", "//evil.net/") == "https://shop.example.com/",
   "a protocol-relative path cannot smuggle a second host")
ok(oauth._valid_rd(S, "zz", "2f".encode().hex()) is None, "non-hex is refused outright")
ok(rd("good.example.com@evil.net") is None, "userinfo tricks do not parse as a host")

# -- state -------------------------------------------------------------------
st = oauth._sign(SECRET, json.dumps({"rd": "https://a.example.com/", "n": "n1",
                                     "ts": int(time.time())}))
ok(oauth._unsign(SECRET, st, 600)["n"] == "n1", "state signs and verifies")
stale = oauth._sign(SECRET, json.dumps({"rd": "x", "n": "n1",
                                        "ts": int(time.time()) - 3600}))
ok(oauth._unsign(SECRET, stale, 600) is None, "a state older than its window is dead")
ok(oauth._unsign("b" * 64, st, 600) is None, "and another secret's state never verifies")
v = oauth._pkce_verifier(SECRET, "n1")
ok(oauth._pkce_verifier(SECRET, "n1") == v != oauth._pkce_verifier(SECRET, "n2"),
   "the PKCE verifier is derived from the nonce, so no node has to remember it")

# -- what it renders ---------------------------------------------------------
def fresh():
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["acme"]["settings"]["haproxy_integration"] = False
    cfg["access"]["oauth"].update(
        enabled=True, issuer="https://idp.example.net", client_id="ham",
        client_secret="cs", auth_host="auth.example.com",
        cookie_domain="example.com", secret=SECRET)
    cfg["haproxy"]["servers"] = [{"id": "s1", "name": "web1", "address": "10.0.0.5",
                                  "port": 80, "enabled": True}]
    cfg["haproxy"]["backends"] = [{"id": "b1", "name": "shop", "mode": "http",
                                   "servers": ["s1"], "oauth_enabled": True,
                                   "oauth_allow": "alice@example.com\n@corp.example.com"}]
    cfg["haproxy"]["frontends"] = [{"id": "f1", "name": "https", "mode": "http",
                                    "binds": "0.0.0.0:443", "ssl_enabled": True,
                                    "rules": [], "enabled": True}]
    return cfg


cfg = fresh()
out = haproxy.render_haproxy(cfg)
be = out.split("backend be_shop")[1]
ok('hmac(sha256,' in be and "secure_memcmp(txn.sso_sig)" in be,
   "the signature is verified in configuration, timing-safely")
ok("-m str " + b"alice@example.com".hex() in be,
   "an allowed email is matched hex-exact")
ok("-m end " + b"@corp.example.com".hex() in be,
   "and a domain as a hex suffix, which byte-aligns by construction")
ok("rd_h=%[req.hdr(host),hex]&rd_p=%[pathq,hex]" in be,
   "the return address travels as two separately decodable halves")
ok("deny_status 403 if !sso_who_ok" in be,
   "a valid session that is not on the list is told no, not sent round the loop")
strip = be.index("replace-header Cookie")
ok(strip > be.index("http-request redirect"),
   "the cookie is stripped after the checks, before the servers")
ok("acl ham_sso_host" in out and "use_backend bk_ham_sso" in out,
   "the sign-in host is routed to the app")
ok("path_sub .." in out, "with dot-segments refused at the edge")
ok('status 404' in out.split("frontend")[1].split("backend")[0],
   "and everything else on that host answered 404")

cfg = fresh()
cfg["haproxy"]["backends"][0]["oauth_allow"] = "*"
be = haproxy.render_haproxy(cfg).split("backend be_shop")[1]
ok("sso_who_ok" not in be and "http-request redirect" in be,
   "'*' skips the allow-list but never the signature")

cfg = fresh()
cfg["access"]["oauth"]["enabled"] = False
be = haproxy.render_haproxy(cfg).split("backend be_shop")[1]
ok("http-request deny" in be and "redirect" not in be,
   "a protected pool with SSO unconfigured refuses everyone")
cfg = fresh()
cfg["haproxy"]["backends"][0]["oauth_allow"] = ""
be = haproxy.render_haproxy(cfg).split("backend be_shop")[1]
ok("http-request deny" in be and "sso_valid" not in be,
   "an emptied allow-list fails closed, not open")

cfg = fresh()
cfg["haproxy"]["backends"].append({"id": "b2", "name": "open", "mode": "http",
                                   "servers": ["s1"]})
be2 = haproxy.render_haproxy(cfg).split("backend be_open")[1]
ok("replace-header Cookie" in be2,
   "even an unprotected pool has the domain cookie stripped before its servers")

# -- the shared validation gate ----------------------------------------------
def refuses(opts, cur=None):
    try:
        oauth.validate_pool_oauth(fresh(), opts, cur)
        return False
    except ValueError:
        return True


ok(refuses({"oauth_enabled": True, "mode": "tcp", "oauth_allow": "*"}),
   "OIDC on a TCP pool is refused")
ok(refuses({"oauth_enabled": True, "auth_enabled": True, "oauth_allow": "*"}),
   "and together with basic auth")
ok(refuses({"oauth_enabled": True, "oauth_allow": ""}),
   "and with nobody allowed -- anyone must be said out loud, as *")
ok(not refuses({"oauth_enabled": True, "mode": "http", "oauth_allow": "*"}),
   "a well-formed request passes the same gate")

# -- the routes --------------------------------------------------------------
ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["access"]["oauth"].update(
    enabled=True, issuer="https://idp.example.net", client_id="ham",
    client_secret="cs", auth_host="auth.example.com",
    cookie_domain="example.com", secret=SECRET)
save_config(cfg)

r = client.get("/.ham-sso/login?rd_h=%s&rd_p=%s"
               % (b"shop.example.com".hex(), b"/".hex()),
               headers={"Host": "elsewhere.example.com"})
ok(r.status_code == 404, "the sign-in answers only on its own host")
r = client.get("/.ham-sso/login?rd_h=%s&rd_p=%s"
               % (b"evil.net".hex(), b"/".hex()),
               headers={"Host": "auth.example.com"})
ok(r.status_code == 400, "a return address outside the domain is refused at the door")


class FakeResp:
    status_code = 200
    def __init__(self, doc): self._d = doc
    def raise_for_status(self): pass
    def json(self): return self._d


DOC = {"authorization_endpoint": "https://idp.example.net/authz",
       "token_endpoint": "https://idp.example.net/token"}
exchanged = {}


class FakeRequests:
    def get(self, url, **kw):
        return FakeResp(DOC)
    def post(self, url, data=None, **kw):
        exchanged.update(data or {})
        now = int(time.time())
        idt = "h." + __import__("base64").urlsafe_b64encode(json.dumps(
            {"iss": "https://idp.example.net", "aud": "ham", "exp": now + 60,
             "email": "Alice@Example.com", "email_verified": True,
             "nonce": data.get("code_verifier") and "unused"}).encode()).decode().rstrip("=") + ".s"
        return FakeResp({"id_token": idt, "access_token": "at"})


was = oauth._requests
oauth._requests = FakeRequests()
oauth._disco["doc"] = None

r = client.get("/.ham-sso/login?rd_h=%s&rd_p=%s"
               % (b"shop.example.com".hex(), b"/app".hex()),
               headers={"Host": "auth.example.com"})
ok(r.status_code == 302 and "idp.example.net/authz" in r.headers["Location"]
   and "code_challenge=" in r.headers["Location"],
   "the login bounces to the provider with PKCE")
nonce_cookie = next((c for c in r.headers.getlist("Set-Cookie")
                     if c.startswith(oauth.NONCE_COOKIE)), "")
nonce = nonce_cookie.split("=", 1)[1].split(";")[0]
from urllib.parse import parse_qs, urlsplit   # noqa: E402
state = parse_qs(urlsplit(r.headers["Location"]).query)["state"][0]

# the test client keeps a cookie jar, so the login's nonce cookie must be
# dropped deliberately to play the attacker's victim
for dom in ("auth.example.com", "localhost", ""):
    try:
        client.delete_cookie(oauth.NONCE_COOKIE, domain=dom or None)
    except Exception:
        pass
r = client.get("/.ham-sso/callback?code=xyz&state=" + state,
               headers={"Host": "auth.example.com"})
ok(r.status_code == 400 and b"different browser" in r.data,
   "a callback without the browser's nonce cookie is refused -- login CSRF")

client.set_cookie("ham_sso_n", nonce, domain="auth.example.com")
r = client.get("/.ham-sso/callback?code=xyz&state=" + state,
               headers={"Host": "auth.example.com"})
sso = next((c for c in r.headers.getlist("Set-Cookie") if c.startswith("ham_sso=")), "")
ok(r.status_code == 302 and r.headers["Location"] == "https://shop.example.com/app",
   "with it, the sign-in completes and returns to the service")
ok("Domain=example.com" in sso and "Secure" in sso and "HttpOnly" in sso,
   "the cookie is domain-wide, secure, and out of script's reach")
value = sso.split("=", 1)[1].split(";")[0]
ok(oauth.read_cookie(SECRET, value) == "alice@example.com",
   "and carries the lowercased address, verifiable by every node")
ok(exchanged.get("code_verifier") == oauth._pkce_verifier(SECRET, nonce),
   "the exchange proves the same PKCE verifier the login promised")

oauth._requests = was

print("\n" + ("%d failed" % len(fails) if fails
              else "the sign-in guards hold, and the rendering enforces"))
sys.exit(1 if fails else 0)
