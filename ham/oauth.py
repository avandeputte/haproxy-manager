"""Single sign-on for published services, through any OpenID Connect provider.

HAProxy cannot speak OIDC, and this app must not sit in the traffic path --
so the work is split at the only seam that lets both stay what they are. This
app plays the relying party on one dedicated hostname: it redirects to the
provider, exchanges the code, decides nothing about traffic. What it hands
the browser is a stateless cookie -- expiry, the signed-in email in hex, and
an HMAC over both -- and HAProxy verifies that signature and matches the
email against each service's allow-list entirely in configuration, on every
request, with this app nowhere in sight. The signing secret is shared
configuration, so every node validates every cookie and a failover changes
nothing for anyone signed in.

The ID token's own signature is deliberately not checked: the token arrives
on a private TLS connection to the token endpoint, authenticated by the
client secret, which OIDC Core 3.1.3.7 accepts in place of verifying the
JWS -- and checking it would mean vendoring RSA. The claims still are
checked: issuer, audience, expiry, nonce, and that the provider calls the
email verified.
"""

from flask import Response, jsonify, redirect, request
import base64
import hashlib
import hmac
import json
import os
import re
import time
from urllib.parse import urlsplit, quote

from .base import PEER_CONNECT_TIMEOUT, _requests, app, log
from .config import load_config, merged, save_config
from .base import _lock

COOKIE = "ham_sso"
NONCE_COOKIE = "ham_sso_n"
STATE_MINUTES = 10
DISCOVERY_TTL = 3600

_disco = {"issuer": "", "at": 0.0, "doc": None}

_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?"
                       r"(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def settings_of(cfg):
    return (cfg.get("access") or {}).get("oauth") or {}


def ready(s):
    """Everything the sign-in flow needs before it can work at all."""
    return bool(s.get("enabled") and s.get("issuer") and s.get("client_id")
                and s.get("client_secret") and s.get("auth_host")
                and s.get("cookie_domain") and s.get("secret"))


def valid_host(name):
    return bool(_HOSTNAME.match((name or "").strip().lower()))


def parse_allow(text):
    """(entries, bad): exact emails, @domain suffixes, or '*' for anyone.

    Lowercased here once, so matching is case-insensitive everywhere. An
    empty result refuses everyone -- with a public provider, an accidental
    "anyone" would mean every account that provider has.
    """
    entries, bad = [], []
    for line in (text or "").splitlines():
        tok = line.strip().lower()
        if not tok:
            continue
        if tok == "*" or (tok.startswith("@") and valid_host(tok[1:])) \
                or _EMAIL.match(tok):
            entries.append(tok)
        else:
            bad.append(line.strip())
    return entries, bad


def under_domain(host, domain):
    host, domain = (host or "").lower().strip("."), (domain or "").lower().strip(".")
    return bool(domain) and (host == domain or host.endswith("." + domain))


def validate_pool_oauth(cfg, pool_opts, current=None):
    """The one gate both the wizard and the editor pass through.

    Raises ValueError; called with the fields about to be stored. `current`
    is the pool being edited, for cross-field checks against what stays.
    """
    cur = current or {}
    on = bool(pool_opts.get("oauth_enabled", cur.get("oauth_enabled")))
    if not on:
        return
    if pool_opts.get("mode", cur.get("mode", "http")) == "tcp":
        raise ValueError("a TCP service carries no place for a sign-in redirect; "
                         "OIDC needs an HTTPS service")
    if bool(pool_opts.get("auth_enabled", cur.get("auth_enabled"))):
        raise ValueError("one sign-in per service: this one already requires "
                         "basic auth -- switch that off to use OIDC")
    entries, bad = parse_allow(pool_opts.get("oauth_allow", cur.get("oauth_allow")))
    if bad:
        raise ValueError("not an email, @domain or *: %s" % ", ".join(bad[:3]))
    if not entries:
        raise ValueError("say who is allowed: emails, @domains, or * for anyone "
                         "the provider signs in")


# -- the cookie --------------------------------------------------------------

def issue_cookie(secret, email, hours):
    """exp . hex(email) . base64(email) . signature -- the address twice,
    because HAProxy needs it twice: hex is what makes the @domain suffix
    match byte-exact, and base64 is the one encoding it can turn back into
    text for the identity header. Both halves are under the signature."""
    exp = int(time.time()) + max(1, int(hours or 12)) * 3600
    email = email.strip().lower()
    msg = "%d.%s.%s" % (exp, email.encode().hex(),
                        base64.b64encode(email.encode()).decode())
    sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return "%s.%s" % (msg, sig)


def read_cookie(secret, value):
    """The email carried by a valid, unexpired cookie, else None. HAProxy is
    the real verifier; this exists for the tests and the sign-in page."""
    try:
        exp, who, b64, sig = value.split(".")
        msg = "%s.%s.%s" % (exp, who, b64)
        want = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, sig) or int(exp) < time.time():
            return None
        return bytes.fromhex(who).decode()
    except Exception:
        return None


# -- state, nonce, PKCE: all derived, nothing stored -------------------------

def _sign(secret, payload):
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(("%s|%s" % (payload, sig)).encode()).decode()


def _unsign(secret, token, max_age):
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        payload, sig = raw.rsplit("|", 1)
        want = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, sig):
            return None
        data = json.loads(payload)
        if int(data.get("ts") or 0) + max_age < time.time():
            return None
        return data
    except Exception:
        return None


def _pkce_verifier(secret, nonce):
    # Derived, not stored: the callback can rebuild it from the nonce alone,
    # on whichever node answers after a failover.
    mac = hmac.new(secret.encode(), ("pkce|" + nonce).encode(), hashlib.sha256)
    return base64.urlsafe_b64encode(mac.digest()).decode().rstrip("=")


def _pkce_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


# -- the provider ------------------------------------------------------------

def discover(issuer):
    """The provider's endpoints, from its own metadata, cached for an hour."""
    if _requests is None:
        raise RuntimeError("python3-requests is not installed on this node")
    now = time.time()
    if _disco["doc"] and _disco["issuer"] == issuer and now - _disco["at"] < DISCOVERY_TTL:
        return _disco["doc"]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    r = _requests.get(url, timeout=(PEER_CONNECT_TIMEOUT, 15))
    r.raise_for_status()
    doc = r.json()
    for k in ("authorization_endpoint", "token_endpoint"):
        if not doc.get(k):
            raise RuntimeError("the provider's metadata lacks %s" % k)
    _disco.update(issuer=issuer, at=now, doc=doc)
    return doc


def _redirect_uri(s):
    return "https://%s/.ham-sso/callback" % s["auth_host"]


# -- the flow ----------------------------------------------------------------

def _valid_rd(s, rd_h, rd_p):
    """Rebuild and vet the URL the browser is owed back.

    The two halves arrive hex-encoded and separately, because a hostname can
    consist entirely of hex digits -- concatenated, nobody could say where it
    ends. Only https, only hosts under the cookie domain: the callback hands
    the browser a signed cookie and then this URL, which is exactly the shape
    of a phishing bounce if any host could stand here.
    """
    try:
        host = bytes.fromhex(rd_h or "").decode().lower()
        path = bytes.fromhex(rd_p or "").decode()
    except ValueError:
        return None
    host = host.split(":")[0]
    if not valid_host(host) or not under_domain(host, s["cookie_domain"]):
        return None
    if not path.startswith("/") or path.startswith("//"):
        path = "/"
    split = urlsplit("https://" + host + path)
    if split.netloc != host:                    # userinfo/port smuggled into path
        return None
    return "https://" + host + path


def _wrong_host(s):
    host = (request.headers.get("Host") or "").split(":")[0].lower()
    return host != (s.get("auth_host") or "").lower()


@app.get("/.ham-sso/login")
def sso_login():
    cfg = load_config()
    s = settings_of(cfg)
    if not ready(s) or _wrong_host(s):
        return Response("sign-in is not configured here\n", status=404,
                        mimetype="text/plain")
    rd = _valid_rd(s, request.args.get("rd_h"), request.args.get("rd_p"))
    if not rd:
        return Response("that return address is not one of ours\n", status=400,
                        mimetype="text/plain")
    try:
        doc = discover(s["issuer"])
    except Exception as e:
        log.warning("sso: cannot reach %s: %s", s.get("issuer"), e)
        return Response("the identity provider did not answer: %s\n" % e,
                        status=502, mimetype="text/plain")
    nonce = os.urandom(16).hex()
    state = _sign(s["secret"], json.dumps(
        {"rd": rd, "n": nonce, "ts": int(time.time())}, sort_keys=True))
    url = (doc["authorization_endpoint"]
           + ("&" if "?" in doc["authorization_endpoint"] else "?")
           + "response_type=code&client_id=" + quote(s["client_id"])
           + "&redirect_uri=" + quote(_redirect_uri(s))
           + "&scope=" + quote(s.get("scopes") or "openid email profile")
           + "&state=" + quote(state)
           + "&nonce=" + nonce
           + "&code_challenge=" + _pkce_challenge(_pkce_verifier(s["secret"], nonce))
           + "&code_challenge_method=S256")
    resp = redirect(url, code=302)
    # The browser must come back to the callback carrying this: it binds the
    # transaction to this browser, or anyone could hand a victim their own
    # half-finished sign-in and put their identity in the victim's cookie.
    resp.set_cookie(NONCE_COOKIE, nonce, max_age=STATE_MINUTES * 60,
                    secure=True, httponly=True, samesite="Lax")
    return resp


@app.get("/.ham-sso/callback")
def sso_callback():
    cfg = load_config()
    s = settings_of(cfg)
    if not ready(s) or _wrong_host(s):
        return Response("sign-in is not configured here\n", status=404,
                        mimetype="text/plain")
    state = _unsign(s["secret"], request.args.get("state") or "", STATE_MINUTES * 60)
    if not state:
        return Response("the sign-in took too long or the state does not "
                        "verify -- start again\n", status=400, mimetype="text/plain")
    if request.cookies.get(NONCE_COOKIE) != state.get("n"):
        log.warning("sso: callback without the browser's nonce cookie (%s)",
                    request.headers.get("X-Forwarded-For") or request.remote_addr)
        return Response("this sign-in was started by a different browser -- "
                        "start again\n", status=400, mimetype="text/plain")
    if request.args.get("error"):
        return Response("the identity provider refused: %s\n"
                        % request.args.get("error_description",
                                           request.args.get("error")),
                        status=403, mimetype="text/plain")
    code = request.args.get("code") or ""
    try:
        doc = discover(s["issuer"])
        r = _requests.post(doc["token_endpoint"], data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": _redirect_uri(s),
            "client_id": s["client_id"], "client_secret": s["client_secret"],
            "code_verifier": _pkce_verifier(s["secret"], state["n"]),
        }, timeout=(PEER_CONNECT_TIMEOUT, 15))
        r.raise_for_status()
        tokens = r.json()
    except Exception as e:
        log.warning("sso: the code exchange failed: %s", e)
        return Response("the identity provider did not complete the sign-in\n",
                        status=502, mimetype="text/plain")
    claims = _id_claims(tokens.get("id_token") or "")
    problem = _vet_claims(s, claims, state.get("n"))
    if problem:
        log.warning("sso: rejected a sign-in: %s", problem)
        return Response(problem + "\n", status=403, mimetype="text/plain")
    email = (claims.get("email") or "").strip().lower()
    if not email:
        email = _userinfo_email(s, doc, tokens)
    if not email:
        return Response("the provider did not say who you are: no email claim, "
                        "and none at the userinfo endpoint -- is the 'email' "
                        "scope granted?\n", status=502, mimetype="text/plain")
    if not _EMAIL.match(email):
        # The address goes into a cookie and, forwarded, into a header; a
        # "claim" with spaces or control characters is not getting into either.
        log.warning("sso: refused a sign-in whose email claim is not an email: %r", email)
        return Response("the provider's email claim is not an email address\n",
                        status=502, mimetype="text/plain")
    resp = redirect(state["rd"], code=302)
    resp.set_cookie(COOKIE, issue_cookie(s["secret"], email, s.get("session_hours")),
                    domain=s["cookie_domain"], max_age=int(s.get("session_hours") or 12) * 3600,
                    secure=True, httponly=True, samesite="Lax")
    resp.set_cookie(NONCE_COOKIE, "", max_age=0, secure=True, httponly=True)
    log.info("sso: %s signed in (%s), returning to %s", email,
             request.headers.get("X-Forwarded-For") or request.remote_addr,
             state["rd"])
    return resp


def _id_claims(id_token):
    try:
        body = id_token.split(".")[1]
        body += "=" * (-len(body) % 4)
        return json.loads(base64.urlsafe_b64decode(body.encode()))
    except Exception:
        return {}


def _vet_claims(s, claims, nonce=None):
    """What must hold even though the signature is vouched for by the TLS
    channel: right issuer, meant for us, current, this browser's, and a real
    email."""
    if not claims:
        return "the token endpoint returned no readable ID token"
    if (claims.get("iss") or "").rstrip("/") != s["issuer"].rstrip("/"):
        return "the ID token names a different issuer"
    aud = claims.get("aud")
    if s["client_id"] not in (aud if isinstance(aud, list) else [aud]):
        return "the ID token is for a different client"
    if int(claims.get("exp") or 0) < time.time():
        return "the ID token is already expired"
    # The nonce ties the token to the authorization request this browser
    # started. The state's nonce is already bound to the browser by the nonce
    # cookie, so a token minted for a different request -- a provider mix-up,
    # a replayed authorization -- is caught here. Only enforced when the token
    # carries one (it always should, since the request sent one).
    if nonce and claims.get("nonce") and not hmac.compare_digest(
            str(claims.get("nonce")), str(nonce)):
        return "the ID token is for a different sign-in request"
    if claims.get("email_verified") is False and not s.get("allow_unverified"):
        # The allow-lists trust this string; a provider that has not checked
        # it is a provider anyone might be alice at. Overridable, with the
        # warning where the switch is, for providers that cannot say so.
        return ("the provider says that email address is unverified -- mark it "
                "verified at the provider, or allow unverified claims under "
                "Sign-in > Single sign-on")
    return ""


def _userinfo_email(s, doc, tokens):
    """Some providers keep email at the userinfo endpoint, not in the token."""
    try:
        if not (doc.get("userinfo_endpoint") and tokens.get("access_token")):
            return ""
        r = _requests.get(doc["userinfo_endpoint"], headers={
            "Authorization": "Bearer %s" % tokens["access_token"]},
            timeout=(PEER_CONNECT_TIMEOUT, 15))
        r.raise_for_status()
        info = r.json()
        if info.get("email_verified") is False and not s.get("allow_unverified"):
            return ""
        return (info.get("email") or "").strip().lower()
    except Exception as e:
        log.warning("sso: userinfo did not answer: %s", e)
        return ""


@app.get("/.ham-sso/logout")
def sso_logout():
    cfg = load_config()
    s = settings_of(cfg)
    if not ready(s) or _wrong_host(s):
        return Response("sign-in is not configured here\n", status=404,
                        mimetype="text/plain")
    resp = Response("Signed out. Closing the identity provider's own session "
                    "is done at the provider.\n", mimetype="text/plain")
    resp.set_cookie(COOKIE, "", domain=s["cookie_domain"], max_age=0,
                    secure=True, httponly=True)
    return resp


# -- settings ----------------------------------------------------------------

FIELDS = ("enabled", "issuer", "client_id", "auth_host", "cookie_domain",
          "scopes", "session_hours", "allow_unverified")


@app.get("/api/access/oauth")
def api_oauth_get():
    cfg = load_config()
    s = settings_of(cfg)
    out = {k: s.get(k) for k in FIELDS}
    out["has_client_secret"] = bool((s.get("client_secret") or "").strip())
    out["configured"] = ready(s)
    out["redirect_uri"] = _redirect_uri(s) if s.get("auth_host") else ""
    # Protected services whose host is not under the cookie domain can never
    # receive the session cookie, so a visitor there would loop through the
    # sign-in forever. Surfaced here rather than failing silently at request
    # time -- the one v1 limitation of a single cookie domain, said plainly.
    out["unreachable_hosts"] = hosts_outside_domain(cfg) if s.get("enabled") else []
    return jsonify(out)


@app.put("/api/access/oauth")
def api_oauth_put():
    body = request.get_json(force=True, silent=True) or {}
    with _lock:
        cfg = load_config()
        s = cfg["access"].setdefault("oauth", {})
        for k in ("issuer", "client_id", "auth_host", "cookie_domain", "scopes"):
            if k in body:
                s[k] = str(body.get(k) or "").strip()
        if "session_hours" in body:
            try:
                s["session_hours"] = min(24 * 30, max(1, int(body["session_hours"])))
            except (TypeError, ValueError):
                return jsonify({"error": "session hours must be a number"}), 400
        if str(body.get("client_secret") or "").strip():
            s["client_secret"] = str(body["client_secret"]).strip()
        if "enabled" in body:
            s["enabled"] = bool(body["enabled"])
        if "allow_unverified" in body:
            s["allow_unverified"] = bool(body["allow_unverified"])
        if s.get("enabled"):
            for k, label in (("issuer", "an issuer URL"), ("client_id", "a client id"),
                             ("client_secret", "a client secret"),
                             ("auth_host", "a sign-in host"),
                             ("cookie_domain", "a cookie domain")):
                if not (s.get(k) or "").strip():
                    return jsonify({"error": "%s is required" % label}), 400
            if not s["issuer"].startswith("https://"):
                return jsonify({"error": "the issuer must be an https:// URL"}), 400
            if not valid_host(s["auth_host"]):
                return jsonify({"error": "the sign-in host is not a valid hostname"}), 400
            if not valid_host(s["cookie_domain"]) or s["cookie_domain"].count(".") < 1:
                return jsonify({"error": "the cookie domain is not a valid domain"}), 400
            if not under_domain(s["auth_host"], s["cookie_domain"]):
                return jsonify({"error": "the sign-in host must sit under the "
                                         "cookie domain, or the browser will not "
                                         "send the cookie back"}), 400
            if not s.get("secret"):
                # Generated exactly once, here: the one thing that must never
                # be typed, guessed, or default.
                s["secret"] = os.urandom(32).hex()
        save_config(cfg)
    log.info("single sign-on settings changed (enabled=%s)", bool(s.get("enabled")))
    return jsonify({"ok": True})


@app.post("/api/access/oauth/rotate")
def api_oauth_rotate():
    """New signing secret: every session everywhere stops verifying. The only
    revocation a stateless cookie has, so it is a button."""
    with _lock:
        cfg = load_config()
        cfg["access"].setdefault("oauth", {})["secret"] = os.urandom(32).hex()
        save_config(cfg)
    log.warning("the SSO signing secret was rotated: everyone is signed out")
    from . import apply
    return jsonify({"ok": True, "applied": apply.do_apply()})


@app.post("/api/access/oauth/test")
def api_oauth_test():
    """Fetch the provider's metadata, so the issuer is proven before anything
    depends on it. Blank secret means the stored one, as everywhere."""
    body = request.get_json(force=True, silent=True) or {}
    issuer = str(body.get("issuer") or "").strip() \
        or settings_of(load_config()).get("issuer") or ""
    if not issuer.startswith("https://"):
        return jsonify({"ok": False, "error": "the issuer must be an https:// URL"})
    try:
        _disco["doc"] = None
        doc = discover(issuer)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    return jsonify({"ok": True, "message":
                    "The provider answered. Authorization at %s, tokens at %s." %
                    (doc.get("authorization_endpoint"), doc.get("token_endpoint"))})


def pool_summary(pool):
    """What the services list shows, mirroring the basic-auth 'auth' object."""
    entries, _bad = parse_allow(pool.get("oauth_allow"))
    return {"enabled": bool(pool.get("oauth_enabled")),
            "allow": entries,
            "forward": bool(pool.get("oauth_forward"))}


def hosts_outside_domain(cfg):
    """Protected services whose hosts the cookie can never reach -- the one
    v1 limitation, surfaced at validation rather than as silent redirects."""
    cfg = merged(cfg)
    s = settings_of(cfg)
    if not s.get("cookie_domain"):
        return []
    from . import probe
    protected = {"be_" + name for name in
                 (b.get("name") or "" for b in cfg["haproxy"]["backends"]
                  if b.get("oauth_enabled"))}
    out = []
    for entry in probe.published_urls(cfg):
        if entry.get("kind") in ("http", "https") and entry.get("pool") in protected \
                and not under_domain(entry.get("host"), s["cookie_domain"]):
            out.append(entry["host"])
    return sorted(set(out))
