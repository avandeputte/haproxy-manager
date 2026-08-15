#!/usr/bin/env python3
"""The fixes from the code review, pinned so they cannot quietly regress.

Each of these was a real defect: a password change that left stolen sessions
alive, a backup that carried DNS credentials, a corrupt file that reopened
setup, a mesh push that undid TLS verification, an operator field that could
inject a directive. One assertion each, at the seam where the fix lives.

    HAM_DATA_DIR=/tmp/x python3 tools/test-hardening.py
"""
import copy
import os
import pathlib
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
auth.set_admin(cfg, "alex", "second-password")
ok(cfg["local"]["session_secret"] != first_secret,
   "changing the password rotates the session secret")
ok(auth.read_session(cfg, token) is None,
   "so a session signed with the old secret -- a stolen cookie -- stops verifying")

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

print("\n" + ("%d failed" % len(fails) if fails
              else "the review's fixes hold"))
sys.exit(1 if fails else 0)
