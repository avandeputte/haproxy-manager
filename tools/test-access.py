#!/usr/bin/env python3
"""The sign-in a service can ask visitors for.

Two things are pinned here. The first is the password format: HAProxy reads
$6$ hashes through crypt(3), so what this app writes has to be byte-for-byte
what crypt(3) would have produced -- the hashes are compared against openssl
passwd -6 when it is available, and against fixed vectors when it is not.

The second is what the generated configuration does at the edges: a service
that requires a sign-in nobody can give, or that admits a group which has been
deleted, must refuse requests rather than serve them to everyone.

    HAM_DATA_DIR=/tmp/x python3 tools/test-access.py
"""
import copy
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-access-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham   # noqa: E402
from ham import access, haproxy   # noqa: E402
from ham.config import DEFAULT_CONFIG, load_config, save_config, shared_view   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


# -- the hash ---------------------------------------------------------------
# Produced by `openssl passwd -6 -salt <salt> <password>`.
VECTORS = [
    ("secret", "abcdefgh",
     "$6$abcdefgh$ltjgWl6579NluT/Vi1nwEvcil.G5Nbc4NiXZaNGStk8PSwGfQv72N2CKPPrVACtLtip/cZ/1GM/O6IND4WQhG."),
    ("p", "a",
     "$6$a$2.GZ8yudlr5SHiCPkX5N4O16VrDiQ2OZrbwWIoAlxZVHQFGoqZP6JY4XB1c.jTYlVXS7wOdfIg7aItV3orkit0"),
]
for password, salt, want in VECTORS:
    ok(access.sha512_crypt(password, salt) == want,
       "%r hashes to what crypt(3) produces" % password)

ok(access.verify("secret", VECTORS[0][2]), "the right password verifies")
ok(not access.verify("Secret", VECTORS[0][2]), "a near miss does not")
ok(not access.verify("secret", "not-a-hash"), "and neither does a mangled hash")

made = access.sha512_crypt("hunter2")
ok(made.startswith("$6$") and len(made.split("$")[2]) == 16,
   "a generated hash carries a 16-character salt")
ok(access.sha512_crypt("hunter2") != made, "and a different one every time")

# Anything openssl is here to check, check against openssl rather than trust
# the table above.
try:
    out = subprocess.run(["openssl", "passwd", "-6", "-salt", "0123456789abcdef",
                          "a longer password, with spaces"],
                         capture_output=True, text=True, timeout=20)
    if out.returncode == 0 and out.stdout.strip().startswith("$6$"):
        ok(access.sha512_crypt("a longer password, with spaces", "0123456789abcdef")
           == out.stdout.strip(), "openssl agrees, on this machine, right now")
    else:
        print("  ....  openssl declined to say; the vectors above stand")
except (OSError, subprocess.SubprocessError):
    print("  ....  no openssl here; the vectors above stand")

# -- names ------------------------------------------------------------------
for bad in ("", "with space", "-leading", "a" * 65, "quote\"name", "semi;colon"):
    ok(access._check_name(bad, "The user name")[1] is not None,
       "%r is refused as a name" % bad)
for good in ("alice", "a.b-c_d", "user@example.com", "A1"):
    ok(access._check_name(good, "The user name")[1] is None,
       "%r is accepted as a name" % good)


# -- what it renders --------------------------------------------------------
def fresh():
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["acme"]["settings"]["haproxy_integration"] = False
    cfg["access"]["groups"] = [{"id": "g1", "name": "staff"},
                               {"id": "g2", "name": "admins"}]
    cfg["access"]["users"] = [
        {"id": "u1", "username": "alice", "enabled": True, "groups": ["g1", "g2"],
         "hash": access.sha512_crypt("secret1", "abcdefgh")},
        {"id": "u2", "username": "bob", "enabled": True, "groups": [],
         "hash": access.sha512_crypt("secret2", "abcdefgh")}]
    cfg["haproxy"]["backends"] = [
        {"id": "b1", "name": "shop", "mode": "http", "servers": [],
         "auth_enabled": True, "auth_groups": ["g1"], "auth_realm": "The Shop"}]
    return cfg


cfg = fresh()
out = haproxy.render_haproxy(cfg)
ok("userlist ham_users" in out, "the users are written as a userlist")
ok("    group staff" in out and "    group admins" in out, "with every group declared")
ok("user alice password $6$" in out, "and every user as a hash, never a password")
ok("groups staff,admins" in out, "carrying the groups they belong to")
ok('http-request auth realm "The Shop" unless { http_auth_group(ham_users) staff }' in out,
   "the pool asks for a sign-in and admits the group it was given")

cfg = fresh()
cfg["haproxy"]["backends"][0]["auth_groups"] = []
out = haproxy.render_haproxy(cfg)
ok("unless { http_auth(ham_users) }" in out,
   "no group named admits any user in the list")

cfg = fresh()
cfg["haproxy"]["backends"][0]["auth_realm"] = ""
out = haproxy.render_haproxy(cfg)
ok('realm "shop"' in out, "an empty prompt falls back to the pool's name")

cfg = fresh()
cfg["haproxy"]["backends"][0]["auth_realm"] = 'a "quoted" name'
out = haproxy.render_haproxy(cfg)
ok('realm "a quoted name"' in out, "and a quote in it cannot end the line early")

cfg = fresh()
cfg["access"]["users"] = []
out = haproxy.render_haproxy(cfg)
ok("userlist" not in out, "no users means no userlist")
ok("http-request deny" in out and "http_auth" not in out,
   "a service that requires a sign-in nobody can give refuses everyone")

cfg = fresh()
cfg["haproxy"]["backends"][0]["auth_groups"] = ["deleted-group"]
out = haproxy.render_haproxy(cfg)
ok("http-request deny" in out,
   "a service admitting only a group that no longer exists refuses everyone")

cfg = fresh()
cfg["access"]["users"][0]["enabled"] = False
cfg["access"]["users"][1]["hash"] = ""
out = haproxy.render_haproxy(cfg)
ok("alice" not in out and "bob" not in out,
   "a disabled user and one with no password are not in the list")
ok("http-request deny" in out, "which leaves the service refusing everyone")

cfg = fresh()
cfg["haproxy"]["backends"][0]["mode"] = "tcp"
out = haproxy.render_haproxy(cfg)
ok("http-request auth" not in out and "http-request deny" not in out,
   "a TCP pool gets no sign-in: there is nowhere in the protocol to put one")

# -- source addresses -------------------------------------------------------
ok(access.networks("192.168.0.0/16\n10.0.0.5")[0] == ["192.168.0.0/16", "10.0.0.5/32"],
   "a bare address is one host, a CIDR is itself")
ok(access.networks("192.168.1.7/24")[0] == ["192.168.1.0/24"],
   "host bits under a prefix are masked rather than refused")
ok(access.networks("not-a-net 10.0.0.0/8")[1] == ["not-a-net"],
   "what does not parse is reported, not dropped in silence")

cfg = fresh()
cfg["haproxy"]["backends"][0]["allow_src"] = "192.168.0.0/16\n10.0.0.5"
out = haproxy.render_haproxy(cfg)
ok("http-request deny unless { src 192.168.0.0/16 10.0.0.5/32 }" in out,
   "an allow list refuses everyone it does not name")
ok(out.index("http-request deny unless") < out.index("http-request auth"),
   "and is checked before the sign-in")

cfg = fresh()
cfg["haproxy"]["backends"][0]["mode"] = "tcp"
cfg["haproxy"]["backends"][0]["allow_src"] = "192.168.0.0/16"
out = haproxy.render_haproxy(cfg)
ok("tcp-request content reject unless { src 192.168.0.0/16 }" in out,
   "a TCP pool gets the same restriction in its own dialect")

cfg = fresh()
cfg["haproxy"]["backends"][0]["auth_enabled"] = False
cfg["haproxy"]["backends"][0]["allow_src"] = "not-a-network"
out = haproxy.render_haproxy(cfg)
ok("http-request deny" in out and "unless" not in out.split("backend be_shop")[1],
   "an allow list nobody can parse refuses everyone rather than admitting everyone")

cfg = fresh()
cfg["haproxy"]["backends"][0]["auth_exempt_src"] = "192.168.1.0/24"
out = haproxy.render_haproxy(cfg)
ok('unless { src 192.168.1.0/24 } or { http_auth_group(ham_users) staff }' in out,
   "an exempt network skips the prompt, everyone else is asked")

cfg = fresh()
cfg["access"]["users"] = []
cfg["haproxy"]["backends"][0]["auth_exempt_src"] = "192.168.1.0/24"
out = haproxy.render_haproxy(cfg)
ok("http-request deny unless { src 192.168.1.0/24 }" in out,
   "with nobody able to sign in, the exempt networks still get in and nobody else does")

# -- what is shared ---------------------------------------------------------
cfg = fresh()
ok("access" in shared_view(cfg),
   "users and groups are shared, so a failover meets the same credentials")

# -- the routes -------------------------------------------------------------
ham.app.config["TESTING"] = True
client = ham.app.test_client()
save_config(copy.deepcopy(DEFAULT_CONFIG))


def call(path, method="GET", body=None):
    fn = getattr(client, method.lower())
    r = fn(path, json=body) if body is not None else fn(path)
    return r.status_code, (r.get_json() if r.data else {})


# The routes are behind the session check, so exercise them the way the rest
# of the app does: with the API key this node holds.
cfg = load_config()
cfg["local"]["api_key"] = "test-key"
save_config(cfg)
client.environ_base["HTTP_X_API_KEY"] = "test-key"

code, body = call("/api/access/groups", "POST", {"name": "staff"})
ok(code == 200 and body.get("id"), "a group is created")
gid = body.get("id")
code, body = call("/api/access/groups", "POST", {"name": "STAFF"})
ok(code == 400, "a second group by the same name, in any case, is refused")

code, body = call("/api/access/users", "POST",
                  {"username": "alice", "password": "hunter2", "groups": [gid]})
ok(code == 400, "a password under eight characters is refused")
code, body = call("/api/access/users", "POST",
                  {"username": "alice", "password": "hunter2!!", "groups": [gid]})
ok(code == 200, "a user is created")
uid = body.get("id")
ok("hash" not in body and body.get("has_password") is True,
   "the hash never leaves the node -- only whether there is one")

code, body = call("/api/access/users")
ok(code == 200 and all("hash" not in u for u in body), "nor when they are listed")

stored = load_config()["access"]["users"][0]
ok(access.verify("hunter2!!", stored["hash"]), "and the stored hash is of that password")

code, body = call("/api/access/users/" + uid, "PUT", {"username": "alice", "groups": [gid]})
ok(code == 200, "a user is edited")
ok(load_config()["access"]["users"][0]["hash"] == stored["hash"],
   "an empty password field keeps the password rather than clearing it")

code, body = call("/api/access/users/" + uid, "PUT",
                  {"username": "alice", "password": "somethingelse"})
ok(code == 200 and load_config()["access"]["users"][0]["hash"] != stored["hash"],
   "and a new one replaces it")

# A group a service depends on cannot be pulled out from under it.
cfg = load_config()
cfg["haproxy"]["backends"] = [{"id": "b1", "name": "shop", "auth_enabled": True,
                               "auth_groups": [gid]}]
save_config(cfg)
code, body = call("/api/access/groups/" + gid, "DELETE")
ok(code == 409 and "shop" in (body.get("error") or ""),
   "deleting a group a service admits is refused, and says which service")

cfg = load_config()
cfg["haproxy"]["backends"] = []
save_config(cfg)
code, body = call("/api/access/groups/" + gid, "DELETE")
ok(code == 200, "and allowed once nothing uses it")
ok(load_config()["access"]["users"][0]["groups"] == [],
   "the users who were in it are taken out of it")

code, body = call("/api/access/users/" + uid, "DELETE")
ok(code == 200 and not load_config()["access"]["users"], "a user is deleted")

print("\n" + ("%d failed" % len(fails) if fails
              else "the sign-in behaves, and the hashes are crypt(3)'s"))
sys.exit(1 if fails else 0)
