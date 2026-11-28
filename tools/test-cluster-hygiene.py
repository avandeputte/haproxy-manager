#!/usr/bin/env python3
"""What a node must and must not do with what the other nodes send it.

Each of these was a real defect found by the November 2026 review: a push
that overwrote the passive node's own UI certificate, a receive that saved a
null section and then failed every request, a mesh list that dropped the
peers only this node knew, a passive node pushing its configuration over the
active node's, setup that any peer could run again, sign-in users that never
read as unapplied, and a world-readable haproxy.cfg carrying password hashes.
One assertion each, at the seam where the fix lives.

    HAM_DATA_DIR=/tmp/x python3 tools/test-cluster-hygiene.py
"""
import base64
import copy
import grp
import hashlib
import json
import logging
import os
import pathlib
import stat
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
_tmp = tempfile.mkdtemp(prefix="ham-hyg-")
os.environ.setdefault("HAM_DATA_DIR", _tmp)
os.environ.setdefault("HAM_CERT_DIR", os.path.join(_tmp, "certs"))
os.environ.setdefault("HAM_HAPROXY_CFG", os.path.join(_tmp, "haproxy.cfg"))
os.environ.setdefault("HAM_KEEPALIVED_CFG", os.path.join(_tmp, "keepalived.conf"))
os.environ["HAM_DRY_RUN"] = "1"

import ham   # noqa: E402
from ham import apply, auth, crowdsec, history, peering, sync, vrrp, webui   # noqa: E402
from ham.base import CERT_DIR, CONF_PATH, HAPROXY_CFG, _lock, log   # noqa: E402
from ham.config import (DEFAULT_CONFIG, HASH_FORMULA, SHARED_SECTIONS, check_section, config_hash,   # noqa: E402
                        load_config, save_config, shared_fingerprint, shared_view, write_private)

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


def b64(text):
    return base64.b64encode(text.encode()).decode()


def rev():
    return int(load_config()["_meta"].get("shared_rev") or 0)


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "hyg-key"
cfg["local"]["session_secret"] = "s" * 64
cfg["local"]["admin"].update(auth.hash_password("pw"), username="alex")
save_config(cfg)
client.environ_base["HTTP_X_API_KEY"] = "hyg-key"
# HAProxy is not running here, and waiting ten seconds to find that out at
# every Apply is not what is under test.
apply._haproxy_not_serving = lambda: ""


def receive(body, **kw):
    body = dict({"rev": rev() + 1, "fp": "x", "config": {}, "source": "hostB"}, **body)
    return client.post("/api/sync/receive", json=body, **kw)


# -- one list of shared sections -----------------------------------------------
print("the shared sections")
ok(set(shared_view(load_config())) == set(SHARED_SECTIONS),
   "the shared view holds exactly SHARED_SECTIONS")
ok(history.SECTIONS is SHARED_SECTIONS, "and the history reads the same list")
before = rev()
r = receive({"config": {"haproxy": None}})
ok(r.status_code == 400 and "haproxy" in r.get_json()["error"],
   "a null section from a peer is refused, naming the section: %s" % r.get_json()["error"])
ok(rev() == before and isinstance(load_config()["haproxy"], dict), "and nothing was taken")
r = receive({"config": {"haproxy": {"settings": None}}})
ok(r.status_code == 400 and "haproxy.settings" in r.get_json()["error"],
   "a null settings block likewise")
ok(client.get("/api/status?brief=1").status_code == 200, "and the node still answers afterwards")
r = receive({"config": {"acme": {"certificates": [1]}}})
ok(r.status_code == 400 and "acme.certificates" in r.get_json()["error"],
   "a collection holding bare values likewise")
ok(check_section("haproxy", {"servers": {}}), "a dict where a list belongs is caught")
ok(check_section("notify", {"events": [], "destinations": []}), "a list where a dict belongs is caught")
ok(check_section("cluster", {"vips": "10.0.0.9"}) == "", "a well-shaped section passes")
ok(rev() == before, "none of the refusals moved the revision")

# -- what Cloudflare was told is not a change ----------------------------------
print("what Cloudflare was told")
cfg = load_config()
cfg["cloudflare"]["told"] = "deadbeef"
fp_before, rev_before = shared_fingerprint(cfg), rev()
save_config(cfg)
ok(rev() == rev_before and shared_fingerprint(load_config()) == fp_before,
   "noting what Cloudflare was told moves neither the revision nor the fingerprint")
ok("told" not in shared_view(load_config())["cloudflare"], "it is not in the shared view")
payload = sync.shared_payload(load_config())
ok(payload.get("cloudflare_told") == "deadbeef" and payload["config"] == shared_view(load_config()),
   "but it travels with a push, beside the configuration")
receive({"cloudflare_told": "cafe"})
ok(load_config()["cloudflare"]["told"] == "cafe", "and the receiver takes it")

# -- the sign-in users count as configuration ----------------------------------
print("sign-in users and the applied marker")
cfg = load_config()
cfg["_meta"]["applied_hash"] = config_hash(cfg)
save_config(cfg)
ok(client.get("/api/status?brief=1").get_json()["dirty"] is False, "a node with nothing waiting")
cfg = load_config()
cfg["access"]["users"].append({"id": "u1", "username": "bob", "hash": "x", "enabled": True})
save_config(cfg)
ok(client.get("/api/status?brief=1").get_json()["dirty"] is True,
   "adding a sign-in user is an unapplied change: the userlist is rendered")
cfg = load_config()
cfg["access"]["users"] = []          # a hash haproxy -c would refuse: not for the Applies below
save_config(cfg)


def hash_as_2_5_1(stored):
    """config_hash as 2.5.1 computed it: no access, the whole of local.keepalived."""
    parts = {"haproxy": stored["haproxy"], "acme": stored["acme"], "cluster": stored["cluster"],
             "keepalived": stored["local"]["keepalived"], "crowdsec": stored["crowdsec"],
             "cloudflare": {k: v for k, v in stored["cloudflare"].items() if k != "told"}}
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


# A file as 2.5.1 left it: the dead copies of the cluster's VRRP settings
# still under local.keepalived, the marker computed its way, no formula named.
stored = json.loads(CONF_PATH.read_text())
stored["local"]["keepalived"].update({"enabled": False, "vrid": 51, "state": "BACKUP", "nopreempt": True,
                                      "advert_int": 1, "auth_pass": "", "vips": "", "track_haproxy": True,
                                      "custom": ""})
stored["_meta"].pop("applied_hash_formula", None)
stored["_meta"]["applied_hash"] = hash_as_2_5_1(stored)
CONF_PATH.write_text(json.dumps(stored))
cfg = load_config()
ok(cfg["_meta"]["applied_hash"] == config_hash(cfg) and cfg["_meta"]["applied_hash_formula"] == HASH_FORMULA,
   "a 2.5.1 file whose last Apply covered everything is not dirty after the upgrade")
ok(client.get("/api/status?brief=1").get_json()["dirty"] is False, "which is what the status says")
ok("enabled" not in DEFAULT_CONFIG["local"]["keepalived"] and cfg["local"]["keepalived"].get("vrid") == 51,
   "the dead keys are gone from the defaults, and a file that still has them is read as it is")
save_config(load_config())
ok(json.loads(CONF_PATH.read_text())["_meta"].get("applied_hash_formula") == HASH_FORMULA,
   "the next save writes the formula down")
stored["_meta"]["applied_hash"] = "something-else"
CONF_PATH.write_text(json.dumps(stored))
ok(client.get("/api/status?brief=1").get_json()["dirty"] is True,
   "a 2.5.1 file with a change waiting still reads dirty")
cfg = load_config()
cfg["_meta"]["applied_hash"] = config_hash(cfg)
save_config(cfg)

# -- a node's own UI certificate never travels ---------------------------------
print("certificate files")
CERT_DIR.mkdir(parents=True, exist_ok=True)
(CERT_DIR / "haproxy-manager-ui.pem").write_text("LOCAL-UI")
(CERT_DIR / "shop.pem").write_text("SHOP")
(CERT_DIR / "orphan.pem").write_text("ORPHAN")
cfg = load_config()
cfg["acme"]["certificates"] = [{"id": "c1", "name": "shop", "domains": "shop.example"}]
cfg["local"]["acme"]["certificates"] = [{"id": "ui", "name": "haproxy-manager-ui", "domains": "node1.example"}]
save_config(cfg)
ok(set(sync.shared_payload(load_config())["certs"]) == {"shop.pem"},
   "a push carries the files of the shared certificates only -- not this node's UI certificate, "
   "not a stray file")
shared_acme = copy.deepcopy(load_config()["acme"])
r = receive({"config": {"acme": shared_acme},
             "certs": {"haproxy-manager-ui.pem": b64("EVIL"), "shop.pem": b64("NEW-SHOP"),
                       "other.pem": b64("OTHER")}})
ok(r.status_code == 200, "a receive carrying the UI certificate's name is still taken")
ok((CERT_DIR / "haproxy-manager-ui.pem").read_text() == "LOCAL-UI",
   "and this node's own UI certificate was not overwritten")
ok((CERT_DIR / "shop.pem").read_text() == "NEW-SHOP", "the shared certificate was")
ok(not (CERT_DIR / "other.pem").exists(), "a file no record names was not written")
ok(mode_of(CERT_DIR / "shop.pem") == 0o600, "and the file is private")
r = receive({"config": {"acme": shared_acme}, "certs": {"shop.pem": "%%not-base64%%"}})
ok(r.status_code == 400 and "shop.pem" in r.get_json()["error"],
   "a certificate that does not decode refuses the offer, naming the file")
ok((CERT_DIR / "shop.pem").read_text() == "NEW-SHOP", "with nothing written")
r = receive({"config": {"acme": shared_acme}, "certs": {"../etc/x.pem": b64("x")}})
ok(r.status_code == 400, "a name that is not a plain file name likewise")
two = copy.deepcopy(shared_acme)
two["certificates"].append({"id": "c2", "name": "shop2", "domains": "shop2.example"})
r = receive({"config": {"acme": two},
             "certs": {"shop.pem": b64("A"), "shop2.pem": "%%bad%%"}})
ok(r.status_code == 400 and (CERT_DIR / "shop.pem").read_text() == "NEW-SHOP",
   "everything is decoded before anything is written")
# The stand-ins are not certificates; the Applies below load real files.
cfg = load_config()
cfg["acme"]["certificates"], cfg["local"]["acme"]["certificates"] = [], []
save_config(cfg)
for name in ("haproxy-manager-ui.pem", "shop.pem", "orphan.pem"):
    (CERT_DIR / name).unlink()

# -- the membership list is joined, not replaced ---------------------------------
print("the membership list")
cfg = load_config()
cfg["local"]["sync"]["peers"] = [
    {"id": "p1", "name": "node-a", "url": "http://a.example", "api_key": "ka", "verify_tls": False, "enabled": True},
    {"id": "p2", "name": "only-here", "url": "http://b.example", "api_key": "kb", "verify_tls": True, "enabled": True}]
save_config(cfg)
receive({"peers": [{"id": "self-a", "name": "node-a", "url": "http://a.example", "api_key": "ka", "self": True},
                   {"id": "p9", "name": "node-c", "url": "http://c.example", "api_key": "kc"}]})
peers = {p["url"]: p for p in load_config()["local"]["sync"]["peers"]}
ok(set(peers) == {"http://a.example", "http://b.example", "http://c.example"},
   "a peer only this node knows survives an inbound list: %s" % sorted(peers))
ok(peers["http://b.example"]["api_key"] == "kb" and peers["http://b.example"]["verify_tls"] is True,
   "with its key and its policy")
here = rev()
receive({"rev": 0})
ok(rev() == here, "a sender that names no revision does not put this node back at zero")

# -- a passive node does not push ---------------------------------------------
print("a passive node")
pushed = []
real_push, real_role = sync.sync_push, auth.node_role
sync.sync_push = lambda cfg, **kw: pushed.append(1) or {"ok": True, "results": []}
auth.node_role = lambda cfg: ("passive", [])
res = apply.do_apply()
ok(res.get("ok") and not pushed and any("passive" in s for s in res["steps"]),
   "an Apply on a passive node does not push, and says why: %s"
   % next((s for s in res["steps"] if "passive" in s), ""))
auth.node_role = lambda cfg: ("active", ["10.0.0.9"])
apply.do_apply()
ok(pushed == [1], "the same Apply on the active node pushes")
sync.sync_push, auth.node_role = real_push, real_role

real_ro = auth.readonly_state
auth.readonly_state = lambda cfg: (True, "This node is passive.")
cfg = load_config()
cfg["cluster"]["ui_url"] = "https://ham.example"
save_config(cfg)
r = client.post("/api/webui", json={"enabled": True, "url": "https://node1.example",
                                    "shared_url": "https://other.example", "certificate": "auto"})
ok(r.status_code == 409 and r.get_json().get("read_only"),
   "a passive node refuses to change the shared UI address: %s" % r.get_json().get("error", "")[:70])
ok(load_config()["cluster"]["ui_url"] == "https://ham.example", "and it is unchanged")
r = client.post("/api/webui", json={"enabled": True, "url": "https://node1.example",
                                    "shared_url": "https://ham.example", "certificate": "auto"})
ok(r.status_code == 200, "its own address, with the shared one as it is, can still be saved")
auth.readonly_state = real_ro
r = client.post("/api/webui", json={"enabled": True, "url": "https://node1.example",
                                    "shared_url": "https://other.example", "certificate": "auto"})
ok(r.status_code == 200 and load_config()["cluster"]["ui_url"] == "https://other.example",
   "the active node changes it")
client.post("/api/webui", json={"enabled": False})

# -- setup runs once ---------------------------------------------------------
print("setup")
cfg = load_config()
cfg["_meta"]["setup_complete"] = True
save_config(cfg)
key_before = load_config()["local"]["api_key"]
r = client.post("/api/setup/create", json={"mode": "standalone", "api_key": "stolen", "apply": False})
ok(r.status_code == 409 and load_config()["local"]["api_key"] == key_before,
   "once set up, setup/create is refused: %s" % r.get_json()["error"][:60])
r = client.post("/api/setup/create", json={"mode": "standalone", "api_key": "stolen", "force": True, "apply": False})
ok(r.status_code == 409 and load_config()["local"]["api_key"] == key_before,
   "even with force, when the caller is an API key -- which every peer holds")
r = client.post("/api/setup/join", json={"peer_url": "http://a.example", "peer_api_key": "k"})
ok(r.status_code == 409, "and so is setup/join")
token = auth.make_session(load_config(), "alex")
try:
    client.set_cookie(auth.SESSION_COOKIE, token)
except TypeError:                           # Werkzeug before 2.3 wanted the server name first
    client.set_cookie("localhost", auth.SESSION_COOKIE, token)
client.environ_base.pop("HTTP_X_API_KEY")
r = client.post("/api/setup/create", json={"mode": "standalone", "api_key": "hyg-key", "force": True, "apply": False})
ok(r.status_code == 200, "a person at a browser who says force may run it again")
client.delete_cookie(auth.SESSION_COOKIE)
client.environ_base["HTTP_X_API_KEY"] = "hyg-key"

# -- Apply fills in unicast addresses, never overwrites them ---------------------------
print("unicast addresses")
c = copy.deepcopy(DEFAULT_CONFIG)
c["cluster"]["vips"] = "10.0.0.100/24"
c["local"]["keepalived"].update({"unicast_src": "192.168.5.1", "unicast_peer": "192.168.5.2"})
ok(vrrp.derive_unicast(c, ("10.0.0.2", "10.0.0.1")) is False
   and c["local"]["keepalived"]["unicast_peer"] == "192.168.5.2",
   "the addresses 'Apply unicast plan' set are left alone by Apply")
c["local"]["keepalived"].update({"unicast_src": "", "unicast_peer": ""})
ok(vrrp.derive_unicast(c, ("10.0.0.2", "10.0.0.1")) is True
   and c["local"]["keepalived"] == dict(c["local"]["keepalived"], unicast_peer="10.0.0.2", unicast_src="10.0.0.1"),
   "empty ones are filled in")

# -- this node's own settings are checked before they are written -----------------------
print("this node's own settings")
v = vrrp.validate_local_update
ok(v({"keepalived": {"unicast_peer": "10.0.0.2\n    notify_master /bin/sh"}}),
   "a line break in a unicast address is refused: it would be a directive")
ok(v({"keepalived": {"interface": "eth0\nnotify_master /bin/sh"}}), "and in the interface name")
ok(v({"keepalived": {"unicast_peer": "10.0.0.2, 10.0.0.3", "unicast_src": "10.0.0.1", "priority": 150}}) == "",
   "addresses and a priority pass")
ok(v({"keepalived": {"priority": "high"}}) and v({"keepalived": {"priority": 300}}), "a priority that is not one is refused")
real_ifaces = apply.node_interfaces
apply.node_interfaces = lambda: [{"name": "eth9", "addresses": ["10.0.0.1/24"], "up": True}]
ok(v({"keepalived": {"interface": "eth0"}}) and v({"keepalived": {"interface": "eth9"}}) == "",
   "the interface must be one this node has, as setup requires")
apply.node_interfaces = real_ifaces
ok(v({"sync": {"auto_sync": False}}) == "" and v({"keepalived": "eth0"}), "other settings pass; a non-object does not")

# -- a peer's URL is normalised however it arrives -------------------------------------
print("a peer's URL")
pid = load_config()["local"]["sync"]["peers"][0]["id"]
r = client.put("/api/peers/%s" % pid, json={"url": "10.0.0.2:8080"})
ok(r.status_code == 200 and r.get_json()["url"] == "http://10.0.0.2:8080",
   "a bare host:port gets its scheme on PUT as it does on POST")
ok(client.put("/api/peers/%s" % pid, json={"url": 5}).status_code == 400, "a URL that is not text is a 400, not a 500")
ok(client.put("/api/peers/%s" % pid, json={"url": " "}).status_code == 400, "and so is an empty one")
ok(client.put("/api/peers/%s" % pid, json={"name": ["x"]}).status_code == 400, "a name that is not text likewise")
ok(load_config()["local"]["sync"]["peers"][0]["url"] == "http://10.0.0.2:8080", "the stored entry is the normalised one")

# -- private files have no public moment ------------------------------------------
print("private files")
p = pathlib.Path(_tmp) / "secret.pem"
p.write_text("old")
os.chmod(p, 0o644)
write_private(p, "new")
ok(p.read_text() == "new" and mode_of(p) == 0o600, "a file that was world-readable is private once rewritten")
ok(not [n for n in os.listdir(_tmp) if n.startswith(".secret.pem")], "and no temporary file is left beside it")
ok(mode_of(CONF_PATH) == 0o600, "config.json is private")

# -- haproxy.cfg is not world-readable -------------------------------------------------
print("haproxy.cfg")
res = apply.do_apply()
ok(res.get("ok"), "an Apply goes through: %s" % (res.get("error") or res["steps"][:2]))
m = mode_of(HAPROXY_CFG)
ok(not (m & stat.S_IROTH), "haproxy.cfg is not world-readable: %o" % m)
try:
    gid = grp.getgrnam("haproxy").gr_gid
except KeyError:
    gid = None
if gid is None:
    ok(m == 0o600, "with no haproxy group here it is 0600")
else:
    ok(m == 0o640 and os.stat(HAPROXY_CFG).st_gid == gid, "with a haproxy group it is 0640 root:haproxy")
apply.do_apply()
ok(not (mode_of(str(HAPROXY_CFG) + ".bak") & stat.S_IROTH), "and neither is the copy kept beside it")

# -- the slow parts of an Apply run with the store unlocked ----------------------------
print("the store's lock during an Apply")
seen = {}
real_cs = (crowdsec.configured, crowdsec.installed, crowdsec.ensure_installed)
crowdsec.configured = lambda cfg: True
crowdsec.installed = lambda: False
crowdsec.ensure_installed = lambda cfg: (seen.setdefault("install", _lock._is_owned()), (False, "not here"))[1]
real_values = vrrp.derive_unicast_values
vrrp.derive_unicast_values = lambda cfg: (seen.setdefault("resolve", _lock._is_owned()), ("", ""))[1]
apply._haproxy_not_serving = lambda: (seen.setdefault("probe", _lock._is_owned()), "")[1]
cfg = load_config()
cfg["cluster"]["vips"] = "10.0.0.100/24"
save_config(cfg)
apply.do_apply()
ok(seen.get("install") is False, "a package install runs before the lock is taken")
ok(seen.get("resolve") is False, "name resolution runs before the lock is taken")
ok(seen.get("probe") is False, "waiting for HAProxy runs after it is released")
crowdsec.configured, crowdsec.installed, crowdsec.ensure_installed = real_cs
vrrp.derive_unicast_values = real_values
apply._haproxy_not_serving = lambda: ""
cfg = load_config()
cfg["cluster"]["vips"] = ""
save_config(cfg)
real_apply = apply.do_apply
apply.do_apply = lambda *a, **kw: (seen.setdefault("receive", _lock._is_owned()), {"ok": True, "steps": []})[1]
receive({})
ok(seen.get("receive") is False, "a received configuration is applied with the lock released")
apply.do_apply = real_apply

# -- a failure to rebuild the UI service is said ------------------------------------
print("the log")
records = []


class Catch(logging.Handler):
    def emit(self, record):
        records.append(record)


log.addHandler(Catch())
cfg = load_config()
cfg["local"]["web_ui"].update({"enabled": True, "url": "https://node1.example"})
save_config(cfg)
real_rebuild = webui.rebuild_webui
webui.rebuild_webui = lambda cfg: (_ for _ in ()).throw(RuntimeError("boom"))
receive({})
webui.rebuild_webui = real_rebuild
ok(any(r.levelno >= logging.ERROR and "rebuild" in r.getMessage() for r in records),
   "a UI service that could not be rebuilt after a receive is in the log")
cfg = load_config()
cfg["local"]["web_ui"].update({"enabled": False, "url": ""})
save_config(cfg)

# -- the preview says what Keepalived does -------------------------------------
print("the preview")
ka = client.get("/api/preview").get_json()["keepalived"]
ok("not used" in ka and "disabled on this node" not in ka,
   "without a virtual IP the preview says Keepalived is not used, not that it is disabled on the node")
cfg = load_config()
cfg["cluster"]["vips"] = "10.0.0.100/24"
save_config(cfg)
ok("vrrp_instance" in client.get("/api/preview").get_json()["keepalived"], "with one it renders keepalived.conf")

print("\n" + ("%d failed" % len(fails) if fails
              else "a node keeps what is its own and takes what is shared"))
sys.exit(1 if fails else 0)
