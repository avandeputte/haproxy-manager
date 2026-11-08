#!/usr/bin/env python3
"""Address lists, and rules that test "any of these, and all of those".

    HAM_DATA_DIR=/tmp/x python3 tools/test-lists.py

Issue #19: an operator with users behind home connections, whose addresses
change every few weeks, had to edit every service that let them in; and a
rule could only AND or OR its conditions, so "one of these hosts, from one of
these addresses" could not be said. Now a list is named from a pool, the
networks that skip its sign-in, or a condition, and edited in one place; and
a rule has two lists, any_of and conditions, rendered as the alternatives
HAProxy understands. The wizard writes the new shape only when a service
needs it, and no longer drops a condition an operator added by hand.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-lists-"))
os.environ["HAM_CERT_DIR"] = os.path.join(os.environ["HAM_DATA_DIR"], "certs")
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import access, apply, haproxy   # noqa: E402
from ham.base import CERT_DIR   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402
from ham.util import _by_id, rule_cond_ids   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "lists-key"
save_config(cfg)
H = {"X-API-Key": "lists-key"}


def post(path, body, want=200):
    r = client.post("/api/" + path, headers=H, json=body)
    ok(r.status_code == want, "POST %s -> %d: %s" % (path, r.status_code, (r.get_json() or {}).get("error", "")[:80]))
    return r.get_json()


def put(path, body, want=200):
    r = client.put("/api/" + path, headers=H, json=body)
    ok(r.status_code == want, "PUT %s -> %d" % (path, r.status_code))
    return r.get_json()


def render():
    return haproxy.render_haproxy(load_config())


def lines_with(text, needle):
    return [ln.strip() for ln in text.splitlines() if needle in ln]


# ---- the lists themselves ---------------------------------------------------
bad = post("haproxy/addresslists", {"name": "typo", "networks": "192.168.1.0/24\nnot-a-network"}, want=400)
ok("not a network" in (bad or {}).get("error", ""), "a list with an entry that is not a network is refused, naming it")
friends = post("haproxy/addresslists", {"name": "friends", "networks": "192.168.1.0/24\n203.0.113.7"})
big = post("haproxy/addresslists", {"name": "big", "networks": "\n".join("10.%d.0.0/16" % i for i in range(100))})
nets, _ = access.list_networks(load_config(), [friends["id"], "gone", big["id"]])
ok(nets[:2] == ["192.168.1.0/24", "203.0.113.7/32"] and len(nets) == 102,
   "list_networks flattens the lists named, in order, and a missing one adds nothing")
ok(access.list_names(load_config(), [big["id"], "gone", friends["id"]]) == ["big", "friends"],
   "list_names gives the names, dropping ids that name nothing")

# ---- a pool's allow-list, typed and named together ---------------------------
r = post("wizard/publish", {"url": "https://shop.example.com", "target": "10.0.0.5:80",
                            "certificate": False, "dry_run": False, "allow_lists": [friends["id"], "gone"]})
pool = next(b for b in load_config()["haproxy"]["backends"] if b["name"] == "shop")
ok(pool.get("allow_lists") == [friends["id"]], "the wizard stores the lists named, less one that does not exist")
ok("http-request deny unless { src 192.168.1.0/24 203.0.113.7/32 }" in render(),
   "a pool naming a list refuses everyone outside it")
pool["allow_src"] = "10.9.9.0/24\n203.0.113.7"
c = load_config(); c["haproxy"]["backends"] = [pool]; save_config(c)
ok("deny unless { src 10.9.9.0/24 203.0.113.7/32 192.168.1.0/24 }" in render(),
   "typed networks and named lists count together, without repeating an address")
pool["allow_src"], pool["allow_lists"] = "", [big["id"]]
c = load_config(); c["haproxy"]["backends"] = [pool]; save_config(c)
out = render()
decl = lines_with(out, "acl allowed_src src")
ok(len(decl) == 3 and all(len(ln.split()) <= 64 for ln in decl),
   "a hundred networks are declared as a named ACL over %d lines, none over HAProxy's 64 words" % len(decl))
ok("http-request deny unless allowed_src" in out, "and the refusal names that ACL")
pool["allow_lists"] = ["gone"]
c = load_config(); c["haproxy"]["backends"] = [pool]; save_config(c)
out = render()
ok("# every allowed network is malformed, so nobody is" in out and "http-request deny\n" in out,
   "a pool whose only list was deleted refuses everyone rather than everyone in")
svc = client.get("/api/services", headers=H).get_json()[0]
pool["allow_lists"] = [friends["id"]]
c = load_config(); c["haproxy"]["backends"] = [pool]; save_config(c)
svc = client.get("/api/services", headers=H).get_json()[0]
ok(svc["allow_lists"] == [friends["id"]] and svc["allow_list_names"] == ["friends"],
   "the Services API reports the lists a service names, with their names")

# ---- the networks that skip a sign-in ---------------------------------------
post("access/users", {"username": "ann", "password": "hunter2hunter2", "enabled": True})
pool.update({"auth_enabled": True, "auth_exempt_src": "10.1.1.0/24", "auth_exempt_lists": [friends["id"]]})
c = load_config(); c["haproxy"]["backends"] = [pool]; save_config(c)
out = render()
ok("unless { src 10.1.1.0/24 192.168.1.0/24 203.0.113.7/32 } or { http_auth(ham_users) }" in out,
   "the lists that skip the sign-in join the typed networks in front of the auth test")
pool.update({"auth_exempt_src": "", "auth_exempt_lists": [big["id"]]})
c = load_config(); c["haproxy"]["backends"] = [pool]; save_config(c)
out = render()
ok(len(lines_with(out, "acl exempt_src src")) == 3 and "unless exempt_src or { http_auth(ham_users) }" in out,
   "a long exemption list is declared as a named ACL and tested by name")
r = post("wizard/publish", {"url": "https://shop.example.com", "target": "10.0.0.5:80",
                            "certificate": False, "dry_run": False, "service_id": svc["id"],
                            "auth": {"enabled": True, "exempt": "", "exempt_lists": [friends["id"], "gone"]}})
pool = next(b for b in load_config()["haproxy"]["backends"] if b["name"] == "shop")
ok(pool.get("auth_exempt_lists") == [friends["id"]], "the wizard stores the exempt lists inside auth, known ones only")
pool.update({"auth_enabled": False, "auth_exempt_lists": [], "allow_lists": []})
c = load_config(); c["haproxy"]["backends"] = [pool]; save_config(c)

# ---- a condition that names a list -------------------------------------------
cond = post("haproxy/conditions", {"name": "from-friends", "type": "source_list", "list": friends["id"]})
nolist = post("haproxy/conditions", {"name": "from-nobody", "type": "source_list", "list": "gone"})
c = load_config()
hp = c["haproxy"]
rule = next(r for r in hp["rules"] if r["type"] == "use_backend")
host = rule["conditions"][0]
rule["conditions"] = [host, cond["id"], nolist["id"]]
save_config(c)
out = render()
ok("acl acl_from-friends src 192.168.1.0/24 203.0.113.7/32" in out,
   "a source_list condition renders the list's networks")
ok("acl acl_from-nobody always_false" in out,
   "one naming a list that is gone matches nobody, stated so HAProxy still parses")
ok("use_backend be_shop if acl_host-shop acl_from-friends acl_from-nobody" in out,
   "and the rule tests all of them")

# ---- any of these, and all of those --------------------------------------------
tv = post("haproxy/conditions", {"name": "host-tv", "type": "host_matches", "value": "tv.example.com"})
films = post("haproxy/conditions", {"name": "host-films", "type": "host_matches", "value": "films.example.com"})
lan = post("haproxy/conditions", {"name": "lan", "type": "source_ip", "value": "192.168.0.0/16"})
api = post("haproxy/conditions", {"name": "api", "type": "path_starts_with", "value": "/api", "negate": True})
conds = _by_id(load_config()["haproxy"]["conditions"])


def test_of(**shape):
    return haproxy._rule_test(dict({"test": "if"}, **shape), conds)


ok(test_of(any_of=[tv["id"], films["id"]], conditions=[lan["id"]])
   == " if acl_host-tv acl_lan || acl_host-films acl_lan",
   "(tv or films) and lan is written out as the alternatives HAProxy understands")
ok(test_of(any_of=[tv["id"], films["id"]], conditions=[lan["id"], api["id"]])
   == " if acl_host-tv acl_lan !acl_api || acl_host-films acl_lan !acl_api",
   "every all-of condition rides with each alternative, negation included")
ok(test_of(any_of=[tv["id"], films["id"]]) == " if acl_host-tv || acl_host-films",
   "alternatives alone")
ok(test_of(conditions=[tv["id"], lan["id"]]) == " if acl_host-tv acl_lan", "all-of alone, as before")
ok(test_of(conditions=[tv["id"], films["id"]], operator="or") == " if acl_host-tv || acl_host-films",
   "a rule from before 2.0 with \"or\" over its one list is read as alternatives")
ok(test_of(any_of=[lan["id"]], conditions=[tv["id"]], operator="or") == " if acl_lan || acl_host-tv",
   "and with the old operator everything is an alternative, so nothing an old node ANDed is lost")
ok(test_of(any_of=[tv["id"]], conditions=[lan["id"]], test="unless") == " unless acl_host-tv acl_lan",
   "unless negates the whole test")
ok(test_of(any_of=["gone"], conditions=["gone-too"]) == "", "conditions that no longer exist leave no test")
ok(rule_cond_ids({"any_of": ["a", "b"], "conditions": ["b", "c"]}) == ["a", "b", "c"],
   "rule_cond_ids is every condition a rule tests, once")

# ---- the wizard: which shape, and what it keeps --------------------------------
r = post("wizard/publish", {"url": "https://tv.example.com\nhttps://erstatztv.example.com",
                            "target": "10.0.0.6:80", "certificate": False, "dry_run": False})
rid = next(a for a in r["actions"] if a["type"] == "Rule")
rule = next(x for x in load_config()["haproxy"]["rules"] if x["name"] == rid["name"])
ok(rule["operator"] == "or" and not rule.get("any_of") and len(rule["conditions"]) == 2,
   "two names and nothing else: the shape every version renders the same")
ok("use_backend be_tv if acl_host-tv || acl_host-erstatztv" in render(), "rendered as alternatives")
# the operator adds a condition by hand on the Rules page
c = load_config()
x = next(x for x in c["haproxy"]["rules"] if x["id"] == rule["id"])
x["conditions"].append(lan["id"])
save_config(c)
r = post("wizard/publish", {"url": "https://tv.example.com\nhttps://erstatztv.example.com",
                            "target": "10.0.0.6:80", "certificate": False, "dry_run": False,
                            "service_id": rule["id"]})
rule = next(x for x in load_config()["haproxy"]["rules"] if x["id"] == rule["id"])
ok(rule["conditions"] == [lan["id"]] and len(rule["any_of"]) == 2 and rule["operator"] == "and",
   "editing the service keeps the condition added by hand: the names become any-of, it is all-of")
ok("use_backend be_tv if acl_host-tv acl_lan || acl_host-erstatztv acl_lan" in render(),
   "so the LAN test holds for either name -- what #19 asked for")
svcs = client.get("/api/services", headers=H).get_json()
mine = next(s for s in svcs if s["pool"] == "tv")
ok(sorted(mine["urls"]) == ["https://erstatztv.example.com", "https://tv.example.com"],
   "the Services page still reads both names off the any_of list")
# a rule from before 2.0 with a hand-added condition in its one "or" list
c = load_config()
x = next(x for x in c["haproxy"]["rules"] if x["id"] == rule["id"])
x.update({"operator": "or", "any_of": [], "conditions": x["any_of"] + [lan["id"]]})
save_config(c)
r = post("wizard/publish", {"url": "https://tv.example.com\nhttps://erstatztv.example.com",
                            "target": "10.0.0.6:80", "certificate": False, "dry_run": False,
                            "service_id": rule["id"]})
rule = next(x for x in load_config()["haproxy"]["rules"] if x["id"] == rule["id"])
ok(rule["conditions"] == [lan["id"]] and len(rule["any_of"]) == 2 and rule["operator"] == "and",
   "a pre-2.0 rule whose \"or\" list held a hand-added condition is reshaped: the names any, the rest all")
# one name and an extra: one list, as always
r = post("wizard/publish", {"url": "https://films.example.com", "target": "10.0.0.7:80",
                            "certificate": False, "dry_run": False})
fr = next(x for x in load_config()["haproxy"]["rules"] if x["name"] == next(a for a in r["actions"] if a["type"] == "Rule")["name"])
c = load_config()
x = next(x for x in c["haproxy"]["rules"] if x["id"] == fr["id"])
x["conditions"].append(lan["id"])
save_config(c)
post("wizard/publish", {"url": "https://films.example.com", "target": "10.0.0.7:80",
                        "certificate": False, "dry_run": False, "service_id": fr["id"]})
fr = next(x for x in load_config()["haproxy"]["rules"] if x["id"] == fr["id"])
ok(not fr["any_of"] and len(fr["conditions"]) == 2 and fr["conditions"][-1] == lan["id"] and fr["operator"] == "and",
   "one name and an extra stay one list, the extra kept")
# deleting a service takes the conditions from both lists with it, when nothing else uses them
r = client.delete("/api/services/" + rule["id"], headers=H)
ok(r.status_code == 200, "the two-name service is removed")
names = {c["name"] for c in load_config()["haproxy"]["conditions"]}
ok("host-erstatztv" not in names and "lan" in names,
   "its own host conditions went with it; the LAN condition another rule uses stayed")

# ---- the rendered file is one HAProxy accepts ----------------------------------
# A listener published without a certificate binds the certificate directory,
# which HAProxy wants to exist with something in it: the stand-in Apply would make.
CERT_DIR.mkdir(parents=True, exist_ok=True)
apply._selfsigned_placeholder(CERT_DIR / "stand-in.pem", ["stand-in"])
text = render()
fd, path = tempfile.mkstemp(suffix=".cfg")
with os.fdopen(fd, "w") as f:
    f.write(text)
try:
    r = subprocess.run(["haproxy", "-c", "-f", path], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        ok(True, "haproxy -c accepts the rendered configuration")
    else:
        ok(False, "haproxy -c: " + (r.stderr or r.stdout).strip()[-300:])
except FileNotFoundError:
    print("  ....  no haproxy here; the text checks above stand")
finally:
    os.unlink(path)

print("\n" + ("%d failed" % len(fails) if fails else "one list, named from everywhere; any of these, and all of those"))
sys.exit(1 if fails else 0)
