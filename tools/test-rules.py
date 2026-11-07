#!/usr/bin/env python3
"""The rule wizard: one request builds a rule, attaches it, and asks HAProxy.

    HAM_DATA_DIR=/tmp/x python3 tools/test-rules.py

A rule made on the Rules page did nothing until the listener was opened and
the rule ticked there, and its conditions had to be made first on a third
page. The wizard takes the conditions typed, reuses one that already exists,
names what it makes, places the rule on the listeners picked, and refuses --
before storing anything -- a rule HAProxy would not load.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-rules-"))
os.environ["HAM_CERT_DIR"] = os.path.join(os.environ["HAM_DATA_DIR"], "certs")
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import haproxy, rules   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402
from ham.util import _by_id   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "rules-key"
save_config(cfg)
H = {"X-API-Key": "rules-key"}


def post(path, body, want=200):
    r = client.post("/api/" + path, headers=H, json=body)
    ok(r.status_code == want, "POST %s -> %d %s" % (path, r.status_code, ((r.get_json() or {}).get("error") or "")[:90].replace("\n", " ")))
    return r.get_json()


def have_haproxy():
    try:
        return subprocess.run(["haproxy", "-v"], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


def rule_named(name):
    return next((r for r in load_config()["haproxy"]["rules"] if r["name"] == name), None)


def fe():
    return load_config()["haproxy"]["frontends"][0]


post("wizard/publish", {"url": "http://shop.example.com", "target": "10.0.0.5:80", "certificate": False,
                        "http_redirect": False, "dry_run": False})
post("wizard/publish", {"url": "http://admin.example.com", "target": "10.0.0.6:80", "certificate": False,
                        "http_redirect": False, "dry_run": False})
friends = post("haproxy/addresslists", {"name": "friends", "networks": "192.168.1.0/24"})
pools = {b["name"]: b["id"] for b in load_config()["haproxy"]["backends"]}

# ---- what a request must say -------------------------------------------------------
bad = post("wizard/rule", {"listeners": [fe()["id"]], "action": {"type": "use_backend"}}, want=400)
ok("Backend Pool" in bad["error"], "routing without a pool is refused")
bad = post("wizard/rule", {"listeners": ["gone"], "action": {"type": "http_request_deny"}}, want=400)
ok("no longer exists" in bad["error"], "a listener that does not exist is refused")
bad = post("wizard/rule", {"all_of": [{"type": "source_ip", "value": "not-a-net"}], "action": {"type": "http_request_deny"}}, want=400)
ok("not a network" in bad["error"], "a source that is not a network is refused")
bad = post("wizard/rule", {"all_of": [{"type": "http_header", "value": "x"}], "action": {"type": "http_request_deny"}}, want=400)
ok("name of the header" in bad["error"], "a header test without the header's name is refused")
bad = post("wizard/rule", {"action": {"type": "redirect_location"}}, want=400)
ok("location" in bad["error"], "a redirect without a location is refused")
bad = post("wizard/rule", {"all_of": [{"id": "gone"}], "action": {"type": "http_request_deny"}}, want=400)
ok("no longer exists" in bad["error"], "a picked condition that is gone is refused")

# ---- a preview says what would happen, and what HAProxy thinks -----------------------
body = {"listeners": [fe()["id"]],
        "any_of": [{"type": "host_matches", "value": "tv.example.com"},
                   {"type": "host_matches", "value": "films.example.com"}],
        "all_of": [{"type": "source_list", "list": friends["id"]}],
        "action": {"type": "http_request_deny", "test": "unless"}, "dry_run": True}
r = post("wizard/rule", body)
acts = ["%s %s" % (a["action"], a["name"]) for a in r["actions"]]
ok(acts == ["created host-tv", "created host-films", "created from-friends", "created deny-host-tv",
            "attached " + fe()["name"]],
   "a preview lists what would be made, named for what it tests: %s" % ", ".join(acts))
ok(r["validation"]["ok"] is True, "and HAProxy's verdict on the result: " + r["validation"]["message"].splitlines()[0])
ok("http-request deny unless acl_host-tv acl_from-friends || acl_host-films acl_from-friends" in r["preview"]
   and r["preview"].startswith("frontend fe_"),
   "the preview is the listener's block, the rule written out as its alternatives")
ok(rule_named("deny-host-tv") is None and not any(c["name"] == "host-tv" for c in load_config()["haproxy"]["conditions"]),
   "a preview stores nothing")

# ---- saved: conditions made once, the rule attached and placed ----------------------
body["dry_run"] = False
r = post("wizard/rule", body)
rule = rule_named("deny-host-tv")
ok(rule is not None and len(rule["any_of"]) == 2 and len(rule["conditions"]) == 1 and rule["test"] == "unless",
   "saved: the rule holds its two lists and its test")
ok(rule["id"] in fe()["rules"], "and sits on the listener picked")
conds = _by_id(load_config()["haproxy"]["conditions"])
made = [conds[c] for c in rule["any_of"] + rule["conditions"]]
ok(all(c.get("description") == rules.MARK for c in made), "the conditions it made are marked as its own")
ok(conds[rule["conditions"][0]].get("list") == friends["id"], "a source_list condition names the list")
r = post("wizard/rule", {"listeners": [fe()["id"]], "any_of": [{"type": "host_matches", "value": "tv.example.com"}],
                         "action": {"type": "redirect_scheme_https"}})
ok(any(a["action"] == "reused" and a["name"] == "host-tv" for a in r["actions"]),
   "a condition identical to one that exists is reused, not made again")
ok(r["rule"]["name"] == "https-host-tv", "a rule is named for its action and first condition: " + r["rule"]["name"])
r = post("wizard/rule", {"listeners": [fe()["id"]], "any_of": [{"type": "host_matches", "value": "tv.example.com"}],
                         "action": {"type": "use_backend", "backend": pools["shop"]}})
ok(r["rule"]["name"] == "to-shop-2" or r["rule"]["name"].startswith("to-shop"),
   "a routing rule is named for its pool, kept apart from the service's own: " + r["rule"]["name"])
text = haproxy.render_haproxy(load_config())
block = text[text.index("frontend fe_"):]
ok(block.index("http-request deny unless") < block.index("use_backend be_shop if acl_host-shop"),
   "requests are written before routes, whatever the order they were made in")

# ---- edited: moved to another listener, a condition dropped and cleaned up ---------------
cfg = load_config()
hp = cfg["haproxy"]
hp["frontends"].append({"id": "fe2", "name": "other-8080", "binds": "0.0.0.0:8080", "mode": "http",
                        "enabled": True, "rules": [], "certificates": []})
save_config(cfg)
r = post("wizard/rule", {"id": rule["id"], "listeners": ["fe2"],
                         "any_of": [{"id": rule["any_of"][0]}],
                         "all_of": [{"id": rule["conditions"][0]}],
                         "action": {"type": "http_request_deny", "test": "unless"}})
acts = ["%s %s" % (a["action"], a["name"]) for a in r["actions"]]
ok("updated deny-host-tv" in acts and "attached other-8080" in acts and "detached " + fe()["name"] in acts,
   "editing moves the rule between listeners: %s" % ", ".join(acts))
ok("removed host-films" in acts, "a condition the wizard made and nothing tests any more is removed")
names = {c["name"] for c in load_config()["haproxy"]["conditions"]}
ok("host-films" not in names and "host-tv" in names,
   "host-tv stays: another rule still tests it")
rule = rule_named("deny-host-tv")
ok(rule["id"] not in fe()["rules"] and rule["id"] in _by_id(load_config()["haproxy"]["frontends"])["fe2"]["rules"],
   "and the listeners' lists say so")
by_hand = post("haproxy/conditions", {"name": "by-hand", "type": "path_starts_with", "value": "/x"})
r = post("wizard/rule", {"id": rule["id"], "listeners": ["fe2"], "all_of": [{"id": by_hand["id"]}],
                         "action": {"type": "http_request_deny"}})
r = post("wizard/rule", {"id": rule["id"], "listeners": ["fe2"], "all_of": [{"type": "path_starts_with", "value": "/y"}],
                         "action": {"type": "http_request_deny"}})
ok(any(c["name"] == "by-hand" for c in load_config()["haproxy"]["conditions"]),
   "a condition made by hand is left alone when a rule stops testing it")
r = post("wizard/rule", {"id": rule["id"], "listeners": [], "action": {"type": "http_request_deny"}})
ok(any("attached to no Public Service" in w for w in r["warnings"]), "a rule on no listener is saved with a warning")

# ---- a rule from before 2.0, opened and saved by the wizard ---------------------------------
cfg = load_config()
old = next(x for x in cfg["haproxy"]["rules"] if x["name"].startswith("to-shop"))
old.update({"operator": "or", "any_of": [], "conditions": old["conditions"] + [by_hand["id"]]})
save_config(cfg)
r = post("wizard/rule", {"id": old["id"], "listeners": [fe()["id"]],
                         "any_of": [{"id": c} for c in old["conditions"]],
                         "action": {"type": "use_backend", "backend": pools["shop"]}})
old = next(x for x in load_config()["haproxy"]["rules"] if x["id"] == old["id"])
ok(old["operator"] == "and" and old["any_of"] and not old["conditions"], "it is stored in the two-list shape")

# ---- a rule a service holds for itself ---------------------------------------------------
deny = post("wizard/rule", {"listeners": [], "all_of": [{"type": "path_starts_with", "value": "/admin"},
                                                        {"type": "source_ip", "value": "203.0.113.0/24", "negate": True}],
                            "action": {"type": "http_request_deny"}})
route = post("wizard/rule", {"listeners": [], "any_of": [{"type": "host_matches", "value": "x.example.com"}],
                             "action": {"type": "use_backend", "backend": pools["shop"]}})
r = post("wizard/publish", {"url": "http://shop.example.com", "target": "10.0.0.5:80", "certificate": False,
                            "http_redirect": False, "dry_run": False,
                            "service_id": next(s for s in client.get("/api/services", headers=H).get_json() if s["pool"] == "shop")["id"],
                            "rules": [deny["rule"]["id"], route["rule"]["id"], "gone"]})
shop = next(b for b in load_config()["haproxy"]["backends"] if b["name"] == "shop")
ok(shop.get("rules") == [deny["rule"]["id"]], "the wizard stores the rules picked, less routing ones and ones that are gone")
text = haproxy.render_haproxy(load_config())
be = text[text.index("backend be_shop\n"):text.index("\n\n", text.index("backend be_shop\n"))]
ok("acl acl_path-admin path_beg /admin" in be and "acl acl_not-from-203.0.113.0 src 203.0.113.0/24" in be,
   "its conditions are declared inside the pool")
ok("http-request deny if acl_path-admin !acl_not-from-203.0.113.0" in be, "and the rule acts there, reaching this service alone")
other = text[text.index("backend be_admin\n"):].split("\n\n")[0]
ok("acl_path-admin" not in other, "not its neighbour")
ok("use_backend" not in be, "a routing rule would mean nothing in a pool and is not written")
svc = next(s for s in client.get("/api/services", headers=H).get_json() if s["pool"] == "shop")
ok(svc["rules"] == [deny["rule"]["id"]] and svc["rule_names"] == [deny["rule"]["name"]], "the Services API reports them by name")

# ---- what HAProxy refuses is refused, with its reason ---------------------------------------
if have_haproxy():
    r = post("wizard/rule", {"listeners": [fe()["id"]], "all_of": [{"type": "custom", "value": "this is not an acl"}],
                             "action": {"type": "http_request_deny"}}, want=400)
    ok("HAProxy would not load this rule" in r["error"] and r["validation"]["ok"] is False,
       "a raw ACL HAProxy rejects is refused before it is stored")
    ok(not any(c.get("value") == "this is not an acl" for c in load_config()["haproxy"]["conditions"]),
       "and the condition it would have made is not there")
    r = post("wizard/rule", {"listeners": [fe()["id"]], "all_of": [{"type": "custom", "value": "this is not an acl"}],
                             "action": {"type": "http_request_deny"}, "dry_run": True})
    ok(r["ok"] and r["validation"]["ok"] is False and "acl" in r["validation"]["message"].lower(),
       "a preview of the same says so without refusing: " + r["validation"]["message"].splitlines()[-1][:80])
else:
    print("  ....  no haproxy here; HAProxy's verdict is not checked")

print("\n" + ("%d failed" % len(fails) if fails else "on these, when this, then that -- and HAProxy agrees"))
sys.exit(1 if fails else 0)
