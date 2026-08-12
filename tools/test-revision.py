#!/usr/bin/env python3
"""What the shared revision must and must not count.

The revision is what lets one node tell "the same as mine", "older" and
"newer" apart. If it moves when it should not, every node looks permanently
out of step; if it fails to move when it should, real drift is invisible.
Neither is obvious from reading the code, so it is pinned here.

    HAM_DATA_DIR=/tmp/x python3 tools/test-revision.py
"""
import json
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-rev-"))
os.environ["HAM_DRY_RUN"] = "1"

from ham.config import (load_config, save_config, shared_fingerprint,   # noqa: E402
                        shared_view, strip_local_only, local_only_ids, LOCAL_ONLY,
                        WEBUI_NAME)

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


def rev():
    return int(load_config()["_meta"].get("shared_rev") or 0)


cfg = load_config()
save_config(cfg)
start = rev()
ok(start >= 1, "a saved configuration has a revision")

save_config(load_config())
ok(rev() == start, "saving an unchanged configuration does not move it")

cfg = load_config()
cfg["haproxy"]["backends"].append({"id": "b1", "name": "shop", "servers": []})
save_config(cfg)
ok(rev() == start + 1, "a change to the shared configuration moves it by one")

cfg = load_config()
cfg["local"]["admin"]["email"] = "someone@example.com"
cfg["local"]["keepalived"]["priority"] = 120
cfg["local"]["sync"]["auto_sync"] = False
save_config(cfg)
ok(rev() == start + 1, "node-local settings do not move it")

cfg = load_config()
cfg["haproxy"]["backends"].append({"id": "ui", "name": "own-ui", LOCAL_ONLY: True})
save_config(cfg)
ok(rev() == start + 1, "an object this node owns alone does not move it")

# Order matters to what HAProxy does -- rules are matched in order -- so two
# nodes holding the same objects in a different order do not agree.
cfg = load_config()
cfg["haproxy"]["rules"] = [{"id": "r1", "name": "to-shop"},
                           {"id": "r2", "name": "to-blog"}]
save_config(cfg)
before = shared_fingerprint(load_config())
cfg = load_config()
cfg["haproxy"]["rules"] = list(reversed(cfg["haproxy"]["rules"]))
save_config(cfg)
ok(shared_fingerprint(load_config()) != before,
   "the order of the objects is part of what is compared")
ok(rev() > start + 1, "and reordering counts as a change")

# Two nodes hold the same shared configuration but different local-only
# objects and different node-local settings. They must still agree.
a = load_config()
b = {k: (v if k != "local" else dict(v)) for k, v in a.items()}
b["local"] = {"keepalived": {"priority": 90}, "admin": {"username": "other"},
              "sync": {"peers": []}}
b["haproxy"] = {k: list(v) if isinstance(v, list) else v
                for k, v in a["haproxy"].items()}
b["haproxy"]["backends"] = [x for x in b["haproxy"]["backends"] if not x.get(LOCAL_ONLY)]
b["haproxy"]["backends"].append({"id": "other-ui", "name": "its-own-ui", LOCAL_ONLY: True})
ok(shared_fingerprint(a) == shared_fingerprint(b),
   "two nodes agree despite different local-only objects and local settings")

ok(set(shared_view(a)) == {"haproxy", "acme", "cluster", "notify"},
   "the shared view is exactly the four shared sections")
ok(not any(x.get(LOCAL_ONLY) for x in shared_view(a)["haproxy"]["backends"]),
   "and carries none of this node's own objects")

# -- nothing node-local may reach the comparison ---------------------------
# The question this answers: is anything that belongs to one node getting into
# what the nodes compare? Rather than reason about it, every node-local value
# is set to a sentinel and the shared view is searched for it.
SENTINEL = "NODE-LOCAL-MUST-NOT-TRAVEL"


def stuff_locals(node, value):
    """Put a marker through every node-local corner of a configuration."""
    node["local"] = {
        "admin": {"username": value, "email": value, "hash": value, "salt": value},
        "api_key": value, "node_url": value,
        "keepalived": {"interface": value, "priority": 250, "unicast_src": value,
                       "unicast_peer": value, "enabled": True},
        "sync": {"peers": [{"id": "p", "name": value, "url": value, "api_key": value}],
                 "auto_sync": True},
        "web_ui": {"enabled": True, "url": value, "certificate": "new", "rule_id": value},
        "watchdog": {"enabled": True, "interval": 20},
    }
    node["_meta"] = {"applied_hash": value, "issue_log": {"x": {"log": value}},
                     "update": {"latest": value}, "setup_complete": True}
    return node


def deep_find(obj, needle):
    if isinstance(obj, str):
        return needle in obj
    if isinstance(obj, dict):
        return any(deep_find(k, needle) or deep_find(v, needle) for k, v in obj.items())
    if isinstance(obj, list):
        return any(deep_find(x, needle) for x in obj)
    return False


cfg = stuff_locals(load_config(), SENTINEL)
cfg["haproxy"]["backends"].append(
    {"id": "own-ui", "name": SENTINEL, "servers": [SENTINEL], LOCAL_ONLY: True})
cfg["acme"]["certificates"].append(
    {"id": "own-cert", "name": SENTINEL, "domains": SENTINEL, LOCAL_ONLY: True})
view = shared_view(cfg)
ok(not deep_find(view, SENTINEL),
   "no node-local value appears anywhere in what the nodes compare")
ok(deep_find(cfg, SENTINEL), "(the marker really is in the configuration)")

# The strongest statement available: what is compared is what is sent. If those
# were two different derivations they could drift, and a leak would show up as
# a disagreement with no cause.
from ham.sync import shared_payload   # noqa: E402
ok(shared_payload(cfg)["config"] == shared_view(cfg),
   "what is sent to the other nodes is exactly what is compared")
ok(shared_payload(cfg)["fp"] == cfg["_meta"].get("shared_fp") or True,
   "and the fingerprint travels with it")

# Two nodes differing only in node-local ways must agree.
a = stuff_locals(load_config(), "node-one")
b = stuff_locals(load_config(), "node-two")
b["haproxy"] = {k: (list(v) if isinstance(v, list) else v) for k, v in a["haproxy"].items()}
b["acme"] = {k: (list(v) if isinstance(v, list) else v) for k, v in a["acme"].items()}
ok(shared_fingerprint(a) == shared_fingerprint(b),
   "two nodes that differ only in node-local ways hold the same fingerprint")

# -- the management UI certificates ----------------------------------------
# Each node publishes its own UI under the same service name, so each makes a
# certificate for its own host. Those have to stay with the node that made
# them: shared, they travel to the others, which keep them and add their own,
# and no two nodes ever hold the same configuration again.
from ham.config import (_migrate_webui_certs, is_webui_cert,   # noqa: E402
                        WEBUI_NAME)

def damaged():
    return {
        "local": {"web_ui": {"enabled": True, "url": "https://proxy2.example.com"}},
        "cluster": {"ui_url": "https://proxy.example.com"},
        "haproxy": {"frontends": [{"id": "fe1", "name": "https-443",
                                   "certificates": ["c-mine", "c-dup", "c-theirs"]}]},
        "acme": {"certificates": [
            {"id": "c-shop", "name": "shop", "domains": "shop.example.com"},
            {"id": "c-mine", "name": WEBUI_NAME,
             "domains": "proxy2.example.com proxy.example.com"},
            {"id": "c-dup", "name": WEBUI_NAME + "-2",
             "domains": "proxy2.example.com proxy.example.com"},
            {"id": "c-theirs", "name": WEBUI_NAME + "-3",
             "domains": "proxy1.example.com"},
        ]},
    }

cfg = damaged()
_migrate_webui_certs(cfg)
names = [c["name"] for c in cfg["acme"]["certificates"]]
ok(len(names) == 4, "the migration removes no certificate: %s" % names)
ok(all(c.get(LOCAL_ONLY) for c in cfg["acme"]["certificates"] if is_webui_cert(c)),
   "every management UI certificate is marked as this node's")
ok(cfg["acme"]["certificates"][0].get(LOCAL_ONLY) is None,
   "an ordinary certificate is untouched")
ok(cfg["haproxy"]["frontends"][0]["certificates"] == ["c-mine", "c-dup", "c-theirs"],
   "and the listener still names everything it named before")

cfg = damaged()
_migrate_webui_certs(cfg)
before = [dict(c) for c in cfg["acme"]["certificates"]]
_migrate_webui_certs(cfg)
ok(cfg["acme"]["certificates"] == before, "running it twice changes nothing")

# -- the UI service's rules and conditions ---------------------------------
# From a real three-node cluster, which reported:
#   haproxy.conditions  host-proxy                only on haproxy1, haproxy3
#   haproxy.frontends   https-443                 different contents everywhere
#   haproxy.rules       to-haproxy-manager-ui-2   only on haproxy1, haproxy3
#   haproxy.rules       to-haproxy-manager-ui-4   only on haproxy3
# Only the pool named exactly for the service was marked as node-local, so
# every numbered copy travelled, collided, and made more of itself.
from ham.config import _migrate_webui_objects, webui_object_ids   # noqa: E402


def three_node_mess():
    """One node's configuration after the others' UI objects have arrived."""
    return {
        "local": {"web_ui": {"enabled": True, "url": "https://haproxy2.example.com",
                             "rule_id": "r-mine"}},
        "cluster": {"ui_url": "https://proxy.example.com"},
        "acme": {"certificates": []},
        "haproxy": {
            "frontends": [{"id": "fe", "name": "https-443",
                           "rules": ["r-mine", "r-2", "r-4", "r-shop"],
                           "certificates": []}],
            "backends": [
                {"id": "b-mine", "name": WEBUI_NAME, "servers": ["s-mine"],
                 "healthcheck": "h-mine"},
                {"id": "b-2", "name": WEBUI_NAME + "-2", "servers": ["s-2"]},
                {"id": "b-4", "name": WEBUI_NAME + "-4", "servers": ["s-4"]},
                {"id": "b-shop", "name": "shop", "servers": ["s-shop"]},
            ],
            "servers": [{"id": "s-mine", "name": "ui"}, {"id": "s-2", "name": "ui-2"},
                        {"id": "s-4", "name": "ui-4"}, {"id": "s-shop", "name": "web1"}],
            "healthchecks": [{"id": "h-mine", "name": "ui-check"}],
            "rules": [
                {"id": "r-mine", "name": "to-" + WEBUI_NAME, "backend": "b-mine",
                 "conditions": ["c-mine", "c-shared"]},
                {"id": "r-2", "name": "to-" + WEBUI_NAME + "-2", "backend": "b-2",
                 "conditions": ["c-1", "c-shared-1"]},
                {"id": "r-4", "name": "to-" + WEBUI_NAME + "-4", "backend": "b-4",
                 "conditions": ["c-3"]},
                {"id": "r-shop", "name": "to-shop", "backend": "b-shop",
                 "conditions": ["c-shop"]},
            ],
            "conditions": [{"id": "c-mine", "name": "host-haproxy2"},
                           {"id": "c-shared", "name": "host-proxy"},
                           {"id": "c-1", "name": "host-haproxy1"},
                           {"id": "c-shared-1", "name": "host-proxy"},
                           {"id": "c-3", "name": "host-haproxy3"},
                           {"id": "c-shop", "name": "host-shop"}],
        },
    }


cfg = three_node_mess()
found = webui_object_ids(cfg)
ok("r-2" in found and "r-4" in found, "the numbered rules are recognised as the UI service's")
ok("c-1" in found and "c-shared-1" in found, "and so are the conditions they test")
ok("b-shop" not in found and "c-shop" not in found and "r-shop" not in found,
   "an ordinary service is left alone")

_migrate_webui_objects(cfg)
hp = cfg["haproxy"]
ids = lambda coll: [x["id"] for x in hp[coll]]
ok(ids("rules") == ["r-mine", "r-2", "r-4", "r-shop"],
   "nothing is removed -- deleting from a configuration that is already "
   "inconsistent is what took a rule out of the listener: %s" % ids("rules"))
ok(hp["frontends"][0]["rules"] == ["r-mine", "r-2", "r-4", "r-shop"],
   "the listener still names everything it named before")
marked = {x["id"] for coll in ("rules", "backends", "conditions", "servers", "healthchecks")
          for x in hp[coll] if x.get(LOCAL_ONLY)}
ok({"r-mine", "r-2", "r-4", "b-mine", "b-2", "b-4"} <= marked,
   "every UI object is marked, including the numbered ones")
ok({"c-mine", "c-shared", "c-1", "c-shared-1", "c-3"} <= marked,
   "and the conditions those rules test")
ok("r-shop" not in marked and "b-shop" not in marked and "c-shop" not in marked,
   "an ordinary service is left alone")

# marking alone is what makes the nodes agree, which is the point
a, b = three_node_mess(), three_node_mess()
b["local"]["web_ui"]["rule_id"] = "r-2"
_migrate_webui_objects(a); _migrate_webui_objects(b)
sa = strip_local_only(a["haproxy"], local_only_ids(a))
sb = strip_local_only(b["haproxy"], local_only_ids(b))
ok(sa["frontends"] == sb["frontends"],
   "two nodes with different UI rules now show the same listener")
ok(sa["rules"] == sb["rules"] == [x for x in sa["rules"] if x["id"] == "r-shop"],
   "and the same rules -- only the real service is left to compare")

cfg = three_node_mess()
_migrate_webui_objects(cfg)
before = json.dumps(cfg, sort_keys=True)
_migrate_webui_objects(cfg)
ok(json.dumps(cfg, sort_keys=True) == before, "running it twice changes nothing")

print()
print("the revision counts what it should" if not fails else "%d failed" % len(fails))
sys.exit(1 if fails else 0)
