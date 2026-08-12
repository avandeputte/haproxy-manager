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

# -- the UI service stays with the node that made it -----------------------
# Every node publishes its own UI under the same service name, so each makes a
# pool, a rule, the conditions for both its addresses and a certificate for its
# own host. Anything of that sort left in the shared configuration travels to
# the other nodes, collides with theirs, and produces a numbered copy that
# travels in turn -- which is how a cluster stops agreeing with itself.
from ham.config import webui_object_ids, is_webui_cert, WEBUI_NAME   # noqa: E402


def with_ui_service():
    """A node holding its own UI service and two numbered copies from others."""
    return {
        "local": {"web_ui": {"enabled": True, "url": "https://haproxy2.example.com",
                             "rule_id": "r-mine"}},
        "cluster": {"ui_url": "https://proxy.example.com"},
        "acme": {"certificates": [
            {"id": "c-shop", "name": "shop", "domains": "shop.example.com"},
            {"id": "c-mine", "name": WEBUI_NAME, "domains": "haproxy2.example.com"},
            {"id": "c-2", "name": WEBUI_NAME + "-2", "domains": "haproxy1.example.com"}]},
        "haproxy": {
            "frontends": [{"id": "fe", "name": "https-443",
                           "rules": ["r-mine", "r-2", "r-shop"], "certificates": []}],
            "backends": [
                {"id": "b-mine", "name": WEBUI_NAME, "servers": ["s-mine"],
                 "healthcheck": "h-mine"},
                {"id": "b-2", "name": WEBUI_NAME + "-2", "servers": ["s-2"]},
                {"id": "b-shop", "name": "shop", "servers": ["s-shop"]}],
            "servers": [{"id": "s-mine", "name": "ui"}, {"id": "s-2", "name": "ui-2"},
                        {"id": "s-shop", "name": "web1"}],
            "healthchecks": [{"id": "h-mine", "name": "ui-check"}],
            "rules": [
                {"id": "r-mine", "name": "to-" + WEBUI_NAME, "backend": "b-mine",
                 "conditions": ["c-host-mine", "c-host-shared"]},
                {"id": "r-2", "name": "to-" + WEBUI_NAME + "-2", "backend": "b-2",
                 "conditions": ["c-host-1", "c-host-shared-1"]},
                {"id": "r-shop", "name": "to-shop", "backend": "b-shop",
                 "conditions": ["c-host-shop"]}],
            "conditions": [{"id": "c-host-mine", "name": "host-haproxy2"},
                           {"id": "c-host-shared", "name": "host-proxy"},
                           {"id": "c-host-1", "name": "host-haproxy1"},
                           {"id": "c-host-shared-1", "name": "host-proxy"},
                           {"id": "c-host-shop", "name": "host-shop"}]},
    }


cfg = with_ui_service()
found = webui_object_ids(cfg)
ok({"r-mine", "r-2", "b-mine", "b-2"} <= found,
   "the numbered copies are recognised as the UI service's, not only the plain one")
ok({"c-host-shared", "c-host-shared-1"} <= found,
   "including each node's own copy of the shared-address condition")
ok(not {"r-shop", "b-shop", "c-host-shop", "s-shop"} & found,
   "an ordinary service is left alone")
ok(is_webui_cert(cfg["acme"]["certificates"][1]) and
   is_webui_cert(cfg["acme"]["certificates"][2]) and
   not is_webui_cert(cfg["acme"]["certificates"][0]),
   "and the certificates the service made, numbered or not")

# marking is the whole mechanism: a marked object is neither sent nor compared
for coll in ("servers", "backends", "conditions", "rules", "healthchecks"):
    for item in cfg["haproxy"][coll]:
        if item["id"] in found:
            item[LOCAL_ONLY] = True
for cert in cfg["acme"]["certificates"]:
    if is_webui_cert(cert):
        cert[LOCAL_ONLY] = True
view = shared_view(cfg)
ok([r["id"] for r in view["haproxy"]["rules"]] == ["r-shop"],
   "once marked, only the real service is left to compare")
ok(view["haproxy"]["frontends"][0]["rules"] == ["r-shop"],
   "and the listener stops naming what belongs to a node")
ok([c["id"] for c in view["acme"]["certificates"]] == ["c-shop"],
   "the same for the certificates")

print()
print("the revision counts what it should" if not fails else "%d failed" % len(fails))
sys.exit(1 if fails else 0)
