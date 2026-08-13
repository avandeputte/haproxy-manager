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

import ham   # noqa: E402
from ham import wizard   # noqa: E402
from ham.config import (load_config, save_config, shared_fingerprint,   # noqa: E402
                        shared_view, WEBUI_NAME)

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
cfg["local"]["haproxy"]["backends"].append({"id": "ui", "name": "own-ui"})
save_config(cfg)
ok(rev() == start + 1, "an object this node owns does not move it")

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

ok(set(shared_view(load_config())) == {"haproxy", "acme", "access", "cluster", "notify"},
   "the shared view is exactly the five shared sections")
ok("own-ui" not in [x.get("name") for x in shared_view(load_config())["haproxy"]["backends"]],
   "and carries none of this node's own objects")

# -- nothing of this node's may reach the comparison -----------------------
# Node-local settings were always excluded by section. What kept going wrong
# was node-local *objects* sitting in the shared collections, kept out by a
# flag that four different code paths had to honour. They live in their own
# container now, so there is nothing to honour and nothing to forget.
SENTINEL = "NODE-LOCAL-MUST-NOT-TRAVEL"


def stuff_locals(node, value):
    node["local"].update({
        "admin": {"username": value, "email": value, "hash": value, "salt": value},
        "api_key": value, "node_url": value,
        "keepalived": {"interface": value, "priority": 250, "unicast_src": value},
        "sync": {"peers": [{"id": "p", "name": value, "url": value, "api_key": value}],
                 "auto_sync": True},
        "web_ui": {"enabled": True, "url": value, "certificate": "new", "rule_id": value},
    })
    node["_meta"] = {"applied_hash": value, "issue_log": {"x": {"log": value}}}
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
cfg["local"]["haproxy"]["backends"].append(
    {"id": "own-ui", "name": SENTINEL, "servers": [SENTINEL]})
cfg["local"]["acme"]["certificates"].append(
    {"id": "own-cert", "name": SENTINEL, "domains": SENTINEL})
ok(not deep_find(shared_view(cfg), SENTINEL),
   "no node-local value appears anywhere in what the nodes compare")
ok(deep_find(cfg, SENTINEL), "(the marker really is in the configuration)")

from ham.sync import shared_payload   # noqa: E402
ok(shared_payload(cfg)["config"] == shared_view(cfg),
   "what is sent to the other nodes is exactly what is compared")

a = stuff_locals(load_config(), "node-one")
b = stuff_locals(load_config(), "node-two")
ok(shared_fingerprint(a) == shared_fingerprint(b),
   "two nodes that differ only in node-local ways hold the same fingerprint")

# -- the container, not the flag -------------------------------------------
from ham.config import merged, move_to_local   # noqa: E402


def with_ui_service():
    cfg = load_config()
    cfg["local"]["haproxy"] = {"servers": [], "backends": [], "healthchecks": [],
                               "conditions": [], "rules": []}
    cfg["local"]["acme"] = {"certificates": []}
    cfg["local"]["attach"] = {}
    cfg["haproxy"] = {
        "settings": {}, "frontends": [{"id": "fe", "name": "https-443",
                                       "rules": ["r-ui", "r-shop"], "certificates": ["c-ui"]}],
        "backends": [{"id": "b-ui", "name": "ui", "servers": ["s-ui"], "healthcheck": "h-ui"},
                     {"id": "b-shop", "name": "shop", "servers": ["s-shop"]}],
        "servers": [{"id": "s-ui", "name": "ui-srv"}, {"id": "s-shop", "name": "web1"}],
        "healthchecks": [{"id": "h-ui", "name": "ui-check"}],
        "rules": [{"id": "r-ui", "name": "to-ui", "backend": "b-ui",
                   "conditions": ["c-mine", "c-shared"]},
                  {"id": "r-shop", "name": "to-shop", "backend": "b-shop",
                   "conditions": ["c-shop"]}],
        "conditions": [{"id": "c-mine", "name": "host-proxy1"},
                       {"id": "c-shared", "name": "host-proxy"},
                       {"id": "c-shop", "name": "host-shop"}]}
    cfg["acme"]["certificates"] = [{"id": "c-ui", "name": "haproxy-manager-ui"},
                                   {"id": "c-wild", "name": "wildcard"}]
    return cfg


cfg = with_ui_service()
moved = move_to_local(cfg, {"b-ui", "s-ui", "h-ui", "r-ui", "c-mine", "c-shared", "c-ui"})
ok(moved == 7, "the service's objects move into this node's own container (%d)" % moved)
ok([b["id"] for b in cfg["haproxy"]["backends"]] == ["b-shop"],
   "and are gone from the shared collections")
ok([b["id"] for b in cfg["local"]["haproxy"]["backends"]] == ["b-ui"],
   "and present in this node's")
ok(cfg["haproxy"]["frontends"][0]["rules"] == ["r-shop"],
   "the shared listener no longer names an id the other nodes do not have")
ok(cfg["local"]["attach"]["https-443"]["rules"] == ["r-ui"],
   "the attachment records it by the listener's name instead")
ok(cfg["local"]["attach"]["https-443"]["certificates"] == ["c-ui"],
   "including the certificate")
ok(not deep_find(shared_view(cfg), "r-ui"), "nothing of it is left in what is shared")

back = merged(cfg)
ok(sorted(b["id"] for b in back["haproxy"]["backends"]) == ["b-shop", "b-ui"],
   "merging puts this node's objects back for rendering")
ok(back["haproxy"]["frontends"][0]["rules"] == ["r-ui", "r-shop"],
   "and re-attaches them where they were, not at the end: %s"
   % back["haproxy"]["frontends"][0]["rules"])
ok(back["haproxy"]["frontends"][0]["certificates"] == ["c-ui"],
   "and the certificate")
ok(sorted(c["id"] for c in back["acme"]["certificates"]) == ["c-ui", "c-wild"],
   "a certificate that was never the service's stays shared")

# receiving is a straight replacement now: nothing has to be rescued
cfg = with_ui_service()
move_to_local(cfg, {"b-ui", "s-ui", "h-ui", "r-ui", "c-mine", "c-shared", "c-ui"})
mine_before = json.dumps(cfg["local"], sort_keys=True)
cfg["haproxy"] = {"settings": {}, "frontends": [{"id": "fe", "name": "https-443",
                                                 "rules": [], "certificates": []}],
                  "backends": [], "servers": [], "healthchecks": [], "rules": [],
                  "conditions": []}
ok(json.dumps(cfg["local"], sort_keys=True) == mine_before,
   "replacing the shared sections cannot touch what this node owns")
ok(merged(cfg)["haproxy"]["frontends"][0]["rules"] == ["r-ui"],
   "and its service is still attached to the listener afterwards")

# position matters: HAProxy takes the first matching use_backend, and serves
# the first certificate to a client that sends no SNI
cfg = with_ui_service()
cfg["haproxy"]["frontends"][0]["rules"] = ["r-shop", "r-ui"]
move_to_local(cfg, {"b-ui", "s-ui", "h-ui", "r-ui", "c-mine", "c-shared", "c-ui"})
ok(merged(cfg)["haproxy"]["frontends"][0]["rules"] == ["r-shop", "r-ui"],
   "a rule that was second comes back second")
ok(merged(cfg)["haproxy"]["frontends"][0]["certificates"] == ["c-ui"],
   "and the certificate that was first is still first")

# -- two machines using one address ----------------------------------------
# Invisible from every layer above the network: the address is configured
# here, the socket is listening here, and a client reaches whichever machine
# won the last ARP exchange. It cost two days of looking at the proxy.
from ham import watchdog   # noqa: E402

_calls = []


def _fake_run(cmd, **kw):
    _calls.append(cmd)
    if cmd[0] == "arping" and cmd[-1] == "192.168.1.87":
        return 1, "Unicast reply from 192.168.1.87 [AA:BB:CC:DD:EE:FF]"
    return 0, ""


watchdog.run = _fake_run
watchdog.shutil.which = lambda n: "/usr/sbin/arping" if n == "arping" else None
ham.apply.node_interfaces = lambda: [
    {"name": "lo", "up": True, "addresses": ["127.0.0.1/8"]},
    {"name": "eth0", "up": True,
     "addresses": ["192.168.1.87/24", "192.168.1.89/24", "fe80::1/64"]},
    {"name": "eth1", "up": False, "addresses": ["10.0.0.1/24"]}]
found = watchdog.probe_duplicate_addresses()
ok([f["address"] for f in found] == ["192.168.1.87"],
   "the address another machine answers for is reported")
ok(found[0]["interface"] == "eth0" and "AA:BB:CC" in found[0]["detail"],
   "with the interface and what the other machine said")
asked = sorted(c[-1] for c in _calls if c[0] == "arping")
ok(asked == ["192.168.1.87", "192.168.1.89"],
   "every address the node holds is asked about, and nothing else: %s" % asked)
ok(all("-D" in c for c in _calls if c[0] == "arping"),
   "asked without claiming it, so a reply can only come from somebody else")
watchdog.shutil.which = lambda n: None
ok(watchdog.probe_duplicate_addresses() == [],
   "with arping missing it reports nothing rather than an all-clear")

print()
print("the revision counts what it should" if not fails else "%d failed" % len(fails))
sys.exit(1 if fails else 0)
