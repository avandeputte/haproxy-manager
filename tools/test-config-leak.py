#!/usr/bin/env python3
"""The "took a configuration and then did not match it" warning (issue #44).

It is meant for one thing: something belonging to one node sitting inside the
shared configuration. It was also raised by an ordinary rolling upgrade -- a
node took the configuration from a peer on another version, which has fewer
settings, filled in its own defaults and so came out different -- and once
raised it never went away, because only a later receive cleared it and the
node holding the virtual IP is the one that pushes, not the one that receives.

    python3 tools/test-config-leak.py
"""
import copy
import json
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
_tmp = tempfile.mkdtemp(prefix="ham-leak-")
os.environ.setdefault("HAM_DATA_DIR", _tmp)
os.environ.setdefault("HAM_CERT_DIR", os.path.join(_tmp, "certs"))
os.environ.setdefault("HAM_HAPROXY_CFG", os.path.join(_tmp, "haproxy.cfg"))
os.environ.setdefault("HAM_KEEPALIVED_CFG", os.path.join(_tmp, "keepalived.conf"))
os.environ["HAM_DRY_RUN"] = "1"

import ham   # noqa: E402
from ham import cluster, peering, sync   # noqa: E402
from ham.base import CONF_PATH, VERSION, _requests   # noqa: E402
from ham.config import _fp, load_config, save_config, shared_fingerprint, shared_view   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "recv-key"
save_config(cfg)
client.environ_base["HTTP_X_API_KEY"] = "recv-key"
rev = [int(load_config()["_meta"].get("shared_rev") or 0)]


def push(view, fp, version=None):
    rev[0] += 1
    body = {"rev": rev[0], "fp": fp, "config": view, "source": "hostB"}
    if version:
        body["version"] = version
    r = client.post("/api/sync/receive", json=body)
    return load_config()["_meta"].get("config_leak")


def status_leak():
    return client.get("/api/status").get_json().get("config_leak")


# A peer on an older version: its cluster section lacks a setting this
# version has, and its fingerprint is over what it holds.
old = copy.deepcopy(shared_view(load_config()))
old["cluster"].pop("beta_updates", None)
old["cloudflare"] = {}
print("a peer on an older version")
ok(push(old, _fp(old)) is None,
   "taking its configuration is not reported as a leak: the difference is the version's, not a node's")
ok(push(old, _fp(old), version="2.4.0") is None,
   "nor when it says which version it runs")

print("a peer on the same version")
same = copy.deepcopy(shared_view(load_config()))
ok(push(same, _fp(same), version=VERSION) is None, "a configuration that matches is quiet")
bad = copy.deepcopy(same)
bad["haproxy"]["settings"]["maxconn"] = 1234
leak = push(bad, "0123456789abcdef", version=VERSION)
ok(bool(leak) and leak.get("theirs") == "0123456789abcdef",
   "a real mismatch between nodes on the same version is still reported")
ok(status_leak(), "and shown")

print("an old warning does not stay forever")
cfg = load_config()
cfg["haproxy"]["settings"]["maxconn"] = 4321
save_config(cfg)
ok(load_config()["_meta"].get("config_leak") is None,
   "a change made here, which every peer then takes from this node, clears it")
cfg = load_config()
cfg["_meta"]["config_leak"] = {"at": "2026-11-20T00:00:00+00:00", "source": "hostB",
                               "mine": "88f1f51987dc6f56", "theirs": "cbdbe1af6272edf1"}
save_config(cfg)
ok(status_leak() is None,
   "one recorded by a version before this one is not shown: it may be that version's mistake")

print("what a node sends")
cfg = load_config()
cfg["_meta"]["shared_fp"] = "stale-from-before"
payload = sync.shared_payload(cfg)
ok(payload["fp"] == shared_fingerprint(cfg) and payload.get("version") == VERSION,
   "the fingerprint is of what is sent, and the version is sent with it")

print("what a node reports")
# A release that adds a shared setting changes the fingerprint of what a node
# holds without anything being saved, so the stored one is stale until the
# next save -- and the status reported it while a push carried the live one.
stored = json.loads(CONF_PATH.read_text())
stored["_meta"]["shared_fp"] = "stale-from-before"
CONF_PATH.write_text(json.dumps(stored))
st = client.get("/api/status?brief=1").get_json()
ok(st["config_fp"] == shared_fingerprint(load_config()) and st["config_fp"] != "stale-from-before",
   "the status reports the fingerprint of what the node holds now, as a push does")

print("what the cluster page concludes")
if _requests is None:
    print("  skip  python3-requests is not installed here")
else:
    cfg = load_config()
    cfg["local"]["sync"]["peers"] = [{"id": "p1", "name": "node-b", "url": "http://b.example",
                                      "api_key": "kb", "enabled": True}]
    save_config(cfg)
    mine = int(load_config()["_meta"]["shared_rev"])
    peer_says = {}
    real_query = peering._query_peer
    peering._query_peer = lambda p, timeout=None, brief=False: dict(
        {"id": p["id"], "name": p["name"], "url": p["url"], "self": False, "reachable": True,
         "error": "", "ms": 1, "hostname": "node-b", "role": "passive", "haproxy": "active",
         "keepalived": "disabled", "vips": [], "vip_held": [], "dirty": False, "config_rev": mine,
         "config_fp": "0000000000000000", "config_parts": {}, "config_objects": {}, "brief": brief,
         "config_objects_capped": False, "config_leak": None, "update_available": False,
         "certs_total": 0, "certs_bad": 0}, **peer_says)
    peer_says["version"] = "0.0.1"
    s = cluster.cluster_snapshot(load_config())["summary"]
    ok(s["config_agreed"] and not any("independently" in w for w in s["warnings"]),
       "a peer on another version at the same revision with another fingerprint is not "
       "'changed independently': it is mid-upgrade")
    ok(any("different versions" in w for w in s["warnings"]), "the versions are what is reported")
    peer_says["version"] = VERSION
    s = cluster.cluster_snapshot(load_config())["summary"]
    ok(not s["config_agreed"] and any("independently" in w for w in s["warnings"]),
       "on the same version the same disagreement is reported")
    peering._query_peer = real_query

print("\n" + ("%d failed" % len(fails) if fails
              else "a leak is a leak, and an upgrade is not one"))
sys.exit(1 if fails else 0)
