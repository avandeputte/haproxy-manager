#!/usr/bin/env python3
"""The configuration history: what is kept, what a diff says, what Restore does.

The property that matters most is the last one checked: a state adopted from a
peer is snapshotted too, because "a peer pushed over my configuration" is the
disaster the history exists to undo, and adopting deliberately does not move
the revision counter -- so counting revisions would miss it.

    HAM_DATA_DIR=/tmp/x python3 tools/test-history.py
"""
import json
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-hist-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham   # noqa: E402
from ham.config import (HISTORY_KEEP, _history_files, load_config, save_config,   # noqa: E402
                        shared_fingerprint)
from ham.history import diff_views   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


def snaps():
    return [json.loads(p.read_text()) for p in _history_files()]


ham.app.config["TESTING"] = True
client = ham.app.test_client()

cfg = load_config()
cfg["local"]["api_key"] = "test-key"
save_config(cfg)
client.environ_base["HTTP_X_API_KEY"] = "test-key"
base = len(snaps())
ok(base >= 1, "the first save leaves the first snapshot")

save_config(load_config())
save_config(load_config())
ok(len(snaps()) == base, "saving an unchanged configuration adds nothing")

cfg = load_config()
cfg["haproxy"]["backends"].append({"id": "b1", "name": "shop", "servers": [],
                                   "enabled": True})
save_config(cfg)
ok(len(snaps()) == base + 1, "a change adds one")

cfg = load_config()
cfg["local"]["admin"]["email"] = "a@b.c"
save_config(cfg)
ok(len(snaps()) == base + 1, "a node-local change does not")

cfg = load_config()
cfg["haproxy"]["backends"][0]["name"] = "store"
cfg["haproxy"]["settings"]["maxconn"] = 9999
save_config(cfg)

# -- the list ---------------------------------------------------------------
r = client.get("/api/history").get_json()
ok(r["ok"] and len(r["snapshots"]) == base + 2, "the list holds every state")
ok(r["snapshots"][0]["current"] is True, "and knows which one is current")
ok("haproxy.backends" in (r["snapshots"][0].get("summary") or ""),
   "each entry says what it changed: %s" % r["snapshots"][0].get("summary"))

# -- the diff ---------------------------------------------------------------
first = r["snapshots"][-1]["id"]
d = client.get("/api/history/%s/diff" % first).get_json()
parts = {p["part"]: p["objects"] for p in d["parts"]}
ok("haproxy.backends" in parts and parts["haproxy.backends"][0]["state"] == "added",
   "the diff against the beginning shows the pool as added since")
ok("haproxy.settings" in parts and any(o["name"] == "maxconn" for o in parts["haproxy.settings"]),
   "and the settings key that moved, by name")

d2 = diff_views({"haproxy": {"backends": [{"id": "x", "name": "old", "v": 1}]}},
                {"haproxy": {"backends": [{"id": "x", "name": "old", "v": 2}]}})
ok(d2 and d2[0]["objects"][0]["state"] == "changed",
   "an object present in both but different reads as changed")

# -- restore ----------------------------------------------------------------
rev_before = load_config()["_meta"]["shared_rev"]
r = client.post("/api/history/%s/restore" % first).get_json()
ok(r["ok"] and r["changed"], "an old state restores")
cfg = load_config()
ok(not cfg["haproxy"]["backends"], "and the pool added after it is gone")
ok(cfg["haproxy"]["settings"]["maxconn"] != 9999, "with the setting back too")
ok(cfg["_meta"]["shared_rev"] > rev_before,
   "restoring counts as a new change, so the cluster takes it as newest")
ok(cfg["local"]["admin"]["email"] == "a@b.c", "node-local settings are untouched")
ok(len(snaps()) == base + 3, "and the restored state is itself kept")

r = client.post("/api/history/%s/restore" % first).get_json()
ok(r["ok"] and not r["changed"], "restoring what is already current changes nothing")

missing = client.post("/api/history/nope.json/restore")
ok(missing.status_code == 404, "a snapshot that does not exist is a 404")

# -- adoption from a peer is remembered -------------------------------------
cfg = load_config()
cfg["haproxy"]["backends"] = [{"id": "b9", "name": "theirs", "servers": []}]
# what sync.py does when taking a peer's configuration: fp and rev are set to
# the sender's before saving, so the revision does not move
cfg["_meta"]["shared_fp"] = shared_fingerprint(cfg)
cfg["_meta"]["shared_rev"] = 99
before = len(snaps())
save_config(cfg)
ok(len(snaps()) == before + 1,
   "a configuration adopted from a peer is snapshotted despite not counting as a change")

# -- the cap ----------------------------------------------------------------
for i in range(HISTORY_KEEP + 10):
    cfg = load_config()
    cfg["haproxy"]["backends"].append({"id": "n%d" % i, "name": "b%d" % i, "servers": []})
    save_config(cfg)
files = _history_files()
ok(len(files) == HISTORY_KEEP, "the history is capped at %d states" % HISTORY_KEEP)
newest = json.loads(files[-1].read_text())
ok(any(o.get("id") == "n%d" % (HISTORY_KEEP + 9)
       for o in newest["view"]["haproxy"]["backends"]),
   "and it is the oldest that are dropped")

print("\n" + ("%d failed" % len(fails) if fails else "the history remembers and restores"))
sys.exit(1 if fails else 0)
