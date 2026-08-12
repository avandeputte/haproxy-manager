#!/usr/bin/env python3
"""What the shared revision must and must not count.

The revision is what lets one node tell "the same as mine", "older" and
"newer" apart. If it moves when it should not, every node looks permanently
out of step; if it fails to move when it should, real drift is invisible.
Neither is obvious from reading the code, so it is pinned here.

    HAM_DATA_DIR=/tmp/x python3 tools/test-revision.py
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-rev-"))
os.environ["HAM_DRY_RUN"] = "1"

from ham.config import (load_config, save_config, shared_fingerprint,   # noqa: E402
                        shared_view, LOCAL_ONLY)

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

print()
print("the revision counts what it should" if not fails else "%d failed" % len(fails))
sys.exit(1 if fails else 0)
