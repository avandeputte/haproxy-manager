#!/usr/bin/env python3
"""An upgrade that adds a collection is not an unapplied change.

    HAM_DATA_DIR=/tmp/x python3 tools/test-upgrade.py

The dirty flag compares a hash of the configuration with the one the last
Apply stored. 2.0 adds two empty collections to every configuration on load,
so a node upgraded from 1.100 came up saying "unapplied changes" with nothing
to apply. The marker is now carried over when the stored file lacks nothing
but defaults -- and left alone when something really did change.
"""
import hashlib
import json
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-upgrade-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham.base import CONF_PATH   # noqa: E402
from ham.config import config_hash, load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


def old_hash(stored):
    """config_hash as 1.100 computed it, over the file as 1.100 wrote it."""
    payload = json.dumps({"haproxy": stored["haproxy"], "acme": stored["acme"],
                          "cluster": stored["cluster"],
                          "keepalived": stored["local"]["keepalived"]}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


# A file as 1.100.2 left it: every section, no addresslists, no errorpages,
# and the marker of its last Apply.
cfg = load_config()
cfg["local"]["api_key"] = "up-key"
cfg["haproxy"]["servers"] = [{"id": "s1", "name": "web1", "address": "10.0.0.5", "port": 80, "enabled": True}]
save_config(cfg)
stored = json.loads(CONF_PATH.read_text())
for key in ("addresslists", "errorpages"):
    stored["haproxy"].pop(key)
stored["_meta"]["applied_hash"] = old_hash(stored)
CONF_PATH.write_text(json.dumps(stored))

cfg = load_config()
ok("addresslists" in cfg["haproxy"] and "errorpages" in cfg["haproxy"], "loading adds the new collections")
ok(cfg["_meta"]["applied_hash"] == config_hash(cfg), "and the applied marker covers them: not dirty")
ham.app.config["TESTING"] = True
client = ham.app.test_client()
st = client.get("/api/status?brief=1", headers={"X-API-Key": "up-key"}).get_json()
ok(st["dirty"] is False, "which is what the status says")

# The same file, but with a change made since the last Apply.
stored["haproxy"]["servers"][0]["port"] = 8080
CONF_PATH.write_text(json.dumps(stored))
cfg = load_config()
ok(cfg["_meta"]["applied_hash"] != config_hash(cfg), "a real change since the last Apply still reads dirty")
st = client.get("/api/status?brief=1", headers={"X-API-Key": "up-key"}).get_json()
ok(st["dirty"] is True, "and the status says so")

# Saved once, the carried-over marker is in the file.
stored["haproxy"]["servers"][0]["port"] = 80
CONF_PATH.write_text(json.dumps(stored))
save_config(load_config())
again = json.loads(CONF_PATH.read_text())
ok("addresslists" in again["haproxy"] and again["_meta"]["applied_hash"] == config_hash(load_config()),
   "after the next save the file holds the collections and the marker that covers them")

print("\n" + ("%d failed" % len(fails) if fails else "an upgrade is not a change"))
sys.exit(1 if fails else 0)
