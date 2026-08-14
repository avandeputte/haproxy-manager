#!/usr/bin/env python3
"""The per-object haproxy.cfg preview behind the editor's second tab.

    HAM_DATA_DIR=/tmp/x python3 tools/test-preview.py
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-prev-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "preview-key"
cfg["haproxy"]["servers"] = [{"id": "s1", "name": "web1", "address": "10.0.0.5",
                              "port": 80, "enabled": True}]
cfg["haproxy"]["backends"] = [{"id": "b1", "name": "shop", "mode": "http",
                               "servers": ["s1"], "enabled": True}]
save_config(cfg)
H = {"X-API-Key": "preview-key"}


def prev(col, item):
    return client.post("/api/haproxy/preview-object", json={"col": col, "item": item},
                       headers=H).get_json()


r = prev("backends", {"id": "b1", "name": "shop", "mode": "http", "servers": ["s1"],
                      "balance": "leastconn"})
ok(r["ok"] and "backend be_shop" in r["text"], "a pool previews as its backend block")
ok("balance leastconn" in r["text"],
   "with the values as typed, not as saved -- the whole point of the tab")
ok("leastconn" not in
   __import__("ham.haproxy", fromlist=["render_haproxy"]).render_haproxy(load_config()),
   "and nothing was saved by looking")

r = prev("servers", {"id": "s1", "name": "web1", "address": "10.0.0.9", "port": 8080,
                     "enabled": True})
ok("10.0.0.9:8080" in r["text"] and "backend be_shop" in r["text"],
   "a server previews inside the pools that use it")

r = prev("frontends", {"name": "brand-new", "mode": "http", "binds": "0.0.0.0:8088",
                       "enabled": True, "rules": []})
ok("frontend fe_brand-new" in r["text"] and "bind 0.0.0.0:8088" in r["text"],
   "an object that does not exist yet previews as what it would create")

r = prev("conditions", {"name": "lonely", "type": "host_matches", "value": "x.example.com"})
ok(r["ok"] and not r["text"] and "renders nothing on its own" in r["note"],
   "an unused condition says it renders nothing, rather than showing the wrong block")

r = client.post("/api/haproxy/preview-object", json={"col": "nope", "item": {}}, headers=H)
ok(r.status_code == 404, "an unknown collection is a 404")

print("\n" + ("%d failed" % len(fails) if fails else "the editor's cfg tab shows the truth"))
sys.exit(1 if fails else 0)
