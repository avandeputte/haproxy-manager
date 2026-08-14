#!/usr/bin/env python3
"""The /metrics endpoint: guarded, well-formed, and telling the truth.

    HAM_DATA_DIR=/tmp/x python3 tools/test-metrics.py
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-metrics-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import probe, stats   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "metrics-key-123"
save_config(cfg)

r = client.get("/metrics")
ok(r.status_code == 401, "no key, no metrics -- the names in here are nobody's business")
r = client.get("/metrics", headers={"X-API-Key": "wrong"})
ok(r.status_code == 401, "and a wrong key is a wrong key")

stats.haproxy_stats = lambda: {"ok": True, "backends": [
    {"proxy": "be_shop", "servers_up": 2, "servers_total": 3, "stot": "12345",
     "hrsp_5xx": "7", "hrsp_4xx": "0", "scur": "4", "servers": []}], "frontends": []}
probe._state["results"] = [
    {"url": "https://shop.example.com", "state": "ok", "ms": 42},
    {"url": "https://media.example.com", "state": "down", "ms": 5000},
]
probe._state["at"] = 1

r = client.get("/metrics", headers={"X-API-Key": "metrics-key-123"})
ok(r.status_code == 200, "the key opens it")
r2 = client.get("/metrics", headers={"Authorization": "Bearer metrics-key-123"})
ok(r2.status_code == 200, "and so does the same key as a bearer token, "
                          "which is what prometheus.yml can send")
body = r.get_data(as_text=True)
ok('ham_pool_servers_up{pool="be_shop"} 2' in body, "servers up, per pool")
ok('ham_pool_requests_total{pool="be_shop"} 12345' in body, "the raw request counter")
ok('ham_pool_http_5xx_total{pool="be_shop"} 7' in body, "and the errors")
ok('ham_probe_up{url="https://shop.example.com"} 1' in body, "a probed URL that answers is 1")
ok('ham_probe_up{url="https://media.example.com"} 0' in body, "one that does not is 0")
ok("# TYPE ham_pool_requests_total counter" in body, "counters say they are counters")
ok("# TYPE ham_pool_servers_up gauge" in body, "and gauges say they are gauges")
# every metric family must be one consecutive group -- the stricter parsers
# reject interleaved samples outright
seen_done = set()
current = None
grouped = True
for line in body.splitlines():
    if line.startswith("# TYPE "):
        name = line.split()[2]
        if name in seen_done:
            grouped = False
        current = name
    elif line and not line.startswith("#"):
        name = line.split("{")[0].split(" ")[0]
        if name != current:
            grouped = False
        seen_done.add(current)
ok(grouped, "every metric's samples sit together under its TYPE line")
for line in body.splitlines():
    if line and not line.startswith("#"):
        parts = line.rsplit(" ", 1)
        ok2 = len(parts) == 2
        try:
            float(parts[1])
        except (ValueError, IndexError):
            ok2 = False
        if not ok2:
            ok(False, "malformed exposition line: %r" % line)
            break
else:
    ok(True, "every line parses as the exposition format")

print("\n" + ("%d failed" % len(fails) if fails else "the metrics tell Prometheus the truth"))
sys.exit(1 if fails else 0)
