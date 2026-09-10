#!/usr/bin/env python3
"""A rate limit per client address on a pool, and what it renders to.

    HAM_DATA_DIR=/tmp/x python3 tools/test-ratelimit.py

The limit shares the pool's stick table with source persistence -- HAProxy
allows one table per proxy -- so the shape of that one line under every
combination is what most of this checks. The rest is that a value the
renderer would silently ignore is refused at the form instead, on both the
paths that save a pool: the wizard and the Backend Pools editor.
"""
import os
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-rate-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import haproxy   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "rate-key"
cfg["haproxy"]["servers"] = [{"id": "s1", "name": "web1", "address": "10.0.0.5",
                              "port": 80, "enabled": True}]
save_config(cfg)
H = {"X-API-Key": "rate-key"}


def block(text, name):
    """The lines of one backend, so a check cannot match another pool's."""
    m = re.search(r"^backend be_%s\n(.*?)(?=^\S|\Z)" % name, text, re.S | re.M)
    return m.group(1) if m else ""


def render(**pool):
    c = load_config()
    c["haproxy"]["backends"] = [dict({"id": "b1", "name": "shop", "mode": "http",
                                      "servers": ["s1"], "enabled": True}, **pool)]
    save_config(c)
    return block(haproxy.render_haproxy(load_config()), "shop")


# ---- no limit: nothing appears --------------------------------------------
b = render()
ok("track-sc0" not in b and "stick-table" not in b,
   "a pool with no limit has no counter and no table")

# ---- HTTP: the example from the request, line for line --------------------
b = render(rate_limit=100, rate_window=10)
ok("    http-request track-sc0 src\n" in b, "HTTP: the client address is tracked")
ok("    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }\n" in b,
   "HTTP: over the limit is a 429")
ok(b.count("stick-table") == 1, "exactly one stick table")
ok("    stick-table type ipv6 size 30k expire 30s store http_req_rate(10s)\n" in b,
   "on its own the table is keyed by ipv6 (holds IPv4 too), kept three windows")
ok("stick on src" not in b, "no persistence was added by asking for a limit")
ok(b.index("track-sc0") < b.index("deny deny_status 429"),
   "tracking starts before the rate is read")

# ---- the limit refuses before any sign-in ---------------------------------
b = render(rate_limit=5, rate_window=1, allow_src="10.0.0.0/8", auth_enabled=True,
           auth_groups=[])
ok(b.index("deny unless { src") < b.index("track-sc0"),
   "the allow-list is checked first, so a refused network fills no table")
ok(b.index("track-sc0") < b.index("http-request auth") if "http-request auth" in b else True,
   "and the limit is enforced before the sign-in is asked for")

# ---- together with source persistence: one table, both purposes ----------
b = render(rate_limit=100, rate_window=10, persistence="source", stick_type="ip",
           stick_size="50k", stick_expire="30m")
ok(b.count("stick-table") == 1, "with source persistence there is still one table")
ok("    stick-table type ip size 50k expire 30m store http_req_rate(10s)\n" in b,
   "it keeps the persistence shape and gains the rate counter")
ok("    stick on src\n" in b, "and persistence still sticks on source")

# ---- cookie persistence needs no table; the limit gets its own ------------
b = render(rate_limit=100, rate_window=10, persistence="cookie")
ok("cookie SRVID insert" in b and "store http_req_rate(10s)" in b and "stick on src" not in b,
   "cookie persistence and a rate limit coexist without a stick on src")

# ---- TCP: connections, not requests ---------------------------------------
b = render(mode="tcp", rate_limit=20, rate_window=60)
ok("    tcp-request content track-sc0 src\n" in b, "TCP: the client address is tracked")
ok("    tcp-request content reject if { sc_conn_rate(0) gt 20 }\n" in b,
   "TCP: over the limit the connection is dropped")
ok("store conn_rate(60s)" in b and "expire 180s" in b, "TCP: a connection rate over the window")
ok("http-request" not in b, "TCP: no HTTP rule leaks into a tcp pool")

# ---- what the renderer does with junk: nothing, never a broken line ------
b = render(rate_limit="lots", rate_window=10)
ok("track-sc0" not in b, "a limit that is not a number renders as no limit")
b = render(rate_limit=100, rate_window=0)
ok("track-sc0" not in b, "a zero window renders as no limit")

# ---- ...which is why the forms refuse such values ------------------------
r = client.put("/api/haproxy/backends/b1", headers=H,
               json={"id": "b1", "name": "shop", "mode": "http", "servers": ["s1"],
                     "rate_limit": "lots", "rate_window": 10})
ok(r.status_code == 400 and "whole number" in r.get_json()["error"],
   "the editor refuses a limit that is not a number: " + r.get_json().get("error", ""))
r = client.put("/api/haproxy/backends/b1", headers=H,
               json={"id": "b1", "name": "shop", "mode": "http", "servers": ["s1"],
                     "rate_limit": 100, "rate_window": 0})
ok(r.status_code == 400 and "between 1 and 3600" in r.get_json()["error"],
   "and a window outside 1..3600 seconds")
r = client.put("/api/haproxy/backends/b1", headers=H,
               json={"id": "b1", "name": "shop", "mode": "http", "servers": ["s1"],
                     "rate_limit": "", "rate_window": ""})
ok(r.status_code == 200, "empty is no limit, and is accepted")

# ---- the wizard carries it, and refuses the same junk --------------------
base = {"url": "http://shop.example.test", "target": "10.0.0.5:80", "certificate": False,
        "health": {"type": "none"}, "dry_run": True}
r = client.post("/api/wizard/publish", headers=H,
                json=dict(base, rate_limit=100, rate_window=10))
j = r.get_json()
ok(r.status_code == 200 and j.get("ok"), "the wizard publishes with a limit: " + str(j.get("error", "")))
pv = j.get("preview", "")
ok("deny deny_status 429 if { sc_http_req_rate(0) gt 100 }" in pv
   and "store http_req_rate(10s)" in pv, "and the preview shows the limit")
r = client.post("/api/wizard/publish", headers=H, json=dict(base, rate_limit="x"))
ok(r.status_code == 400 and "whole number" in r.get_json().get("error", ""),
   "the wizard refuses a limit that is not a number")
r = client.post("/api/wizard/publish", headers=H, json=dict(base, rate_limit=100, rate_window=9999))
ok(r.status_code == 400 and "between 1 and 3600" in r.get_json().get("error", ""),
   "and a window that is too long")

# ---- a published service reports its limit, so the edit form can show it --
r = client.post("/api/wizard/publish", headers=H,
                json=dict(base, dry_run=False, rate_limit=100, rate_window=10))
ok(r.status_code == 200 and r.get_json().get("ok"), "publish for real")
svcs = client.get("/api/services", headers=H).get_json()
svc = next((s for s in svcs
            if any("shop.example.test" in (u or "") for u in (s.get("urls") or [s.get("url")]))), {})
ok(svc.get("rate_limit") == 100 and svc.get("rate_window") == 10,
   "the Services page gets the limit and window back: %r/%r"
   % (svc.get("rate_limit"), svc.get("rate_window")))
r = client.post("/api/wizard/publish", headers=H,
                json=dict(base, dry_run=False, service_id=svc.get("id"), rate_limit=""))
svc2 = next((s for s in client.get("/api/services", headers=H).get_json()
             if s.get("id") == svc.get("id")), {})
ok(r.status_code == 200 and svc2.get("rate_limit") == "",
   "editing the service with an empty limit switches it off")
r = client.post("/api/wizard/publish", headers=H,
                json=dict(base, dry_run=False, service_id=svc.get("id"), rate_limit=50))
r = client.post("/api/wizard/publish", headers=H,
                json={"url": "http://shop.example.test", "target": "10.0.0.5:80",
                      "certificate": False, "dry_run": False, "service_id": svc.get("id")})
svc3 = next((s for s in client.get("/api/services", headers=H).get_json()
             if s.get("id") == svc.get("id")), {})
ok(svc3.get("rate_limit") == 50, "an edit that does not mention the limit leaves it alone")

print("\n" + ("%d failed" % len(fails) if fails else "a pool can say how much is too much"))
sys.exit(1 if fails else 0)
