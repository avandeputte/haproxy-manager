#!/usr/bin/env python3
"""The URL probes: what is probed, and what each outcome is called.

The extractor is checked against the objects the wizard builds, and the probe
itself against a real listener on the loopback -- a probe that is never
exercised against an actual socket is a probe whose failure modes are guesses.

    HAM_DATA_DIR=/tmp/x python3 tools/test-probe.py
"""
import http.server
import os
import pathlib
import socket
import sys
import tempfile
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-probe-"))
os.environ["HAM_DRY_RUN"] = "1"

import copy   # noqa: E402
import ham; ham   # noqa: E402  (imported for its route registration)
from ham import probe   # noqa: E402
from ham.config import DEFAULT_CONFIG   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


# -- what gets probed --------------------------------------------------------
cfg = copy.deepcopy(DEFAULT_CONFIG)
cfg["haproxy"]["conditions"] = [
    {"id": "c1", "name": "host-shop", "type": "host_matches", "value": "shop.example.com"},
    {"id": "c2", "name": "host-www", "type": "host_matches", "value": "www.example.com"},
    {"id": "c3", "name": "api-path", "type": "path_starts_with", "value": "/api"},
]
cfg["haproxy"]["backends"] = [
    {"id": "b1", "name": "shop", "enabled": True, "servers": []},
    {"id": "b2", "name": "off", "enabled": False, "servers": []},
    {"id": "b3", "name": "db", "enabled": True, "servers": []},
]
cfg["haproxy"]["rules"] = [
    {"id": "r1", "name": "to-shop", "type": "use_backend", "backend": "b1",
     "conditions": ["c1", "c2"]},
    {"id": "r2", "name": "to-api", "type": "use_backend", "backend": "b1",
     "conditions": ["c1", "c3"]},
    {"id": "r3", "name": "to-off", "type": "use_backend", "backend": "b2",
     "conditions": ["c2"]},
]
cfg["haproxy"]["frontends"] = [
    {"id": "f1", "name": "https-443", "enabled": True, "mode": "http",
     "binds": "0.0.0.0:443", "ssl_enabled": True, "rules": ["r1", "r2", "r3"]},
    {"id": "f2", "name": "galera", "enabled": True, "mode": "tcp",
     "binds": "0.0.0.0:3306", "default_backend": "b3"},
    {"id": "f3", "name": "dark", "enabled": False, "mode": "tcp",
     "binds": "0.0.0.0:5432", "default_backend": "b3"},
]
urls = probe.published_urls(cfg)
have = {u["url"] for u in urls}
ok("https://shop.example.com" in have and "https://www.example.com" in have,
   "every name on a service is probed, not just the first")
ok("https://shop.example.com/api" in have, "a path-routed service is asked at its path")
ok("tcp://127.0.0.1:3306" in have, "a TCP service is a port to connect to")
ok(not any("5432" in u for u in have), "a disabled listener is not probed")
ok(len([u for u in have if "www" in u]) == 1,
   "a name whose only pool is disabled is not probed twice over")

# -- the probe against a real socket -----------------------------------------
class Quiet(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        code = 401 if self.path.startswith("/auth") else 200
        self.send_response(code)
        self.end_headers()
        self.wfile.write(b"hi")
    def log_message(self, *a):
        pass


srv = http.server.HTTPServer(("127.0.0.1", 0), Quiet)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

r = probe.probe_one({"kind": "http", "url": "u", "host": "127.0.0.1", "port": port, "path": "/"})
ok(r["state"] == "ok" and r["status"] == 200, "a listener that answers is ok")
ok(r["resolved"] == "127.0.0.1", "and the address it resolved to is recorded")

r = probe.probe_one({"kind": "http", "url": "u", "host": "127.0.0.1", "port": port, "path": "/auth"})
ok(r["state"] == "ok" and r["status"] == 401,
   "a 401 is an answer: the sign-in in front of a service is not an outage")

# a port with nothing behind it
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    free = s.getsockname()[1]
r = probe.probe_one({"kind": "http", "url": "u", "host": "127.0.0.1", "port": free, "path": "/"})
ok(r["state"] == "down" and "no answer" in r["note"], "a refused connection is down")

r = probe.probe_one({"kind": "tcp", "url": "u", "host": "127.0.0.1", "port": port})
ok(r["state"] == "ok", "a TCP probe only asks whether the port accepts")
r = probe.probe_one({"kind": "tcp", "url": "u", "host": "127.0.0.1", "port": free})
ok(r["state"] == "down", "and says down when it does not")

r = probe.probe_one({"kind": "https", "url": "u",
                     "host": "does-not-exist.invalid", "port": 443, "path": "/"})
ok(r["state"] == "down" and "resolve" in r["note"],
   "a name DNS cannot answer for is reported as exactly that")

# https against a plain listener: TLS never establishes
r = probe.probe_one({"kind": "https", "url": "u", "host": "127.0.0.1", "port": port, "path": "/"})
ok(r["state"] == "down", "https against something that does not speak TLS is down")

# -- counting what we put through ourselves ----------------------------------
probe.drain_generated()
urls2 = probe.published_urls(cfg)
ok(all(u.get("pool") for u in urls2), "every probed URL knows which pool it counts against")
probe._count_self("be_shop", 200)
probe._count_self("be_shop", 401)
probe._count_self("be_db", None)          # a TCP connect: a session, no status
mine = probe.drain_generated()
ok(mine["be_shop"] == {"req": 2, "e4": 1, "e5": 0},
   "requests and the 401s they were answered with are both counted")
ok(mine["be_db"] == {"req": 1, "e4": 0, "e5": 0}, "a TCP session counts as one request")
ok(probe.drain_generated() == {}, "draining hands the counts over exactly once")

srv.shutdown()

print("\n" + ("%d failed" % len(fails) if fails else "the probes ask the way a browser would"))
sys.exit(1 if fails else 0)
