#!/usr/bin/env python3
"""A service that waits longer than the listener lends it its patience. Issue #37.

    HAM_DATA_DIR=/tmp/x python3 tools/test-client-timeout.py

A pool's server timeout says how long its connections are meant to last, but
the visitor's side is held to the listener's client timeout, 50 s unless
changed, and a gRPC stream that is quiet both ways is cut by it. On HAProxy
3.0 and later the listener raises the client timeout for the requests of a
service whose server timeout is longer; on an older HAProxy, which does not
know the directive, nothing is written. Never shortened, never for tcp://.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-ct-"))
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
cfg["local"]["api_key"] = "ct-key"
save_config(cfg)
H = {"X-API-Key": "ct-key"}


def publish(url, **kw):
    r = client.post("/api/wizard/publish", headers=H, json=dict(
        {"url": url, "target": "10.0.0.5:80", "certificate": False, "http_redirect": False, "dry_run": False}, **kw))
    ok(r.status_code == 200, "publish %s -> %d %s" % (url, r.status_code, (r.get_json() or {}).get("error", "")))


def lines(version):
    haproxy.haproxy_version = lambda: version
    return [ln.strip() for ln in haproxy.render_haproxy(load_config()).splitlines()]


def waits(version):
    return [ln for ln in lines(version) if ln.startswith("http-request set-timeout client")]


real_version = haproxy.haproxy_version
publish("http://quick.example.com", name="quick")
publish("http://grpc.example.com", name="grpc", timeout_server="24h")
publish("http://short.example.com", name="short", timeout_server="30s")
publish("http://grpc.example.com/admin", name="admin", timeout_server="2h")
publish("tcp://0.0.0.0:5432", name="pg", target="10.0.0.9:5432", timeout_server="8h")

got = waits((3, 0))
ok("http-request set-timeout client 24h if acl_host-grpc" in got,
   "a service that waits a day gives its visitors a day: %s" % got)
ok(not any("quick" in ln or "short" in ln for ln in got),
   "one with no server timeout of its own, or a shorter one, leaves the listener's alone")
ok(len(got) == 2 and not any("pg" in ln for ln in got), "and a tcp:// service has its tunnel timeout instead")
all_lines = lines((3, 0))
routes = [ln for ln in all_lines if ln.startswith("use_backend be_")]
ok(routes.index(next(r for r in routes if "be_admin" in r)) < routes.index(next(r for r in routes if "be_grpc " in r))
   and got.index(next(g for g in got if " 2h " in g)) > got.index(next(g for g in got if " 24h " in g)),
   "of two services a request could be for, the one that routes it has the last word")
ok(max(all_lines.index(g) for g in got) < min(all_lines.index(r) for r in routes),
   "the lines sit with the other requests, before the routing")
ok(waits((3, 4)) == got, "the same on a newer HAProxy")
ok(waits((2, 8)) == [] and waits((2, 4)) == [], "an HAProxy before 3.0 does not know the directive, and gets none")
ok(waits(None) == [], "nor does a node where HAProxy cannot be asked its version")

c = load_config()
c["haproxy"]["settings"]["timeout_client"] = "48h"
save_config(c)
ok(waits((3, 0)) == [], "a listener already more patient than the service is not made less so")
c = load_config()
c["haproxy"]["settings"]["timeout_client"] = "50s"
save_config(c)

ok(haproxy._ms("50s") == 50000 and haproxy._ms("2h") == 7200000 and haproxy._ms("5000") == 5000
   and haproxy._ms("1d") == 86400000 and haproxy._ms("soon") is None and haproxy._ms("") is None,
   "times are read the way HAProxy reads them: a bare number is milliseconds")

haproxy.haproxy_version = real_version
haproxy._version.update(at=0.0, value=None)
bin_ = os.environ.get("HAM_HAPROXY_BIN") or shutil.which("haproxy")
if bin_:
    v = haproxy.haproxy_version()
    ok(isinstance(v, tuple) and len(v) == 2, "this node's HAProxy says which it is: %r" % (v,))
    path = pathlib.Path(os.environ["HAM_DATA_DIR"]) / "check.cfg"
    path.write_text(haproxy.render_haproxy(load_config()))
    r = subprocess.run([bin_, "-c", "-f", str(path)], capture_output=True, text=True)
    ok(r.returncode == 0, "and haproxy -c accepts what is rendered for it: %s" % (r.stdout + r.stderr).strip()[-300:])
    ok(("set-timeout client" in path.read_text()) == (v >= (3, 0)), "with the lines exactly when it is 3.0 or later")
else:
    ok(haproxy.haproxy_version() is None, "no haproxy here: the version is unknown")
    print("  SKIP  haproxy -c (no haproxy binary; set HAM_HAPROXY_BIN)")

print("\n" + ("%d failed" % len(fails) if fails else "a patient service has patient visitors"))
sys.exit(1 if fails else 0)
