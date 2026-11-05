#!/usr/bin/env python3
"""A host condition matches whatever port the browser came in on.

    HAM_DATA_DIR=/tmp/x python3 tools/test-host-port.py

A browser sends "Host: app.example.com:3456" to any port that is not the
scheme's default, so a host compared exactly as sent matched nothing on such a
port: a service published at https://app.example.com:3456 answered 503 to
everyone, and changing the condition to "host starts with" -- which does match
-- made the service vanish from the Services page (issue #14). The port is cut
off before comparing now, for "matches" and "ends with".

With HAM_HAPROXY_BIN pointing at an haproxy binary (or one on the PATH), the
rendered configuration goes through `haproxy -c`, and the rendered ACLs are run
in a real HAProxy and sent requests with real Host headers.
"""
import http.client
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-hp-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import haproxy   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


CONDS = {"exact": ("host_matches", "service.mydomain.com"),
         "v6": ("host_matches", "[2001:db8::1]"),
         "suffix": ("host_ends_with", ".mydomain.com"),
         "prefix": ("host_starts_with", "service.")}

c = load_config()
c["haproxy"]["conditions"] = [{"id": k, "name": k, "type": t, "value": v} for k, (t, v) in CONDS.items()]
c["haproxy"]["servers"] = [{"id": "s1", "name": "app", "address": "10.0.0.5", "port": 3456, "enabled": True}]
c["haproxy"]["backends"] = [{"id": "b1", "name": "app", "mode": "http", "servers": ["s1"], "enabled": True}]
c["haproxy"]["rules"] = [{"id": "r%d" % i, "type": "use_backend", "backend": "b1", "conditions": [k],
                          "frontend": "f1", "enabled": True} for i, k in enumerate(CONDS)]
c["haproxy"]["frontends"] = [{"id": "f1", "name": "web", "mode": "http", "enabled": True,
                              "binds": "127.0.0.1:18080", "rules": ["r%d" % i for i in range(len(CONDS))],
                              "ssl_enabled": False, "certificates": []}]
save_config(c)
cfg = haproxy.render_haproxy(load_config())
acl = {k: (re.search(r"^\s*acl acl_%s (.*)$" % k, cfg, re.M) or [None, ""])[1] for k in CONDS}

ok(acl["exact"] == "hdr(host),regsub(':[0-9]+$','') -i service.mydomain.com",
   "host matches drops the port before comparing: " + acl["exact"])
ok(acl["suffix"] == "hdr(host),regsub(':[0-9]+$','') -m end -i .mydomain.com",
   "and so does host ends with: " + acl["suffix"])
ok(acl["prefix"] == "hdr_beg(host) -i service.", "starts with is left as it was: " + acl["prefix"])

bin_ = os.environ.get("HAM_HAPROXY_BIN") or shutil.which("haproxy")
if not bin_:
    print("  SKIP  haproxy -c and live requests (no haproxy binary; set HAM_HAPROXY_BIN)")
else:
    path = pathlib.Path(os.environ["HAM_DATA_DIR"]) / "rendered.cfg"
    path.write_text(cfg)
    r = subprocess.run([bin_, "-c", "-f", str(path)], capture_output=True, text=True)
    ok(r.returncode == 0, "haproxy -c accepts the rendered configuration: "
       + (r.stdout + r.stderr).strip()[-300:])

    # The rendered ACLs, each behind its own port answering 200 on a match.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    base = s.getsockname()[1]
    s.close()
    lines = ["defaults", "  mode http", "  timeout connect 1s", "  timeout client 5s",
             "  timeout server 5s"]
    for i, k in enumerate(CONDS):
        lines += ["frontend %s" % k, "  bind 127.0.0.1:%d" % (base + i), "  acl m " + acl[k],
                  "  http-request return status 200 if m", "  http-request return status 404"]
    live = pathlib.Path(os.environ["HAM_DATA_DIR"]) / "live.cfg"
    live.write_text("\n".join(lines) + "\n")
    proc = subprocess.Popen([bin_, "-f", str(live)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        def status(k, host):
            for _ in range(50):
                try:
                    h = http.client.HTTPConnection("127.0.0.1", base + list(CONDS).index(k), timeout=2)
                    h.putrequest("GET", "/", skip_host=True)
                    h.putheader("Host", host)
                    h.endheaders()
                    return h.getresponse().status
                except ConnectionRefusedError:
                    time.sleep(0.1)
            return None

        for host, want in (("service.mydomain.com", 200), ("service.mydomain.com:3456", 200),
                           ("SERVICE.MyDomain.com:443", 200), ("service.mydomain.com.evil", 404),
                           ("service.mydomain.com.evil:3456", 404), ("other.mydomain.com:3456", 404)):
            got = status("exact", host)
            ok(got == want, "host matches, Host: %s -> %s" % (host, got))
        for host, want in (("[2001:db8::1]", 200), ("[2001:db8::1]:3456", 200), ("[2001:db8::2]:3456", 404)):
            got = status("v6", host)
            ok(got == want, "an IPv6 literal is kept whole, Host: %s -> %s" % (host, got))
        for host, want in (("a.mydomain.com", 200), ("a.mydomain.com:3456", 200),
                           ("a.mydomain.com.evil:3456", 404)):
            got = status("suffix", host)
            ok(got == want, "host ends with, Host: %s -> %s" % (host, got))
        got = status("prefix", "service.mydomain.com:3456")
        ok(got == 200, "starts with matched with a port before, and still does -> %s" % got)
    finally:
        proc.terminate()
        proc.wait()

print("\n" + ("%d failed" % len(fails) if fails else "a host is a host on any port"))
sys.exit(1 if fails else 0)
