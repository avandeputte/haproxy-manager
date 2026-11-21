#!/usr/bin/env python3
"""HTTP/2 to a Real Server, and what it renders to. Issue #37.

    HAM_DATA_DIR=/tmp/x python3 tools/test-server-http2.py

HAProxy speaks HTTP/1.1 to a server unless told otherwise, and gRPC cannot do
without HTTP/2. A server with the option gets `alpn h2,http/1.1` when the
connection is encrypted and `proto h2` when it is not, on HTTP pools only;
an HTTP health check on the traffic port speaks the same. The wizard sets it
on every server behind a service, switches it off when sent false, leaves it
alone when not sent, and hands it back so the edit form shows it.

With an haproxy binary on the PATH the rendered configuration is also run
through `haproxy -c`.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-h2-"))
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
cfg["local"]["api_key"] = "h2-key"
save_config(cfg)
H = {"X-API-Key": "h2-key"}


def server_line(name, text):
    m = re.search(r"^\s+server %s .*$" % re.escape(name), text, re.M)
    return m.group(0).strip() if m else ""


def render(server, monitor=None, **pool):
    c = load_config()
    c["haproxy"]["servers"] = [dict({"id": "s1", "name": "api1", "address": "10.0.0.25",
                                     "port": 443, "enabled": True}, **server)]
    c["haproxy"]["healthchecks"] = [dict({"id": "h1", "name": "chk"}, **monitor)] if monitor else []
    c["haproxy"]["backends"] = [dict({"id": "b1", "name": "api", "mode": "http", "servers": ["s1"], "enabled": True,
                                      "healthcheck_enabled": bool(monitor), "healthcheck": "h1" if monitor else ""}, **pool)]
    save_config(c)
    return haproxy.render_haproxy(load_config())


# ---- the renderer ----------------------------------------------------------
line = server_line("api1", render({"ssl": True}))
ok("alpn" not in line and "proto" not in line, "no setting, HTTP/1.1 to the server as before: " + line)
line = server_line("api1", render({"ssl": True, "http2": True}))
ok(line.endswith("ssl verify none alpn h2,http/1.1"), "an encrypted server is offered HTTP/2 and chooses: " + line)
line = server_line("api1", render({"http2": True}))
ok(line.endswith(" proto h2") and "alpn" not in line, "a plain one is spoken HTTP/2 to, there being nothing to negotiate with: " + line)
line = server_line("api1", render({"ssl": True, "http2": True}, mode="tcp"))
ok("alpn" not in line and "proto" not in line, "a TCP pool carries bytes, and gets neither: " + line)
line = server_line("api1", render({"ssl": True, "http2": True, "backup": True, "proxy_protocol": "v2"}))
ok(" ssl verify none send-proxy-v2 alpn h2,http/1.1 backup" in line, "it sits with the other options: " + line)
line = server_line("api1", render({"ssl": True, "http2": True}, monitor={"type": "http", "http_uri": "/healthz"}))
ok(" check " in line + " " and "check-alpn h2,http/1.1" in line, "an HTTP health check speaks what the traffic speaks: " + line)
line = server_line("api1", render({"http2": True}, monitor={"type": "http"}))
ok("check-proto h2" in line and "proto h2" in line, "in the clear too: " + line)
line = server_line("api1", render({"ssl": True, "http2": True}, monitor={"type": "tcp"}))
ok("check-alpn" not in line, "a connect check needs no protocol: " + line)
line = server_line("api1", render({"ssl": True, "http2": True, "check_port": 8008}, monitor={"type": "http"}))
ok("check-alpn" not in line and "alpn h2,http/1.1" in line, "a separate check port is another service, and is checked as before: " + line)

bin_ = os.environ.get("HAM_HAPROXY_BIN") or shutil.which("haproxy")
if bin_:
    for name, server, monitor in (("tls", {"ssl": True, "http2": True}, {"type": "http"}),
                                  ("clear", {"http2": True}, {"type": "http"}),
                                  ("tls-tcp-check", {"ssl": True, "http2": True}, {"type": "tcp"})):
        path = pathlib.Path(os.environ["HAM_DATA_DIR"]) / ("check-%s.cfg" % name)
        path.write_text(render(server, monitor=monitor))
        r = subprocess.run([bin_, "-c", "-f", str(path)], capture_output=True, text=True)
        ok(r.returncode == 0, "haproxy -c accepts %s: %s" % (name, (r.stdout + r.stderr).strip()[-300:]))
else:
    print("  SKIP  haproxy -c (no haproxy binary; set HAM_HAPROXY_BIN)")

# ---- the wizard -------------------------------------------------------------
c = load_config()
c["haproxy"]["servers"], c["haproxy"]["backends"], c["haproxy"]["healthchecks"] = [], [], []
save_config(c)
base = {"url": "http://grpc.example.com", "target": "a=https://10.0.0.31:443, b=https://10.0.0.32:443",
        "certificate": False, "http_redirect": False, "health": {"type": "tcp"}, "dry_run": False}

r = client.post("/api/wizard/publish", headers=H, json=dict(base, server_http2=True))
j = r.get_json()
ok(r.status_code == 200 and j.get("ok"), "publish with HTTP/2 to the servers: " + str(j.get("error", "")))
pv = j.get("preview", "")
ok(server_line("a", pv).endswith("alpn h2,http/1.1") and server_line("b", pv).endswith("alpn h2,http/1.1"),
   "every server behind the service gets it")


def service():
    return next((s for s in client.get("/api/services", headers=H).get_json() if s.get("host") == "grpc.example.com"), {})


svc = service()
ok(svc.get("server_http2") is True, "the Services page gets it back for the edit form")
r = client.post("/api/wizard/publish", headers=H, json=dict(base, service_id=svc.get("id")))
ok(r.status_code == 200 and service().get("server_http2") is True, "an edit that does not mention it leaves it alone")
r = client.post("/api/wizard/publish", headers=H, json=dict(base, service_id=svc.get("id"), server_http2=False))
ok(r.status_code == 200 and service().get("server_http2") is False, "an edit sending it false switches it off")
ok(all("http2" not in s for s in load_config()["haproxy"]["servers"]), "and leaves no trace on the servers")
r = client.post("/api/wizard/publish", headers=H, json={"url": "tcp://0.0.0.0:5432", "target": "10.0.0.9:5432",
                                                        "health": {"type": "tcp"}, "dry_run": False, "server_http2": True})
ok(r.status_code == 200 and all("http2" not in s for s in load_config()["haproxy"]["servers"]),
   "a tcp:// service does not take it")

print("\n" + ("%d failed" % len(fails) if fails else "the servers are spoken to in HTTP/2 where asked"))
sys.exit(1 if fails else 0)
