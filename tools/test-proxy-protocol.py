#!/usr/bin/env python3
"""The PROXY protocol on a Real Server, and what it renders to.

    HAM_DATA_DIR=/tmp/x python3 tools/test-proxy-protocol.py

A server set to v1 or v2 gets send-proxy or send-proxy-v2 on its line, and
anything else gets nothing: the field is stored as the form sends it, so the
renderer is what keeps a stray value out of haproxy.cfg. The wizard sets it on
every server behind a service, turns it off when sent empty, leaves it alone
when not sent at all, and hands it back so the edit form shows it.

With HAM_HAPROXY_BIN pointing at an haproxy binary (or one on the PATH), the
rendered configuration is also run through `haproxy -c`.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-pp-"))
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
cfg["local"]["api_key"] = "pp-key"
save_config(cfg)
H = {"X-API-Key": "pp-key"}


def server_line(name, text):
    m = re.search(r"^\s+server %s .*$" % re.escape(name), text, re.M)
    return m.group(0).strip() if m else ""


def render(server, **pool):
    c = load_config()
    c["haproxy"]["servers"] = [dict({"id": "s1", "name": "mail1", "address": "10.0.0.25",
                                     "port": 25, "enabled": True}, **server)]
    c["haproxy"]["backends"] = [dict({"id": "b1", "name": "smtp", "mode": "tcp",
                                      "servers": ["s1"], "enabled": True}, **pool)]
    save_config(c)
    return haproxy.render_haproxy(load_config())


# ---- the renderer ----------------------------------------------------------
ok("send-proxy" not in server_line("mail1", render({})), "no setting, no PROXY line")
ok(server_line("mail1", render({"proxy_protocol": "v1"})).endswith(" send-proxy"),
   "v1 renders send-proxy: " + server_line("mail1", render({"proxy_protocol": "v1"})))
ok(server_line("mail1", render({"proxy_protocol": "v2"})).endswith(" send-proxy-v2"),
   "v2 renders send-proxy-v2")
for junk in ("", "v3", "send-proxy check-send-proxy", True, None):
    ok("proxy" not in server_line("mail1", render({"proxy_protocol": junk})),
       "a value other than v1/v2 renders nothing: %r" % (junk,))
line = server_line("mail1", render({"proxy_protocol": "v2", "ssl": True, "backup": True,
                                    "check_port": 8008},
                                   healthcheck_enabled=True))
ok(" ssl verify none send-proxy-v2 backup" in line and "check-send-proxy" not in line,
   "it sits beside ssl and backup, and a separate check port keeps HAProxy's "
   "default of no PROXY line on checks: " + line)
ok("send-proxy" in server_line("mail1", render({"proxy_protocol": "v1"}, mode="http")),
   "an HTTP pool can use it too")

bin_ = os.environ.get("HAM_HAPROXY_BIN") or shutil.which("haproxy")
if bin_:
    for v in ("v1", "v2"):
        path = pathlib.Path(os.environ["HAM_DATA_DIR"]) / ("check-%s.cfg" % v)
        path.write_text(render({"proxy_protocol": v, "check_port": 2525},
                               healthcheck_enabled=True))
        r = subprocess.run([bin_, "-c", "-f", str(path)], capture_output=True, text=True)
        ok(r.returncode == 0, "haproxy -c accepts %s: %s" % (v, (r.stdout + r.stderr).strip()[-300:]))
else:
    print("  SKIP  haproxy -c (no haproxy binary; set HAM_HAPROXY_BIN)")

# ---- the wizard -------------------------------------------------------------
c = load_config()
c["haproxy"]["servers"], c["haproxy"]["backends"] = [], []
save_config(c)
base = {"url": "tcp://0.0.0.0:2525", "target": "a=10.0.0.31:25, b=10.0.0.32:25",
        "health": {"type": "tcp"}, "dry_run": False}

r = client.post("/api/wizard/publish", headers=H, json=dict(base, proxy_protocol="v4"))
ok(r.status_code == 400 and "PROXY protocol" in r.get_json().get("error", ""),
   "the wizard refuses an unknown version")

r = client.post("/api/wizard/publish", headers=H, json=dict(base, proxy_protocol="v2"))
j = r.get_json()
ok(r.status_code == 200 and j.get("ok"), "publish with v2: " + str(j.get("error", "")))
pv = j.get("preview", "")
ok(server_line("a", pv).endswith("send-proxy-v2") and server_line("b", pv).endswith("send-proxy-v2"),
   "every server behind the service gets it")


def service():
    return next((s for s in client.get("/api/services", headers=H).get_json()
                 if (s.get("urls") or [s.get("url")])[0].startswith("tcp://")), {})


svc = service()
ok(svc.get("proxy_protocol") == "v2", "the Services page gets it back for the edit form: %r"
   % svc.get("proxy_protocol"))

r = client.post("/api/wizard/publish", headers=H,
                json={k: v for k, v in dict(base, service_id=svc.get("id")).items()})
ok(r.status_code == 200 and service().get("proxy_protocol") == "v2",
   "an edit that does not mention it leaves it alone")

r = client.post("/api/wizard/publish", headers=H,
                json=dict(base, service_id=svc.get("id"), proxy_protocol=""))
ok(r.status_code == 200 and service().get("proxy_protocol") == "",
   "an edit sending it empty switches it off")
ok(all("proxy_protocol" not in s for s in load_config()["haproxy"]["servers"]),
   "and leaves no trace on the servers")

print("\n" + ("%d failed" % len(fails) if fails else "the servers know who is really calling"))
sys.exit(1 if fails else 0)
