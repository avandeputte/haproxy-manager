#!/usr/bin/env python3
"""One service, several ports.

    HAM_DATA_DIR=/tmp/x python3 tools/test-multiport.py

https://app.example.com and https://app.example.com:3456 on one service: one
rule, put into a listener for each port, listed once on the Services page with
both URLs, edited and removed as one thing. Every name answers on every port,
and when the URLs typed do not say so the wizard does. Editing a port off the
list takes it out of that listener; a publish that is not an edit takes
nothing away. A port another kind of listener holds is refused (issue #14).

With HAM_HAPROXY_BIN pointing at an haproxy binary (or one on the PATH), the
rendered configuration is run, with a small HTTP server behind it, and asked
for the service on both ports.
"""
import http.client
import http.server
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-mp-"))
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
cfg["local"]["api_key"] = "mp-key"
save_config(cfg)
H = {"X-API-Key": "mp-key"}


def publish(url, **kw):
    body = dict({"url": url, "target": "10.0.0.5:3456", "certificate": False,
                 "dry_run": False}, **kw)
    r = client.post("/api/wizard/publish", headers=H, json=body)
    return r.status_code, r.get_json()


def services():
    return client.get("/api/services", headers=H).get_json()


def serving(rule_id):
    """The ports of the listeners that hold this rule."""
    hp = load_config()["haproxy"]
    return sorted(int(b.rsplit(":", 1)[1]) for f in hp["frontends"]
                  if rule_id in (f.get("rules") or []) for b in (f.get("binds") or "").split())


# ---- both ports on one service ------------------------------------------------
code, j = publish("https://app.example.com\nhttps://app.example.com:3456")
ok(code == 200 and j.get("ok"), "two URLs differing only in port are one service: %s"
   % (j.get("error") or ""))
svcs = services()
ok(len(svcs) == 1, "listed once on the Services page, not once per listener: %d" % len(svcs))
svc = svcs[0] if svcs else {}
ok(svc.get("urls") == ["https://app.example.com", "https://app.example.com:3456"],
   "with both URLs: %r" % svc.get("urls"))
ok(serving(svc.get("id")) == [443, 3456], "one rule, in a listener on each port: %r"
   % serving(svc.get("id")))
hp = load_config()["haproxy"]
ok(len(hp["rules"]) == 1 and len(hp["conditions"]) == 1,
   "the name is one condition, not one per port: %d rule(s), %d condition(s)"
   % (len(hp["rules"]), len(hp["conditions"])))
fes = {f["name"]: f for f in hp["frontends"]}
ok("https-3456" in fes and fes["https-3456"].get("ssl_enabled"),
   "the new port is an HTTPS listener like the first")

# ---- the edit form sends back what it was shown ----------------------------------
code, j = publish("\n".join(svc["urls"]), service_id=svc["id"])
ok(code == 200 and len(services()) == 1 and serving(svc["id"]) == [443, 3456],
   "saving the edit form unchanged changes nothing")
code, j = publish("https://app.example.com:3456", service_id=svc["id"])
ok(code == 200 and serving(svc["id"]) == [3456],
   "an edit that drops a port takes the service out of that listener: %r" % serving(svc["id"]))
ok(services()[0].get("urls") == ["https://app.example.com:3456"], "and the list says so")
code, j = publish("https://app.example.com\nhttps://app.example.com:3456", service_id=svc["id"])
ok(serving(svc["id"]) == [443, 3456], "and adding it back puts it back")

# a publish that is not an edit adds, and takes nothing away
code, j = publish("https://app.example.com:8443")
ok(code == 200 and serving(svc["id"]) == [443, 3456, 8443],
   "a publish of the same name on another port adds that port: %r" % serving(svc["id"]))
ok(len(services()) == 1, "still one service")

# ---- names and ports that do not make a full grid ----------------------------------
code, j = publish("https://a.example.org\nhttps://b.example.org:3457", name="grid")
ok(code == 200, "two names on two ports publish: %s" % (j.get("error") or ""))
warned = " ".join(j.get("warnings") or [])
ok("https://b.example.org" in warned and "https://a.example.org:3457" in warned,
   "and the wizard says every name answers on every port: " + warned[:160])
grid = next((s for s in services() if "https://a.example.org" in s.get("urls", [])), {})
ok(sorted(grid.get("urls") or []) == sorted(["https://a.example.org", "https://b.example.org",
                                             "https://a.example.org:3457",
                                             "https://b.example.org:3457"]),
   "the list shows all four, which is what is served: %r" % grid.get("urls"))

# ---- what is still refused ----------------------------------------------------------------
code, j = publish("https://app.example.com:3456\nhttps://APP.example.com:3456")
ok(code == 400 and "listed twice" in j.get("error", ""),
   "the same name on the same port twice: %s" % j.get("error"))
code, j = publish("https://x.example.com\nhttp://x.example.com:8080")
ok(code == 400 and "same scheme" in j.get("error", ""), "http and https on one service")
code, j = publish("tcp://0.0.0.0:3306", target="10.0.0.9:3306")
code, j = publish("https://db.example.com\nhttps://db.example.com:3306", name="db")
ok(code == 400 and "3306" in j.get("error", ""),
   "a port a TCP listener holds is refused, not shared: %s" % j.get("error"))

# ---- removing it removes it from every port --------------------------------------------
r = client.delete("/api/services/" + svc["id"], headers=H).get_json()
ok(r.get("ok") and serving(svc["id"]) == [], "deleting the service takes it off every listener")
ok(not any("app.example.com" in u for s in services() for u in s.get("urls", [])),
   "and it is gone from the list")

# ---- real traffic on both ports ---------------------------------------------------------
bin_ = os.environ.get("HAM_HAPROXY_BIN") or shutil.which("haproxy")
if not bin_:
    print("  SKIP  live requests (no haproxy binary; set HAM_HAPROXY_BIN)")
else:
    def free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    class Hello(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"hello from the backend")

        def log_message(self, *a):
            pass

    backend = http.server.HTTPServer(("127.0.0.1", free_port()), Hello)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    p1, p2 = free_port(), free_port()

    c = load_config()
    for k in ("servers", "backends", "rules", "conditions", "frontends"):
        c["haproxy"][k] = []
    save_config(c)
    code, j = publish("http://live.example.com:%d\nhttp://live.example.com:%d" % (p1, p2),
                      target="127.0.0.1:%d" % backend.server_port)
    ok(code == 200, "an http service on two ports publishes: %s" % (j.get("error") or ""))
    text = haproxy.render_haproxy(load_config())
    # The global section points at sockets and a user this sandbox may not
    # have; the proxies are what is being tested, so they run as rendered
    # behind a minimal global.
    proxies = text[re.search(r"^defaults\b", text, re.M).start():]
    live = pathlib.Path(os.environ["HAM_DATA_DIR"]) / "live.cfg"
    live.write_text("global\n    maxconn 100\n\n" + proxies)
    r = subprocess.run([bin_, "-c", "-f", str(live)], capture_output=True, text=True)
    ok(r.returncode == 0, "haproxy -c accepts it: " + (r.stdout + r.stderr).strip()[-300:])
    proc = subprocess.Popen([bin_, "-f", str(live)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        def get(port, host):
            for _ in range(50):
                try:
                    h = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                    h.putrequest("GET", "/", skip_host=True)
                    h.putheader("Host", host)
                    h.endheaders()
                    resp = h.getresponse()
                    return resp.status, resp.read()
                except ConnectionRefusedError:
                    time.sleep(0.1)
            return None, b""

        for port in (p1, p2):
            # what a browser sends: the name, and the port it is not the default
            st, body = get(port, "live.example.com:%d" % port)
            ok(st == 200 and body == b"hello from the backend",
               "port %d reaches the backend, Host carrying the port: %s" % (port, st))
        st, _ = get(p1, "other.example.com:%d" % p1)
        ok(st == 503, "another name on that port does not: %s" % st)
    finally:
        proc.terminate()
        proc.wait()
        backend.shutdown()

print("\n" + ("%d failed" % len(fails) if fails else "one service answers on every port it lists"))
sys.exit(1 if fails else 0)
