#!/usr/bin/env python3
"""What the Services page reads back, and what editing sends again.

    HAM_DATA_DIR=/tmp/x python3 tools/test-services.py

The Edit button refills the publish form from GET /api/services, so every
setting the wizard takes has to come back from there, as it stands. The one
that did not was the HTTP-to-HTTPS redirect: the form fell back to its
default, on, and saving any HTTPS service turned a redirect back on that had
been turned off under Advanced > Public Services. Pinned here: the redirect
is reported, and an edit that sends the reported state leaves it alone.
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-svc-"))
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
cfg["local"]["api_key"] = "svc-key"
save_config(cfg)
H = {"X-API-Key": "svc-key"}


def publish(url, **kw):
    body = dict({"url": url, "target": "10.0.0.5:8080", "certificate": False, "dry_run": False}, **kw)
    r = client.post("/api/wizard/publish", headers=H, json=body)
    return r.status_code, r.get_json()


def services():
    return client.get("/api/services", headers=H).get_json()


def plain80():
    return [f for f in load_config()["haproxy"]["frontends"]
            if "0.0.0.0:80" in (f.get("binds") or "") and not f.get("ssl_enabled")]


# ---- the redirect is reported as it stands --------------------------------
code, r = publish("https://app.example.com")
ok(code == 200 and r.get("ok"), "an HTTPS service publishes with the redirect on by default")
ok(len(plain80()) == 1 and plain80()[0].get("http_to_https") is True, "and port 80 sends visitors on to HTTPS")
svc = [s for s in services() if s["url"] == "https://app.example.com"]
ok(len(svc) == 1 and svc[0].get("http_redirect") is True, "the Services page reports the redirect on")

# turned off where the listener is edited by hand
c = load_config()
fe = [f for f in c["haproxy"]["frontends"] if "0.0.0.0:80" in (f.get("binds") or "") and not f.get("ssl_enabled")][0]
fe["http_to_https"] = False
save_config(c)
svc = [s for s in services() if s["url"] == "https://app.example.com"][0]
ok(svc.get("http_redirect") is False, "once turned off on the listener, the page reports it off")

# ---- an edit that sends the reported state leaves it off -------------------
code, r = publish("https://app.example.com", service_id=svc["id"], http_redirect=svc["http_redirect"],
                  timeout_server="45s")
ok(code == 200 and r.get("ok"), "the service is edited")
ok(plain80()[0].get("http_to_https") is False, "and the redirect stays off: the edit sent what it read")
ok(len(plain80()) == 1, "no second port-80 listener was made for it")
ok(not any(a["type"] == "Public Service" and a["name"] == plain80()[0]["name"] and a["action"] == "updated"
           for a in r["actions"]), "the port-80 listener is not among the objects the edit touched")

# the way the form used to behave -- the default sent back -- is what did the damage
code, r = publish("https://app.example.com", service_id=svc["id"], http_redirect=True)
ok(plain80()[0].get("http_to_https") is True, "asking for the redirect turns it on again, as before")
ok(services()[0].get("http_redirect") is True, "and the page says so")

# ---- services without HTTPS have no redirect to report ---------------------
code, r = publish("http://plain.example.com", http_redirect=False)
svc = [s for s in services() if s["url"] == "http://plain.example.com"]
ok(len(svc) == 1 and svc[0].get("http_redirect") is False,
   "an http:// service reports no redirect, whatever port 80 does for the HTTPS ones")

print("\n" + ("%d failed" % len(fails) if fails else "the Services page reads back what the wizard set"))
sys.exit(1 if fails else 0)
