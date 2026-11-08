#!/usr/bin/env python3
"""Custom error pages: in the configuration, on every node's disk, in the file.

    HAM_DATA_DIR=/tmp/x python3 tools/test-errorpages.py

Issue #20 asked for pages that reach every node without a second thing to
synchronise. A page is a shared object, so it travels with the
configuration; what HAProxy needs is a file, so each node writes its pages
before it validates or applies, and the renderer names them. Checked here:
what is refused at the form, what is written and when, what the file holds,
and where the directives land.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-pages-"))
os.environ["HAM_ERROR_DIR"] = os.path.join(os.environ["HAM_DATA_DIR"], "error-pages")
os.environ["HAM_CERT_DIR"] = os.path.join(os.environ["HAM_DATA_DIR"], "certs")
os.environ["HAM_HAPROXY_CFG"] = os.path.join(os.environ["HAM_DATA_DIR"], "haproxy.cfg")
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import apply, errorpages, haproxy   # noqa: E402
from ham.base import CERT_DIR, ERROR_DIR   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "pages-key"
save_config(cfg)
H = {"X-API-Key": "pages-key"}


def post(path, body, want=200):
    r = client.post("/api/" + path, headers=H, json=body)
    ok(r.status_code == want, "POST %s -> %d %s" % (path, r.status_code, (r.get_json() or {}).get("error", "")[:70]))
    return r.get_json()


def on_disk():
    return sorted(p.name for p in ERROR_DIR.iterdir()) if ERROR_DIR.exists() else []


# ---- what is refused -------------------------------------------------------------
def refused(item):
    try:
        errorpages.check(item)
        return ""
    except ValueError as e:
        return str(e)


ok("418" in refused({"name": "tea", "codes": "418", "html": "<p>x</p>"}),
   "a code HAProxy never generates is refused, by number")
ok("not a status code" in refused({"name": "x", "codes": "five", "html": "<p>x</p>"}),
   "and so is a code that is not one")
ok("empty" in refused({"name": "x", "codes": "503", "html": "  "}), "an empty page is refused")
ok("buffer" in refused({"name": "x", "codes": "503", "html": "x" * (errorpages.MAX_HTML + 1)}),
   "a page too big for HAProxy's buffer is refused, with advice")
ok(refused({"name": "x", "codes": "503, 502 504", "html": "<p>x</p>"}) == "",
   "codes may be separated by spaces or commas")
ok(errorpages.codes_of({"codes": "504 502 503 502"}) == [502, 503, 504], "codes come back sorted, once each")
post("haproxy/errorpages", {"name": "tea", "codes": "418", "html": "<p>x</p>"}, want=400)

# ---- written when saved, and what the file holds ------------------------------------
page = post("haproxy/errorpages", {"name": "Oops", "codes": "502 503 504", "everywhere": True,
                                   "html": "<h1>{error_code}</h1><p>{error_message} — sorry</p>"})
ok(on_disk() == ["Oops-502.html", "Oops-502.http", "Oops-503.html", "Oops-503.http",
                 "Oops-504.html", "Oops-504.http"],
   "saving a page writes a response and a body per code: %s" % ", ".join(on_disk()))
raw = (ERROR_DIR / "Oops-503.http").read_bytes()
head, _, body = raw.partition(b"\r\n\r\n")
ok(head.startswith(b"HTTP/1.0 503 Service Unavailable\r\n"), "the response starts with the status line")
ok(b"Content-Type: text/html; charset=utf-8" in head and b"Cache-Control: no-cache" in head,
   "says it is HTML, and not to cache it")
ok(("Content-Length: %d" % len(body)).encode() in head, "and its length is the body's")
ok(body == "<h1>503</h1><p>Service Unavailable — sorry</p>".encode("utf-8"),
   "the placeholders are filled in per code, and the text is UTF-8")
ok((ERROR_DIR / "Oops-502.html").read_bytes() == "<h1>502</h1><p>Bad Gateway — sorry</p>".encode(),
   "the body file is the page alone, for http-request return")

# ---- where the directives land ----------------------------------------------------
post("wizard/publish", {"url": "https://shop.example.com", "target": "10.0.0.5:80",
                        "certificate": False, "dry_run": False})
post("wizard/publish", {"url": "tcp://0.0.0.0:5432", "target": "10.0.0.9:5432",
                        "certificate": False, "dry_run": False})
text = haproxy.render_haproxy(load_config())
defaults = text[text.index("defaults\n"):text.index("\n\n", text.index("defaults\n"))]
ok(all("errorfile %d %s" % (c, ERROR_DIR / ("Oops-%d.http" % c)) in defaults for c in (502, 503, 504)),
   "a page for every service is an errorfile in defaults, one line per code")
own = post("haproxy/errorpages", {"name": "shop-only", "codes": "503", "everywhere": False,
                                  "html": "<p>The shop is closed.</p>"})
text = haproxy.render_haproxy(load_config())
defaults = text[text.index("defaults\n"):text.index("\n\n", text.index("defaults\n"))]
ok("shop-only" not in defaults, "a page that is not for every service stays out of defaults")
c = load_config()
shop = next(b for b in c["haproxy"]["backends"] if b["name"] == "shop")
db = next(b for b in c["haproxy"]["backends"] if b["mode"] == "tcp")
shop["error_pages"] = [own["id"], "gone"]
db["error_pages"] = [own["id"]]
save_config(c)
text = haproxy.render_haproxy(load_config())
be = text[text.index("backend be_shop\n"):text.index("\n\n", text.index("backend be_shop\n"))]
tcp = text[text.index("backend be_%s\n" % db["name"]):]
tcp = tcp[:tcp.index("\n\n")] if "\n\n" in tcp else tcp
ok("errorfile 503 %s" % (ERROR_DIR / "shop-only-503.http") in be,
   "a pool that picks a page gets it inside its own block, over the default")
ok("errorfile" not in tcp, "a TCP pool gets none: there is no HTTP to answer with")
shop["maintenance"] = True
save_config(c)
text = haproxy.render_haproxy(load_config())
be = text[text.index("backend be_shop\n"):text.index("\n\n", text.index("backend be_shop\n"))]
ok('http-request return status 503 content-type "text/html; charset=utf-8" file %s'
   % (ERROR_DIR / "shop-only-503.html") in be,
   "a paused service answers with its 503 page, the pool's own first")
shop["error_pages"] = []
save_config(c)
text = haproxy.render_haproxy(load_config())
be = text[text.index("backend be_shop\n"):text.index("\n\n", text.index("backend be_shop\n"))]
ok("file %s" % (ERROR_DIR / "Oops-503.html") in be, "then the one every service has")
c = load_config()
c["haproxy"]["errorpages"] = [p for p in c["haproxy"]["errorpages"] if p["name"] == "shop-only"]
save_config(c)
text = haproxy.render_haproxy(load_config())
be = text[text.index("backend be_shop\n"):text.index("\n\n", text.index("backend be_shop\n"))]
ok('string "This service is down for maintenance."' in be, "and with no 503 page, the plain words as before")
shop = next(b for b in c["haproxy"]["backends"] if b["name"] == "shop")
shop["maintenance"] = False
save_config(c)

# ---- picked from the publish wizard -------------------------------------------------
r = client.post("/api/wizard/publish", headers=H, json={
    "url": "https://shop.example.com", "target": "10.0.0.5:80", "certificate": False,
    "dry_run": False, "service_id": client.get("/api/services", headers=H).get_json()[0]["id"],
    "error_pages": [own["id"], "gone"]})
ok(r.status_code == 200, "the wizard takes the pages a service picks")
shop = next(b for b in load_config()["haproxy"]["backends"] if b["name"] == "shop")
ok(shop.get("error_pages") == [own["id"]], "and stores the ones that exist on the pool")
svc = next(s for s in client.get("/api/services", headers=H).get_json() if s["pool"] == "shop")
ok(svc["error_pages"] == [own["id"]] and svc["error_page_names"] == ["shop-only"],
   "the Services API reports them, with their names")
shop["error_pages"] = []
c = load_config(); c["haproxy"]["backends"] = [b if b["name"] != "shop" else shop for b in c["haproxy"]["backends"]]; save_config(c)

# ---- renamed, deleted, and written back before a check ---------------------------
r = client.put("/api/haproxy/errorpages/" + own["id"], headers=H,
               json={"name": "closed", "codes": "503", "everywhere": True, "html": "<p>Closed.</p>"})
ok(r.status_code == 200 and on_disk() == ["closed-503.html", "closed-503.http"],
   "renaming a page replaces its files; the old name's are gone: %s" % ", ".join(on_disk()))
for p in list(ERROR_DIR.iterdir()):
    p.unlink()
# A listener published without a certificate binds the certificate directory,
# which HAProxy wants to exist with something in it: the stand-in Apply would make.
CERT_DIR.mkdir(parents=True, exist_ok=True)
apply._selfsigned_placeholder(CERT_DIR / "stand-in.pem", ["stand-in"])
good, msg = apply.check_rendered(load_config())
ok(on_disk() == [], "a settings check writes nothing for real: haproxy -c reads staged copies")
ok(good, "and the check passes: " + msg.splitlines()[0])
res = apply.do_apply(load_config(), allow_push=False)
ok(res.get("ok") and on_disk() == ["closed-503.html", "closed-503.http"],
   "Apply writes them, after the check: %s" % ", ".join(res.get("steps", [])))
r = client.delete("/api/haproxy/errorpages/" + own["id"], headers=H)
ok(r.status_code == 200 and on_disk() == [], "deleting the last page leaves nothing on disk")
ok("errorfile" not in haproxy.render_haproxy(load_config()), "and nothing in the file")

# ---- the rendered file is one HAProxy accepts, pages and all -----------------------
post("haproxy/errorpages", {"name": "again", "codes": "503 404", "everywhere": True,
                            "html": "<!doctype html><title>{error_code}</title><p>{error_message}</p>"})
c = load_config()
next(b for b in c["haproxy"]["backends"] if b["name"] == "shop")["maintenance"] = True
save_config(c)
text = haproxy.render_haproxy(load_config())
fd, path = tempfile.mkstemp(suffix=".cfg")
with os.fdopen(fd, "w") as f:
    f.write(text)
try:
    r = subprocess.run(["haproxy", "-c", "-f", path], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        ok("errorfile" not in (r.stderr + r.stdout),
           "haproxy -c accepts the pages without a word about them")
    else:
        ok(False, "haproxy -c: " + (r.stderr or r.stdout).strip()[-300:])
except FileNotFoundError:
    print("  ....  no haproxy here; the text checks above stand")
finally:
    os.unlink(path)

print("\n" + ("%d failed" % len(fails) if fails else "a page in the configuration is a file on every node"))
sys.exit(1 if fails else 0)
