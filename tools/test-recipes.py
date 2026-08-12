"""Publish every recipe against a running node and read what it generated.

A recipe that produces a configuration HAProxy rejects, or that quietly loses
its health check, is worse than no recipe at all -- someone would trust it.

    python3 tools/test-recipes.py http://127.0.0.1:8080 admin password
"""
import json, sys, urllib.request, http.cookiejar
B = sys.argv[1]
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
def call(p, m="GET", b=None):
    d = json.dumps(b).encode() if b is not None else None
    r = urllib.request.Request(B+p, data=d, method=m, headers={"Content-Type":"application/json"})
    try:
        resp = op.open(r, timeout=120); t = resp.read().decode(); c = resp.status
    except urllib.error.HTTPError as e:
        t = e.read().decode(); c = e.code
    return c, (json.loads(t) if t.strip()[:1] in "{[" else t)

user = sys.argv[2] if len(sys.argv) > 2 else "a"
password = sys.argv[3] if len(sys.argv) > 3 else "recipepass1"
call("/api/login", "POST", {"username": user, "password": password})
recipes = call("/api/recipes")[1]["recipes"]
fail = []
for i, r in enumerate(recipes):
    f = dict(r["fields"])
    f["name"] = r["id"]
    f.setdefault("target", "10.9.0.%d:%s" % (i+1, "8080"))
    # give each one a distinct listener so they can coexist
    url = f.get("url", "")
    if url.startswith("tcp://"):
        port = int(url.rsplit(":",1)[1]) + i
        f["url"] = "tcp://0.0.0.0:%d" % port
    else:
        f["url"] = "https://%s.example.com" % r["id"]
    f.pop("cert_mode", None)
    f["apply"] = False
    # the wizard takes health_* as a nested object
    health = {"type": f.pop("health", "none"),
              "interval": f.pop("health_interval", ""), "uri": f.pop("health_uri", ""),
              "status": f.pop("health_status", ""), "method": f.pop("health_method", ""),
              "version": f.pop("health_version", ""), "host": f.pop("health_host", ""),
              "user": f.pop("health_user", "")}
    f["health"] = {k: v for k, v in health.items() if v}
    code, res = call("/api/wizard/publish", "POST", f)
    if code != 200 or res.get("ok") is False:
        fail.append("%s: %s" % (r["id"], str(res)[:120])); continue
    print("  published %-22s" % r["id"])

code, prev = call("/api/preview")
cfg = prev["haproxy"]
def has(rid, *needles):
    block = ""
    for chunk in cfg.split("\nbackend "):
        if chunk.startswith("be_"+rid) or ("\n" in chunk and chunk.split("\n")[0].strip()=="be_"+rid):
            block = chunk; break
    missing = [n for n in needles if n not in block]
    if missing:
        fail.append("%s: config lacks %s" % (rid, missing))
    return not missing

print()
checks = [
  ("patroni-primary",  "option httpchk", "/primary", "port 8008"),
  ("patroni-replicas", "option httpchk", "/replica", "port 8008"),
  ("galera",           "option mysql-check", "balance source", "stick"),
  ("postgresql-plain", "option pgsql-check"),
  ("redis",            "check"),
  ("elasticsearch",    "option httpchk", "/_cluster/health"),
  ("minio",            "/minio/health/live"),
  ("kubernetes-api",   "check"),
  ("web-websockets",   "timeout server 1h"),
]
for rid, *needles in checks:
    print("  %-22s %s" % (rid, "ok" if has(rid, *needles) else "MISSING"))

# Apply for real: it creates the placeholder certificates an HTTPS bind needs,
# validates with haproxy -c and reloads -- the same path a person takes.
code, res = call("/api/apply", "POST", {})
print("\n  applied: %s" % res.get("ok"))
if not res.get("ok"):
    fail.append("apply: " + str(res.get("error") or res.get("haproxy_check"))[-300:])
print("\n" + ("FAILURES:\n  " + "\n  ".join(fail) if fail else "every recipe produces a working configuration"))
sys.exit(1 if fail else 0)
