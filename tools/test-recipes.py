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
    # every recipe brings its own example servers now
    if not f.get("target"):
        fail.append("%s: no example servers" % r["id"])
        f["target"] = "10.9.0.%d:8080" % (i + 1)
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
# the example servers must survive into the backend, with the right count
counts = {"web":1, "web-websockets":2, "patroni-primary":3, "patroni-replicas":3,
          "galera":3, "postgresql-plain":1, "redis":1, "mongodb":1,
          "elasticsearch":3, "minio":4, "rabbitmq":3, "kubernetes-api":3,
          "smtp":2, "ldap":2, "proxmox":2, "nextcloud":2, "home-assistant":1,
          "grafana":2, "prometheus":1, "gitea":1, "gitlab":1, "jellyfin":1,
          "vaultwarden":1, "mattermost":2, "keycloak":2, "docker-registry":1}
for rid, want in counts.items():
    block = next((c for c in cfg.split("\nbackend ") if c.startswith("be_"+rid+"\n")), "")
    got = block.count("\n    server ")
    print("  %-22s %d server(s)%s" % (rid, got, "" if got == want else "  EXPECTED %d" % want))
    if got != want:
        fail.append("%s: %d servers, expected %d" % (rid, got, want))

print()
checks = [
  ("patroni-primary",  "option httpchk", "/primary", "port 8008"),
  ("keycloak",         "option httpchk", "/health/ready", "port 9000"),
  ("proxmox",          "ssl"),
  ("nextcloud",        "/status.php", "timeout server 1h"),
  ("grafana",          "/api/health"),
  ("jellyfin",         "timeout server 4h"),
  ("ldap",             "check"),
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
