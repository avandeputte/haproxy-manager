#!/usr/bin/env bash
# Refresh the fixtures in navigate.mjs from a real node, so the shapes the
# pages are tested against are the shapes the API actually returns.
#   ./tools/uitests/capture-fixtures.sh http://127.0.0.1:8080 user password
set -eu
BASE=${1:?base url}; USER=${2:?username}; PASS=${3:?password}
JAR=$(mktemp)
curl -s -c "$JAR" -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
     -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" -o /dev/null
python3 - "$BASE" "$JAR" <<'PY'
import json, subprocess, sys, pathlib
base, jar = sys.argv[1], sys.argv[2]
eps = ["status","whoami","cluster","cluster/settings","keepalived/status","local",
       "stats","watchdog","notify","version","preview","webui","setup/state",
       "acme/health","acme/cover","logs","peers","services","acme/dnsapi",
       "update/log","cluster/unicast"]
real = {}
for ep in eps:
    out = subprocess.run(["curl","-s","-b",jar,base+"/api/"+ep],capture_output=True,text=True).stdout
    try: real[ep] = json.loads(out)
    except Exception: pass
p = pathlib.Path("tools/uitests/navigate.mjs"); s = p.read_text()
start = s.index("const FIXTURES = {"); end = s.index("};", start)+2
p.write_text(s[:start] + "const FIXTURES = " + json.dumps(real, indent=2, sort_keys=True) + ";" + s[end:])
print("captured %d endpoints" % len(real))
PY
