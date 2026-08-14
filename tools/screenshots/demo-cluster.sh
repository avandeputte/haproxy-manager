#!/usr/bin/env bash
# A three-node cluster holding made-up data, for the documentation screenshots.
#
# Everything in the pictures is the real application doing real work: VRRP
# elects an actual holder for the virtual IP, the health checks pass against
# listeners that exist, the certificates are issued by a throwaway CA and
# verify, and the URL probes resolve and connect. Nothing is mocked, because a
# picture of a page that cannot happen is worse than no picture.
#
#   docker build -t ham-shot .
#   docker network create --subnet 172.28.0.0/24 shotnet
#   for n in 1 2 3; do docker run -d --name proxy$n --hostname proxy$n \
#       --network shotnet --ip 172.28.0.1$n --cap-add NET_ADMIN \
#       --cap-add NET_BROADCAST --cap-add NET_RAW -p 1590$n:8080 ham-shot; done
#   bash tools/screenshots/demo-cluster.sh
#   OUT=/tmp/shots BASE=http://127.0.0.1:15901 node tools/screenshots/shoot.js
set -euo pipefail

N1=http://127.0.0.1:15901
PASS=demo-password-1
J=/tmp/shot1.jar

c(){ curl -s -b "$J" -H 'Content-Type: application/json' "$@"; }

echo "== accounts and identities"
for n in 1 2 3; do
  curl -s -c /tmp/shot$n.jar -H 'Content-Type: application/json' \
    -X POST http://127.0.0.1:1590$n/api/setup \
    -d "{\"username\":\"admin\",\"password\":\"$PASS\"}" >/dev/null
done

echo "== backend listeners the health checks can reach"
# Each "application server" is a python listener on nodes 2 and 3, so the
# targets in the pictures are addresses that answer.
for n in 2 3; do
  for port in 9401 9402 9403 9404 3306; do
    docker exec -d proxy$n python3 -m http.server $port --bind 0.0.0.0
  done
done

echo "== node 1 starts the cluster"
c -X POST $N1/api/setup/create -d '{
  "mode":"cluster","vips":"172.28.0.250/24","vrid":51,"interface":"eth0",
  "priority":150,"node_url":"http://proxy1:8080","api_key":"demo-key-proxy1-000",
  "auth_pass":"vrrp-pass","apply":true}' >/dev/null

echo "== nodes 2 and 3 join"
for n in 2 3; do
  curl -s -b /tmp/shot$n.jar -H 'Content-Type: application/json' \
    -X POST http://127.0.0.1:1590$n/api/setup/join -d "{
    \"peer_url\":\"http://proxy1:8080\",\"peer_api_key\":\"demo-key-proxy1-000\",
    \"node_url\":\"http://proxy$n:8080\",\"api_key\":\"demo-key-proxy$n-000\",
    \"interface\":\"eth0\",\"priority\":$((150 - n * 20))}" \
    | python3 -c "import sys,json;d=json.load(sys.stdin);print('   proxy$n:',d.get('ok'))"
done

echo "== users and groups"
GID=$(c -X POST $N1/api/access/groups -d '{"name":"staff"}' \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
c -X POST $N1/api/access/users -d "{\"username\":\"alice\",\"password\":\"demo-alice-pw\",\"groups\":[\"$GID\"]}" >/dev/null
c -X POST $N1/api/access/users -d '{"username":"bob","password":"demo-bob-pw","groups":[]}' >/dev/null

echo "== services"
pub(){ c -X POST $N1/api/wizard/publish -d "$1" \
       | python3 -c 'import sys,json;d=json.load(sys.stdin);print("  ",d.get("ok"),d.get("error","")[:70])'; }
pub '{"url":"https://shop.example.com","target":"http://172.28.0.12:9401, http://172.28.0.13:9401",
     "name":"shop","certificate":true,"health":{"type":"http","uri":"/","status":"200"},"apply":false}'
pub '{"url":"https://media.example.com","target":"http://172.28.0.12:9402","name":"media",
     "certificate":true,"health":{"type":"http","uri":"/","status":"200"},"apply":false}'
pub '{"url":"https://git.example.com","target":"http://172.28.0.13:9403","name":"git",
     "certificate":true,"health":{"type":"http","uri":"/","status":"200"},
     "auth":{"enabled":true,"groups":["'"$GID"'"],"realm":"Git"},"apply":false}'
pub '{"url":"https://grafana.example.com","target":"http://172.28.0.12:9404","name":"grafana",
     "certificate":true,"health":{"type":"http","uri":"/","status":"200"},
     "auth":{"enabled":true,"groups":[],"realm":"Grafana","exempt":"172.28.0.0/24"},"apply":false}'
pub '{"url":"tcp://0.0.0.0:3306","target":"galera1=172.28.0.12:3306, galera2=172.28.0.13:3306",
     "name":"galera","balance":"source","persistence":"source",
     "health":{"type":"tcp","interval":"3s"},"allow_src":"172.28.0.0/24","apply":false}'

echo "== the management UI's own name"
c -X POST $N1/api/webui -d '{"enabled":true,"url":"https://proxy1.example.com",
  "shared_url":"https://proxy.example.com","certificate":"auto","http_redirect":true,"apply":false}' \
  | python3 -c 'import sys,json;print("  ",json.load(sys.stdin).get("ok"))'

echo "== a throwaway CA, so the certificates verify"
docker exec -i proxy1 bash -s <<'EOF'
set -e
cd /tmp
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Demo Lab CA" \
  -keyout ca.key -out ca.crt 2>/dev/null
sign(){ # name, SANs...
  local name=$1; shift
  local sans=$(printf "DNS:%s," "$@"); sans=${sans%,}
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$1" \
    -keyout "$name.key" -out "$name.csr" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 30 -extfile <(echo "subjectAltName=$sans") -out "$name.crt" 2>/dev/null
  cat "$name.crt" "$name.key" > "/etc/haproxy/certs/$name.pem"
  chmod 600 "/etc/haproxy/certs/$name.pem"
}
mkdir -p /etc/haproxy/certs
sign shop shop.example.com
sign media media.example.com
sign git git.example.com
sign grafana grafana.example.com
sign haproxy-manager-ui proxy1.example.com proxy.example.com
# trust the CA, so the URL probes see certificates that verify
cp ca.crt /usr/local/share/ca-certificates/demo-lab-ca.crt
update-ca-certificates >/dev/null 2>&1 || true
# the published names resolve to this node
echo "127.0.0.1 shop.example.com media.example.com git.example.com grafana.example.com proxy1.example.com proxy.example.com" >> /etc/hosts
EOF

echo "== a day of plausible traffic, with one incident"
docker exec -i proxy1 python3 - <<'EOF'
import json, math, random, time
random.seed(7)
now = int(time.time()) - (int(time.time()) % 60)
n = 24 * 60
at = [now - (n - 1 - i) * 60 for i in range(n)]
series = {}
def pool(name, base, err_rate=0.001, incident=None, servers=2):
    req, e4, e5, up = [], [], [], []
    for i, t in enumerate(at):
        hour = (t % 86400) / 3600
        day = base * (0.35 + 0.65 * max(0.0, math.sin((hour - 6) / 24 * 2 * math.pi) + 0.6) / 1.6)
        r = max(0, int(random.gauss(day, day * 0.25)))
        bad5 = 1 if random.random() < err_rate else 0
        u = servers
        if incident and incident[0] <= i < incident[1]:
            bad5 = int(r * 0.7); u = 0
        req.append(r); e4.append(1 if random.random() < 0.02 else 0)
        e5.append(bad5); up.append(u)
    series[name] = {"req": req, "e4": e4, "e5": e5, "econn": [0]*n, "eresp": [0]*n,
                    "cur": [max(0, r // 8) for r in req], "up": up, "of": [servers]*n}
pool("be_shop", 55, servers=2)
pool("be_media", 30, incident=(n - 300, n - 280), servers=1)
pool("be_git", 12, servers=1)
pool("be_grafana", 8, servers=1)
pool("be_galera", 25, servers=2)
json.dump({"step": 60, "at": at, "series": series},
          open("/var/lib/haproxy-manager/traffic.json", "w"), separators=(",", ":"))
print("   seeded", n, "samples for", len(series), "pools")
EOF

echo "== apply everywhere and let it settle"
c -X POST $N1/api/apply -d '{}' | python3 -c 'import sys,json;print("   apply:",json.load(sys.stdin).get("ok"))'
docker exec proxy1 supervisorctl restart manager >/dev/null
sleep 5
curl -s -c "$J" -H 'Content-Type: application/json' -X POST $N1/api/login \
  -d "{\"username\":\"admin\",\"password\":\"$PASS\"}" >/dev/null
c -X POST $N1/api/sync/push -d '{}' | python3 -c 'import sys,json;d=json.load(sys.stdin);print("   sync:",d.get("ok"))'
echo "   waiting for probes and the cluster snapshot..."
sleep 70
c $N1/api/cluster | python3 -c 'import sys,json;d=json.load(sys.stdin);s=d["summary"];print("   cluster: %d/%d reachable, agreed: %s" % (s["reachable"],s["total"],s["config_agreed"]))'
c $N1/api/probes | python3 -c 'import sys,json;d=json.load(sys.stdin);print("   probes:", ["%s=%s" % (r["url"].split("//")[1].split(".")[0], r["state"]) for r in d["results"]])'
echo "ready -- shoot with: OUT=/tmp/shots BASE=$N1 node tools/screenshots/shoot.js"
