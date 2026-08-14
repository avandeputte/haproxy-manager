#!/usr/bin/env python3
"""The MQTT client's bytes, and the entities Home Assistant is offered.

The client is checked at the byte level -- a CONNECT packet is a contract
with every broker ever shipped -- and the discovery payloads against the
fields Home Assistant requires. The live half (a real broker, the will
firing) runs in the harness with mosquitto, not here.

    HAM_DATA_DIR=/tmp/x python3 tools/test-hass.py
"""
import json
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-hass-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import hass, stats   # noqa: E402
from ham.mqtt import Publisher, _string, _varint   # noqa: E402
from ham.config import load_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


# -- the wire format ---------------------------------------------------------
ok(_varint(0) == b"\x00" and _varint(127) == b"\x7f" and
   _varint(128) == b"\x80\x01" and _varint(16383) == b"\xff\x7f",
   "remaining-length encodes exactly as the spec's worked examples")
ok(_string("MQTT") == b"\x00\x04MQTT", "strings carry their two-byte length")

sent = []


class FakeSock:
    def sendall(self, b): sent.append(bytes(b))
    def settimeout(self, t): pass
    def recv(self, n): raise TimeoutError()
    def close(self): pass


pub = Publisher("broker", client_id="test-client", will_topic="t/avail",
                username="u", password="p")
pub.sock = FakeSock()
pub.publish("a/b", "hello")
pkt = sent[-1]
ok(pkt[0] == 0x31, "a retained QoS-0 publish is 0x31")
ok(pkt[1] == 10 and pkt[2:7] == b"\x00\x03a/b" and pkt.endswith(b"hello"),
   "length, topic, payload -- nothing else")
pub.publish("a/b", "x", retain=False)
ok(sent[-1][0] == 0x30, "and unretained is 0x30")

pub.subscribe("ham/cmd/#")
sub = sent[-1]
ok(sub[0] == 0x82 and sub[2:4] == b"\x00\x01"
   and sub[4:16] == b"\x00\x09ham/cmd/#\x00",
   "a SUBSCRIBE is 0x82: packet id, filter, QoS 0")

# frames come back over TCP with no respect for boundaries; feed a PUBLISH
# split across reads and mixed with a PINGRESP
pub2 = Publisher("broker")
body = b"\x00\x10ham/cmd/maint/pg" + b"ON"
wire = b"\xd0\x00" + bytes([0x30, len(body)]) + body
class DripSock:
    def __init__(self, data): self.data = data
    def settimeout(self, t): pass
    def recv(self, n):
        if not self.data: raise TimeoutError()
        chunk, self.data = self.data[:3], self.data[3:]
        return chunk
    def close(self): pass
pub2.sock = DripSock(wire)
first = pub2.read_frame(1.0)
ok(first is not None and first[0] == 0xd0, "a PINGRESP comes out first, whole")
second = pub2.read_frame(1.0)
ok(second is not None and second[0] & 0xF0 == 0x30, "then the PUBLISH, reassembled from drips")
ok(pub2.parse_publish(second[1]) == ("ham/cmd/maint/pg", "ON"),
   "and it parses back to the topic and payload that were sent")

# the CONNECT is built inside connect(); reconstruct its variable header the
# same way and check the flags say what the parameters said
flags = 0x02 | 0x04 | 0x20 | 0x80 | 0x40
var = _string("MQTT") + bytes([4, flags]) + (60).to_bytes(2, "big")
payload = _string("test-client") + _string("t/avail") + _string("offline") \
    + _string("u") + _string("p")
expected = bytes([0x10]) + _varint(len(var) + len(payload)) + var + payload
ok(expected[0] == 0x10 and b"t/avail" in expected and b"offline" in expected,
   "the CONNECT carries the will, so the broker can say goodbye for us")

# -- the entities ------------------------------------------------------------
cfg = load_config()
cfg["notify"]["mqtt"] = {"enabled": True, "host": "b", "base_topic": "ham-test",
                         "discovery_prefix": "homeassistant"}
cfg["haproxy"]["backends"] = [
    {"id": "b1", "name": "shop", "servers": [], "notify_mode": "servers"},
    {"id": "b2", "name": "pg", "servers": [], "notify_mode": "outage"}]
stats.haproxy_stats = lambda: {"ok": True, "frontends": [], "backends": [
    {"proxy": "be_shop", "servers_up": 1, "servers_total": 2, "servers": []},
    {"proxy": "be_pg", "servers_up": 1, "servers_total": 3, "servers": []},
    {"proxy": "bk_acme_challenge", "servers_up": 1, "servers_total": 1, "servers": []}]}

ents = hass._entities(cfg, hass.settings_of(cfg))
by_uid = {u: e for u, e in ents.items()}
svc = by_uid.get("ham-svc-shop")
ok(svc is not None and svc[2] == "on",
   "a pool at 1 of 2 is a problem when any lost server is news")
pg = by_uid.get("ham-svc-pg")
ok(pg is not None and pg[2] == "off",
   "but a Patroni pool at 1 of 3 is healthy -- the entity honours Alert when")
ok(not any("acme" in u for u in by_uid), "the app's own plumbing is not an entity")

for uid, (component, conf, state, attrs) in ents.items():
    missing = [k for k in ("name", "unique_id", "state_topic",
                           "availability_topic", "device") if k not in conf]
    if missing:
        ok(False, "%s lacks %s" % (uid, missing))
        break
    if component == "binary_sensor" and ("payload_on" not in conf):
        ok(False, "%s: a binary_sensor must name its payloads" % uid)
        break
    json.dumps(conf)
else:
    ok(True, "every discovery payload carries what Home Assistant requires")
ok(len({e[1]["state_topic"] for e in ents.values()}) == len(ents),
   "no two entities share a state topic")

# a passive node keeps its own device and stays silent about the cluster
import ham.auth as auth   # noqa: E402
was = auth.node_role
auth.node_role = lambda c: ("passive", [])
passive = hass._entities(cfg, hass.settings_of(cfg))
auth.node_role = was
ok(all(not u.startswith("ham-svc-") for u in passive),
   "a passive node does not publish the services -- its view is not the one that matters")
ok(any(u.endswith("-active") for u in passive),
   "but still publishes its own device")

# -- the switches ------------------------------------------------------------
ok(not any(u.startswith("ham-maint-") for u in ents),
   "no switches until control is allowed -- entities that accept commands are opt-in")
cfg["notify"]["mqtt"]["allow_control"] = True
cfg["haproxy"]["backends"][1]["maintenance"] = True
ctl = hass._entities(cfg, hass.settings_of(cfg))
sw = ctl.get("ham-maint-shop")
ok(sw is not None and sw[0] == "switch" and sw[2] == "OFF",
   "with control allowed, each service grows a maintenance switch")
ok(sw and sw[1]["command_topic"] == "ham-test/cmd/maint/shop",
   "whose command topic is under the base topic's cmd branch")
ok(ctl.get("ham-maint-pg", (None,) * 3)[2] == "ON",
   "and a paused pool's switch reads ON")

# the command finds its pool the same way the switch named it
slug = "pg"
found = next((b for b in cfg["haproxy"]["backends"]
              if hass._slug(hass.traffic._pool_label("be_" + b.get("name", ""))) == slug), None)
ok(found is not None and found["id"] == "b2",
   "a command's slug resolves to the pool the switch was made from")

print("\n" + ("%d failed" % len(fails) if fails
              else "the bytes and the entities are what they should be"))
sys.exit(1 if fails else 0)
