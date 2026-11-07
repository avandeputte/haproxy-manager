#!/usr/bin/env python3
"""What a large installation pays per page, held down.

    HAM_DATA_DIR=/tmp/x python3 tools/test-perf.py

Issue #16 was one of these: 62 services, and the Services page took six
seconds. The ones found looking for the next: the whole day of traffic for
every pool went to the browser for sparklines 110 pixels wide; every open tab
fetched a tag for every shared object every ten seconds; the traffic history
was rewritten in full every minute; the History page parsed fifty snapshots
on each visit; and the URL probes ran one at a time, each waiting out its own
timeout. Each is checked here as a count or a size, not a time, so a slow
runner cannot fail it -- except the probes, where parallel is the point.
"""
import json
import os
import pathlib
import socket
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-perf-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import apply, cluster, history, peering, probe, traffic   # noqa: E402
from ham.config import HISTORY_KEEP, load_config, save_config, shared_objects   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "perf-key"
save_config(cfg)
H = {"X-API-Key": "perf-key"}

N = 60
for i in range(N):
    r = client.post("/api/wizard/publish", headers=H, json={
        "url": "https://svc%d.example.com" % i, "target": "10.0.0.%d:80" % (i + 1),
        "certificate": False, "dry_run": False})
    if r.status_code != 200:
        ok(False, "publishing svc%d: %s" % (i, r.get_json()))
        break

# ---- the traffic history, narrowed ------------------------------------------------
S = traffic.KEEP_SAMPLES
# The newest sample half a minute ago, so "the last hour" is a whole number of
# samples however long the checks between here and there take.
newest = int(time.time()) - 30
traffic._state.update({
    "loaded": True, "last": {}, "sampled": 0.0, "saved": 0.0, "unsaved": False,
    "at": [newest - (S - 1 - i) * 60 for i in range(S)],
    "series": {"be_a": {"req": list(range(S)), "e5": [1] * S, "e4": [0] * S,
                        "econn": [0] * S, "eresp": [0] * S, "cur": [2] * S,
                        "up": [2] * S, "of": [2] * S},
               "be_b": {"req": [0] * S, "e5": [0] * S, "e4": [0] * S,
                        "econn": [0] * S, "eresp": [0] * S, "cur": [0] * S,
                        "up": [1] * S, "of": [1] * S}}})

full = client.get("/api/traffic", headers=H).get_json()
ok(len(full["at"]) == S and len(full["series"]["be_a"]["req"]) == S and full["bucket"] == 60
   and len(full["series"]["be_a"]) == 8,
   "asked for nothing in particular, the whole day comes as before")

h = client.get("/api/traffic?series=req,e5&points=110", headers=H).get_json()
row = h["series"]["be_a"]
ok(sorted(row) == ["e5", "req"], "only the series asked for: %r" % sorted(row))
ok(len(h["at"]) <= 110 and len(row["req"]) == len(h["at"]),
   "at most the points asked for, timestamps to match: %d" % len(h["at"]))
ok(h["at"][-1] == newest and h["bucket"] == 60 * -(-S // 110),
   "the last point is the newest minute, and the bucket says how many minutes a point is: %ds"
   % h["bucket"])
spans = traffic._buckets(S, 110)
ok(spans[0][0] == 0 and spans[-1][1] == S and len(spans) <= 110
   and all(e - s == spans[-1][1] - spans[-1][0] for s, e in spans[1:]),
   "the buckets cover the day end to end, only the oldest one short: %d of them" % len(spans))
ok(row["req"] == [e - 1 for _s, e in spans],
   "each point is the busiest minute of its bucket, so a spike stays a spike")
ok(h["totals"]["be_a"] == {"req": sum(range(S)), "e5": S},
   "and the totals are counted from every minute, not from the points: %r" % h["totals"]["be_a"])
ok(len(json.dumps(h)) * 10 < len(json.dumps(full)),
   "which is a tenth of the size or less: %d against %d bytes"
   % (len(json.dumps(h)), len(json.dumps(full))))

seven = traffic.history(points=7)
ok(len(seven["at"]) == 7 and seven["series"]["be_a"]["req"][-1] == S - 1,
   "a count that does not divide the day still gives that many points, newest last")
ok(len(traffic.history(minutes=60, points=110)["at"]) == 60,
   "a window shorter than the points asked for is sent as it is")
ok(len(client.get("/api/traffic?points=1", headers=H).get_json()["at"]) == 2
   and len(client.get("/api/traffic?points=x", headers=H).get_json()["at"]) == S,
   "one point is made two, and nonsense means the whole day")

# ---- written every ten minutes, and when stopping ------------------------------------
writes = []
real_save = traffic._save
traffic._save = lambda: (writes.append(1), real_save())
sample = {"ok": True, "backends": [{"proxy": "be_a", "servers_up": 2, "servers_total": 2,
                                    "stot": "9", "hrsp_4xx": "0", "hrsp_5xx": "0",
                                    "econ": "0", "eresp": "0", "scur": "1"}]}
traffic._state["saved"] = time.time()
traffic.record(sample)
ok(not writes and traffic._state["unsaved"], "a sample a minute does not go to disk each time")
traffic._state["saved"] = time.time() - traffic.SAVE_SECONDS
traffic.record(sample)
ok(len(writes) == 1 and not traffic._state["unsaved"], "after ten minutes it does")
traffic.flush()
ok(len(writes) == 1, "stopping with nothing new writes nothing")
traffic.record(sample)
traffic.flush()
ok(len(writes) == 2, "stopping with a sample unsaved writes it")
d = json.loads(traffic.TRAFFIC_PATH.read_text())
ok(len(d["at"]) == len(traffic._state["at"]), "and the file holds every sample")
traffic._save = real_save

# ---- the status the browser polls ----------------------------------------------------
full = client.get("/api/status", headers=H).get_json()
brief = client.get("/api/status?brief=1", headers=H).get_json()
ok(sum(len(v) for v in full["config_objects"].values()) >= N and "brief" not in full,
   "the full status tags every shared object, for the nodes to compare")
ok(brief["config_objects"] == {} and brief["brief"] is True,
   "the brief one leaves them out and says so")
ok(set(full) == set(brief) - {"brief"}, "and carries everything else")
ok(len(json.dumps(brief)) * 5 < len(json.dumps(full)),
   "at a fifth of the size or less with %d services: %d against %d bytes"
   % (N, len(json.dumps(brief)), len(json.dumps(full))))
ok(shared_objects(load_config(), limit=1) is None,
   "over the cap, the tags are None -- distinct from a node that has none")
real_objects = apply.shared_objects
apply.shared_objects = lambda cfg: None
capped = client.get("/api/status", headers=H).get_json()
apply.shared_objects = real_objects
ok(capped["config_objects"] == {} and capped["config_objects_capped"] is True
   and full["config_objects_capped"] is False,
   "and the status says the cap was hit")

# ---- the cluster asks brief, and in full only when the nodes disagree ----------------
cfg = load_config()
cfg["local"]["sync"]["peers"] = [
    {"id": "p2", "name": "node2", "url": "https://10.9.9.2:8080", "api_key": "x", "enabled": True},
    {"id": "p3", "name": "node3", "url": "https://10.9.9.3:8080", "api_key": "x", "enabled": True}]
save_config(cfg)
me = client.get("/api/status?brief=1", headers=H).get_json()
my_fp, my_rev = me["config_fp"], me["config_rev"]
calls, fps = [], {}


def fake_query(peer, timeout=None, brief=False):
    calls.append((peer["id"], brief))
    return {"id": peer["id"], "name": peer["name"], "url": peer["url"], "self": False,
            "reachable": True, "error": "", "ms": 1, "hostname": peer["name"],
            "version": "1.100.2", "role": "passive", "haproxy": "active",
            "keepalived": "disabled", "vips": [], "vip_held": [], "dirty": False,
            "config_rev": my_rev, "config_fp": fps[peer["id"]], "config_parts": {},
            "config_objects": {} if brief else {"haproxy.backends": [["b", "b", "ffff"]]},
            "brief": brief, "config_objects_capped": False, "config_leak": None,
            "update_available": False, "certs_total": 0, "certs_bad": 0}


real_query = peering._query_peer
peering._query_peer = fake_query
fps.update(p2=my_fp, p3=my_fp)
snap = cluster.cluster_snapshot()
ok(calls == [("p2", True), ("p3", True)] and snap["summary"]["config_agreed"],
   "nodes that agree are asked once each, briefly: %r" % calls)
calls.clear()
fps.update(p3="0000000000000000")
snap = cluster.cluster_snapshot()
ok(sorted(calls) == [("p2", False), ("p2", True), ("p3", False), ("p3", True)]
   and not snap["summary"]["config_agreed"],
   "nodes that disagree are asked again in full, so the page can name the object: %r" % calls)
ok(all(n["config_objects"] for n in snap["nodes"] if not n["self"]),
   "and the snapshot holds the full answers")
peering._query_peer = real_query
cfg = load_config()
cfg["local"]["sync"]["peers"] = []
save_config(cfg)

# ---- the History page parses each snapshot once -----------------------------------
parsed = []
real_load_view = history._load_view
history._load_view = lambda p: (parsed.append(p.name), real_load_view(p))[1]
first = client.get("/api/history", headers=H).get_json()["snapshots"]
files = len(parsed)
ok(files == len(first) and files > 10, "the first visit reads every snapshot: %d" % files)
parsed.clear()
second = client.get("/api/history", headers=H).get_json()["snapshots"]
ok(not parsed, "the next reads none")
ok(second == first, "and says the same: counts, summaries, which is current")
client.post("/api/wizard/publish", headers=H, json={
    "url": "https://one-more.example.com", "target": "10.0.1.1:80",
    "certificate": False, "dry_run": False})
parsed.clear()
third = client.get("/api/history", headers=H).get_json()["snapshots"]
ok(len(third) == min(len(first) + 1, HISTORY_KEEP) and 1 <= len(parsed) <= 2 and third[0]["summary"],
   "a new snapshot is read, with the one before it for the summary: %r" % parsed)
oldest = history._history_files()[0]
oldest_key = history._stamp(oldest)
oldest.unlink()
parsed.clear()
fourth = client.get("/api/history", headers=H).get_json()["snapshots"]
ok(not parsed and len(fourth) == len(third) - 1 and oldest_key not in history._facts
   and not any(k[0] == oldest_key for k in history._summaries),
   "a snapshot that is gone is forgotten, not kept")
history._load_view = real_load_view

# ---- the URL probes, side by side -------------------------------------------------------
# A listener that never accepts: the handshake completes in the kernel and the
# request is never answered, which is what a hung backend looks like.
hung = socket.socket()
hung.bind(("127.0.0.1", 0))
hung.listen(16)
port = hung.getsockname()[1]
entries = [{"kind": "http", "url": "http://hung%d.example.com" % i, "host": "127.0.0.1",
            "port": port, "path": "/", "pool": "be_hung"} for i in range(8)]
probe.TIMEOUT = 1
began = time.time()
probe._run(load_config(), entries)
took = time.time() - began
results = probe._state["results"]
ok(all(r["state"] == "down" for r in results) and len(results) == 8,
   "eight hung URLs are all reported down")
ok(took < 4, "in about one timeout rather than eight: %.1fs" % took)
ok([r["url"] for r in results] == [e["url"] for e in entries],
   "and listed in the order they were given")
hung.close()

print("\n" + ("%d failed" % len(fails) if fails else "a large installation pays once, not per object"))
sys.exit(1 if fails else 0)
