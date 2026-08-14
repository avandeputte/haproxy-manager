#!/usr/bin/env python3
"""Traffic history, and telling someone when a service loses its servers.

    HAM_DATA_DIR=/tmp/x python3 tools/test-traffic.py
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-traffic-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham                                   # noqa: E402  (route registration)
from ham import auth, notify, traffic             # noqa: E402
from ham.config import load_config                # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


def stats_for(up, total, req=0, e5=0, pool="be_shop"):
    return {"ok": True, "backends": [{
        "proxy": pool, "servers_up": up, "servers_total": total,
        "stot": str(req), "hrsp_4xx": "0", "hrsp_5xx": str(e5), "econ": "0",
        "eresp": "0", "scur": "1",
        "servers": [{"name": "web%d" % i, "addr": "10.0.0.%d:80" % i,
                     "status": "UP" if i <= up else "DOWN",
                     "check_status": "L7OK" if i <= up else "L4CON"}
                    for i in range(1, total + 1)]}]}


sent = []
notify.send_to = lambda dest, subject, body, severity="warning", event="": (
    sent.append((subject, severity)), (True, ""))[1]

cfg = load_config()
cfg["notify"] = {"enabled": True, "repeat_hours": 24, "min_severity": "warning",
                 "destinations": [{"id": "d", "name": "t", "type": "webhook",
                                   "url": "http://example.invalid/", "enabled": True,
                                   "events": ["service"]}]}

# -- what gets said, and when ----------------------------------------------
traffic.check_services(cfg, stats_for(2, 2))
sent.clear()
traffic.check_services(cfg, stats_for(0, 2))
ok(len(sent) == 1 and "no servers left" in sent[0][0],
   "a service losing every server is reported once: %s" % (sent,))
traffic.check_services(cfg, stats_for(0, 2))
traffic.check_services(cfg, stats_for(0, 2))
ok(len(sent) == 1, "and not repeated while it stays down")
traffic.check_services(cfg, stats_for(1, 2))
ok(len(sent) == 2 and "1 of 2" in sent[1][0],
   "losing some of them is a different thing to say: %s" % (sent[-1:],))

# Recoveries are informational and the severity floor defaults to warning, so
# without care someone is told what broke and never that it came back -- which
# is worse than silence, because it leaves them thinking it is still broken.
traffic.check_services(cfg, stats_for(2, 2))
ok(len(sent) == 3 and "healthy again" in sent[2][0] and sent[2][1] == "info",
   "coming back is sent even though it is below the severity floor")

notify._notify_state.clear()
sent.clear()
traffic.check_services(cfg, stats_for(2, 2))
ok(sent == [], "but a recovery for something never reported is not sent")

# -- who says it -----------------------------------------------------------
sent.clear()
notify._notify_state.clear()
traffic.stats.haproxy_stats = lambda: stats_for(0, 2)
auth.node_role = lambda c: ("passive", [])
traffic.poll(cfg)
ok(sent == [], "a passive node says nothing about the services")
auth.node_role = lambda c: ("active", ["10.0.0.10"])
traffic.poll(cfg)
ok(len(sent) == 1, "the node holding the virtual IP does")
sent.clear()
notify._notify_state.clear()
auth.node_role = lambda c: ("standalone", [])
traffic.check_services(cfg, stats_for(0, 2))
ok(len(sent) == 1, "and so does a node that is on its own")

sent.clear()
traffic.check_services(cfg, {"ok": True, "backends": [
    {"proxy": "bk_acme_challenge", "servers_up": 0, "servers_total": 1, "servers": []}]})
ok(sent == [], "the app's own acme pool is not a service anybody published")

# -- what losing a server means is the pool's own business -------------------
# A Patroni pool is designed to have one server passing its check -- the check
# IS the routing -- so "down to 1 of 3" is its healthy state, and reporting it
# as degraded cried wolf on every round. Its news is nobody passing at all.
sent.clear()
notify._notify_state.clear()
cfg["haproxy"]["backends"] = [{"id": "pg", "name": "shop", "servers": [],
                               "notify_mode": "outage"}]
traffic.check_services(cfg, stats_for(1, 3))
ok(sent == [], "an outage-only pool with one of three passing is healthy, not degraded")
traffic.check_services(cfg, stats_for(0, 3))
ok(len(sent) == 1 and "no servers left" in sent[0][0],
   "losing the last one is still the emergency it always was")
traffic.check_services(cfg, stats_for(1, 3))
ok(len(sent) == 2 and "serving again" in sent[1][0],
   "and one server coming back closes it: %s" % (sent[-1:],))
ok("meant to run" not in sent[1][0], "with a subject that does not overclaim")

sent.clear()
notify._notify_state.clear()
cfg["haproxy"]["backends"][0]["notify_mode"] = "off"
traffic.check_services(cfg, stats_for(0, 3))
traffic.check_services(cfg, stats_for(3, 3))
ok(sent == [], "a pool set to never is never spoken about, even for an outage")

sent.clear()
notify._notify_state.clear()
cfg["haproxy"]["backends"][0]["notify_mode"] = "servers"
traffic.check_services(cfg, stats_for(1, 3))
ok(len(sent) == 1 and "1 of 3" in sent[0][0],
   "the default still treats any lost server as news")
cfg["haproxy"]["backends"] = []
notify._notify_state.clear()

# -- the history -----------------------------------------------------------
traffic._state.update({"loaded": True, "at": [], "series": {}, "last": {}, "sampled": 0.0})
traffic.record(stats_for(2, 2, req=100))
traffic.record(stats_for(2, 2, req=160))
traffic.record(stats_for(2, 2, req=200, e5=3))
h = traffic.history()
ok(h["series"]["be_shop"]["req"] == [0, 60, 40],
   "requests are stored per interval, not as a running total: %s"
   % h["series"]["be_shop"]["req"])
ok(h["series"]["be_shop"]["e5"] == [0, 0, 3], "and so are the errors")
ok(len(h["at"]) == 3, "every sample carries its timestamp")

traffic.record(stats_for(2, 2, req=5))
ok(traffic.history()["series"]["be_shop"]["req"][-1] == 0,
   "a counter that has gone backwards is a restart, not negative traffic")

# A pool that appears later must not have its history line up with the wrong
# minute, so shorter series are padded to the timeline.
traffic.record(stats_for(1, 1, req=10, pool="be_new"))
h = traffic.history()
ok(len(h["series"]["be_new"]["req"]) == len(h["at"]),
   "a pool that appears later is padded to the same timeline")
ok(h["series"]["be_new"]["up"][-1] == 1 and h["series"]["be_new"]["up"][0] == 0,
   "and padded at the front, where the pool did not exist -- not at the end, "
   "which would slide its history backwards in time: %s" % h["series"]["be_new"]["up"])
ok(h["series"]["be_shop"]["up"][-1] == 0,
   "a pool that has gone quiet shows the gap at the end")

traffic.KEEP_SAMPLES = 3
traffic.record(stats_for(2, 2, req=300))
h = traffic.history()
ok(len(h["at"]) == 3, "the window is bounded: %d samples kept" % len(h["at"]))
ok(all(len(v) == 3 for v in h["series"]["be_shop"].values()),
   "and every series is trimmed with it")

print()
print("traffic history and service alerts behave" if not fails
      else "%d failed" % len(fails))
sys.exit(1 if fails else 0)
