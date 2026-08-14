#!/usr/bin/env python3
"""The grace period on "the nodes no longer hold the same configuration".

Saving a change makes the cluster disagree by design -- the peers catch up
when Apply pushes to them -- so an alert sent at the moment of divergence
names a problem that heals itself two clicks later. It went out anyway, after
a save and before the Apply. What is pinned here: nothing is said while the
disagreement is younger than the grace, it is said once it has stood longer,
and the all-clear closes the loop only when something was actually said.

    HAM_DATA_DIR=/tmp/x python3 tools/test-drift.py
"""
import os
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-drift-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (imported for its side effects)
from ham import cluster, notify   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


# Watch what notify() is asked to deliver, without any destination configured.
asked = []
real_notify = notify.notify


def watching(event, subject, body, severity="warning", cfg=None, force=False):
    asked.append({"subject": subject, "severity": severity, "force": force})
    return real_notify(event, subject, body, severity, cfg, force)


notify.notify = watching
cfg = load_config()
save_config(cfg)

DETAIL = "node2 holds an older configuration (revision 3 against 4)"

# -- fresh divergence says nothing -------------------------------------------
cluster._drift["since"] = None
notify._notify_state.pop("cluster:config", None)
cluster._report_drift(cfg, True, DETAIL)
ok(cluster._drift["since"] is not None, "divergence starts the clock")
ok(not asked, "and nothing is said while it is younger than the grace")

# -- healing inside the grace stays silent ------------------------------------
cluster._report_drift(cfg, False, "")
ok(cluster._drift["since"] is None, "agreement resets the clock")
ok(not asked, "a divergence that healed inside the grace was never worth an "
              "email, and neither is its healing")

# -- divergence that stands is said -------------------------------------------
cluster._report_drift(cfg, True, DETAIL)
cluster._drift["since"] = time.time() - cluster.CONFIG_DRIFT_GRACE - 300
cluster._report_drift(cfg, True, DETAIL)
ok(len(asked) == 1 and "not held the same configuration" in asked[0]["subject"],
   "one that has stood past the grace is reported")
ok("35 minutes" in asked[0]["subject"],
   "and the subject says how long, so the reader knows it is not "
   "the save they made a minute ago: %s" % asked[0]["subject"])
ok(cluster.CONFIG_DRIFT_GRACE == 30 * 60, "the grace is thirty minutes")

# -- repetition is the transition machinery's business, not a new email -------
cluster._report_drift(cfg, True, DETAIL)
ok(len(asked) == 1, "the next round does not send it again")

# -- healing afterwards closes the loop ---------------------------------------
# With no destination configured nothing was truly delivered, and an all-clear
# is only forced past the severity floor for an alert somebody received -- so
# mark the open report as delivered, the way a real one would be.
notify._notify_state["cluster:config"]["sent"] = True
cluster._report_drift(cfg, False, "")
ok(len(asked) == 2 and "same configuration again" in asked[1]["subject"],
   "agreement afterwards sends the all-clear")
ok(asked[1]["force"], "delivered as the close of an open report, so the "
                      "severity floor cannot swallow it")

# -- an unchanged divergence does not restart the clock -----------------------
cluster._drift["since"] = time.time() - 600
cluster._report_drift(cfg, True, DETAIL)
ok(time.time() - cluster._drift["since"] >= 600,
   "seeing the same divergence again does not restart the clock")

notify.notify = real_notify
print("\n" + ("%d failed" % len(fails) if fails
              else "drift is reported when it stands, not when it happens"))
sys.exit(1 if fails else 0)
