"""A day of traffic history, so "when did this start failing" has an answer."""

from datetime import datetime
from datetime import timezone
from flask import jsonify, request
import json
import os
import time

from .base import DATA_DIR, _lock, app, log
from .config import merged
from .util import _sec
from . import auth, notify, stats

# One sample a minute for a day. Enough to see when something began and how
# long it lasted; not enough to be a monitoring system, which is deliberate --
# this answers a question the live stats page cannot, and stops there.
STEP_SECONDS = 60
KEEP_SAMPLES = 24 * 60
TRAFFIC_PATH = DATA_DIR / "traffic.json"

# Counters read from HAProxy, and the name each is kept under. They are
# cumulative since the process started, so what is stored is the difference
# between samples: what happened during that minute.
COUNTERS = {"stot": "req", "hrsp_4xx": "e4", "hrsp_5xx": "e5",
            "econ": "econn", "eresp": "eresp"}
# And these are levels rather than counts: kept as they were at the sample.
LEVELS = {"scur": "cur"}

_state = {"loaded": False, "at": [], "series": {}, "last": {}, "sampled": 0.0}


def _load():
    if _state["loaded"]:
        return
    _state["loaded"] = True
    try:
        d = json.loads(TRAFFIC_PATH.read_text())
    except (OSError, ValueError):
        return
    if not isinstance(d, dict) or not isinstance(d.get("at"), list):
        return
    _state["at"] = d.get("at") or []
    _state["series"] = d.get("series") or {}
    log.info("traffic history: %d samples covering %s",
             len(_state["at"]), _span_text(_state["at"]))


def _span_text(at):
    if not at:
        return "nothing yet"
    minutes = int((at[-1] - at[0]) / 60)
    return "%dh%02dm" % (minutes // 60, minutes % 60)


def _save():
    """Written like the configuration: whole file, then renamed into place."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = TRAFFIC_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps({"step": STEP_SECONDS, "at": _state["at"],
                                   "series": _state["series"]}, separators=(",", ":")))
        os.replace(tmp, TRAFFIC_PATH)
    except OSError as e:
        log.warning("could not write the traffic history: %s", e)


def _delta(name, key, now):
    """What happened since the last sample.

    HAProxy's counters restart with HAProxy, so a value that has gone backwards
    means it was reloaded rather than that traffic was negative. The sample is
    counted as zero rather than as a spike of whatever the old total was.
    """
    was = _state["last"].get((name, key))
    _state["last"][(name, key)] = now
    if was is None or now < was:
        return 0
    return now - was


def record(data):
    """Add one sample of what HAProxy has just reported to the history.

    Every series gets exactly one value per timestamp, always: a pool that was
    not reported this time gets a zero, and a pool seen for the first time is
    filled with zeros back to the start. Guessing afterwards which end of a
    short series the gap belonged to cannot be done -- a new pool is missing
    values at the start and a departed one at the end, and they look identical.
    """
    _load()
    at = int(time.time())
    n = len(_state["at"])
    seen = set()
    for be in data.get("backends") or []:
        name = be.get("proxy")
        if not name:
            continue
        seen.add(name)
        new_pool = name not in _state["series"]
        row = _state["series"].setdefault(name, {})

        def put(key, value):
            values = row.get(key)
            if values is None:
                # Seen for the first time: nothing was happening here before,
                # which is exactly zero.
                values = row[key] = [0] * n
            values.append(value)

        for col, key in COUNTERS.items():
            try:
                put(key, _delta(name, key, int(be.get(col) or 0)))
            except ValueError:
                put(key, 0)
        for col, key in LEVELS.items():
            try:
                put(key, int(be.get(col) or 0))
            except ValueError:
                put(key, 0)
        put("up", int(be.get("servers_up") or 0))
        put("of", int(be.get("servers_total") or 0))
        if new_pool:
            log.debug("traffic history: first sample for %s", name)

    # A pool HAProxy did not report is a pool that served nothing this minute.
    for name, row in _state["series"].items():
        if name in seen:
            continue
        for values in row.values():
            values.append(0)

    _state["at"].append(at)
    _trim()
    _save()
    return True


def _trim():
    over = len(_state["at"]) - KEEP_SAMPLES
    if over <= 0:
        return
    _state["at"] = _state["at"][over:]
    for name, row in list(_state["series"].items()):
        for key, values in list(row.items()):
            row[key] = values[over:]
        # A pool with nothing in the whole window is gone; keeping it would
        # grow the file forever with services that no longer exist.
        if not any(sum(v) for k, v in row.items() if k in ("req", "e4", "e5")):
            del _state["series"][name]


def poll(cfg):
    """One read of the stats socket per watchdog round.

    Health is checked every round, because a service losing its servers is
    worth hearing about in seconds rather than at the next minute boundary.
    The history only takes a sample when a minute has passed -- reading the
    socket is cheap, storing a point a round would not be.
    """
    try:
        data = stats.haproxy_stats()
    except Exception:
        log.exception("traffic: reading the stats socket failed")
        return
    if not data.get("ok"):
        return
    # Only the node holding the virtual IP says anything about the services.
    # Every node runs the same health checks, so three nodes would send three
    # copies of every alert -- and a passive node's view is not the one that
    # matters: it is not carrying the traffic, and a server it cannot reach
    # may be perfectly reachable from the node that is.
    #
    # Faults about a node itself -- its HAProxy stopped, its certificate could
    # not be renewed -- still come from that node, because nobody else can see
    # them and silencing them would be silencing the only report there is.
    if auth.node_role(cfg)[0] != "passive":
        try:
            check_services(cfg, data)
        except Exception:
            log.exception("traffic: checking service health failed")
    if time.time() - _state["sampled"] >= STEP_SECONDS:
        _state["sampled"] = time.time()
        try:
            record(data)
        except Exception:
            log.exception("traffic history: sampling failed")


# Pools the app makes for its own plumbing rather than for a service.
INTERNAL_POOLS = ("bk_acme_challenge",)


def _pool_label(name):
    """be_shop is what HAProxy calls it; shop is what it is called here."""
    for prefix in ("be_", "bk_"):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def notify_modes(cfg):
    """Each pool's "Alert when" setting, keyed by the name HAProxy reports.

    Not every pool means the same thing by a failing server. A load-balanced
    pool losing one of three is degraded; a Patroni pool is *designed* to have
    one server passing and the rest failing -- the health check is doing the
    routing -- so "down to 1 of 3" is its healthy state, and the only news
    would be nobody passing at all.
    """
    return {"be_" + _sec(b.get("name") or ""): b.get("notify_mode") or "servers"
            for b in merged(cfg)["haproxy"]["backends"]}


def check_services(cfg, data):
    """Say when a service loses servers, and when it gets them back.

    From the health checks HAProxy is already running -- it knows which servers
    are up long before anything here would, and it is the thing actually
    deciding where traffic goes. Only changes are reported: a service that has
    been down for a week does not need saying again. What counts as news is
    the pool's own "Alert when" setting: any server lost, only a full outage,
    or nothing at all.
    """
    modes = notify_modes(cfg)
    for be in data.get("backends") or []:
        name = be.get("proxy") or ""
        if name in INTERNAL_POOLS:
            continue
        mode = modes.get(name, "servers")
        if mode == "off":
            continue                      # this service looks after itself
        total = int(be.get("servers_total") or 0)
        if not total:
            continue                      # nothing to be up or down
        up = int(be.get("servers_up") or 0)
        label = _pool_label(name)
        down = [s for s in be.get("servers") or []
                if not (s.get("status", "").startswith("UP") or s.get("status") == "no check")]
        detail = "\n".join(
            "  %s (%s) %s" % (s.get("name"), s.get("addr") or "?",
                              s.get("check_status") or s.get("status") or "")
            for s in down)
        if up == 0:
            notify.notify_transition(
                "service:" + name, "down", "service",
                "%s has no servers left" % label,
                "Every server behind %s is failing its health check, so requests for it "
                "get a 503.\n\n%s" % (label, detail), "error", cfg)
        elif down and mode == "servers":
            notify.notify_transition(
                "service:" + name, "degraded", "service",
                "%s is down to %d of %d servers" % (label, up, total),
                "%s is still serving on the servers that are up.\n\n%s" % (label, detail),
                "warning", cfg)
        else:
            # Healthy -- which for an outage-only pool includes servers
            # failing their checks, so the recovery text must not claim they
            # all pass when the point of the setting is that they need not.
            body = ("All %d server%s behind %s are passing their health checks."
                    % (total, "" if total == 1 else "s", label)) if not down else \
                   ("%d of %d servers behind %s pass the health check, which is how "
                    "this pool is meant to run -- it alerts only when none are left."
                    % (up, total, label))
            notify.notify_transition(
                "service:" + name, "ok", "service",
                "%s is %s again" % (label, "healthy" if not down else "serving"),
                body, "info", cfg)


def history(pool=None, minutes=None):
    _load()
    at = _state["at"]
    keep = len(at)
    if minutes:
        cutoff = time.time() - minutes * 60
        keep = sum(1 for t in at if t >= cutoff)
    series = _state["series"]
    if pool:
        series = {k: v for k, v in series.items() if k == pool}
    return {"ok": True, "step": STEP_SECONDS,
            "at": at[len(at) - keep:],
            "series": {name: {k: v[len(v) - keep:] for k, v in row.items()}
                       for name, row in series.items()},
            "span": _span_text(at),
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds")}


@app.get("/api/traffic")
def api_traffic():
    """Per-pool request and error counts, a minute at a time.

    ?pool=<name> for one, ?minutes=<n> for a shorter window.
    """
    try:
        minutes = int(request.args.get("minutes") or 0)
    except ValueError:
        minutes = 0
    with _lock:
        return jsonify(history(request.args.get("pool") or None, minutes))
