"""The cached view of how every node is doing."""

from datetime import datetime
from datetime import timezone
from flask import jsonify
from flask import request
import concurrent.futures
import json
import socket
import threading
import time

from .base import CLUSTER_SNAPSHOT_MAX_AGE, _requests, app
from .config import load_config
from . import apply, notify, peering

_cluster_cache = {"at": 0.0, "value": None}
_cluster_cache_lock = threading.Lock()

# Disagreement between the nodes is only worth an email once it has lasted.
# Saving a change on one node makes the cluster disagree *by design* -- the
# others catch up when Apply pushes to them -- so the moment of divergence is
# nearly always the middle of ordinary work, and an alert sent then names a
# problem that heals itself two clicks later. What deserves attention is
# disagreement that persists: a push that failed, a node that was edited and
# forgotten. Half an hour is long enough to finish what anyone was doing.
CONFIG_DRIFT_GRACE = 30 * 60
_drift = {"since": None}


def _report_drift(cfg, diverged, detail):
    """The cluster:config notification, with its grace period.

    The UI is told immediately -- the Cluster page showing "configurations
    differ" during an edit is information. The email waits, and when it does
    go out it says how long the disagreement has stood, so the reader knows it
    is not the one they caused a minute ago.
    """
    if not diverged:
        _drift["since"] = None
        # Only close what was opened: agreement is the normal state of
        # affairs, not news. And "ok" rather than a synonym -- it is the state
        # notify_transition recognises as closing an open report, which is
        # what forces the recovery past the severity floor.
        if notify.transition_state("cluster:config") not in (None, "ok"):
            notify.notify_transition(
                "cluster:config", "ok", "cluster",
                "The nodes hold the same configuration again",
                "The nodes agree again.", "info", cfg)
        return
    if _drift["since"] is None:
        _drift["since"] = time.time()
    stood = time.time() - _drift["since"]
    if stood < CONFIG_DRIFT_GRACE:
        return
    notify.notify_transition(
        "cluster:config", "diverged", "cluster",
        "The nodes have not held the same configuration for %d minutes" % (stood // 60),
        "%s.\n\nThis has stood for %d minutes -- longer than an edit-then-Apply "
        "should take -- so it will not settle on its own. A node with an older "
        "configuration serves it the moment it takes the virtual IP."
        % (detail.rstrip("."), stood // 60), "warning", cfg)


def invalidate():
    """Forget the collected health, so the next read goes and asks.

    The snapshot is deliberately up to a minute old -- it is collected in the
    background so the page does not wait on the slowest node. But after
    something has just changed the configuration or pushed it, showing the
    verdict from before that is worse than making the reader wait: it says the
    nodes still disagree when they have just been put right.
    """
    with _cluster_cache_lock:
        _cluster_cache["at"] = 0.0


def _differing_parts(nodes):
    """Which collections the nodes do not agree on, named.

    A node running a version that does not report its parts is left out of the
    comparison rather than counted as differing from everything.
    """
    parts = [n.get("config_parts") or {} for n in nodes if n.get("config_parts")]
    if len(parts) < 2:
        return ""
    keys = set().union(*(set(p) for p in parts))
    differ = sorted(k for k in keys if len({p.get(k) for p in parts}) > 1)
    if not differ:
        return ""
    return " -- they differ in " + ", ".join(differ)


def cluster_snapshot(cfg=None):
    """Ask every node how it is. Slow by nature -- it waits on the network."""
    cfg = cfg or load_config()
    peers = cfg["local"]["sync"].get("peers") or []

    with app.test_request_context("/api/status"):
        me = peering._node_summary(json.loads(apply.api_status().get_data()))
    me.update({"id": "self", "name": me["hostname"] or "this node", "url": "",
               "self": True, "reachable": True, "error": "", "ms": 0})

    nodes = [me]
    if peers:
        if _requests is None:
            nodes += [dict(peering._query_peer(p), error="python3-requests is not installed on this node")
                      for p in peers]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(peers))) as ex:
                nodes += list(ex.map(peering._query_peer, peers))

    reachable = [n for n in nodes if n.get("reachable")]
    holders = [n for n in reachable if n.get("vip_held")]
    warnings = []
    if len(nodes) - len(reachable):
        warnings.append("%d of %d nodes did not answer." % (len(nodes) - len(reachable), len(nodes)))
    vips_configured = any(n.get("vips") for n in reachable)
    if vips_configured and not holders:
        warnings.append("No node holds the virtual IP, so nothing is being served on it. "
                        "Check Keepalived on each node.")
    if len(holders) > 1:
        warnings.append("%d nodes hold the virtual IP at the same time (split brain): %s. "
                        "They are not seeing each other's VRRP."
                        % (len(holders), ", ".join(n["name"] for n in holders)))
    dirty = [n["name"] for n in reachable if n.get("dirty")]
    if dirty:
        warnings.append("Unapplied changes on: %s." % ", ".join(dirty))
    versions = {n.get("version") for n in reachable if n.get("version")}
    if len(versions) > 1:
        warnings.append("Nodes run different versions: %s." % ", ".join(sorted(versions)))

    # Do the nodes hold the same configuration? A node that was unreachable
    # when a change was applied keeps the old one indefinitely, and until this
    # was reported it looked exactly like a healthy node -- until it took the
    # virtual IP and served something out of date.
    newest = max((n.get("config_rev") or 0) for n in reachable) if reachable else 0
    fps = {n.get("config_fp") for n in reachable if n.get("config_fp")}
    behind = [n for n in reachable if n.get("config_fp") and (n.get("config_rev") or 0) < newest]
    agree = len(fps) <= 1
    # "The nodes disagree" is not something anyone can act on. Which part they
    # disagree about very nearly always is, so it is worked out once and said
    # in every case, not only in the tidy one.
    differs_in = _differing_parts(reachable)
    # The one cause the comparison cannot diagnose from the outside: a node
    # took a configuration and did not end up matching it.
    leaking = [n for n in reachable if n.get("config_leak")]
    if leaking:
        warnings.append(
            "%s took a configuration and then did not match it, so something "
            "belonging to one node is inside the shared configuration. It will "
            "not settle on its own -- the object named below is the one to look "
            "at." % ", ".join(n["name"] for n in leaking))
    if behind:
        warnings.append(
            "%s %s an older configuration (revision %s against %d)%s. "
            "%s serve it if %s take%s the virtual IP; push from the node that has "
            "the newest one."
            % (", ".join(n["name"] for n in behind),
               "holds" if len(behind) == 1 else "hold",
               ", ".join(str(n.get("config_rev") or 0) for n in behind), newest,
               differs_in,
               "It will" if len(behind) == 1 else "They will",
               "it" if len(behind) == 1 else "they", "s" if len(behind) == 1 else ""))
    elif not agree:
        # Same revision, different content: two nodes were changed while they
        # could not see each other. Nothing here can decide which is right.
        warnings.append(
            "The nodes hold different configurations at the same revision (%d), "
            "so they were changed independently%s. Choose the node that is right "
            "and apply from it, or use Overwrite to replace what is on the others."
            % (newest, differs_in))

    # Each node reports what it can see, so a node that vanishes is reported
    # by each of its peers -- which also tells you who lost sight of it.
    for n in nodes:
        if n.get("self"):
            continue
        key = "node:" + (n.get("url") or n.get("name") or "?")
        if n.get("reachable"):
            notify.notify_transition(key, "ok", "cluster",
                              "Node %s is reachable again" % n.get("name"),
                              "%s is answering again." % n.get("url") or "", "info", cfg)
        elif n.get("error") != "disabled":
            notify.notify_transition(key, "unreachable", "cluster",
                              "Node %s is not answering" % n.get("name"),
                              "%s could not be reached from %s.\n\n%s\n\nIf it holds the "
                              "virtual IP, check that another node has taken it over."
                              % (n.get("url"), socket.gethostname(), n.get("error")),
                              "error", cfg)
    _report_drift(cfg, bool(behind or not agree),
                  warnings[-1] if (behind or not agree) else "")

    if len(holders) > 1:
        notify.notify_transition("cluster:splitbrain", "split", "cluster",
                          "Split brain: %d nodes hold the virtual IP" % len(holders),
                          "%s hold the virtual IP at the same time, so they are not seeing "
                          "each other's VRRP traffic. Traffic to the VIP is being answered "
                          "by more than one node."
                          % ", ".join(n["name"] for n in holders), "error", cfg)
    elif holders:
        notify.notify_transition("cluster:splitbrain", "ok", "cluster",
                          "The virtual IP is held by one node again",
                          "%s holds it." % holders[0]["name"], "info", cfg)

    payload = {
        "ok": True, "nodes": nodes,
        "summary": {"total": len(nodes), "reachable": len(reachable),
                    "active": len(holders), "warnings": warnings,
                    # What the Cluster page needs to show agreement at a glance
                    # and to offer to fix it.
                    "config_rev": newest, "config_agreed": bool(agree and not behind),
                    "config_behind": [n["name"] for n in behind],
                    "config_differs_in": differs_in},
        "taken": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    with _cluster_cache_lock:
        _cluster_cache["value"], _cluster_cache["at"] = payload, time.time()
    return payload


@app.get("/api/cluster")
def api_cluster():
    """Every node's health -- served from the snapshot the watchdog keeps.

    The fan-out waits on the slowest node, so doing it inside a page load put
    that wait in front of the user. The background loop refreshes it instead,
    and the UI reads whatever was last collected, with its age attached so it
    can say how old it is. `?fresh=1` forces a live round.
    """
    if request.args.get("fresh") == "1":
        payload = cluster_snapshot()
        return jsonify(dict(payload, age_seconds=0, live=True))
    with _cluster_cache_lock:
        hit = _cluster_cache["value"]
        age = time.time() - _cluster_cache["at"]
    if hit is None or age > CLUSTER_SNAPSHOT_MAX_AGE:
        # Nothing collected yet (or the refresher has stalled): do it inline
        # once rather than show the user nothing.
        payload = cluster_snapshot()
        return jsonify(dict(payload, age_seconds=0, live=True))
    return jsonify(dict(hit, age_seconds=int(age), live=False))
