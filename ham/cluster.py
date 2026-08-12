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
                    "active": len(holders), "warnings": warnings},
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
