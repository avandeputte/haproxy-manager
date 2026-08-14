"""What Prometheus should know, in the format it reads.

One endpoint, no client library -- the exposition format is lines of text,
and writing them is smaller than a dependency. Everything here is read from
state the app already keeps: the stats socket, the certificate files, the
probe results, the cluster snapshot. Nothing is computed specially for
scraping, so a scrape costs what a page load costs.

The endpoint requires this node's API key, as a bearer token or the usual
X-API-Key header, because service names and certificate expiries are not for
whoever can reach the port. In prometheus.yml:

    scrape_configs:
      - job_name: haproxy-manager
        authorization:
          credentials: <the API key from Cluster > This node>
        static_configs:
          - targets: ["node1:8080", "node2:8080", "node3:8080"]
"""

from flask import Response, request
import socket
import time

from .base import VERSION, app
from .config import load_config, merged
from .util import cert_details, cert_path, parse_domains
from . import auth, cluster, probe, stats, watchdog

_STATE_VALUE = {"ok": 1, "warn": 0.5, "down": 0}


def _esc(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _line(out, name, labels, value):
    if labels:
        body = ",".join('%s="%s"' % (k, _esc(v)) for k, v in labels.items())
        out.append("%s{%s} %s" % (name, body, value))
    else:
        out.append("%s %s" % (name, value))


def render_metrics(cfg):
    out = []

    def head(name, kind, text):
        out.append("# HELP %s %s" % (name, text))
        out.append("# TYPE %s %s" % (name, kind))

    host = socket.gethostname()
    head("ham_info", "gauge", "Version and node, as labels; always 1.")
    _line(out, "ham_info", {"version": VERSION, "node": host}, 1)

    role, held = auth.node_role(cfg)
    head("ham_node_active", "gauge", "1 when this node holds the virtual IP (or is standalone).")
    _line(out, "ham_node_active", {}, 1 if role in ("active", "standalone") else 0)

    st = stats.haproxy_stats()
    head("ham_haproxy_up", "gauge", "1 when HAProxy answers on its stats socket.")
    _line(out, "ham_haproxy_up", {}, 1 if st.get("ok") else 0)
    if st.get("ok"):
        # Metric by metric, every pool under it: the exposition format wants
        # all samples of one metric consecutive under its TYPE line, and
        # writing pool-by-pool interleaved the families -- which the stricter
        # parsers reject outright.
        backends = st.get("backends") or []
        for metric, col, text in (
                ("ham_pool_servers_up", "servers_up", "Servers passing their health check, per pool."),
                ("ham_pool_servers", "servers_total", "Servers configured, per pool."),
                ("ham_pool_requests_total", "stot", "Requests HAProxy has counted, per pool. "
                 "A raw counter from HAProxy: it includes this app's own URL probes."),
                ("ham_pool_http_5xx_total", "hrsp_5xx", "5xx responses, per pool."),
                ("ham_pool_http_4xx_total", "hrsp_4xx", "4xx responses, per pool."),
                ("ham_pool_sessions", "scur", "Sessions open right now, per pool.")):
            head(metric, "counter" if metric.endswith("_total") else "gauge", text)
            for be in backends:
                try:
                    _line(out, metric, {"pool": be.get("proxy") or ""}, int(be.get(col) or 0))
                except (TypeError, ValueError):
                    pass

    certs = []
    for c in merged(cfg)["acme"]["certificates"]:
        info = cert_details(cert_path(c))
        expires = 0
        if info.get("expires_iso") and info.get("days_left") is not None:
            expires = int(time.time()) + info["days_left"] * 86400
        certs.append(({"name": c.get("name") or "?",
                       "domains": " ".join(parse_domains(c))},
                      expires, 1 if info.get("self_signed") else 0))
    head("ham_certificate_expiry_seconds", "gauge",
         "When the deployed certificate file expires, as a Unix timestamp; "
         "0 when no file is deployed.")
    for labels, expires, _ph in certs:
        _line(out, "ham_certificate_expiry_seconds", labels, expires)
    head("ham_certificate_placeholder", "gauge",
         "1 while the deployed file is the self-signed stand-in, not an issued certificate.")
    for labels, _expires, ph in certs:
        _line(out, "ham_certificate_placeholder", labels, ph)

    with probe._state_lock:
        results = list(probe._state["results"])
        probed_at = probe._state["at"]
    if results:
        head("ham_probe_up", "gauge",
             "The URL probe's verdict: 1 answers, 0.5 answers with a certificate "
             "problem, 0 no answer. Probed from the node holding the virtual IP.")
        for r in results:
            _line(out, "ham_probe_up", {"url": r["url"]}, _STATE_VALUE.get(r["state"], 0))
        head("ham_probe_duration_ms", "gauge", "How long the probe took, per URL.")
        for r in results:
            _line(out, "ham_probe_duration_ms", {"url": r["url"]}, r.get("ms", 0))
        head("ham_probe_age_seconds", "gauge", "Seconds since the last probe round.")
        _line(out, "ham_probe_age_seconds", {}, int(time.time() - probed_at) if probed_at else -1)

    snap = cluster._cluster_cache.get("value")
    if snap:
        s = snap["summary"]
        head("ham_cluster_nodes", "gauge", "Nodes in the cluster, and how many answer.")
        _line(out, "ham_cluster_nodes", {}, s["total"])
        head("ham_cluster_nodes_reachable", "gauge", "Nodes that answered the last health poll.")
        _line(out, "ham_cluster_nodes_reachable", {}, s["reachable"])
        head("ham_cluster_config_agreed", "gauge",
             "1 while every reachable node holds the same shared configuration.")
        _line(out, "ham_cluster_config_agreed", {}, 1 if s.get("config_agreed") else 0)

    with watchdog._watchdog_lock:
        services = dict(watchdog._watchdog.get("services") or {})
    if services:
        head("ham_watchdog_service_ok", "gauge",
             "1 while the watchdog's liveness probe passes, per supervised service.")
        for unit, entry in services.items():
            _line(out, "ham_watchdog_service_ok", {"service": unit},
                  1 if entry.get("state") in ("ok", "idle", "disabled", "unwatched") else 0)

    return "\n".join(out) + "\n"


@app.get("/metrics")
def api_metrics():
    """Prometheus exposition. Requires the API key: bearer token or header."""
    cfg = load_config()
    presented = request.headers.get("X-API-Key")
    bearer = request.headers.get("Authorization") or ""
    if bearer.lower().startswith("bearer "):
        presented = presented or bearer[7:]
    if not auth.key_matches(cfg["local"].get("api_key"), presented):
        return Response("the API key is required: Authorization: Bearer <key>, "
                        "or X-API-Key\n", status=401, mimetype="text/plain")
    return Response(render_metrics(cfg), mimetype="text/plain; version=0.0.4")
