# Metrics for Prometheus


`GET /metrics` speaks the Prometheus exposition format: per-pool request and
error counters straight from HAProxy, servers up per pool, certificate expiry
timestamps (and whether the deployed file is still the self-signed stand-in),
the URL probes' verdicts, cluster agreement, and the watchdog's view of each
service. Everything is read from state the app already keeps, so a scrape
costs what a page load costs. Note the request counters are HAProxy's own and
include this app's URL probes — the subtraction only applies to the built-in
traffic history.

It requires the node's API key, because service names and certificate
expiries are not for whoever can reach the port:

```yaml
scrape_configs:
  - job_name: haproxy-manager
    authorization:
      credentials: <the API key from Cluster - This node>
    static_configs:
      - targets: ["proxy1:8080", "proxy2:8080", "proxy3:8080"]
```

Scrape every node: each answers for itself, and `ham_node_active` says which
one holds the virtual IP.
