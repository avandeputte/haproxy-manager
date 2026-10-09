# Home Assistant


Point **Notifications → Home Assistant** at an MQTT broker and the entities
appear in Home Assistant by themselves — MQTT discovery, no YAML, no polling,
and nothing extra installed on either side. The **Test** button connects and
publishes before anything depends on the settings.

Each node publishes a small device of its own: whether it holds the virtual
IP, and whether its HAProxy is answering. The node that *is* serving also
publishes the cluster's view, as one shared device:

- a **problem sensor per service**, honouring that service's *Alert when*
  setting — a Patroni pool at 1 of 3 shows healthy here too
- a **connectivity sensor per published URL**, from the URL probes
- **days to expiry per certificate**, with its domains as attributes
- **configuration drift** and **nodes reachable**, when there is a cluster
- **requests per minute per service**, from the traffic history (with this
  app's own probes already subtracted)

On failover the new active node simply continues publishing the same topics,
so the entities carry on rather than duplicating per node.

The connection is held open for the sake of the **will**: the broker flips
this node's availability topic to `offline` the moment the process dies, and
Home Assistant greys the entities out — the one state a dead process cannot
report for itself, and the reason MQTT beats polling here.

**Allow control from Home Assistant** (off by default) adds a **maintenance
switch per service**: flipping it pauses the service with a clean 503, exactly
like Pause on the Services page, and flipping it back resumes. Leave it off
unless you want it — anyone who can publish to the broker holds this power
the moment it is on, so keep the broker behind credentials you trust.

No broker, or no wish for MQTT? The webhook destination under Notifications
posts JSON that a Home Assistant webhook trigger can consume directly — zero
code, though it only carries alerts, not entities.
