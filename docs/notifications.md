# Notifications


**Notifications** sends when something needs a person. Nothing extra is
installed for any of it: the whole feature uses the standard library and the
`requests` package that is already there.

| Destination | Notes |
| --- | --- |
| **Email (SMTP)** | STARTTLS, SSL or plain; authentication optional |
| **Pushover** | severity maps to Pushover priority (quiet / normal / high) |
| **Webhook** | `POST {subject, message, severity, event, node, time}`, custom headers |

The webhook is the escape hatch: it posts JSON, so a few lines of script can
forward an alert to anything not listed above.

Test each destination from the page: it sends a real message, so it is proven
before it is needed.

### When a service loses its servers

HAProxy is already health-checking every server, and it is the thing actually
deciding where traffic goes — so that is what the alerts come from. A service
whose servers all fail their checks is reported as down, one that loses some
of them as degraded, naming the servers and what their last check said. When
it recovers, that is reported too.

**A paused service says nothing about its servers.** Pausing a service is
usually the prelude to taking its backend down and working on it, at which
point the servers fail their checks — so a paused service is left out of these
alerts entirely. When it is resumed and its servers pass again, the next round
picks up from wherever it left off.

**What losing a server means is the service's own business.** Not every pool
means the same thing by a failing check. A load-balanced pool losing one of
three is degraded — but a Patroni pool is *designed* to have exactly one
server passing, because the health check is what does the routing: "down to
1 of 3" is its healthy state, and alerting on it is crying wolf on every
round. So each service carries an **Alert when** setting, in the publish
wizard beside the health check:

- **a server is lost** (the default) — any failing server is a warning, a
  pool with none left is an error
- **no server is left** — only the outage is news; servers failing their
  checks is normal running. The right choice for leader-election pools, and
  what the Patroni recipes now set by themselves. Recovery is reported the
  moment one server passes again, worded for what it is — "serving again",
  not a false "all servers healthy".
- **never** — this service looks after itself

**Only the node holding the virtual IP says anything about services.** Every
node runs the same checks, so three nodes would send three copies of every
alert — and a passive node's view is not the one that matters: it is not
carrying the traffic, and a server it cannot reach may be perfectly reachable
from the node that is. Faults about a node *itself* — its HAProxy stopped, its
certificate could not be renewed — still come from that node, because nobody
else can see them.

### It alerts on changes, not on conditions

A recovery is always delivered, whatever the severity threshold says. Recovery
messages are informational and the threshold defaults to warning, so without
that exception someone would be told what broke and never that it came back —
which is worse than silence, because it leaves them believing it is still
broken. A recovery for something that was never reported is not sent.

The watchdog runs every twenty seconds. Anything that reported a *state* would
arrive thousands of times a week, so alerts fire on **transitions** and an
unresolved problem is repeated only every `repeat_hours` (6 by default) until it
clears. Six watchdog rounds against one dead service produce two messages — "was
restarted", then "is healthy again" — not six.

A service that loses its servers is held for a **grace period** — 30 seconds by
default, on Notifications — before it is reported, so a reboot or an update that
takes it down for a few seconds does not page anyone. The clock starts when it
first goes bad, and a service that recovers inside the window says nothing at
all: no down alert, so no recovery either. Set it to 0 to alert on the first
check. (This is separate from the config-drift alert below, which has its own
much longer wait.)

**Several services at once are one message.** A host with ten services on it
going down is one event to the reader, so service alerts that fire within a
window of each other — 60 seconds by default, also on Notifications — are sent
as a single message listing every one of them, and their recoveries likewise.
Alerts from the same check round are always combined; the window just holds
the message open for stragglers whose health checks trip a round later. Set
it to 0 to combine only what one round found.

One alert waits deliberately: **the nodes holding different configurations**.
Saving a change makes the cluster disagree *by design* — the other nodes catch
up when Apply pushes to them — so the moment of divergence is nearly always
the middle of ordinary work. That alert is sent only once the disagreement has
stood for **30 minutes**, longer than an edit-then-Apply should take, and its
subject says how long — so the reader knows it is not the save they made a
minute ago. The Cluster page still shows the disagreement immediately; it is
only the email that waits.

What it can tell you about, each switchable:

- **Certificates** — issued, or failed with the reason
- **Watchdog** — a service restarted, beyond repair, or unrestartable because
  its configuration is broken (the message names the offending line)
- **Apply** — refused by validation, or HAProxy did not reload
- **Cluster** — a node stopped answering, came back, or split brain
- **Updates** — a new version is published

`min_severity` sets the floor: `error` for breakage only, `warning` to include
repairs, `info` to include recoveries and new versions.

Settings are **shared**, so configure them on one node and they propagate — each
node then alerts about its own troubles. Note that this means SMTP passwords and
Pushover tokens travel in the sync payload: run peer sync over HTTPS, or keep it
on a trusted network. Because every node watches every other one, a node that
vanishes is reported by each of its peers — which also tells you who lost sight
of it.
