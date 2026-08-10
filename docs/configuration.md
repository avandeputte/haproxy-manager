# Configuration

Everything is set from the UI and stored in one file,
`/var/lib/haproxy-manager/config.json` (mode 0600 — it holds the API key, the
session secret, the peers' keys and the password hash). HAProxy's and
Keepalived's own configuration files are **generated** from it on Apply; editing
them by hand is pointless, because the next Apply overwrites them (keeping a
`.bak`).

- [The model](#the-model)
- [Publishing a service](#publishing-a-service)
- [Certificates](#certificates)
- [Serving the UI over HTTPS](#serving-the-ui-over-https)
- [Clustering](#clustering)
- [Addressing nodes](#addressing-nodes)
- [Watchdog](#watchdog)
- [Notifications](#notifications)
- [Logs](#logs)
- [Backup and restore](#backup-and-restore)
- [What is shared and what is per node](#what-is-shared-and-what-is-per-node)
- [Environment variables](#environment-variables)
- [Ports](#ports)

## The model

A **service** is the unit you work with: one or more public URLs, a pool of
real servers behind them, and optionally a health check and a certificate.
Publishing one creates the underlying HAProxy objects — a frontend binding, a
host-matching condition, a routing rule, a backend and its servers.

The advanced pages expose those objects directly if you need them. Anything the
wizard created is marked as such, and hand-edits to those objects survive: the
wizard updates in place.

Nothing reaches HAProxy until you press **Apply**, which renders the
configuration, validates it with `haproxy -c`, writes it only if valid, and
reloads. A configuration that does not validate is never written.

## Publishing a service

**Services → Publish a service.**

| Field | Notes |
| --- | --- |
| Public URL | `https://shop.example.com`. Several are allowed, separated by commas — they must share a scheme and port. A path (`/api`) routes only that prefix. |
| Target | `10.0.0.5:8080`, or `name=10.0.0.5:8080` to name the server. Several make a pool. |
| Certificate | reuse an existing one, issue a new one, use a wildcard that already covers the name, or none |
| Health check | none, TCP connect, HTTP request, PostgreSQL login, MySQL/MariaDB login |
| Balance | round robin, least connections, source |
| Persistence | none, or source-IP stickiness with a table size and expiry |

**TCP services.** Use `tcp://0.0.0.0:3306` as the public URL and the service is
published in TCP mode — the way to front Galera, PostgreSQL or anything that is
not HTTP.

**Health checks on a different port or protocol.** A Patroni cluster is the
classic case: traffic goes to PostgreSQL on 5432, but the check is an HTTP
request to 8008 that only the leader answers. Set **Check port** and choose an
HTTP check; the rendered backend then checks one place and routes to another.

## Certificates

**Certificates → Request a certificate** walks through an ACME account, a
challenge type and the domains.

- **HTTP-01** needs port 80 reachable from the internet. The app runs acme.sh's
  standalone listener on 9080 and routes `/.well-known/acme-challenge/` to it
  automatically when "HAProxy integration" is on.
- **DNS-01** needs an API hook and its credentials. The UI lists all 191 hooks
  acme.sh ships with and shows exactly which variables each one needs.
- **Wildcards** require DNS-01. The wizard offers an existing wildcard when it
  covers the name you are publishing, instead of issuing another certificate.

Renewal is automatic and runs **only on the node that holds the virtual IP** —
that node has port 80, so it is the only one that can answer an HTTP-01
challenge. A renewed certificate is deployed, pushed to the other nodes, and
HAProxy is reloaded, without anything to configure.

If acme.sh is missing or broken the Certificates page says so, with the reason.

## Serving the UI over HTTPS

**System → Web UI access.** Give it a name (`https://proxy.example.com`) and it
publishes this UI as a normal service with a certificate, so you stop using
plain HTTP.

This service is deliberately **not editable** on the Services page and does not
propagate: each node publishes its own UI under its own name. Changing the
address here rebuilds it.

Do this early. Over plain HTTP both the password and the session cookie cross
the network in clear.

## Clustering

**Cluster** holds everything about running more than one node.

- **This node** — its URL (how the others reach it) and its API key.
- **Shared settings** — VRID, virtual IPs, authentication, advertisement
  interval. These must match on every node, and they propagate.
- **Per node** — interface, priority, state. These never propagate.
- **Nodes** — the members, their keys and their health.

**Joining.** On a new node choose *Join an existing cluster* and give it any
existing node's URL and API key. It pulls the shared configuration and the
membership list, and tells the others about itself. Unicast peers are derived
from the member list — there is no unicast setting to maintain.

**Only the active node is editable.** Passive nodes are read-only, so two people
cannot edit two nodes into conflict. The lock can be lifted deliberately for a
single session; signing out or in re-locks it.

**Split brain** — more than one node holding the VIP — is detected and reported
on the Overview, and notified if you have notifications configured. It means the
nodes cannot see each other's VRRP.

## Addressing nodes

**Use IP addresses for peer URLs, not DNS names.** The Cluster page marks any
peer addressed by name.

Every health check resolves that name again, because nothing caches DNS on a
stock Debian or Ubuntu server: there is no caching resolver installed, and glibc
has none of its own. Measured against a local DNS server, five lookups of one
name produced ten queries (an A and an AAAA each) — none reused. With the
default `timeout:5 attempts:2`, a nameserver that does not answer costs **10
seconds per lookup, every time**, and a failure is precisely the thing no cache
can help with. The name may also be published by the very cluster that is in
trouble.

If you must use names, put them in `/etc/hosts`, or shorten the resolver's
patience with `options timeout:1 attempts:1` in `/etc/resolv.conf`, or install a
caching resolver.

## Watchdog

**System → Watchdog.** Each node supervises its own services. The distinction
that matters is between *stopped* and *hung*: `systemctl is-active` reports a
wedged process as healthy, so each service must prove it is answering.

| Service | Probe |
| --- | --- |
| HAProxy | `show info` on its stats socket |
| Keepalived | the service is running when the cluster wants it |
| The app itself | a real HTTP request to its own listener |

| Setting | Default | Meaning |
| --- | --- | --- |
| Run the watchdog | on | supervision on this node |
| Supervise HAProxy / Keepalived | on | per service |
| Check every | 20s | one round |
| Restarts allowed per window | 3 | then it stops trying and reports |
| Window | 900s | the window those restarts are counted in |

It will not restart a service whose configuration does not validate (that is a
loop which hides the fault — it reports the offending line instead), nor one you
have masked or disabled, and never more than the budget above.

**Watching the app itself.** A watchdog inside a process cannot restart that
process, so systemd does: the unit sets `WatchdogSec=90`, and the app pings
systemd only when a real request to its own listener succeeds. In Docker there
is no systemd, so a hung manager is reported by the container health check but
not repaired.

## Notifications

**System → Notifications.** Email (SMTP), Pushover and a JSON webhook. Nothing
extra is installed for any of it.

Alerts fire on **transitions**, not conditions: the watchdog runs every twenty
seconds, so a message per round would be thousands a week. An unresolved problem
is repeated every `repeat_hours` (6 by default) until it clears.

| Setting | Meaning |
| --- | --- |
| Only at or above | `error` for breakage only; `warning` adds repairs; `info` adds recoveries and new versions |
| Categories | certificates, watchdog, apply, cluster, updates — each switchable |

Each destination has a **Test** button that sends a real message. Settings are
shared, so configure them on one node and they propagate — which also means
**SMTP passwords and Pushover tokens travel in the sync payload**: run peer sync
over HTTPS, or keep it on a trusted network.

Because every node watches every other, a node that vanishes is reported by each
of its peers.

## Logs

**System → Logs** merges four sources into one timeline: the UI's own log,
HAProxy, acme.sh and Keepalived. Filter by source, level and text, and download
exactly what you are looking at.

The app's log is `/var/lib/haproxy-manager/haproxy-manager.log` (mode 0600,
rotated at 4 MB, three kept) and also goes to stdout, so
`journalctl -u haproxy-manager` shows the same lines. Every configuration change
is logged with who made it and from where; request bodies never are, so
passwords and credentials do not reach the log.

## Backup and restore

**System → Backup & Export** downloads the whole configuration as JSON, and the
rendered `haproxy.cfg` and `keepalived.conf` for inspection.

Restoring replaces the shared objects and keeps node-local settings — the API
key, this node's URL, its Keepalived identity — so a restore does not turn a
node into a copy of another one. Nothing is applied until you press Apply.

The JSON backup contains secrets. Store it accordingly.

## What is shared and what is per node

| Shared (propagates) | Per node (never propagates) |
| --- | --- |
| HAProxy objects: services, pools, servers, rules | API key |
| ACME accounts, challenge types, certificates | This node's URL |
| Cluster VRRP settings: VRID, VIPs, auth, interval | Keepalived interface, priority, state |
| Notification settings and destinations | The UI's own HTTPS service |
| | Administrator login |
| | Watchdog settings |

## Environment variables

Read by the app at startup. Set them in the unit
(`systemctl edit haproxy-manager`) or the container's environment.

| Variable | Default | Purpose |
| --- | --- | --- |
| `HAM_DATA_DIR` | `/var/lib/haproxy-manager` | config.json and the log |
| `HAM_CERT_DIR` | `/etc/haproxy/certs` | deployed certificate PEMs |
| `HAM_HAPROXY_CFG` | `/etc/haproxy/haproxy.cfg` | generated HAProxy config |
| `HAM_KEEPALIVED_CFG` | `/etc/keepalived/keepalived.conf` | generated Keepalived config |
| `HAM_ACME_HOME` | `~/.acme.sh` | ACME accounts and issued certificates |
| `HAM_ACME_SH` | `$HAM_ACME_HOME/acme.sh` | the acme.sh executable |
| `HAM_STATS_SOCK` | `/run/haproxy/admin.sock` | HAProxy's admin socket |
| `HAM_LISTEN` | `0.0.0.0` | bind address |
| `HAM_PORT` | `8080` | UI and API port |
| `HAM_THREADS` | `16` | waitress worker threads (single process — see below) |
| `HAM_LOG_FILE` | `$HAM_DATA_DIR/haproxy-manager.log` | the app's log |
| `HAM_DEBUG` | — | `1` for verbose logging |
| `HAM_PEER_CONNECT_TIMEOUT` | `3` | waiting for a node to accept a connection |
| `HAM_PEER_READ_TIMEOUT` | `5` | waiting for it to answer a health query |
| `HAM_PUSH_READ_TIMEOUT` | `90` | waiting for it to accept a pushed configuration |
| `HAM_CLUSTER_POLL` | `15` | how often node health is collected in the background |
| `HAM_CLUSTER_MAX_AGE` | `60` | age at which a stale snapshot is collected inline |
| `HAM_WATCHDOG_PROBE_TIMEOUT` | `5` | how long a service may take to answer its probe |
| `HAM_WATCHDOG_SELF_TIMEOUT` | `10` | how long the app's self-check may take |
| `HAM_REPO` / `HAM_REF` | `avandeputte/haproxy-manager` / `main` | where updates come from |
| `HAM_VERSION_URL` / `HAM_INSTALL_URL` | GitHub | override for a fork or mirror |
| `HAM_DRY_RUN` | — | `1` renders and validates but never reloads services |

**Do not run this behind a multi-process WSGI server.** It is served by waitress
as a single process with a thread pool on purpose: the lock that makes
configuration writes atomic, the failed-sign-in counters and the renewal timer
all live in process memory. Several worker *processes* would each get their own
copy, and concurrent edits would overwrite one another. Raise `HAM_THREADS` if
you need more concurrency.

## Ports

| Port | What | Who needs to reach it |
| --- | --- | --- |
| 8080 | UI and API | you, and the other nodes (peer sync) |
| 9080 | acme.sh HTTP-01 standalone listener | nothing directly — HAProxy routes to it |
| 80 / 443 | whatever your services bind | your users, and Let's Encrypt for HTTP-01 |
| — | VRRP (protocol 112, multicast or unicast) | the other nodes |

The API key is a bearer token with full control of a node. Restrict who can
reach port 8080, and put the UI behind TLS.
