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

The advanced pages expose those objects directly if you need them. Anything a
published service owns is marked **service** there, and its editor says which
service and warns that publishing that service again rebuilds it. Ownership is
worked out from what the services actually reference, so it stays right even
after objects are edited or rebuilt. Anything the
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

### Recipes

The wizard asks for a dozen settings, and for a well-known service there is one
right answer for nearly all of them. **Start from a recipe** fills those in and
leaves the two things only you know: the name to publish and the servers behind
it.

**Web**

| Recipe | What it sets up |
| --- | --- |
| Web application | An ordinary HTTP or HTTPS site with a health check on / |
| Web application with WebSockets | As above, but connections are allowed to stay open for hours |

**Databases**

| Recipe | What it sets up |
| --- | --- |
| Apache Solr | HTTP 8983 checked with the ping handler |
| Cassandra / ScyllaDB | TCP 9042 for CQL clients |
| ClickHouse | HTTP 8123 checked with /ping |
| CockroachDB | TCP 26257 with the check aimed at the HTTP readiness endpoint |
| CouchDB | HTTP 5984 checked with /_up |
| etcd | HTTP 2379 checked against /health |
| InfluxDB | HTTP 8086 checked against /health |
| Kafka (single broker) | TCP 9092 to one broker |
| MariaDB / MySQL — Galera cluster | TCP 3306 with every client pinned to one node |
| MariaDB / MySQL — single server | TCP 3306 with a MySQL login check |
| Meilisearch | HTTP 7700 checked with /health |
| Memcached | TCP 11211 with a connection check |
| MongoDB | TCP 27017 with a connection check |
| Neo4j (Bolt) | TCP 7687 for the Bolt protocol |
| PostgreSQL — Patroni, read-only | TCP 5433 spread across the replicas, never the leader |
| PostgreSQL — Patroni, writes | TCP 5432 to whichever node is the leader, found by asking Patroni |
| PostgreSQL — single server or streaming replica | TCP 5432 with a PostgreSQL login check |
| Qdrant | HTTP 6333 checked with /healthz |
| Redis / Valkey | TCP 6379 with a connection check |
| Typesense | HTTP 8108 checked with /health |
| VictoriaMetrics | HTTP 8428 checked with /health |
| Weaviate | HTTP 8080 checked against its readiness endpoint |
| ZooKeeper | TCP 2181 for clients |

**Applications**

| Recipe | What it sets up |
| --- | --- |
| Actual Budget | HTTP 5006 with clients pinned for sync |
| Alertmanager | HTTP 9093 checked with /-/healthy |
| Apache Guacamole | HTTP 8080 with sessions pinned to one node |
| Argo CD | HTTP 8080 checked with /healthz |
| Audiobookshelf | HTTP 13378 checked against /healthcheck |
| Authelia | HTTP 9091 checked against /api/health |
| authentik | HTTP 9000 checked against its liveness endpoint |
| Bambuddy (Bambu Lab printers) | HTTP 8080 with live print status kept open |
| Bitwarden (official server) | HTTP 8080 for the self-hosted Bitwarden stack |
| BookStack | HTTP 80 checked against /status |
| Calibre-Web | HTTP 8083 for the library |
| Channels DVR | HTTP 8089 with timeouts sized for streaming a recording |
| Checkmk | HTTP 5000 for the interface |
| Consul | HTTP 8500 checked against the leader endpoint |
| Directus | HTTP 8055 checked against /server/health |
| Discourse | HTTP 3000 checked with /srv/status |
| Docker registry | HTTP 5000 with room to push a large image |
| Dockge | HTTP 5001 with the WebSocket its interface needs |
| Duplicati | HTTP 8200 for the backup interface |
| Elasticsearch / OpenSearch | HTTP 9200 checked against the cluster health endpoint |
| ERPNext / Frappe | HTTP 8000 with sessions pinned |
| ESPHome | HTTP 6052 with log streaming kept alive |
| File Browser | HTTP 80 checked with /health |
| Firefly III | HTTP 8080 checked with /health |
| Frigate NVR | HTTP 5000 with camera streams kept open |
| Gatus | HTTP 8080 checked with /health |
| Gerrit | HTTP 8080 checked against its version API |
| Ghost | HTTP 2368 for publishing |
| Gitea / Forgejo | HTTP 3000 with room for a large clone |
| GitLab | HTTP with the timeouts a git push needs |
| Gotify | HTTP 80 with the message WebSocket kept open |
| Grafana | HTTP 3000 checked against its own health endpoint |
| Graylog | HTTP 9000 checked against the endpoint meant for load balancers |
| Grocy | HTTP 80 for household management |
| Harbor registry | HTTP with Harbor's health endpoint and room for large layers |
| HashiCorp Vault | HTTP 8200 to the active node, found by its own health endpoint |
| Healthchecks | HTTP 8000 for cron monitoring |
| Home Assistant | HTTP 8123, with the WebSocket the interface depends on |
| Homebox | HTTP 7745 checked against its status endpoint |
| Homebridge | HTTP 8581 for the management interface |
| Homepage / Homarr | HTTP 3000 for a dashboard |
| Immich | HTTP 2283 with timeouts sized for uploading a phone's library |
| Jellyfin / Emby | HTTP 8096 with timeouts long enough to watch a film |
| Jenkins | HTTP 8080, sticky, with room for long builds |
| JFrog Artifactory | HTTP 8082 checked with its system ping |
| Joplin Server | HTTP 22300 checked with /api/ping |
| Karakeep / Hoarder | HTTP 3000 for bookmarks |
| Kavita | HTTP 5000 checked against its health API |
| Keycloak | HTTP 8080 checked on its separate management port |
| Kibana | HTTP 5601 checked against its status API |
| Kimai | HTTP 8001 for time tracking |
| Komga | HTTP 25600 checked with its actuator |
| Kopia | HTTP 51515 for the backup interface |
| Lemmy | HTTP 8536 for the API and federation |
| LibreNMS | HTTP 8000 for the interface |
| Loki | HTTP 3100 checked with /ready |
| Mailpit | HTTP 8025 for the interface, checked with /readyz |
| Mainsail / Fluidd (Klipper) | HTTP 80 with Moonraker's WebSocket kept open |
| Mastodon | HTTP 3000 checked with /health |
| Matomo | HTTP 80 for analytics |
| Matrix (Synapse) | HTTP 8008 checked against the client API |
| Mattermost | HTTP 8065, sticky, with WebSockets |
| Mealie | HTTP 9000 checked against its about endpoint |
| Miniflux / FreshRSS | HTTP 8080 checked with /healthcheck |
| MinIO / S3-compatible storage | HTTP with MinIO's liveness endpoint and long timeouts |
| Moodle | HTTP 80 with sessions pinned |
| n8n | HTTP 5678 checked with /healthz |
| Navidrome | HTTP 4533 checked with /ping |
| Netdata | HTTP 19999 checked against its info endpoint |
| Nextcloud | HTTP with long timeouts and clients pinned to one server |
| NocoDB | HTTP 8080 checked against /api/v1/health |
| Node-RED | HTTP 1880 with the editor's WebSocket kept open |
| ntfy | HTTP 80 with subscriptions held open |
| OctoPrint | HTTP 5000 with the print stream kept open |
| Odoo | HTTP 8069 with sessions pinned |
| Ollama | HTTP 11434 with timeouts long enough to generate an answer |
| Open WebUI | HTTP 8080, sticky, with streaming replies |
| Outline | HTTP 3000 checked with /_health |
| Overseerr / Jellyseerr | HTTP 5055 checked against its status API |
| Owncast | HTTP 8080 with the stream and chat kept open |
| Paperless-ngx | HTTP 8000 with WebSockets for the consumption status |
| PeerTube | HTTP 9000 with room to upload and watch |
| pgAdmin | HTTP 80 checked with /misc/ping |
| PhotoPrism | HTTP 2342 checked against its status API |
| PhotoStructure | HTTP 1787 with timeouts sized for a library import |
| phpMyAdmin | HTTP 80 with the session kept on one server |
| Planka / Focalboard | HTTP 3000 with live board updates |
| Plausible | HTTP 8000 checked with /api/health |
| Plex Media Server | HTTP 32400 with timeouts long enough to watch a film |
| Portainer | HTTPS 9443 passed through, with the console WebSocket kept open |
| Prometheus | HTTP 9090 checked against /-/healthy |
| qBittorrent | HTTP 8080 for the web interface |
| RabbitMQ (AMQP) | TCP 5672 for AMQP clients |
| Rancher | HTTPS 443 passed through to a self-signed backend |
| Redmine | HTTP 3000 with sessions kept in place |
| Rocket.Chat | HTTP 3000 checked against /api/info |
| Roundcube | HTTP 80 with the session kept on one server |
| SABnzbd | HTTP 8080 for the web interface |
| Scrypted | HTTPS 10443 passed through, with camera streams kept open |
| Seafile | HTTP 8000 with room to sync |
| Snipe-IT | HTTP 80 for asset management |
| SonarQube | HTTP 9000 checked against its system status |
| Sonarr / Radarr / Lidarr | HTTP 8989 checked with /ping |
| Sonatype Nexus | HTTP 8081 checked against its status endpoint |
| Stirling PDF | HTTP 8080 for PDF tools |
| Tandoor Recipes | HTTP 8080 for the recipe manager |
| Tautulli | HTTP 8181 checked with /status |
| TeamCity | HTTP 8111 with build logs streaming |
| Transmission | HTTP 9091 for the web interface |
| Umami | HTTP 3000 checked with /api/heartbeat |
| UniFi Network controller | HTTPS 8443 passed through to a self-signed backend |
| Uptime Kuma | HTTP 3001 with the WebSocket its interface is built on |
| Vaultwarden / Bitwarden | HTTP with the notification WebSocket kept alive |
| Verdaccio (npm registry) | HTTP 4873 checked with /-/ping |
| Vikunja | HTTP 3456 checked against /api/v1/info |
| Wallabag | HTTP 80 for read-it-later |
| Wiki.js | HTTP 3000 checked with /healthz |
| Woodpecker CI | HTTP 8000 checked with /healthz |
| WordPress | HTTP with clients pinned and room for uploads |
| Z-Wave JS UI | HTTP 8091 with the control WebSocket kept open |
| Zabbix web interface | HTTP 8080 with the session kept on one server |
| Zigbee2MQTT | HTTP 8080 with the WebSocket its interface uses |

**Infrastructure**

| Recipe | What it sets up |
| --- | --- |
| AdGuard Home | HTTP 3000 for the admin interface |
| Cockpit | HTTPS 9090 passed through, with the terminal WebSocket kept open |
| CrowdSec local API | HTTP 8080 checked with /health |
| IMAP | TCP 993 for mail clients |
| Kubernetes API servers | TCP 6443 across the control plane |
| LDAP directory | TCP 389 across the directory servers |
| LLDAP (directory) | TCP 3890 for LDAP clients |
| MQTT (Mosquitto) | TCP 1883 for long-lived publish/subscribe connections |
| Mumble | TCP 64738 for voice chat |
| Nginx Proxy Manager | HTTP 81 for the administration interface |
| OPNsense / pfSense | HTTPS passed through to the firewall's own interface |
| Pi-hole | HTTP 80 for the admin interface |
| Proxmox VE | HTTPS 8006, passed through to a self-signed backend |
| Remote Desktop (RDP) | TCP 3389 with each client returning to the same host |
| SMTP relay | TCP 25 to a pool of mail servers |
| SMTP submission | TCP 587 for authenticated mail submission |
| SSH bastion | TCP 22 to a pool of jump hosts |
| Syncthing (interface) | HTTP 8384 checked against its unauthenticated health endpoint |
| Syslog over TCP | TCP 514 to a pool of log collectors |
| Teleport | TCP 443 passed through without terminating TLS |
| Traefik dashboard | HTTP 8080 checked with /ping |
| TrueNAS | HTTPS passed through to the appliance |
| Unraid | HTTP 80 passed through, with the dashboard's live updates kept open |
| Zabbix server | TCP 10051 for agents reporting in |

Every one carries example servers, so the shape of the answer is visible before
you replace it with your own.

Recipes are one JSON file each in `static/recipes/`, read when the wizard asks
for them. Adding your own is a matter of dropping a file in — no restart — and
an upgrade will not remove it. A file that is not valid JSON is skipped and the
reason logged, so one bad recipe cannot empty the list. The filename is the
recipe's identity; a minimal one looks like this:

```json
{
  "name": "My application",
  "category": "Applications",
  "summary": "What it sets up, in a line.",
  "notes": "Why these settings and not others.",
  "fields": { "url": "https://app.example.com", "target": "10.0.0.10:8080",
              "health": "http", "health_uri": "/healthz", "health_status": "200" }
}
```

The interesting ones are the databases, because the right configuration is not
obvious:

- **Patroni** answers `GET /primary` with 200 on the leader and 503 everywhere
  else, so the health check does the routing. Every replica is simply down for
  that pool, and a failover moves traffic with nothing to change here. Traffic
  goes to 5432 while the check goes to 8008 — different port, different
  protocol.
- **Galera** accepts writes on any node, which is the problem: two nodes writing
  the same rows deadlock on commit. Source stickiness keeps each client on one
  node, so the cluster behaves as a single writer with the others ready.

A recipe is a starting point, not a constraint: every field stays editable, and
recipes are only offered for a new service — applying one to an existing service
would rewrite settings already in use.

**TCP services.** Use `tcp://0.0.0.0:3306` as the public URL and the service is
published in TCP mode — the way to front Galera, PostgreSQL or anything that is
not HTTP.

**Health checks on a different port or protocol.** A Patroni cluster is the
classic case: traffic goes to PostgreSQL on 5432, but the check is an HTTP
request to 8008 that only the leader answers. Set **Check port** and choose an
HTTP check; the rendered backend then checks one place and routes to another.

## Certificates

**Certificates → Request a certificate** walks through an ACME account, a
challenge type and the domains. The accounts, the challenge types and the
issuance settings are all on one page, **Settings → ACME Settings**.

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

## The account

The gear beside your name at the foot of the menu opens **Account**: the
username, an email, and the password.

Changing the password or the username asks for the current password — a session
alone is not enough to change how you sign in. The email is not a credential
and there is no reset-by-email here, so it can be set without one. It is
offered as the default when an ACME account is created and when notifications
are set up, so it is only typed once.

**Applying it to the other nodes.** The login is stored per node, so changing
it here changes it only here — and a node with the old password is something
you usually find out about during a failover, at the worst possible moment. So
when the cluster has other nodes, the dialog offers **Apply to the other
nodes**, ticked by default. It sends the stored salt and digest — not the
password — to each node's `/api/admin/receive`, authenticated with that node's
API key. A browser cannot reach that endpoint: a session on the receiving node
is not enough, only the key is. Nodes that do not take it are named, with the
reason, and keep the login they had.

The login is node-local: set it on each node.

## Serving the UI over HTTPS

**System → Web UI access.** Give it a name (`https://proxy.example.com`) and it
publishes this UI as a normal service with a certificate, so you stop using
plain HTTP.

The page says which names this node **actually answers for**, read from the
objects rather than from the setting that made them. The watchdog checks the
same thing every round: if a configured address stops being routed, it rebuilds
the service, applies, and says so in the log and by notification. It does that
at most twice an hour — if the address goes again inside that, something is
actively removing it, and rebuilding on a loop would reload HAProxy every round
while hiding the cause, so it reports and leaves it alone. Those come apart — a name
that was never published, or one that stopped being — and when they do, the
form still shows the address that was typed while the node no longer routes it.
A name listed as not routed here is put back by pressing Save.

Two addresses, and they do different jobs:

| | |
| --- | --- |
| **This node's address** | `https://proxy1.example.com` — reaches this node specifically. Node-local: each node has its own. |
| **Shared address** | `https://proxy.example.com` — point it at the virtual IP and it reaches whichever node is active. Shared across the cluster, so every node answers for it. |

Both names sit on one listener, so they must use the same scheme and port, and
the certificate covers both. The shared name is the one to bookmark; the
per-node names are how you reach a specific node when you need to.

This service is deliberately **not editable** on the Services page: each node
builds its own copy from these settings.

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

**Keeping the nodes in step.** The shared configuration carries a revision: a
counter that moves whenever it changes, and a fingerprint of its contents. Both
travel with every push, every node reports them, and the Cluster page shows
which node holds what.

- A node offered a configuration **older** than the one it already has refuses
  it, and says both revisions. Without that, an isolated node that was edited
  and later reconnected would overwrite the current configuration with its own.
- **Overwrite** is how you discard a change made on the wrong node. Editing a
  passive node moves it ahead of the active one, so an ordinary Sync from the
  active node is refused — correctly, because it is older. **Cluster → Nodes**
  offers *Overwrite* beside each node and *Overwrite every node* below the
  list. It lifts this node's revision above every other node's and then pushes
  normally, so afterwards every node holds the same configuration **and** the
  same revision; nothing is left disagreeing about who is newest. What was on
  the other node is discarded.
- **Keep the nodes in step** (Cluster → Nodes) does three things: pushes after
  every Apply, brings any node reporting an older revision up to date in the
  background, and takes the newest configuration from the cluster when this
  node starts. It is on by default for a new installation; an existing one
  keeps whatever it was set to. Turn it off to move configuration between nodes
  by hand.

Reconciliation runs from the node holding the virtual IP, on the health it
already collects, so there is no queue of pending pushes to lose: a push that
fails is simply observed again next round.

**When the nodes do not agree**, the Cluster page lists what differs: the
object, whether it is missing from a node or present everywhere with different
contents, and which nodes hold which version. Settings have no identity of
their own and are compared whole.

The health behind that view is collected in the background and can be up to a
minute old, so anything that changes or pushes the configuration throws the
collected copy away — the next look asks the nodes again rather than repeating
a verdict from before the change.

**What is shared, and what is this node's.** They are separate containers in
the configuration, not one container with some objects marked. The shared
sections hold what every node has; `local` holds what only this node has — and
that includes whole objects, not only settings: the pool, server, health
monitor, rule, conditions and certificate that publish this node's own
management UI.

That makes sharing a copy rather than a filter. What is sent to the other
nodes is the shared sections as they are, and what is compared is the same
value, so the two cannot drift apart. There is no marking to honour and
nothing that has to remember to honour it — which is where four separate
faults came from.

A listener is shared while the rule attaching this node's UI to it is not, so
`local.attach` records that by the listener's **name** (every node has one
called `https-443`, with a different id) and by position — HAProxy takes the
first matching `use_backend`, and serves the first certificate to clients that
send no SNI. Rendering merges the two; nothing else needs to know.

Each node still checks itself after taking a configuration: it compares its own
fingerprint with the one that arrived, and records a mismatch. That should now
be impossible, which is exactly why it is worth reporting if it happens.

**What counts as HAProxy being up.** Keepalived gives the virtual IP up when
its tracking script fails. The default script asks HAProxy through its admin
socket whether it is serving, so an instance that is running but wedged fails
the check; *process* only looks for a process by that name, which a hung one
still has. The script is written next to `keepalived.conf` by the Apply that
writes it, and falls back to looking for the process where there is no admin
socket to ask — a node whose HAProxy is fine should never lose the virtual IP
to the health check itself.

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

## Upgrades and the browser cache

The page is served with `no-cache`, and everything it loads lives under a path
that contains the version — `/static/v/1.78.0/js/main.js`. Those files are then
cached for a year, which is safe because the URL changes whenever the version
does.

The version has to be in the *path* rather than a query string: each
`import "./shell.js"` inside a module is its own request, resolved relative to
the module that wrote it, so a version in the path is inherited by every import
without touching any of them. After an upgrade a browser fetches the whole set
fresh, and can never hold a mixture of old and new modules.

If you put a caching proxy in front of the UI, let it honour those headers.

## Sorting tables

Every table in the UI sorts: click a heading, click it again to reverse. The
column keeps its arrow so it is clear what the order is.

Values sort by what they mean rather than by how they are spelled — `900 MB`
before `1.2 GB`, `srv9` before `srv10`, `30 mins` before `2 days` — numbers come
before words, blanks stay at the bottom whichever way the column is sorted, and
a totals row stays where it belongs. Pages that refresh on a timer, like
Statistics and Logs, keep the sort you chose instead of resetting it every few
seconds.

## Logs

**System → Logs** merges four sources into one timeline: the UI's own log,
HAProxy, acme.sh and Keepalived. Filter by source, level and text, and download
exactly what you are looking at.

The app's log is `/var/lib/haproxy-manager/haproxy-manager.log` (mode 0600,
rotated at 4 MB, three kept) and also goes to stdout, so
`journalctl -u haproxy-manager` shows the same lines. Every configuration change
is logged with who made it and from where; request bodies never are, so
passwords and credentials do not reach the log.

### "soft-stop running for too long, performing a hard-stop"

Seen in the HAProxy log after an Apply, followed by a line per listener saying
how many connections it closed:

```
[WARNING] : soft-stop running for too long, performing a hard-stop.
[WARNING] : Proxy fe_https-443 hard-stopped (1 remaining conns will be closed).
[WARNING] : Proxy fe_galera-listener hard-stopped (2 remaining conns will be closed).
```

Nothing is broken. A reload starts a new HAProxy and leaves the old one running
so connections opened before it can finish; **Hard stop after** (Advanced →
HAProxy → Settings, `60s` by default) is how long it waits. When it expires the
old process closes what is left, and says so.

What gets closed is anything longer-lived than that grace period — a database
session, a WebSocket, a stream — so those reconnect on every Apply. The
recipes give such services long server timeouts precisely because their
connections are meant to last, which is why they are the ones that show up
here.

The choice is between two costs:

| Setting | What it costs |
| --- | --- |
| `60s` (default) | long-lived connections are cut on every reload and reconnect |
| something longer | fewer cuts, and old processes hang around that much longer |
| empty | nothing is ever cut, and an old process lingers after every reload for as long as its longest connection — with an hour-long server timeout, potentially an hour, one per reload |

For a database pool, clients reconnect and source stickiness sends them back to
the same node, so the default is usually right. Raise it if a reconnect is
disruptive to what is behind the proxy.

## Traffic history

Each node records, once a minute, how many requests each pool served and how
many server errors it returned, and keeps a day of it in
`$HAM_DATA_DIR/traffic.json`. The Statistics page draws it; the Services page
shows a sparkline per service.

| | |
| --- | --- |
| Resolution | one point a minute |
| Kept | 24 hours |
| Scope | this node only |
| Written to | `traffic.json`, never the configuration — it must not move the shared revision |

Counts are what happened during that minute, not running totals, and a counter
that has gone backwards is treated as HAProxy having restarted rather than as
negative traffic. Every series carries one value per timestamp, so a pool that
appeared later shows zeros before it existed rather than having its history
slid backwards in time.

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
| Notification settings and destinations | The UI's own HTTPS service, and its certificate |
| | Administrator login |
| | Watchdog settings |

The UI's own service is the reason the right-hand column matters more than it
looks. Every node publishes it under the same name, for a different host, so
everything it is made of — the pool, the server, the health monitor, the rule,
the conditions it tests and the certificate for that node's own name — belongs
to the node that made it. Anything of that sort left in the shared
configuration travels to the other nodes, where it collides with theirs; the
wizard then makes a numbered copy, which travels in turn, and the cluster never
agrees with itself again.

None of that can happen now: those objects are not in the shared sections at
all, so there is nothing to send. Upgrading moves what was there into place,
once, and the generated `haproxy.cfg` is unchanged by the move apart from where
one `backend` block sits in the file — which HAProxy resolves by name.

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
