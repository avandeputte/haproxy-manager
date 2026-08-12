<img src="static/logo.svg" alt="HAProxy Cluster Manager" width="268" height="64">


A small self-hosted web UI to manage an **HAProxy** configuration, obtain
**Let's Encrypt** certificates, and run a **cluster of any number of nodes with
Keepalived** on a shared virtual IP — one node active, the rest ready to take
over, with settings and certificates syncing across all of them.

```bash
# from a package: .deb and .rpm on every release (Debian, Ubuntu, RHEL, Fedora)
sudo apt-get install -y ./haproxy-manager_1.66.0_all.deb

# or the install script, on any Debian-based server
curl -fsSL https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/install.sh | sudo bash

# or in Docker (linux/amd64 and linux/arm64)
docker run -d --network host --cap-add NET_ADMIN --cap-add NET_BROADCAST --cap-add NET_RAW \
  -v ham-data:/var/lib/haproxy-manager -v ham-acme:/var/lib/acme.sh \
  -v ham-haproxy:/etc/haproxy -v ham-keepalived:/etc/keepalived \
  ghcr.io/avandeputte/haproxy-manager:latest
```

Then open `http://<node>:8080`.

**Detailed guides**

| | |
| --- | --- |
| [Installing on a server](docs/install-standalone.md) | requirements, what the installer does, options, updating, uninstalling, troubleshooting |
| [Running in Docker](docs/install-docker.md) | images, compose, networking, volumes, capabilities, limitations |
| [Configuration](docs/configuration.md) | every setting, what is shared between nodes, environment variables, ports |

The rest of this file describes what each part does and why.

## First run

The first visit asks for a username and password, then offers a setup wizard
with two branches:

- **Join an existing cluster** — point it at any node already running and give
  that node's API key. It registers itself there and that node pushes the
  whole configuration, the cluster settings and the membership list back. You do
  not touch the other nodes.
- **Create a new cluster, or run standalone** — set the virtual IP the nodes will
  share (or skip it and run alone). Other nodes join later by pointing at this
  one.

Either way it ends with this node's API key, which is what the other nodes need
to reach it. "Set this up later" skips straight to the UI.

## Publishing a service

The normal way to use this is **Services → Publish a service**: give it the URL
people will visit and the server behind it.

```
Public URL    https://app.example.com
Forward to    http://192.168.1.100:1781
```

From those two lines it creates the Real Server, Backend Pool, host Condition,
routing Rule, the HTTPS listener, an ACME certificate, and an HTTP listener that
redirects to HTTPS — then applies. **Preview** shows exactly what it will create,
and the resulting `haproxy.cfg`, before anything is written.

- **Wildcard certificates are reused, not duplicated.** If a certificate already
  covers the host — `*.example.com` for `app.example.com`, or an exact name —
  the wizard attaches it instead of requesting another one, and says so before
  you commit. An exact name wins over a wildcard that would also match, and
  `*.example.com` correctly does **not** cover `example.com` or
  `a.b.example.com`. Set Certificate to *always request a new certificate* to
  override, or *no certificate* to terminate TLS elsewhere.
- **Several public URLs** on one service: put one per line and every name reaches
  the same servers, as a single rule (`use_backend be_app if acl_host-app or
  acl_host-www`). One certificate covers them all, and adding a name later
  extends it rather than requesting another. Names must agree on scheme and
  port, since they share a listener, and a URL with a path cannot be combined
  with others — a host and a path must both match, while several host names are
  alternatives.
- **Several targets**, comma separated, are load balanced across. Each may be
  named: `galera1=192.168.1.81:3306`.
- **Raw TCP** works too — give it `tcp://0.0.0.0:3306` as the public URL and the
  wizard builds a TCP listener, a TCP-mode pool and the servers. TCP carries no
  host name, so one port serves exactly one pool; publishing a port that is
  already taken is refused rather than silently merged. Load balancing,
  source-IP stickiness (a stick table), health check logging and a separate
  check port are all part of the same form, so this comes out of it:

  ```
  backend be_mariadb_galera_pool
      mode tcp
      balance source
      option mysql-check user haproxy post-41
      option log-health-checks
      stick-table type ip size 50k expire 30m
      stick on src
      server galera1 192.168.1.81:3306 check inter 3s port 3306
      server galera2 192.168.1.82:3306 check inter 3s port 3306
      server galera3 192.168.1.83:3306 check inter 3s port 3306
  ```

  Note `type ip`: that is how HAProxy spells an IPv4 stick table. `type ipv4`
  is rejected outright (`unknown type 'ipv4'`).
- **A health check** can be set up in the same step, and servers that fail it are
  taken out of rotation:

  | Check | What HAProxy does |
  |---|---|
  | ping | opens a TCP connection to the port (HAProxy has no ICMP ping) |
  | HTTP request | `option httpchk`, with a path and an expected status |
  | TLS handshake | `option ssl-hello-chk` |
  | PostgreSQL login | `option pgsql-check` — the login handshake only, no password |
  | MariaDB / MySQL login | `option mysql-check`, `post-41` for anything modern |

  The database checks expect the servers to speak that protocol, so point them
  at the database itself; the wizard says so when you pick one.
- **The check can use a different port and protocol from the traffic.** Set a
  **check port** and HAProxy checks each server at its own address on that port,
  which is how a PostgreSQL cluster behind Patroni is fronted: route TCP to 5432
  while an HTTP check asks each node's own API on 8008 whether it is the
  primary. The HTTP check can carry a method, an HTTP version and a Host header,
  and a pool can override the connect, server and check timeouts:

  ```
  backend be_postgres_backend
      mode tcp
      balance source
      option httpchk
      http-check send meth GET uri /master ver HTTP/2 hdr Host localhost
      http-check expect status 200
      timeout connect 5s
      timeout server 30s
      stick-table type ip size 50k expire 30m
      stick on src
      server postgresql1 192.168.1.111:5432 check inter 3000 port 8008
      server postgresql2 192.168.1.112:5432 check inter 3000 port 8008
      server postgresql3 192.168.1.113:5432 check inter 3000 port 8008
  ```
- **A path** works too: `https://app.example.com/api` routes only that prefix.
  More specific rules are placed ahead of broader ones, so a host+path rule is
  never swallowed by the host-only rule for the same name.
- **Publishing the same URL again edits it** — repointing a service replaces its
  target rather than quietly adding a second server behind it.
- **Editing changes a service, it never clones it.** Edit follows the service's
  own objects, so changing its URL, health check, balancing or targets updates
  the rule, pool, monitor and certificate it already has instead of leaving them
  behind beside a new set. New objects appear only where there was none before,
  and settings an edit does not mention are left alone. Objects shared with
  something else — a monitor another pool uses, an already-issued certificate —
  are never altered underneath it.
- **Overview** is the landing page and lists every configured service alongside
  node health, certificates and the generated configuration. **Services** shows
  the same table on its own. Delete removes the objects that mapping alone was
  using.

The **Advanced** section still exposes every object individually, for the cases
the wizard does not cover (header rewriting, custom ACLs, per-object tuning). It
is grouped by topic — **Advanced · HAProxy**, **Advanced · ACME** and
**Advanced · Keepalived** — and mirrors the two OPNsense plugins this UI was
modeled on:

| This UI | OPNsense `net/haproxy` |
|---|---|
| Public Services | Virtual Services → Public Services (frontends) |
| Backend Pools | Virtual Services → Backend Pools |
| Real Servers | Real Servers → Servers |
| Conditions | Rules & Checks → Conditions (ACLs) |
| Rules | Rules & Checks → Rules (actions) |
| Health Monitors | Rules & Checks → Health Monitors |
| Settings | Settings → Global / Default / Statistics |

| This UI | OPNsense `security/acme-client` |
|---|---|
| Accounts | Accounts |
| Challenge Types | Challenge Types (HTTP-01 / DNS-01) |
| Certificates | Certificates |
| Settings | Settings |

(OPNsense's Automations have no equivalent here: what has to happen after a
renewal happens on its own.)

## How it works

- All state lives in a single JSON file (`$HAM_DATA_DIR/config.json`). No database.
- **Apply** renders `haproxy.cfg`, validates it with `haproxy -c` *before* writing
  anything, then writes the file (keeping a `.bak`) and reloads HAProxy. If
  Keepalived is enabled it renders and reloads `keepalived.conf` too.
- **Settings are checked before they are stored.** The settings pages have a
  **Validate** button that renders the configuration those values would produce
  and runs `haproxy -c` (and `keepalived -t` where it applies) without saving
  anything, and Save refuses outright if the result would not work — so a
  mistyped directive cannot be stored and then block every Apply until someone
  finds it. The full checker output is shown either way.
- **Only the node holding the virtual IP issues and renews.** HTTP-01 validation
  arrives at that address, so a passive node could not answer it, and with
  DNS-01 the nodes would race each other for the same certificate and burn the
  CA's rate limits. A passive node says so instead of trying, and refuses a
  manual Issue or *Renew all now*.
- **Everything a renewal needs happens by itself.** Once a certificate is
  written, HAProxy is reloaded so it actually serves it — it keeps certificates
  in memory, so a new file changes nothing until it reloads — and the PEM is
  pushed to every other node, so a failover serves the current certificate
  rather than the one that node last saw. There is nothing to configure: the
  Automations page is gone, and any automations in an existing configuration are
  ignored.
- **ACME** issuance/renewal shells out to [`acme.sh`](https://github.com/acmesh-official/acme.sh).
  Certificates are written as combined `fullchain + key` PEMs into the HAProxy
  certificate directory (what HAProxy's `crt` expects). HAProxy is then reloaded
  and the certificate pushed to the other nodes, with nothing to configure. A
  built-in loop renews on the interval set in ACME → Settings.
- **HTTP-01** challenges use a local `acme.sh --standalone` listener. When
  "HAProxy integration" is on, every HTTP Public Service automatically routes
  `/.well-known/acme-challenge/` to it, and HTTP→HTTPS redirects skip that path —
  so you can keep port 80 fronted by HAProxy and still validate.
- Before a real certificate exists, Apply drops in a short-lived **self-signed
  placeholder** so HAProxy can start; the first successful issue replaces it.
- **Certificate status** is shown on Overview and under ACME → Certificates:
  whether the PEM on disk is a real certificate or still the placeholder, its
  issuer, its expiry date with the days remaining, and the outcome, timestamp
  and full `acme.sh` log of the last issue/renew attempt (the **Log** button).

## High availability

Any number of nodes. One holds the virtual IP and serves traffic; the others
stand by with the same configuration, ready to take it.

### Cluster health

**Overview** opens with a **Cluster** table: every node's role, HAProxy and
Keepalived state, which virtual IPs it currently holds, its certificate health,
its version and how long it took to answer. Each node asks the others directly,
in parallel, so the view is live rather than remembered.

It calls out the conditions that are otherwise invisible until traffic stops:

- **No node holds the virtual IP** — nothing is being served on it.
- **Two or more nodes hold it at once** — split brain; they are not seeing each
  other's VRRP.
- Nodes holding an **older configuration** than the rest — see below.
- Nodes with **unapplied changes**, nodes running **different versions**, and
  nodes that **did not answer** (with the reason: unreachable, or the API key
  this node holds for it was rejected).

### The nodes agree, or they do not

Reachable is not the same as up to date. A node that was unreachable when a
change was applied keeps the configuration it had, and until it takes the
virtual IP nothing about it looks wrong.

So the shared configuration — everything except node-local settings and the
objects a node owns alone — carries a **revision**: a counter that moves
whenever that configuration changes, and a fingerprint of its contents. Every
node reports both, the Cluster table shows them per node, and the header says
**configuration agreed** or **configuration differs** at a glance.

Three things follow from it:

- **A node that is behind is named**, with the revision it holds and the one
  the cluster is on.
- **A node cannot push a configuration older than the one already there.** An
  isolated node that was edited and then reconnected would otherwise overwrite
  the current configuration with its own; it is refused, with both revisions in
  the message. To discard what is on the other node instead, **Overwrite** on
  the Cluster page lifts this node's revision above every other node's and
  pushes, so they end up on the same configuration and the same revision.
- **It heals itself.** With *Keep the nodes in step* on, the background health
  check already asks every node how it is; any node reporting an older revision
  is brought up to date from the node holding the newest, and a node that has
  just started takes the newest configuration from the cluster before it can
  serve anything stale. Nothing is queued, so nothing is lost — the next round
  observes the same disagreement and acts on it again.

### The Cluster page

Everything about the cluster lives on one page, split by what it applies to:

- **Cluster settings** — the virtual IPs, virtual router ID, VRRP password,
  advertisement interval, initial state, `nopreempt` and HAProxy tracking. These
  must be identical everywhere, so they are part of the shared configuration and
  travel with a push.
- **This node** — whether Keepalived runs here, the interface, this node's
  priority, its unicast addresses, the URL the others should use to reach it, and
  its API key. Never synced: these are meant to differ.
- **Other nodes** — one entry per node with its URL and the API key configured
  *on that node*. A push also hands each node the membership list, including a
  way back to this one, so you maintain the list in one place. Keys are stored
  per peer and never sent back to the browser.
- **This node right now** — the diagnostics described under Keepalived below.

An existing two-node setup is migrated automatically: the old single peer becomes
the first entry, and the shared VRRP settings move out of the node-local section.

### Only the active node is editable

The node holding the virtual IP is where the shared configuration is edited; the
others are **read-only** and show a banner saying so. This stops nodes from
diverging and then overwriting each other on the next push.

A passive node can still fix **itself** — interface, priority, unicast addresses,
peer list, login, API key, updates, and Apply — because a node that cannot take
the VIP has to be repairable. And when *no* node holds the VIP, the banner's
**Edit here anyway** unlocks that node, so a broken cluster is never a lockout.
The lock is enforced by the API, not just hidden in the UI.

The unlock belongs to the sign-in that asked for it: **Lock again** restores it,
and so does signing out or back in. It is not stored, so it cannot be left on by
accident, and another browser signed in to the same node is unaffected.

### Keepalived

- **Keepalived** runs on every node that has a virtual IP configured — it is not
  a per-node switch, so a node cannot sit in a cluster with VRRP quietly off.
  **Unicast addresses are derived** from the node list: each node asks the
  others for the address on their VRRP interface, excluding the virtual IP,
  which is why a DNS name is never used for this. There is nothing to type.
- **Keepalived** runs VRRP on every node with a shared **virtual IP**. Bind your
  Public Services to that VIP. Keepalived's settings are **node-local** — set them
  separately on each node, and they must agree on the **virtual router ID**. For
  non-preempting failover set every node to `BACKUP` with a different priority
  and enable `nopreempt`; the highest-priority node holds the VIP, and a
  recovered node won't yank it back.
- **Tracking HAProxy** decides when a node should give the virtual IP up. The
  default asks HAProxy through its admin socket whether it is serving, so an
  instance that is running but wedged — accepting connections and answering
  none — hands the address to a node that works. The alternative, *process*,
  only checks that something called `haproxy` exists, which a hung one still
  does. The check is a small script written next to `keepalived.conf` by the
  same Apply that writes it, and where there is no admin socket to ask it falls
  back to looking for the process rather than failing a healthy node.
  The **Keepalived** page diagnoses this node: whether the configured interface
  exists, whether the config was written, the VRRP state, and the
  `keepalived -t` output. The state is read from the journal when it is there
  to read — only the journal distinguishes FAULT from BACKUP — and otherwise
  worked out from whether the node holds the virtual IP, with the page saying
  which.
- **Sync** is push-based: the node you edit pushes to the others. A renewed
  certificate is pushed automatically by the node that renewed it.

### Node-local vs. synced

| Synced between nodes | Node-local (never synced) |
|---|---|
| Real Servers, Backend Pools, Public Services | Keepalived (interface, VRID, priority, VIP) |
| Conditions, Rules, Health Monitors | The peer list and their API keys |
| HAProxy Settings | API key |
| ACME accounts, challenges, certificates, automations | Administrator login |
| Deployed certificate PEM files | |

## Reaching the UI over HTTPS

**System → Web UI access** publishes this management UI through HAProxy itself,
so it answers at a name you choose:

```
Serve the UI through HAProxy   [x]
Address                        https://proxy.example.com
```

It builds the same objects the publish wizard would — a pool pointing at
`127.0.0.1:8080`, a host rule, the HTTPS listener, an HTTP→HTTPS redirect and a
certificate — and reuses a wildcard that already covers the name. Turning it off
removes them again. A host name already used by another service is refused
rather than quietly stolen from it.

**Set it on each node, with that node's own name.** The setting and everything it
creates are node-local: they are stripped from what a node sends its peers and
preserved when a configuration arrives, so `proxy1` never turns up on the other
nodes. The service appears in the Services list marked as managed, with no Edit
or Delete — change it from this page, or turn it off.

Once it works, set `HAM_LISTEN=127.0.0.1` in the service unit and restart, so the
plain-HTTP port is no longer reachable from anywhere but HAProxy. The page says
so while the UI is still listening on all addresses.

## Requesting a certificate

**Certificates → Request a certificate** asks for the domains and then, for the
two things a certificate needs, lets you either reuse what is already there or
create it in the same step:

- **ACME account** — an existing one, or a new one with its e-mail and CA
  (`letsencrypt_test` issues untrusted certificates with no rate limits, which
  is what you want while setting things up).
- **Challenge type** — an existing one, or a new HTTP-01 or DNS-01.

**Preview** shows exactly which objects will be created or reused before
anything is saved, and *Request it now* runs `acme.sh` immediately and shows its
log. It warns about the mistakes that are otherwise only visible in a failed
issuance: a wildcard with an HTTP-01 challenge (only DNS-01 can validate one), a
DNS-01 challenge with no API hook, and an account with no e-mail address.

### DNS API hooks

The **DNS API hook** field lists every hook the `acme.sh` on this node actually
provides — 191 of them, by provider name — and picking one shows the credentials
it needs, with a button that fills the variable names into the credentials box:

```
CloudFlare needs:
  CF_Key    — API Key
  CF_Email  — Your account email
or instead:
  CF_Token  — API Token
  CF_Account_ID — Account ID
  CF_Zone_ID — Zone ID. Optional.
```

That list is parsed from acme.sh itself rather than hard-coded, so it stays
correct as acme.sh adds providers. The field still accepts anything typed, so an
unknown or newer hook name is passed through unchanged.

## Statistics

**Statistics** reads HAProxy's admin socket (`show stat`) and refreshes every
five seconds:

- **Listeners** — status, current/max/total sessions, request rate, bytes in and
  out, denied requests and errors.
- **Each pool** — its own status, how many servers are up, and per server: state
  (UP / DOWN / MAINT / DRAIN / NOLB) with how long it has held it, active or
  backup, weight, sessions, queue, traffic, the last health check result
  (`L7OK`, `L4CON`, …) with its duration, failed-check and flap counts, and
  total downtime.

A server with health checking switched off reports `no check` and counts as up,
because HAProxy still routes to it.

## Notifications

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

### It alerts on changes, not on conditions

The watchdog runs every twenty seconds. Anything that reported a *state* would
arrive thousands of times a week, so alerts fire on **transitions** and an
unresolved problem is repeated only every `repeat_hours` (6 by default) until it
clears. Six watchdog rounds against one dead service produce two messages — "was
restarted", then "is healthy again" — not six.

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

## Watchdog

Each node supervises its own services. **Watchdog** shows what it sees and what
it has done.

The point is the distinction between *stopped* and *hung*. `systemctl is-active`
answers "is the process there", which a wedged process passes while serving
nothing — so each service gets a probe that makes it *do* something:

| Service | Liveness probe | Restarted when |
| --- | --- | --- |
| **HAProxy** | `show info` on its stats socket | the service is stopped or failed, or it does not answer within 5s |
| **Keepalived** | the service is running when the cluster wants it | it is stopped or failed while this node should be running it |
| **This app** | a real HTTP request to its own listener | see below |

It restarts deliberately, not reflexively:

- **Never against a configuration that cannot work.** If `haproxy -c` rejects
  the file, restarting is a loop that hides the fault, so it stops and says
  which line is wrong.
- **Never a service you disabled.** A masked or disabled unit is taken as "leave
  this alone" — a node in maintenance stays in maintenance.
- **Never endlessly.** Three restarts per fifteen minutes by default; after that
  it stops and reports, so a failing service stays visible instead of flapping.
- Everything it does is logged, so the **Logs** page carries the history.

### Watching the app itself

A watchdog inside a process cannot restart that process, so systemd does it. The
unit sets `WatchdogSec=90`, and the app pings systemd **only when a real request
to its own listener succeeds**. That catches the failure that matters: every
worker thread blocked, process healthy, UI answering nothing. Pinging from a
timer would report health from inside a process that serves none.

Verified by stopping the process with `SIGSTOP` — `systemctl is-active` still
said `active`, and systemd restarted it on the deadline:

```
systemd[1]: haproxy-manager.service: Watchdog timeout (limit 1min 30s)!
systemd[1]: haproxy-manager.service: Failed with result 'watchdog'.
systemd[1]: haproxy-manager.service: Scheduled restart job, restart counter is at 1.
```

In Docker there is no systemd: supervisord restarts the app if it *exits*, and
the image's `HEALTHCHECK` reports whether the UI answers, but nothing restarts a
hung container unless your orchestrator acts on that health status.

### Node health is collected here too

The watchdog polls every node on a schedule and keeps the result, so the UI
reads a snapshot instead of asking each node while you wait. The Cluster panel
shows the snapshot's age and has a **Refresh** button for a live round. With one
unresponsive node: **5.1s** to collect, **3ms** to read.

`HAM_CLUSTER_POLL` (15s) sets the collection interval; `HAM_CLUSTER_MAX_AGE`
(60s) is the age beyond which a request collects it inline rather than show
something stale.

## Logs

**Logs** merges four sources into one timeline, newest at the bottom:

| Source | Where it comes from |
| --- | --- |
| **Web UI** | this app's own log — sign-ins, every configuration change and who made it, apply results, certificate outcomes, sync results |
| **HAProxy** | `journalctl -u haproxy`, falling back to `/var/log/haproxy.log` or `/var/log/syslog` |
| **acme.sh** | acme.sh's own log, plus the recorded outcome of every issuance |
| **Keepalived** | `journalctl -u keepalived`, with the same fallback |

Tick the sources you want, filter by level, search the text, and choose how many
lines to keep. **Follow** re-reads every five seconds and stays pinned to the
bottom; untick it to scroll back without the view jumping. **Download** saves
exactly what you are looking at, filters and all, as plain text.

Timestamps are the node's own, and lines that carry none sort to the end rather
than to 1970. Requests are logged with the object's name but never the request
body, so passwords, API keys and DNS credentials do not reach the log.

The app writes its own log to `/var/lib/haproxy-manager/haproxy-manager.log`
(mode 0600, rotated at 4 MB, three kept) and to standard output, so
`journalctl -u haproxy-manager` shows the same lines.

In the Docker image there is no journal, so a small collector binds `/dev/log`
and tees it to both the container log and `/var/log/ham-syslog.log`, which is
what the viewer reads.

## Updates

The app carries a version (`VERSION`, starting at **1.0**) and asks GitHub for
the published one **once a day**. When a newer version exists, a chip appears in
the header and **Settings → Updates** offers a one-click update.

The update runs `install.sh --update --yes` on the node under `systemd-run`, in
its own transient unit. That detail matters: as a child of the service it would
be killed halfway, because restarting `haproxy-manager.service` takes down
everything in that service's cgroup. Progress is streamed into
`/var/lib/haproxy-manager/update.log` and shown live in the UI; the page keeps
polling across the restart. Your configuration, certificates and login are kept,
and **HAProxy keeps serving traffic** — only the management UI restarts.

One-click update applies to the installer-managed (systemd) install. In a
container the button explains that you should pull a new image instead.

To publish a new version: bump `VERSION`, push, and every node offers it within
a day. The check asks the GitHub API rather than `raw.githubusercontent.com`,
because raw is behind a CDN that keeps serving the old file for up to five
minutes after a push — long enough for a check straight after a release to
report the previous version. Raw is the fallback if the API is unreachable or
rate limited. `HAM_VERSION_URL` / `HAM_INSTALL_URL` point the whole mechanism at
a fork or a private mirror.

> The update fetches a script over the network and runs it as root. It is pinned
> to the repository above, and reaching it already requires an administrator
> login — the same login that can run arbitrary commands through an ACME
> automation — but if you would rather not have that path at all, leave the
> button alone and update with `install.sh --update` over SSH.

## Backup & Export

**System → Backup & Export** covers two different jobs:

- **Generated files** — download the `haproxy.cfg` and `keepalived.conf` this
  configuration renders to, exactly as Apply would write them. Downloading
  changes nothing on the node.
- **Configuration backup** — a JSON file holding everything the UI manages
  (Real Servers, Backend Pools, Public Services, Conditions, Rules, Health
  Monitors, HAProxy Settings and every ACME object). Restoring replaces all of
  those and leaves node-local settings — Keepalived, Sync, the login, the API
  key — untouched, so the same file can seed a second node. Nothing is applied
  until you press **Apply**, so you can review the result first.

The backup deliberately contains **no secrets**: no API key, no login, and no
private keys from the certificate directory. Certificates move between nodes
over Sync, or are re-issued.

## Security

- **Sign in with a username and password.** The installer creates the
  administrator and prints the generated password (also written to
  `/var/lib/haproxy-manager/admin-credentials.txt`, mode 0600); change it under
  System → Administrator login. Passwords are stored only as a PBKDF2-SHA256
  hash, the session is an HMAC-signed `HttpOnly` / `SameSite=Strict` cookie that
  expires after 12 hours, and repeated failures lock that address out briefly.
  The login is node-local — set it on each node.
- The **API key** (Cluster → *This node*) is for machines, not
  people: the peer must present it before it may push configuration here, and
  scripts can send it as `X-API-Key` instead of signing in.
- If no administrator exists yet, the UI asks you to create one on first visit.
  Until then only the calls that create it answer — everything else returns 401 —
  so a node waiting to be set up does not hand its configuration to whoever
  reaches it first.
- **Every API endpoint requires a session or the API key.** Of 63 routes exactly
  three answer without either: `/api/login`, `/api/whoami` (which
  unauthenticated returns nothing but whether an administrator exists), and
  `/api/setup`, which refuses once an administrator exists. This is verified by
  a test that walks every route and checks the rest refuse an anonymous caller.
  On a node with no administrator yet, `/api/setup/state` answers too, so the
  browser can tell it must offer the setup wizard; it returns 401 the moment an
  administrator exists.
  The sign-in page and its icons are served without a session too, because the
  page has to render before anyone can sign in; they come from a fixed list of
  filenames, not from the directory.
- **The administrator login is node-local, but it can be copied.** Each node
  stores its own; changing the password on one leaves the others as they were,
  which is a problem you tend to discover during a failover. The account dialog
  therefore offers **Apply to the other nodes** whenever there are any. What
  travels is the stored PBKDF2 salt and digest, over the peer channel,
  authenticated with the receiving node's API key — never the password, and
  never from a browser. If a node does not take it, the dialog says which one
  and why, and stays open: that node keeps the old login until you fix it.
- **Put the UI behind TLS** (or an SSH tunnel / reverse proxy). Over plain HTTP
  both the password and the session cookie cross the network in the clear.
- The service runs as **root** because it writes `/etc/haproxy`, `/etc/keepalived`
  and reloads services. Restrict who can reach port 8080.
- **Served by waitress**, a production WSGI server — deliberately as a single
  process with a thread pool. The app keeps state in process globals (the lock
  that makes configuration writes atomic, the failed-sign-in counters, the
  renewal timer), so running several worker *processes* would give each its own
  copy and let concurrent edits overwrite one another. Raise `HAM_THREADS` if
  you need more concurrency; do not put a multi-process server in front of it.
  If waitress is missing the app still starts, on the development server, and
  says so in the log.
- **Request bodies are capped** at 16 MB, and `config.json` — which holds the
  API key, session secret, peer keys and password hash — is written mode 0600.

## Install

Debian-based distributions (Debian 12/13, Ubuntu 22.04/24.04), on **every** node:

```bash
curl -fsSL https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/install.sh | sudo bash
```

From a checkout, `sudo ./install.sh` installs those files instead of
downloading. If HAProxy Cluster Manager is already installed the same command detects
it and offers to **update**, **remove** (keeping `config.json` and
certificates), **purge** (removing those too), or cancel; piped from `curl`
with no terminal to ask on, it updates in place and says so.

It installs `haproxy`, `keepalived`, `python3-flask`, `python3-requests`,
`python3-waitress`, `openssl`, `socat` and `iproute2` from apt, a pinned
[`acme.sh`](https://github.com/acmesh-official/acme.sh) with no cron of its own
(the manager drives renewals), enables `net.ipv4.ip_nonlocal_bind` so HAProxy
can bind a VIP this node does not hold, creates the administrator and API key,
and installs the systemd unit.

Nothing in HAProxy's configuration is touched until you press Apply. The first
Apply overwrites `/etc/haproxy/haproxy.cfg`, keeping a `.bak`.

**→ [Full installation guide](docs/install-standalone.md)** — every option, what
happens in what order, where each file lives, updating, uninstalling and
troubleshooting.

## Docker

Multi-architecture images (**linux/amd64** and **linux/arm64**) are published to
the GitHub Container Registry:

```bash
docker pull ghcr.io/avandeputte/haproxy-manager:latest   # or :1.46 to pin
docker compose up -d                                     # on every node
```

The image is all-in-one: the manager, HAProxy, Keepalived and `acme.sh` in one
container. There is no systemd inside a container, so `supervisord` runs the
processes and a small `systemctl` shim ([docker/systemctl](docker/systemctl))
translates the calls the app makes. HAProxy runs in master-worker mode and is
reloaded with `SIGUSR2`, so Apply does not drop established connections.

Host networking is the intended mode — Keepalived's VRRP and the virtual IP need
a real interface — and Keepalived needs `NET_ADMIN`, `NET_BROADCAST` and
`NET_RAW`. One container per node.

One thing a container cannot do: **restart a hung manager**. On a systemd host
`WatchdogSec` handles that; supervisord only restarts a process that exits. The
image's `HEALTHCHECK` reports it, but something has to act on that. For a
production cluster, the native install is the better fit.

**→ [Full Docker guide](docs/install-docker.md)** — images and tags, compose,
networking modes, volumes, environment, health, logs, upgrading and limitations.

## If the UI feels slow

Almost always it is waiting on another node, not on itself. A cluster member
that is *hung* — accepting connections but not answering — is far worse than one
that is cleanly down, because a refused connection fails instantly while a hung
one has to time out.

| Knob | Default | What it does |
| --- | --- | --- |
| `HAM_PEER_CONNECT_TIMEOUT` | `3` | how long to wait for a node to accept a connection |
| `HAM_PEER_READ_TIMEOUT` | `5` | how long to wait for it to answer a health query |
| `HAM_PUSH_READ_TIMEOUT` | `90` | how long to wait for it to accept and apply a pushed configuration |
| `HAM_CLUSTER_POLL` | `15` | how often the watchdog collects every node's health in the background |
| `HAM_CLUSTER_MAX_AGE` | `60` | age at which a stale snapshot is collected inline instead |
| `HAM_THREADS` | `16` | waitress worker threads |

Two things worth knowing:

- **Address peers by IP, not by name.** DNS resolution happens *before* any of
  the timeouts above start counting, so a slow or unavailable resolver stalls a
  peer query for as long as `/etc/resolv.conf` allows. It is also the wrong
  dependency: the name may be published by the very cluster that is in trouble.

  DNS is **not** cached on a stock Debian or Ubuntu server unless something is
  installed to do it: `nsswitch.conf` says `hosts: files dns`, and glibc has no
  cache of its own, so every lookup goes to the network. The resolver defaults
  are `timeout:5 attempts:2`, so a nameserver that does not answer costs ten
  seconds per lookup, every time — and a failed lookup is precisely the thing
  nothing can cache.

  If you must use names, do one of these:

  ```bash
  # 1. put the cluster in /etc/hosts -- checked before DNS, always instant
  printf '10.0.0.1 proxy1\n10.0.0.2 proxy2\n' >> /etc/hosts

  # 2. or fail fast instead of hanging
  printf 'options timeout:1 attempts:1\n' >> /etc/resolv.conf

  # 3. or install a caching resolver, and check it is being used
  apt-get install -y systemd-resolved && resolvectl statistics
  ```

  The Cluster page marks any peer that is addressed by name.
- **Apply waits for the push.** With auto-sync on, Apply returns only once every
  peer has taken the configuration or timed out, so a wedged node can keep the
  button spinning for `HAM_PUSH_READ_TIMEOUT`. The rest of the UI stays
  responsive throughout; only that request is waiting.

Set them in the systemd unit (`systemctl edit haproxy-manager`):

```ini
[Service]
Environment=HAM_PEER_READ_TIMEOUT=3
Environment=HAM_THREADS=24
```

## Environment overrides

`HAM_DATA_DIR` · `HAM_CERT_DIR` · `HAM_HAPROXY_CFG` · `HAM_KEEPALIVED_CFG` ·
`HAM_ACME_HOME` · `HAM_ACME_SH` · `HAM_LISTEN` · `HAM_PORT` · `HAM_THREADS` ·
`HAM_LOG_FILE` · `HAM_DEBUG=1` (verbose logging) · `HAM_STATS_SOCK` ·
`HAM_PEER_CONNECT_TIMEOUT` · `HAM_PEER_READ_TIMEOUT` · `HAM_PUSH_READ_TIMEOUT` ·
`HAM_CLUSTER_POLL` · `HAM_CLUSTER_MAX_AGE` · `HAM_WATCHDOG_PROBE_TIMEOUT` ·
`HAM_WATCHDOG_SELF_TIMEOUT` ·
`HAM_VERSION_URL` · `HAM_INSTALL_URL` · `HAM_DRY_RUN=1` (skip `systemctl` calls,
for development).

The app also has a small maintenance CLI, used by the installer and the Docker
entrypoint so neither has to reimplement password hashing:

```bash
python3 app.py show-admin                      # print the configured username
printf '%s' "$PW" | python3 app.py set-admin admin -    # set the login (stdin)
```

## Note

This is a configuration front-end, not a fork of the OPNsense plugins — it borrows
their structure and workflow but generates plain `haproxy.cfg` / `keepalived.conf`
and drives `acme.sh` directly.
