# haproxy-manager

A small self-hosted web UI to manage an **HAProxy** configuration, obtain
**Let's Encrypt** certificates, and run an **active-passive pair with Keepalived**
on a shared virtual IP — with settings and certificates syncing between the two
nodes.

## Publishing a service

The normal way to use this is **Services → Publish a service**: give it the URL
people will visit and the server behind it.

```
Public URL    https://ps2.iothing.net
Forward to    http://192.168.1.100:1781
```

From those two lines it creates the Real Server, Backend Pool, host Condition,
routing Rule, the HTTPS listener, an ACME certificate, and an HTTP listener that
redirects to HTTPS — then applies. **Preview** shows exactly what it will create,
and the resulting `haproxy.cfg`, before anything is written.

- **Wildcard certificates are reused, not duplicated.** If a certificate already
  covers the host — `*.iothing.net` for `ps2.iothing.net`, or an exact name —
  the wizard attaches it instead of requesting another one, and says so before
  you commit. An exact name wins over a wildcard that would also match, and
  `*.iothing.net` correctly does **not** cover `iothing.net` or
  `a.b.iothing.net`. Set Certificate to *always request a new certificate* to
  override, or *no certificate* to terminate TLS elsewhere.
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
- **A path** works too: `https://ps2.iothing.net/api` routes only that prefix.
  More specific rules are placed ahead of broader ones, so a host+path rule is
  never swallowed by the host-only rule for the same name.
- **Publishing the same URL again edits it** — repointing a service replaces its
  target rather than quietly adding a second server behind it.
- **Overview** is the landing page and lists every configured service alongside
  node health, certificates and the generated configuration. **Services** shows
  the same table on its own. Delete removes the objects that mapping alone was
  using.

The **Advanced** section still exposes every object individually, for the cases
the wizard does not cover (TCP mode, header rewriting, custom ACLs). The
navigation there mirrors the two OPNsense plugins this UI was modeled on:

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
| Automations | Automations (run after issue/renew) |
| Settings | Settings |

## How it works

- All state lives in a single JSON file (`$HAM_DATA_DIR/config.json`). No database.
- **Apply** renders `haproxy.cfg`, validates it with `haproxy -c` *before* writing
  anything, then writes the file (keeping a `.bak`) and reloads HAProxy. If
  Keepalived is enabled it renders and reloads `keepalived.conf` too.
- **ACME** issuance/renewal shells out to [`acme.sh`](https://github.com/acmesh-official/acme.sh).
  Certificates are written as combined `fullchain + key` PEMs into the HAProxy
  certificate directory (what HAProxy's `crt` expects), then the certificate's
  Automations run (e.g. reload HAProxy, sync to peer). A built-in loop renews on
  the interval set in ACME → Settings.
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

## High availability (active-passive)

- **Keepalived** runs VRRP on both nodes with a shared **virtual IP**. Bind your
  Public Services to that VIP. Keepalived's settings are **node-local** — set them
  separately on each node. For non-preempting failover, set both nodes to `BACKUP`
  with different priorities and enable `nopreempt`; the higher-priority node holds
  the VIP, and a recovered node won't yank it back. "Track HAProxy process" fails
  over automatically if HAProxy dies.
- **Sync** is push-based. On the active node, set Sync → Peer URL / Peer API key to
  the passive node and either push manually ("Sync to peer now"), enable "Sync
  after every Apply", or add a `sync_to_peer` Automation to a certificate. The peer
  receives the **shared** config (HAProxy + ACME) and the deployed certificate
  files, validates, applies and reloads. Its **node-local** settings — Keepalived,
  Sync target, API key — are never overwritten, so there's no sync loop.

### Node-local vs. synced

| Synced between nodes | Node-local (never synced) |
|---|---|
| Real Servers, Backend Pools, Public Services | Keepalived (interface, VRID, priority, VIP) |
| Conditions, Rules, Health Monitors | Sync peer URL / peer key |
| HAProxy Settings | API key |
| ACME accounts, challenges, certificates, automations | Administrator login |
| Deployed certificate PEM files | |

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
- The **API key** (High Availability → Sync → *This node*) is for machines, not
  people: the peer must present it before it may push configuration here, and
  scripts can send it as `X-API-Key` instead of signing in.
- If no administrator exists yet, the UI asks you to create one on first visit —
  and until you do, the API is unauthenticated. The installer sets one up, so
  this only applies to a hand-rolled deployment.
- **Put the UI behind TLS** (or an SSH tunnel / reverse proxy). Over plain HTTP
  both the password and the session cookie cross the network in the clear.
- The service runs as **root** because it writes `/etc/haproxy`, `/etc/keepalived`
  and reloads services. Restrict who can reach port 8080.

## Install

Debian-based distributions (Debian, Ubuntu, ...). Run it on **both** nodes:

```bash
curl -fsSL https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/install.sh | sudo bash
```

or, from a checkout, `sudo ./install.sh` — the installer uses the local files
when it finds them next to itself, and downloads the release from GitHub
otherwise.

If haproxy-manager is already installed, the same command detects it, prints
where it lives and whether it is running, and offers to **update**, **remove**
(keeping `config.json` and certificates), **purge** (removing those too), or
cancel. Piped from `curl` with no terminal to ask on, it updates in place and
says so. Pass `--update`, `--uninstall` or `--purge` to skip the question, and
`-y` to skip the confirmation. An update keeps the port the node already runs
on and leaves `config.json`, issued certificates and node-local settings alone.

What it does:

- installs `haproxy`, `keepalived`, `python3-flask`, `python3-requests`,
  `openssl`, `socat`, `iproute2` from apt;
- installs a pinned [`acme.sh`](https://github.com/acmesh-official/acme.sh) into
  `/root/.acme.sh` with no cron of its own — the manager drives renewals;
- deploys the app to `/opt/haproxy-manager` and installs + enables
  `haproxy-manager.service`, so it starts on boot;
- enables `haproxy.service` and `keepalived.service`. Keepalived stays inert
  until you enable it in the UI (its unit has
  `ConditionFileNotEmpty=/etc/keepalived/keepalived.conf`) and comes back on
  its own after a reboot once configured;
- sets `net.ipv4/ipv6.ip_nonlocal_bind=1` in `/etc/sysctl.d/`, so HAProxy on the
  **passive** node can bind the shared VIP it does not currently hold;
- creates the administrator login (`admin` with a generated password) and a
  random API key for peer sync, prints both, and stores them in
  `/var/lib/haproxy-manager/admin-credentials.txt` and `api-key.txt` (mode 0600).
  Updating an installation that predates the login creates one for it.

Options — flags, or the equivalent environment variables:

| Flag | Variable | Default |
|---|---|---|
| `--port` | `HAM_PORT` | `8080` |
| `--listen` | `HAM_LISTEN` | `0.0.0.0` |
| `--dest` | `HAM_DEST` | `/opt/haproxy-manager` |
| `--repo` / `--ref` | `HAM_REPO` / `HAM_REF` | `avandeputte/haproxy-manager` / `main` |
| `--admin-user` | `HAM_ADMIN_USER` | `admin` |
| `--admin-password` | `HAM_ADMIN_PASSWORD` | random |
| `--api-key` / `--no-api-key` | `HAM_API_KEY` | random |
| `--skip-acme` | `HAM_SKIP_ACME` | off |
| `--tarball` | `HAM_TARBALL` | — |
| `--update` / `--uninstall` / `--purge` | — | ask |
| `-y`, `--yes` | — | ask |
| — | `GITHUB_TOKEN` | for a private repository |

```bash
curl -fsSL .../install.sh | sudo bash -s -- --port 9000 --no-api-key
```

Then open `http://<node>:8080` and follow the steps the installer prints. See the
table above for what to configure where.

## Docker

The image is all-in-one: the manager, HAProxy, Keepalived and `acme.sh` in one
container. There is no systemd inside a container, so `supervisord` runs the
processes and a small `systemctl` shim ([docker/systemctl](docker/systemctl))
translates the calls the app makes. HAProxy runs in master-worker mode and is
reloaded with `SIGUSR2`, so Apply does not drop established connections.

```bash
docker compose up -d --build     # run on BOTH nodes
```

Then open `http://<node>:8080` and follow the same steps as above.

- **Networking.** `docker-compose.yml` defaults to `network_mode: host`. That is
  the intended setup: HAProxy binds whatever ports your Public Services define,
  and Keepalived's VRRP/VIP needs a real interface. For a single standalone node
  without Keepalived you can switch to bridge mode and publish ports explicitly —
  the compose file has the block commented out.
- **Capabilities.** Keepalived needs `NET_ADMIN`, `NET_BROADCAST` and `NET_RAW`
  (already in the compose file). Without them the VIP cannot be claimed.
- **Login.** Set `HAM_ADMIN_USER` / `HAM_ADMIN_PASSWORD` to seed the
  administrator on first start; otherwise the UI asks you to create one on your
  first visit.
- **State** lives in four volumes: `/var/lib/haproxy-manager` (config.json),
  `/var/lib/acme.sh` (ACME accounts + issued certs), `/etc/haproxy`
  (haproxy.cfg + deployed cert PEMs) and `/etc/keepalived`.
- **Logs.** HAProxy's `log /dev/log` is forwarded to the container's stdout, so
  `docker logs` shows HAProxy, the manager and supervisord together.
- **Keepalived per node.** Keepalived settings are node-local, so set the
  interface/VRID/priority separately in each node's container — they are never
  synced.
- Ports `8080` (UI/API) and `9080` (HTTP-01 standalone listener) are declared by
  the image; the ports your Public Services bind to are yours to publish.

Build the image on its own with `docker build -t haproxy-manager .`; the
`acme.sh` version is pinned by the `ACME_VERSION` build arg.

## Environment overrides

`HAM_DATA_DIR` · `HAM_CERT_DIR` · `HAM_HAPROXY_CFG` · `HAM_KEEPALIVED_CFG` ·
`HAM_ACME_HOME` · `HAM_ACME_SH` · `HAM_LISTEN` · `HAM_PORT` · `HAM_DRY_RUN=1`
(skip `systemctl` calls, for development).

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
