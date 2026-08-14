# Running in Docker

The image is an all-in-one: HAProxy, Keepalived, acme.sh and the manager in one
container, with supervisord in place of systemd.

Read [Limitations](#limitations) before using this in production — a container
cannot supervise itself the way systemd does, and Keepalived needs the host's
network.

- [Images](#images)
- [Quick start](#quick-start)
- [docker compose](#docker-compose)
- [Networking](#networking)
- [Volumes](#volumes)
- [Environment](#environment)
- [Capabilities](#capabilities)
- [Health](#health)
- [Logs](#logs)
- [Upgrading](#upgrading)
- [Limitations](#limitations)
- [Building it yourself](#building-it-yourself)

## Images

Published to the GitHub Container Registry for **linux/amd64** and
**linux/arm64** — the same tag works on an x86 server and on a Raspberry Pi or
Ampere instance; Docker picks the right one.

```
ghcr.io/avandeputte/haproxy-manager:latest    the tip of main
ghcr.io/avandeputte/haproxy-manager:1.83.0      a specific version
ghcr.io/avandeputte/haproxy-manager:sha-abc…  one exact commit
```

Pin a version in production. `latest` moves whenever main does.

## Quick start

```bash
docker run -d --name haproxy-manager \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_BROADCAST --cap-add NET_RAW \
  -e HAM_ADMIN_USER=admin \
  -e HAM_ADMIN_PASSWORD='change-me-please' \
  -v ham-data:/var/lib/haproxy-manager \
  -v ham-acme:/var/lib/acme.sh \
  -v ham-haproxy:/etc/haproxy \
  -v ham-keepalived:/etc/keepalived \
  ghcr.io/avandeputte/haproxy-manager:latest
```

Then open `http://<host>:8080`. Without `HAM_ADMIN_PASSWORD` the UI asks you to
create an administrator on the first visit.

## docker compose

The repository's `docker-compose.yml` is ready to use:

```bash
curl -fsSLO https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/docker-compose.yml
docker compose up -d
```

It uses the published image by default. To build from a checkout instead,
uncomment the `build: .` line.

## Networking

**Host networking is the intended mode**, and the default in the compose file:

```yaml
network_mode: host
```

Two reasons. HAProxy binds whatever ports your Public Services define, and
host networking means you do not have to republish the container every time you
add one. More importantly, Keepalived's VRRP and the virtual IP only work on a
real interface — in bridge mode there is no VIP, and no failover.

Bridge mode is fine for a **single standalone node** with no VIP. Publish every
port you intend to serve:

```yaml
ports:
  - "8080:8080"   # UI and API
  - "80:80"
  - "443:443"
  - "9080:9080"   # acme.sh HTTP-01 standalone listener
```

Run **one container per node**. Several containers on one host cannot each hold
the virtual IP.

## Volumes

Four, and all of them matter:

| Volume | Holds | Losing it means |
| --- | --- | --- |
| `/var/lib/haproxy-manager` | `config.json` — every setting, the API key, the password hash | starting over |
| `/var/lib/acme.sh` | ACME account keys and issued certificates | re-issuing everything, against rate limits |
| `/etc/haproxy` | generated `haproxy.cfg` and deployed certificate PEMs | rebuilt on the next Apply |
| `/etc/keepalived` | generated `keepalived.conf` | rebuilt on the next Apply |

The image declares the first three as `VOLUME`, so Docker creates anonymous
volumes if you do not name them — recoverable, but hard to find. Name them.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `HAM_ADMIN_USER` | `admin` | seeds the login on first start |
| `HAM_ADMIN_PASSWORD` | — | seeds the password; without it the UI asks |
| `HAM_PORT` | `8080` | UI and API port |
| `HAM_LISTEN` | `0.0.0.0` | bind address |
| `HAM_THREADS` | `16` | waitress worker threads |
| `HAM_DRY_RUN` | — | `1` renders and validates but never reloads services |

The full list, including timeouts and the watchdog, is in
[configuration.md](configuration.md#environment-variables). Seeding only
happens when no administrator exists yet; it never overwrites one.

## Capabilities

```yaml
cap_add:
  - NET_ADMIN       # Keepalived: add and remove the virtual IP
  - NET_BROADCAST   # Keepalived: VRRP advertisements
  - NET_RAW         # Keepalived: raw VRRP sockets
```

Drop all three if you are not using Keepalived. HAProxy binds privileged ports
as root inside the container and needs nothing extra.

## Health

The image carries a `HEALTHCHECK` that asks the UI to answer a real request,
rather than checking that a port is open:

```bash
docker inspect --format '{{.State.Health.Status}}' haproxy-manager
```

Note what this does and does not do: it *reports* health. Docker alone will not
restart an unhealthy container — an orchestrator, or `--restart` plus something
watching, has to act on it. See [Limitations](#limitations).

## Logs

Everything goes to the container's stdout, so `docker logs` shows HAProxy,
Keepalived, the manager and supervisord together.

The image has no journal, so a small collector (`docker/syslogd.py`) binds
`/dev/log` and writes each message both to stdout and to
`/var/log/ham-syslog.log`, which is what the UI's **Logs** page reads back for
HAProxy and Keepalived. It is capped at 8 MB with one rotation.

## Upgrading

```bash
docker compose pull && docker compose up -d
```

Your volumes carry the configuration across. The one-click update in the UI is
deliberately disabled in a container — it says so — because replacing files
inside a running image is not how containers are meant to be updated.

## Limitations

Worth knowing before you rely on this:

- **Nothing restarts a hung manager.** On a systemd host, `WatchdogSec` restarts
  the app when it stops answering. supervisord only restarts a process that
  *exits*, so a wedged one stays wedged. The `HEALTHCHECK` reports it; acting on
  that is up to you.
- **Keepalived needs host networking** and the capabilities above. Without them
  there is no virtual IP and no failover.
- **The in-app watchdog still works** — it supervises HAProxy and Keepalived
  through the `systemctl` shim, which maps onto supervisorctl.
- **One container per host.**

For a production cluster the native install is the better fit:
[install-standalone.md](install-standalone.md).

## Building it yourself

```bash
git clone https://github.com/avandeputte/haproxy-manager
cd haproxy-manager
docker build -t haproxy-manager .
```

For both architectures, as the workflow does:

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t haproxy-manager .
```

`--build-arg ACME_VERSION=3.1.4` pins acme.sh. The image is built and published
by `.github/workflows/docker-publish.yml` on every push to `main`, which also
starts both architectures and checks that the UI answers before the run passes.
