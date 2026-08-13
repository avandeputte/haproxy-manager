# Installing HAProxy Cluster Manager on a server

This is the intended way to run HAProxy Cluster Manager. HAProxy, Keepalived and
acme.sh are installed as normal system packages, systemd runs everything, and
the virtual IP works because the node is on a real network.

- [Before you start](#before-you-start)
- [Install](#install)
- [What the installer actually does](#what-the-installer-actually-does)
- [Installer options](#installer-options)
- [First sign-in](#first-sign-in)
- [Building a cluster](#building-a-cluster)
- [Updating](#updating)
- [Uninstalling](#uninstalling)
- [Where everything lives](#where-everything-lives)
- [Troubleshooting](#troubleshooting)

## Before you start

| Requirement | Notes |
| --- | --- |
| Debian-based distribution | Debian 12/13, Ubuntu 22.04/24.04. The installer refuses anything without `apt-get`. |
| systemd | The installer refuses to run without it. For containers see [install-docker.md](install-docker.md). |
| root | `sudo`, or run as root. The service writes `/etc/haproxy` and reloads system services. |
| Outbound HTTPS | To `github.com` for the download, and to your ACME provider for certificates. |
| A spare port | 8080 by default for the UI. |

If you plan to use a shared virtual IP, install on **every** node that should be
able to hold it, and make sure they can reach each other on the UI port and
send VRRP to one another.

## Install

Either a package or the script — both produce the same node: the app in
`/opt/haproxy-manager`, settings in `/var/lib/haproxy-manager`, one systemd
unit called `haproxy-manager`.

### From a package (recommended)

`.deb` and `.rpm` are attached to each [release](https://github.com/avandeputte/haproxy-manager/releases).
They carry acme.sh inside, so installing needs no network beyond your own
package mirrors.

```bash
# Debian / Ubuntu
curl -fsSLO https://github.com/avandeputte/haproxy-manager/releases/latest/download/haproxy-manager_1.78.2_all.deb
sudo apt-get install -y ./haproxy-manager_1.78.2_all.deb

# Fedora
curl -fsSLO https://github.com/avandeputte/haproxy-manager/releases/latest/download/haproxy-manager-1.78.2-1.noarch.rpm
sudo dnf install -y ./haproxy-manager-1.78.2-1.noarch.rpm

# RHEL / Rocky / Alma -- python3-flask and python3-waitress live in EPEL
sudo dnf install -y epel-release
sudo dnf install -y ./haproxy-manager-1.78.2-1.noarch.rpm
```

The package installs and starts the service, prints the generated
administrator password, and requires `haproxy` and `keepalived`, so your
package manager pulls both in.

Upgrading is `apt-get install ./…deb` or `dnf install ./…rpm` again: the
configuration, the login and issued certificates are left alone. Removing the
package keeps `/var/lib/haproxy-manager`; `apt-get purge` deletes it.

Tested on Debian 12, Ubuntu 24.04, Rocky 9 and Fedora 41 — each install is
verified in CI by installing on that distribution and signing in.

### From the script

```bash
curl -fsSL https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/install.sh | sudo bash
```

Or, if you would rather read it first — which is the sensible habit for anything
piped into a root shell:

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/install.sh
less install.sh
sudo bash install.sh
```

Running the script from a checkout installs *that* checkout instead of
downloading, which is the offline path:

```bash
git clone https://github.com/avandeputte/haproxy-manager
cd haproxy-manager
sudo ./install.sh
```

When it finishes it prints the URL, the generated administrator password and
the API key. Both are also written to files under `/var/lib/haproxy-manager`
with mode 0600.

## What the installer actually does

In order, so nothing is a surprise:

1. **Checks it can proceed** — root, `apt-get`, systemd, a valid port.
2. **Detects an existing install** and offers to update or remove it.
3. **Installs packages**: `haproxy`, `keepalived`, `python3`, `python3-flask`,
   `python3-requests`, `python3-waitress`, `openssl`, `curl`, `socat`,
   `iproute2`, `tar`, `ca-certificates`.
4. **Downloads the application** from GitHub. If the archive host cannot be
   reached it retries, then retries over IPv4, then falls back to fetching the
   individual files from `raw.githubusercontent.com`.
5. **Installs acme.sh** into `/root/.acme.sh` at a pinned version. Skipped with
   `--skip-acme`.
6. **Deploys** `app.py`, the `ham/` package, `static/` and `VERSION` to
   `/opt/haproxy-manager`.
7. **Enables `net.ipv4.ip_nonlocal_bind`**, so HAProxy can bind a virtual IP
   this node does not currently hold. Written to
   `/etc/sysctl.d/99-haproxy-manager.conf`.
8. **Creates the administrator** and an API key, unless you supplied them.
9. **Installs and starts the systemd unit** `haproxy-manager.service`.
10. **Waits for the UI to answer**, then prints how to reach it.

Nothing in HAProxy's configuration is touched until you press **Apply** in the
UI. Installing does not disturb an existing HAProxy setup — but the first Apply
overwrites `/etc/haproxy/haproxy.cfg`, keeping a `.bak` beside it.

## Installer options

Every flag has an environment-variable equivalent, which is what you want when
piping into `bash`:

| Flag | Variable | Default |
| --- | --- | --- |
| `--repo <owner/name>` | `HAM_REPO` | `avandeputte/haproxy-manager` |
| `--ref <branch\|tag>` | `HAM_REF` | `main` |
| `--port <port>` | `HAM_PORT` | `8080` |
| `--listen <address>` | `HAM_LISTEN` | `0.0.0.0` |
| `--dest <dir>` | `HAM_DEST` | `/opt/haproxy-manager` |
| `--admin-user <name>` | `HAM_ADMIN_USER` | `admin` |
| `--admin-password <pw>` | `HAM_ADMIN_PASSWORD` | generated |
| `--api-key <key>` | `HAM_API_KEY` | generated |
| `--no-api-key` | — | — |
| `--skip-acme` | `HAM_SKIP_ACME` | — |
| `--tarball <url\|path>` | `HAM_TARBALL` | — |
| — | `HAM_ACME_VERSION` | `3.1.4` — the acme.sh release to install |
| — | `GITHUB_TOKEN` | for a private repository |
| `--update` / `--uninstall` / `--purge` | — | decide up front instead of being asked |
| `-y`, `--yes` | — | do not ask for confirmation |

Unattended, with your own credentials:

```bash
curl -fsSL https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/install.sh \
  | sudo HAM_ADMIN_USER=alex HAM_ADMIN_PASSWORD='...' HAM_PORT=8080 bash -s -- --yes
```

## First sign-in

1. Open `http://<node>:8080`.
2. Sign in with the printed credentials, or create the administrator if you
   installed without one.
3. Change the password under **System → Administrator login**.
4. Publish something under **Services**, then press **Apply**.

Straight after that, do two things:

- Put the UI behind TLS — see [configuration.md](configuration.md#serving-the-ui-over-https),
  which can publish the UI through HAProxy with a certificate in a few clicks.
  Over plain HTTP the password and session cookie cross the network in clear.
- Restrict who can reach port 8080.

## Building a cluster

On the first node, set **Cluster → This node → This node's URL** to an address
the others can reach — **an IP address**, not a DNS name. Then on each further
node, use **Join an existing cluster** and give it that URL and the first
node's API key.

Why an IP: every health check resolves the name again (nothing caches DNS on a
stock Debian), and the name may be published by the very cluster that is in
trouble. See [configuration.md](configuration.md#addressing-nodes).

## Updating

From the UI: **Settings → Updates → Update now**, which can update the other
nodes in the same go. It re-runs the
installer in a transient systemd unit, so the service can restart under it.

From the shell, which does the same thing:

```bash
curl -fsSL https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/install.sh | sudo bash -s -- --update --yes
```

An update replaces `app.py`, `ham/`, `static/` and `VERSION`, and rewrites the systemd
unit. It does not touch `config.json`, certificates or ACME account keys. If the
download fails, nothing is replaced and the running version keeps working.

## Uninstalling

```bash
sudo /opt/haproxy-manager/install.sh --uninstall   # keeps config.json and certificates
sudo /opt/haproxy-manager/install.sh --purge       # also deletes them
```

Neither removes HAProxy, Keepalived or acme.sh — they are ordinary packages, and
whatever configuration was last applied keeps running. Remove them with `apt`
if you want them gone.

## Where everything lives

| Path | What |
| --- | --- |
| `/opt/haproxy-manager` | `app.py`, `ham/`, `static/`, `VERSION` |
| `/var/lib/haproxy-manager/config.json` | every setting, mode 0600 |
| `/var/lib/haproxy-manager/haproxy-manager.log` | the app's log, rotated at 4 MB |
| `/var/lib/haproxy-manager/admin-credentials.txt` | generated password, mode 0600 |
| `/var/lib/haproxy-manager/api-key.txt` | generated API key, mode 0600 |
| `/etc/haproxy/haproxy.cfg` | generated on Apply, previous kept as `.bak` |
| `/etc/haproxy/certs/` | deployed certificate PEMs |
| `/etc/keepalived/keepalived.conf` | generated on Apply when Keepalived is enabled |
| `/root/.acme.sh/` | ACME account keys, issued certificates, acme.sh's own log |
| `/etc/systemd/system/haproxy-manager.service` | the unit |

## Troubleshooting

**The service will not start.**

```bash
systemctl status haproxy-manager
journalctl -u haproxy-manager -n 50 --no-pager
```

**The UI does not answer but the process is running.** That is the case the
watchdog exists for: the unit sets `WatchdogSec=90` and the app only pings
systemd when a real request to its own listener succeeds, so systemd restarts
it. Confirm the unit has it:

```bash
systemctl show haproxy-manager -p WatchdogUSec -p NotifyAccess
```

An install from before 1.42 has no `WatchdogSec`; re-running the installer
rewrites the unit.

**Apply fails validation.** The message contains HAProxy's own complaint,
including the line number. Nothing is written when validation fails, so the
running configuration is untouched.

**HAProxy will not bind the virtual IP.** Check
`sysctl net.ipv4.ip_nonlocal_bind` is `1`.

**The download failed during install.** The installer retries and falls back to
`raw.githubusercontent.com`. If it still fails it prints what to check —
usually the resolver. Nothing caches DNS on a stock Debian, so a nameserver
that is briefly unavailable fails every lookup for as long as it is down.

**Everything looks fine but nothing is being served.** Check the **Statistics**
page for the pool's state, and the **Logs** page, which merges the UI's log with
HAProxy, acme.sh and Keepalived.
