# Proxmox VE LXC

A one-line install of HAProxy Cluster Manager into a Debian LXC on Proxmox VE,
built on the [community-scripts](https://community-scripts.org) engine — the
same machinery behind every script on that site. Run it on the Proxmox host:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/proxmox/ct/haproxy-manager.sh)"
```

It creates an **unprivileged** Debian 13 container (1 CPU, 1 GB, 4 GB disk by
default — the usual advanced-settings dialog lets you change any of it),
installs the current release package inside, starts the service, and prints
the URL and the generated login. The credentials are also kept in
`/root/haproxy-manager.creds` in the container.

## What it installs

The container gets exactly what a package install gets: the release `.deb`,
which carries acme.sh and pulls `haproxy`, `keepalived` and the Python
dependencies through `Depends`. The package is architecture-independent, so
this works on arm64 hosts too. Only stable releases are offered — the beta
channel is never selected here.

## Updating

Run the same script **inside** the container. The engine notices it is in a
container and updates instead of building a new one:

```bash
pct enter <CTID>
bash -c "$(curl -fsSL https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/proxmox/ct/haproxy-manager.sh)"
```

Use this rather than the app's own Updates page on a container built this way:
both install the same files, but this one keeps the package database and the
version check in step.

## Clustering

Keepalived and VRRP failover work in an **unprivileged** container — tested with
two containers and the virtual IP moving between them. One thing to check on
the host: if the container's Proxmox firewall has **IP filtering** enabled, the
shared virtual IP (which is not the container's own address) is dropped.
Disable it for the container's NIC. Unicast VRRP is derived from the node list
automatically, so multicast on the bridge is not a requirement.

## Why it lives here

community-scripts lists new applications only once they are at least six
months old with 600+ GitHub stars. The scripts here are the tested submission,
hosted in this repository until the project qualifies; the engine is designed
to run scripts from any base (`COMMUNITY_SCRIPTS_URL`), and `ct/` sets that to
this folder so nothing has to be typed. When the project is listed there, the
one-liner on their site becomes the canonical one and this folder points at
it.

The two scripts follow the community-scripts CT and install templates and are
MIT-licensed like the engine they build on, which is why their headers carry
both copyrights.
