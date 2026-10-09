# Tuning

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
