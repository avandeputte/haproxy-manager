# How it works

- **All state lives in a single JSON file** (`$HAM_DATA_DIR/config.json`) — no
  database process, no schema, no migrations. The app is one Python process
  behind waitress; the only things running are it, HAProxy, and Keepalived.
  The generated `haproxy.cfg` and `keepalived.conf` are derived from that file
  and can be regenerated at any time, so the JSON is the single source of truth
  and the only thing worth backing up.
- **Timestamps are stored and sent in UTC, and shown in the browser's own
  timezone** — certificate expiries, snapshots, the watchdog's actions, log
  lines. The server has no idea where the reader is; the browser is the one
  thing that does.
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
  rather than the one that node last saw. There is nothing to configure.
- **ACME** issuance/renewal shells out to [`acme.sh`](https://github.com/acmesh-official/acme.sh).
  Certificates are written as combined `fullchain + key` PEMs into the HAProxy
  certificate directory (what HAProxy's `crt` expects). HAProxy is then reloaded
  and the certificate pushed to the other nodes, with nothing to configure. A
  built-in loop renews on the interval set in Settings → ACME Settings.
- **HTTP-01** challenges use a local `acme.sh --standalone` listener. When
  "HAProxy integration" is on, every HTTP Public Service automatically routes
  `/.well-known/acme-challenge/` to it, and HTTP→HTTPS redirects skip that path —
  so you can keep port 80 fronted by HAProxy and still validate.
- **Apply checks that HAProxy is actually serving afterwards.** `systemctl`
  returning success means the reload was accepted, not that HAProxy came back:
  a configuration that passes `haproxy -c` can still fail to start, because
  `-c` never binds a socket. So Apply asks HAProxy over its stats socket, and
  if it is not answering it puts the previous `haproxy.cfg` back, reloads
  again, and says so — loudly, and by notification. Without that a node can be
  left not listening at all, which looks like the node being down rather than
  like a configuration that was just applied.
- Before a real certificate exists, Apply drops in a short-lived **self-signed
  placeholder** so HAProxy can start; the first successful issue replaces it.
  It covers every name the certificate is for, and is replaced when those names
  change — a service answering for two names with a stand-in covering one of
  them serves the wrong certificate on the other.
- **Certificate status** is shown on Overview and under ACME → Certificates:
  whether the PEM on disk is a real certificate or still the placeholder, its
  issuer, its expiry date with the days remaining, and the outcome, timestamp
  and full `acme.sh` log of the last issue/renew attempt (the **Log** button).
- **The names on the record are not the names in the file.** Adding a name to a
  certificate does not reissue it, so until it is issued again that name is
  served whatever was issued before — which a browser reports as a failure to
  connect, not as a certificate problem. The names are read from the PEM
  itself, so the Certificates page says *not in the issued certificate* and
  names them, and the publish wizard says so at the moment it extends one.

## Note

This is a configuration front-end, not a fork of the OPNsense plugins — it borrows
their structure and workflow but generates plain `haproxy.cfg` / `keepalived.conf`
and drives `acme.sh` directly.
