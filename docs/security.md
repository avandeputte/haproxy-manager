# Security


- **A second factor, if you want one.** The account dialog can require a
  six-digit code from an authenticator app at every sign-in — standard TOTP,
  which any app produces. Enrolment only completes once the phone proves it
  holds the secret, so an unscanned QR code can never lock the account, and
  eight single-use recovery codes are shown once at setup. The pushed
  administrator record carries the second factor too, so a failover node asks
  for the same code. Lost phone, no recovery codes: `app.py disable-2fa` on
  the node's own shell — deliberately physical, because whoever can run that
  already owns the machine. The QR code is drawn by a small vendored encoder,
  verified module-for-module against a reference implementation; no
  dependency was added.
- **Sign in with a username and password.** The installer creates the
  administrator and prints the generated password (also written to
  `/var/lib/haproxy-manager/admin-credentials.txt`, mode 0600); change it from
  the account dialog, behind the gear beside your name. Passwords are stored only as a PBKDF2-SHA256
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
- **Every API endpoint requires a session or the API key.** Of 87 routes exactly
  three answer without either: `/api/login`, `/api/whoami` (which
  unauthenticated returns nothing but whether an administrator exists), and
  `/api/setup`, which refuses once an administrator exists. This is verified by
  a test that walks every route and checks the rest refuse an anonymous caller.
  On a node with no administrator yet, `/api/setup/state` answers too, so the
  browser can tell it must offer the setup wizard; it returns 401 the moment an
  administrator exists.
  The sign-in page and its icons are served without a session too, because the
  page has to render before anyone can sign in; they come from a fixed list of
  filenames, not from the directory. The `/.ham-sso/` routes for single
  sign-on are public by design — they exist to authenticate strangers — but
  they answer only on the configured sign-in host, act only on
  HMAC-signed parameters, and HAProxy routes nothing else to them.
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
