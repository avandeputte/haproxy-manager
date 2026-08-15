# Authentication

Three different front doors, deliberately separate:

| Door | Who it is for | Where it is checked |
| --- | --- | --- |
| [The management UI](#the-management-ui) | you, administering this app | this app, per node |
| [Basic auth on a service](#basic-auth-on-a-service) | visitors to a published service | HAProxy, from a `userlist` |
| [Single sign-on on a service](#single-sign-on-oidc) | visitors, via an OIDC provider | HAProxy, from a signed cookie |

A service uses basic auth **or** single sign-on, never both. The
[source-address controls](#source-address-controls) compose with either, and
with neither. None of these share accounts: a service user cannot open this
UI, and this UI's administrator is nobody special to a service.

## The management UI

Each node has one administrator, stored per node — set it on each node, or
let **Apply to the other nodes** do it (below). The password is stored only
as a PBKDF2 hash. Signing in issues a session cookie signed with a per-node
secret; sessions last `session_hours` (12 by default), and rotating the
node's `session_secret` signs everyone out of that node.

Changing the password or the username asks for the current password — a
session alone is not enough to change how you sign in. When the cluster has
other nodes, the account dialog offers **Apply to the other nodes**, ticked
by default: it sends the stored salt and digest — never the password — to
each node's `/api/admin/receive`, authenticated by that node's API key. A
browser session on the receiving node cannot reach that endpoint; only the
key can.

**Two-factor authentication** is optional, per administrator, from the same
dialog: standard TOTP, six digits every thirty seconds. Setup shows a QR
code and completes only when the current code proves the authenticator holds
the secret; eight single-use recovery codes are shown once. A code cannot be
replayed, and *Apply to the other nodes* carries the second factor with the
login. The escape hatch for a lost phone is `app.py disable-2fa` on the
node's shell.

**The API key** (Cluster → This node) is the machine door: automation and
the other nodes present it as `X-API-Key`, and `/metrics` accepts it as a
bearer token. It is node-local and never synced.

## Basic auth on a service

A service can ask visitors for a user name and password — HTTP basic
authentication, checked by HAProxy itself, so a request without valid
credentials is answered 401 and never reaches the servers behind it.

Tick **Require a sign-in** in the publish wizard (or on a Backend Pool under
Advanced), and manage who may answer under **Sign-in → Users** and
**Sign-in → Groups**:

| Field | Notes |
| --- | --- |
| User name | letters, digits, and `. - _ @` — it travels in a configuration line and comes back from a browser |
| Password | at least 8 characters, stored only as a SHA-512 crypt (`$6$`) hash — the format HAProxy reads. Leaving the field empty when editing keeps the current one. |
| Groups | which groups the user belongs to |
| Enabled | off keeps the account but stops it signing in anywhere |

On the service:

| Field | Notes |
| --- | --- |
| Require a sign-in | HTTP services only — a raw TCP port has nowhere to carry one. Use it over HTTPS: on plain HTTP the credentials cross the network in the clear. |
| Allowed groups | none ticked admits any user; otherwise only members of those groups. A service admits groups rather than people, so access changes by moving someone in or out of a group. |
| Sign-in prompt | the realm the browser shows above its password box; defaults to the pool name |
| Skip the sign-in from | networks trusted without a password, typically the LAN — `192.168.1.0/24` browses freely while everyone else meets the password box |

What ends up in `haproxy.cfg` is a `userlist` and one line per protected
pool:

```
userlist ham_users
    group staff
    user alice password $6$... groups staff

backend be_shop
    http-request auth realm "The Shop" unless { http_auth_group(ham_users) staff }
```

Two edges are deliberate. A group that a service admits cannot be deleted
while that service admits it — the request is refused and names the service.
And a service that requires a sign-in nobody can satisfy (no users with a
password yet, or every group it admitted is gone) renders as `http-request
deny`: refusing everyone is safer than quietly becoming public.

Users and groups are shared across the cluster, because the services that
check them are — a failover meets the same credentials. The backup carries
them **without** the password hashes, like every other secret, so users
restored from a backup need a password set again; the users already on the
node keep theirs.

## Source-address controls

Beside the sign-in options in the same wizard section:

- **Allowed networks** — one address or CIDR per line; requests from
  anywhere else are refused. Unlike a sign-in this works for `tcp://`
  services too (`tcp-request content reject`), which is how a database port
  is kept to the LAN. An entry that does not parse is refused at the form;
  one that somehow reaches the renderer anyway is left out, which only ever
  narrows who gets in — and a list with no readable entries refuses everyone
  rather than admitting everyone.
- The addresses HAProxy tests are the **TCP source** — behind another proxy
  that is the proxy's address, not the visitor's.

## Single sign-on (OIDC)

Instead of a password box, a service can send its visitors through an OpenID
Connect provider — Authentik, Keycloak, Authelia, Pocket ID, Google, Entra:
anything that answers OIDC discovery. One sign-in covers every protected
service; who may enter stays a per-service decision.

### Setting it up

**Sign-in → Single sign-on** holds the provider, once:

| Setting | Notes |
| --- | --- |
| Issuer URL | must be `https://`; its `/.well-known/openid-configuration` is read from here. **Test** proves it before saving. |
| Client ID / secret | from the provider's client registration; a blank secret keeps the stored one |
| Sign-in host | e.g. `auth.example.com` — point its DNS at the virtual IP; HAProxy routes exactly `/.ham-sso/` on it to this app and answers 404 for anything else. It needs certificate coverage on the HTTPS listener (a wildcard is enough). |
| Cookie domain | the domain the session spans, e.g. `example.com`. The sign-in host and every protected service must sit under it. Never a bare public suffix (`com`, `co.uk`) — browsers refuse such cookies. |
| Scopes | `openid email profile` unless the provider needs otherwise |
| Session length | default 12 hours. Single sessions cannot be revoked (nothing is stored anywhere); **Rotate secret** is the kill switch and signs everyone out everywhere. |
| Accept unverified email claims | off by default; see [unverified emails](#unverified-emails) |

Register the redirect URI the page shows —
`https://<sign-in host>/.ham-sso/callback` — at the provider. The page
carries step-by-step setup instructions for authentik, Authelia and Google,
with your real hostnames filled in.

On the service — the publish wizard, or a Backend Pool under Advanced:

| Field | Notes |
| --- | --- |
| Require single sign-on | HTTP services only; `tcp://` cannot carry a redirect. Not together with basic auth — one sign-in per service. |
| Allowed identities | one per line: an email, a whole domain as `@example.com`, or a literal `*` for anyone the provider signs in. An empty list refuses everyone — "anyone" is never a silent default, because with a public provider that would mean every account it has. |
| Pass the signed-in email to the servers | sets identity headers for apps that trust a proxy identity; see [what the upstream sees](#what-the-upstream-application-sees) |

### How a sign-in actually runs

1. An unauthenticated request to a protected service meets HAProxy, which
   finds no valid session cookie and redirects the browser to the sign-in
   host, carrying the original URL.
2. This app (reached only through that host) redirects on to the provider's
   authorization endpoint — authorization-code flow with PKCE, a signed
   `state`, and a nonce cookie that binds the transaction to this browser.
3. The visitor authenticates at the provider — their password only ever
   exists there.
4. The provider sends the browser back to `/.ham-sso/callback`; the app
   exchanges the code over TLS, vets the claims (issuer, audience, expiry,
   nonce, verified email), and sets the session cookie:
   `Domain=<cookie domain>; Secure; HttpOnly` — expiry, the address, and an
   HMAC signature over both.
5. The browser lands back on the exact page it first asked for. From here
   on, **HAProxy alone** verifies the cookie on every request — signature
   (timing-safe), expiry, and the service's allow-list — in generated
   configuration, with this app out of the traffic path.

A signed-in visitor who is not on a service's list gets a 403, not another
trip to the provider. The signing secret is shared configuration, so every
node validates every session and a failover signs nobody out. Signing out at
`https://<sign-in host>/.ham-sso/logout` clears the cookie; the provider's
own session is the provider's business.

### What the upstream application sees

Nothing, by default. The password never leaves the provider; the session
cookie is stripped from requests before they are forwarded — on every
service, so no upstream app ever holds a token that opens the others — and
the request arrives looking anonymous.

Apps that *want* the identity — Grafana's auth-proxy mode and its relatives
— get it by ticking **Pass the signed-in email to the servers**, which sets
`X-Auth-Request-Email` and `Remote-User` from the verified session. Client-
sent copies of those headers are deleted on every service whether or not it
forwards, so the header is always the proxy's word: a forgery meets an empty
header, never a passed-through one. Only safe while the app is reachable
through the proxy alone.

### Unverified emails

Authorization is the email string, so it is only as true as the provider's
word for it. A provider sending `email_verified: false` is refused by
default — on a provider where people edit their own profile, an unverified
email is just a text field anyone can set to anyone. Keycloak marks
admin-created users unverified until *Email verified* is switched on; prefer
flipping that. **Accept unverified email claims** exists for providers that
cannot say verified at all, and the warning lives where the switch is. An
absent claim is trusted — some providers simply never send one.

### When something refuses

- **"the provider says that email address is unverified"** — see
  [above](#unverified-emails).
- **"the identity provider did not answer"** on Test or sign-in — the
  issuer URL is wrong, or its certificate does not verify. A provider behind
  a private CA needs `REQUESTS_CA_BUNDLE` pointing at the CA file in this
  app's environment: `Environment=REQUESTS_CA_BUNDLE=/etc/ssl/private-ca.pem`
  in a systemd drop-in, or `-e REQUESTS_CA_BUNDLE=...` with a volume for
  Docker.
- **The provider complains about the redirect URI** — what is registered
  there must match `https://<sign-in host>/.ham-sso/callback` exactly.
- **Signing in loops or never sticks** — the cookie domain is wrong: a bare
  public suffix (browsers refuse the cookie), or the service's host does not
  sit under it (the cookie is never sent back).
- **403 after a successful sign-in** — the sign-in worked; that service's
  allow-list does not include the signed-in address. That is the design: fix
  the list, not the session.
- **"this sign-in was started by a different browser"** — the callback
  arrived without the nonce cookie the login set. Usually a stale bookmark
  of the provider's page or a cookie-blocking extension on the sign-in host.
- **A stolen or leaked session** — **Rotate secret**. Every session on every
  service stops verifying at the next request.

### The trust model, in one place

- The ID token arrives on a private TLS connection to the token endpoint,
  authenticated by the client secret; its claims are checked (issuer,
  audience, expiry, nonce) rather than its signature — the channel vouches
  for it, per OIDC Core 3.1.3.7, and every request afterwards is verified
  against our own HMAC instead.
- PKCE and a browser-bound state stop injected authorization codes and
  login CSRF; the return address is rebuilt from vetted parts, so the
  callback cannot be used as an open redirect.
- Every enforcement decision after sign-in is HAProxy configuration:
  timing-safe signature comparison, expiry, allow-list. The app being down
  does not sign anyone out, and a half-configured service fails closed —
  `http-request deny`, never quietly public.
- The signing secret appears (base64) in the generated `haproxy.cfg`, which
  is root-only — the same trust level as the basic-auth hashes already
  there.
