# Requiring a sign-in


A service can ask its visitors to prove who they are, two ways — and both
are enforced by HAProxy itself, so an unauthenticated request never reaches
the servers behind it:

- **Basic authentication** — a user name and password, checked from a
  `userlist` in the generated configuration. Users and groups are managed
  under **Sign-in**; a service admits groups rather than people, so access
  changes by moving someone in or out of a group. Passwords are stored only
  as SHA-512 crypt hashes, and a sign-in nobody can satisfy renders as
  `http-request deny` — refusing everyone is safer than quietly becoming
  public.
- **Single sign-on (OIDC)** — the service sends visitors through an OpenID
  Connect provider (Authentik, Keycloak, Authelia, Pocket ID, Google,
  Entra), with a per-service allow-list of emails and `@domains`. One
  sign-in covers every protected service; **HAProxy verifies the session on
  every request** in pure configuration — an HMAC-signed cookie, no Lua,
  HAProxy 2.4+ — so the app stays out of the traffic path and a failover
  signs nobody out. The upstream app sees none of the login unless a
  per-service toggle passes the *verified* identity as
  `X-Auth-Request-Email`/`Remote-User` for apps that trust a proxy identity.

Source-address controls compose with either: **Allowed networks** (a CIDR
allow-list, which works for `tcp://` services too) and **Skip the sign-in
from** (networks trusted without a password, typically the LAN).

A **rate limit** rounds this off. *Requests per client* on the service (or
the pool) refuses a client address that asks more than that many times in a
sliding window — HTTP with a 429, TCP by dropping the connection — until it
slows down. The counter lives in the pool's stick table, so it shares the one
table with source persistence when both are on; alone, 100 requests per 10 s
comes out as:

```
http-request track-sc0 src
http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }
stick-table type ipv6 size 30k expire 30s store http_req_rate(10s)
```

The whole subject — the settings, the sign-in flow, provider setup, the
trust model, and what to do when something refuses — lives in
[docs/authentication.md](authentication.md).

The **Advanced · HAProxy** menu group still exposes every object individually,
for the cases the wizard does not cover (header rewriting, custom ACLs,
per-object tuning). Every editor there carries a second tab, **haproxy.cfg**,
showing exactly what Apply will write for that object — recomputed from the
values as they stand in the form, not as they were saved, so an edit can be
read before it is committed. Raw lines the fields do not cover go in each
object's *Extra directives*; the file itself stays generated, because parsing
a hand-written haproxy.cfg back into objects would be guesswork dressed up as
a feature. The pages mirror the OPNsense plugins this UI was modeled on:

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
