# Updates


The app carries a version (`VERSION`, starting at **1.0**) and asks GitHub for
the published one **once a day**. When a newer version exists, a chip appears in
the header and **Settings → Updates** offers a one-click update.

**The whole cluster from one node.** Where there are other nodes, Updates
offers *Update the other N nodes as well*, ticked by default — visiting each
node to press the same button is the thing worth avoiding. They are told
first, while the node you are on is still running to tell them, and each
restarts when its own update finishes. Every node runs the same installer
against the same source, so there is nothing to hand over, only the
instruction. A node that does not take it is named with the reason and stays
on the version it had; nothing retries it, because an update is something a
person started and the node that missed it is their decision to make. The
Cluster page shows the version each node ends up on, and warns when they are
not all the same.

The update runs `install.sh --update --yes` on the node under `systemd-run`, in
its own transient unit. That detail matters: as a child of the service it would
be killed halfway, because restarting `haproxy-manager.service` takes down
everything in that service's cgroup. Progress is streamed into
`/var/lib/haproxy-manager/update.log` and shown live in the UI; the page keeps
polling across the restart. Your configuration, certificates and login are kept,
and **HAProxy keeps serving traffic** — only the management UI restarts.

One-click update applies to the installer-managed (systemd) install. In a
container the button explains that you should pull a new image instead.

**Betas.** A change worth trying before it is released goes out as a beta: the
same code on the `beta` branch with a version like `1.96.0-beta.1`, its own
packages and image, and a release marked *pre-release* on GitHub. No node
offers it until *Also offer beta versions* is ticked under **Settings →
Updates**; from then on the daily check reads both branches and offers
whichever is newer, and a node on a beta takes the release when it comes
(`1.96.0` is newer than `1.96.0-beta.1`). Untick it and the beta stops being
offered at once. Updating the other nodes from a beta node moves them to the
same beta — the update carries its branch — so a cluster stays on one version
either way. `HAM_BETA_REF` names a different branch.

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

### If a configuration change goes wrong

`config.json` is written by rename, so it is never half-written, and the
previous version is kept beside it as `config.json.bak`. `haproxy.cfg` and
`keepalived.conf` keep a `.bak` too, written before each Apply.

The management UI is served by the app itself on port 8080, not through
HAProxy, so **`http://<node-address>:8080` reaches it even when HAProxy is
misrouting** — which is the way back in if a published address stops
answering. To put HAProxy back the way it was:

```bash
cp /etc/haproxy/haproxy.cfg.bak /etc/haproxy/haproxy.cfg
systemctl reload haproxy
```

If the UI's own service is what is broken, **Settings → Web UI access → Save**
rebuilds it from the stored setting — the pool, the rule, the conditions for
both its addresses and the certificate — and re-attaches it to the listener.
Set **Certificate** to request a new one if the listener has lost the one it
was serving: an HTTPS listener with no certificate fails validation, and Apply
refuses rather than writing it, which leaves the node showing unapplied changes
until it is put right. Apply names that case when it happens.
