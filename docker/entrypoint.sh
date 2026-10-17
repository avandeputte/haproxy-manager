#!/bin/sh
# Prepare the writable state that the app expects, then hand off to supervisord.
set -eu

DATA_DIR="${HAM_DATA_DIR:-/var/lib/haproxy-manager}"
CERT_DIR="${HAM_CERT_DIR:-/etc/haproxy/certs}"
ACME_HOME="${HAM_ACME_HOME:-/var/lib/acme.sh}"

mkdir -p "$DATA_DIR" "$CERT_DIR" "$ACME_HOME" /run/haproxy \
         "$(dirname "${HAM_HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}")" \
         "$(dirname "${HAM_KEEPALIVED_CFG:-/etc/keepalived/keepalived.conf}")"
chmod 0700 "$DATA_DIR" "$ACME_HOME" "$CERT_DIR"

# Keepalived (Debian 13's reproducible build) will not start without the
# build-options file its package installs in /etc/keepalived -- a volume, so a
# volume created by an older image hides it. Refresh it from the image copy on
# every start so it always matches the binary. Keepalived reads this fixed
# path regardless of HAM_KEEPALIVED_CFG.
if [ -f /usr/sbin/keepalived.config-opts ]; then
    mkdir -p /etc/keepalived
    cp -f /usr/sbin/keepalived.config-opts /etc/keepalived/keepalived.config-opts
fi

# Refresh acme.sh's program files inside the (persisted) home on every start,
# without touching account keys, issued certificates or account.conf.
for item in acme.sh dnsapi deploy notify; do
    [ -e "/opt/acme.sh/$item" ] && cp -a "/opt/acme.sh/$item" "$ACME_HOME/"
done
[ -f "$ACME_HOME/account.conf" ] || cp -a /opt/acme.sh/account.conf "$ACME_HOME/account.conf" 2>/dev/null || true
chmod 0755 "$ACME_HOME/acme.sh" 2>/dev/null || true

# Optional: seed the UI login from the environment. Without it the first visit
# to the UI asks for a username and password.
if [ -n "${HAM_ADMIN_PASSWORD:-}" ] && [ -z "$(python3 /opt/haproxy-manager/app.py show-admin 2>/dev/null)" ]; then
    printf '%s' "$HAM_ADMIN_PASSWORD" |
        python3 /opt/haproxy-manager/app.py set-admin "${HAM_ADMIN_USER:-admin}" - >/dev/null &&
        echo "seeded administrator '${HAM_ADMIN_USER:-admin}' from the environment"
fi

exec "$@"
