#!/bin/sh
# Prepare the writable state that the app expects, then hand off to supervisord.
set -eu

DATA_DIR="${HAM_DATA_DIR:-/var/lib/haproxy-manager}"
CERT_DIR="${HAM_CERT_DIR:-/etc/haproxy/certs}"
ACME_HOME="${HAM_ACME_HOME:-/var/lib/acme.sh}"

mkdir -p "$DATA_DIR" "$CERT_DIR" "$ACME_HOME" /run/haproxy \
         "$(dirname "${HAM_HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}")" \
         "$(dirname "${HAM_KEEPALIVED_CFG:-/etc/keepalived/keepalived.conf}")"
chmod 0700 "$DATA_DIR" "$ACME_HOME"

# Refresh acme.sh's program files inside the (persisted) home on every start,
# without touching account keys, issued certificates or account.conf.
for item in acme.sh dnsapi deploy notify; do
    [ -e "/opt/acme.sh/$item" ] && cp -a "/opt/acme.sh/$item" "$ACME_HOME/"
done
[ -f "$ACME_HOME/account.conf" ] || cp -a /opt/acme.sh/account.conf "$ACME_HOME/account.conf" 2>/dev/null || true
chmod 0755 "$ACME_HOME/acme.sh" 2>/dev/null || true

exec "$@"
