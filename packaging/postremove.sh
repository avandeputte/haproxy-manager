#!/bin/sh
# Settings, certificates and ACME account keys are deliberately kept: removing
# the package should not destroy the configuration of a proxy that is still
# serving traffic. `apt-get purge` clears them; on rpm, remove them by hand.
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
if [ "${1:-}" = "purge" ]; then
    rm -rf /var/lib/haproxy-manager
    rm -f /etc/sysctl.d/99-haproxy-manager.conf
fi
exit 0
