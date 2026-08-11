#!/bin/sh
# Runs after install and after upgrade, on both .deb and .rpm.
# Must be idempotent: an upgrade runs it again over a working installation.
set -e
# A failing step must not disappear: without this the script could abort
# half-way and leave the service disabled with nothing said about it.
trap 'rc=$?; [ "$rc" -ne 0 ] && echo "HAProxy Cluster Manager: post-install failed at line $LINENO (exit $rc); the service may not be enabled -- run: systemctl enable --now haproxy-manager" >&2; exit $rc' EXIT

DATA=/var/lib/haproxy-manager
CERTS=/etc/haproxy/certs
ACME_HOME=/root/.acme.sh
BUNDLED_ACME=/usr/share/haproxy-manager/acme.sh

install -d -m 0700 "$DATA"
install -d -m 0700 "$CERTS"

# acme.sh ships inside the package, so installing needs no network. Only the
# program files are refreshed; account keys and issued certificates are left
# exactly as they are.
if [ -d "$BUNDLED_ACME" ]; then
    install -d -m 0755 "$ACME_HOME"
    for item in acme.sh dnsapi deploy notify; do
        [ -e "$BUNDLED_ACME/$item" ] && cp -a "$BUNDLED_ACME/$item" "$ACME_HOME/"
    done
    [ -f "$ACME_HOME/account.conf" ] || \
        cp -a "$BUNDLED_ACME/account.conf" "$ACME_HOME/account.conf" 2>/dev/null || true
    chmod 0755 "$ACME_HOME/acme.sh" 2>/dev/null || true
fi

# HAProxy binds a virtual IP this node may not currently hold. /etc/sysctl.d
# is not present on every minimal image, so create it rather than assume it.
install -d -m 0755 /etc/sysctl.d
if [ ! -f /etc/sysctl.d/99-haproxy-manager.conf ]; then
    echo "net.ipv4.ip_nonlocal_bind = 1" > /etc/sysctl.d/99-haproxy-manager.conf
fi
# sysctl lives in /sbin, which is not always on a package script's PATH.
if command -v sysctl >/dev/null 2>&1; then
    sysctl -q -w net.ipv4.ip_nonlocal_bind=1 2>/dev/null || true
elif [ -x /sbin/sysctl ]; then
    /sbin/sysctl -q -w net.ipv4.ip_nonlocal_bind=1 2>/dev/null || true
fi

# Seed the login and API key BEFORE the service starts. Writing into a live
# configuration would race the running process; doing it first cannot.
if [ ! -f "$DATA/config.json" ]; then
    PW="$(head -c 15 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    KEY="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    if printf '%s' "$PW" | /usr/bin/python3 /opt/haproxy-manager/app.py set-admin admin - >/dev/null 2>&1; then
        /usr/bin/python3 /opt/haproxy-manager/app.py set-api-key "$KEY" >/dev/null 2>&1 || KEY=""
        umask 077
        printf 'username: admin\npassword: %s\n' "$PW" > "$DATA/admin-credentials.txt"
        [ -n "$KEY" ] && printf '%s\n' "$KEY" > "$DATA/api-key.txt"
        SEEDED=1
    fi
fi

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable haproxy-manager >/dev/null 2>&1 || true
systemctl restart haproxy-manager >/dev/null 2>&1 || true

if [ -n "${SEEDED:-}" ]; then
    ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -n "$ADDR" ] || ADDR="$(hostname)"
    cat <<EOF

  HAProxy Cluster Manager is running at  http://$ADDR:8080

    username  admin
    password  $PW

  Also saved to $DATA/admin-credentials.txt (mode 0600).
  Change it under System > Administrator login, and put the UI behind TLS.

EOF
fi
exit 0
