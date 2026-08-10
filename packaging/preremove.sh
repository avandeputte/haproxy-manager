#!/bin/sh
# $1 is "remove"/"upgrade" (deb) or 0/1 (rpm). Stop only on a real removal:
# stopping during an upgrade would take the proxy's control plane down for no
# reason, and postinstall restarts it anyway.
set -e
case "${1:-}" in
    upgrade|1) exit 0 ;;
esac
systemctl stop haproxy-manager >/dev/null 2>&1 || true
systemctl disable haproxy-manager >/dev/null 2>&1 || true
exit 0
