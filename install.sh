#!/usr/bin/env bash
#
# haproxy-manager installer for Debian-based distributions (Debian, Ubuntu, ...).
#
#   curl -fsSL https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/install.sh | sudo bash
#
# or from a checkout:
#
#   sudo ./install.sh
#
# Run it on BOTH nodes. Re-running upgrades an existing install in place;
# config.json, issued certificates and node-local settings are preserved.
#
# Options (flags, or the equivalent environment variables):
#   --repo   <owner/name>  HAM_REPO      GitHub repository        (avandeputte/haproxy-manager)
#   --ref    <branch|tag>  HAM_REF       branch or tag to install (main)
#   --port   <port>        HAM_PORT      UI/API port              (8080)
#   --listen <address>     HAM_LISTEN    UI/API bind address      (0.0.0.0)
#   --dest   <dir>         HAM_DEST      install directory        (/opt/haproxy-manager)
#   --api-key <key>        HAM_API_KEY   API key to set on this node
#   --no-api-key                         leave the API unauthenticated
#   --skip-acme            HAM_SKIP_ACME=1   do not install acme.sh
#   --tarball <url|path>   HAM_TARBALL   install from this tarball instead of GitHub
#                          GITHUB_TOKEN  token used to fetch a private repository
#
# Everything is wrapped in functions and only invoked from main() at the very
# bottom, so a truncated download cannot half-execute.

set -euo pipefail
umask 022

REPO="${HAM_REPO:-avandeputte/haproxy-manager}"
REF="${HAM_REF:-main}"
DEST="${HAM_DEST:-/opt/haproxy-manager}"
DATA="${HAM_DATA_DIR:-/var/lib/haproxy-manager}"
CERTS="${HAM_CERT_DIR:-/etc/haproxy/certs}"
ACME_HOME="${HAM_ACME_HOME:-/root/.acme.sh}"
PORT="${HAM_PORT:-8080}"
LISTEN="${HAM_LISTEN:-0.0.0.0}"
TARBALL="${HAM_TARBALL:-}"
SKIP_ACME="${HAM_SKIP_ACME:-0}"
ACME_VERSION="${HAM_ACME_VERSION:-3.1.4}"
UNIT=/etc/systemd/system/haproxy-manager.service

SRC=""        # populated by fetch_source
TMPDIR_=""    # cleaned up on exit
ACME_OK=1

# --------------------------------------------------------------------------
# output helpers
# --------------------------------------------------------------------------

if [ -t 1 ]; then
    C_B=$'\033[1m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_0=$'\033[0m'
else
    C_B=""; C_G=""; C_Y=""; C_R=""; C_0=""
fi

log()  { printf '%s>>%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%s!!%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
die()  { printf '%s!!%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

cleanup() { [ -n "$TMPDIR_" ] && rm -rf "$TMPDIR_"; }

usage() {
    cat <<'EOF'
haproxy-manager installer (Debian-based distributions)

  curl -fsSL https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/install.sh | sudo bash
  sudo ./install.sh

Options (or the equivalent environment variable):
  --repo    <owner/name>   HAM_REPO       GitHub repository        (avandeputte/haproxy-manager)
  --ref     <branch|tag>   HAM_REF        branch or tag            (main)
  --port    <port>         HAM_PORT       UI/API port              (8080)
  --listen  <address>      HAM_LISTEN     UI/API bind address      (0.0.0.0)
  --dest    <dir>          HAM_DEST       install directory        (/opt/haproxy-manager)
  --api-key <key>          HAM_API_KEY    API key for this node (random if unset)
  --no-api-key                            leave the API unauthenticated
  --skip-acme              HAM_SKIP_ACME  do not install acme.sh
  --tarball <url|path>     HAM_TARBALL    install from this tarball instead of GitHub
                           GITHUB_TOKEN   token for a private repository
EOF
}

# --------------------------------------------------------------------------
# arguments
# --------------------------------------------------------------------------

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --repo)       REPO="${2:?--repo needs a value}"; shift 2 ;;
            --ref)        REF="${2:?--ref needs a value}"; shift 2 ;;
            --port)       PORT="${2:?--port needs a value}"; shift 2 ;;
            --listen)     LISTEN="${2:?--listen needs a value}"; shift 2 ;;
            --dest)       DEST="${2:?--dest needs a value}"; shift 2 ;;
            --tarball)    TARBALL="${2:?--tarball needs a value}"; shift 2 ;;
            --api-key)    HAM_API_KEY="${2:?--api-key needs a value}"; shift 2 ;;
            --no-api-key) HAM_API_KEY=""; shift ;;
            --skip-acme)  SKIP_ACME=1; shift ;;
            -h|--help)    usage; exit 0 ;;
            *)            die "unknown option: $1 (try --help)" ;;
        esac
    done
}

# --------------------------------------------------------------------------
# preflight
# --------------------------------------------------------------------------

preflight() {
    [ "$(id -u)" -eq 0 ] || die "this installer must run as root (use sudo)"
    command -v apt-get >/dev/null || die "no apt-get found -- this installer supports Debian-based distributions only"
    [ -d /run/systemd/system ] || die "systemd is not running -- for containers use the Docker image instead (see README)"
    command -v curl >/dev/null || {
        log "Installing curl"
        DEBIAN_FRONTEND=noninteractive apt-get update -q
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl
    }
    case "$PORT" in ''|*[!0-9]*) die "invalid port: $PORT" ;; esac
}

# --------------------------------------------------------------------------
# steps
# --------------------------------------------------------------------------

install_packages() {
    log "Installing packages (haproxy, keepalived, python3-flask, ...)"
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a          # keep Ubuntu's needrestart from prompting
    apt-get update -q
    apt-get install -y --no-install-recommends \
        python3 python3-flask python3-requests \
        haproxy keepalived \
        openssl ca-certificates curl socat iproute2 procps tar
}

fetch_source() {
    # A checkout next to this script wins, so `sudo ./install.sh` stays offline.
    local self_dir=""
    if [ "${BASH_SOURCE[0]:-}" != "" ] && [ -f "${BASH_SOURCE[0]}" ]; then
        self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi
    if [ -n "$self_dir" ] && [ -f "$self_dir/app.py" ] && [ -f "$self_dir/static/index.html" ]; then
        log "Installing from local checkout $self_dir"
        SRC="$self_dir"
        return
    fi

    TMPDIR_="$(mktemp -d)"
    trap cleanup EXIT INT TERM
    local tgz="$TMPDIR_/src.tar.gz"

    if [ -n "$TARBALL" ] && [ -f "$TARBALL" ]; then
        log "Installing from tarball $TARBALL"
        cp "$TARBALL" "$tgz"
    else
        local url="${TARBALL:-https://codeload.github.com/$REPO/tar.gz/$REF}"
        log "Downloading $REPO@$REF"
        local -a auth=()
        [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
        curl -fsSL "${auth[@]}" "$url" -o "$tgz" \
            || die "download failed: $url (private repo? set GITHUB_TOKEN, or check --repo/--ref)"
    fi

    mkdir -p "$TMPDIR_/src"
    tar -xzf "$tgz" -C "$TMPDIR_/src" --strip-components=1 || die "could not unpack the downloaded archive"
    SRC="$TMPDIR_/src"

    [ -f "$SRC/app.py" ] && [ -f "$SRC/static/index.html" ] \
        || die "archive does not contain app.py and static/index.html -- wrong --repo/--ref?"
}

install_acme() {
    if [ "$SKIP_ACME" = "1" ]; then
        log "Skipping acme.sh (--skip-acme)"
        ACME_OK=0
        return
    fi
    if [ -x "$ACME_HOME/acme.sh" ]; then
        log "acme.sh already installed at $ACME_HOME"
        return
    fi

    # Installed from a pinned release tarball rather than get.acme.sh: that
    # bootstrap treats its first argument as "email=..." and mangles anything
    # else into an unknown parameter, and it exits 0 even when it fails.
    log "Installing acme.sh $ACME_VERSION into $ACME_HOME (no cron -- the manager drives renewals)"
    local dir="${TMPDIR_:-/tmp}/acme"
    if mkdir -p "$dir" \
        && curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/tags/$ACME_VERSION.tar.gz" \
             -o "$dir/acme.tar.gz" \
        && tar -xzf "$dir/acme.tar.gz" -C "$dir" --strip-components=1 \
        && ( cd "$dir" && ./acme.sh --install --nocron \
                 --home "$ACME_HOME" --config-home "$ACME_HOME" >/dev/null 2>&1 )
    then
        :
    fi
    rm -rf "$dir"

    if [ ! -x "$ACME_HOME/acme.sh" ]; then
        ACME_OK=0
        warn "acme.sh install failed -- certificates will not issue until it is installed"
        warn "   the manager looks for it at $ACME_HOME/acme.sh (override with HAM_ACME_SH)"
    fi
}

install_app() {
    log "Deploying application to $DEST"
    install -d -m 0755 "$DEST" "$DEST/static"
    install -d -m 0700 "$DATA"
    install -d -m 0700 "$CERTS"
    install -m 0644 "$SRC/app.py" "$DEST/app.py"
    install -m 0644 "$SRC/static/index.html" "$DEST/static/index.html"
}

configure_system() {
    # HAProxy must be able to bind the shared VIP on the node that does not
    # currently hold it, otherwise the passive node cannot start its frontends.
    log "Enabling non-local bind (needed to bind the Keepalived VIP)"
    cat > /etc/sysctl.d/60-haproxy-manager.conf <<'EOF'
# Installed by haproxy-manager: let HAProxy bind the Keepalived VIP even when
# this node is passive and does not hold the address.
net.ipv4.ip_nonlocal_bind = 1
net.ipv6.ip_nonlocal_bind = 1
EOF
    sysctl -q --system >/dev/null 2>&1 || warn "sysctl --system failed -- non-local bind may be inactive until reboot"

    # keepalived.service carries ConditionFileNotEmpty=/etc/keepalived/keepalived.conf,
    # so enabling it now is harmless: it stays inert until the manager writes a
    # config, and then comes back automatically after a reboot.
    install -d -m 0755 /etc/keepalived
    systemctl enable keepalived >/dev/null 2>&1 || warn "could not enable keepalived.service"
    systemctl enable haproxy    >/dev/null 2>&1 || warn "could not enable haproxy.service"
}

seed_api_key() {
    # Only ever touched on a fresh install -- an existing config.json is left alone.
    API_KEY=""
    HAD_KEY=0
    if [ -e "$DATA/config.json" ]; then
        python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("local",{}).get("api_key") else 1)' \
            "$DATA/config.json" 2>/dev/null && HAD_KEY=1
        return
    fi

    if [ "${HAM_API_KEY+set}" = "set" ]; then
        API_KEY="$HAM_API_KEY"                     # may be empty => leave the API open
    else
        API_KEY="$(openssl rand -hex 24)"
    fi
    [ -n "$API_KEY" ] || return

    python3 - "$DATA/config.json" "$API_KEY" <<'EOF'
import json, os, sys
path, key = sys.argv[1], sys.argv[2]
# app.py merges defaults into whatever it finds, so a partial file is enough.
with open(path, "w") as f:
    json.dump({"local": {"api_key": key}}, f)
os.chmod(path, 0o600)
EOF
    printf '%s\n' "$API_KEY" > "$DATA/api-key.txt"
    chmod 0600 "$DATA/api-key.txt"
}

install_service() {
    log "Installing systemd service"
    cat > "$UNIT" <<EOF
[Unit]
Description=HAProxy Manager web UI
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Runs as root: it writes /etc/haproxy, /etc/keepalived and reloads services.
# To harden, grant CAP_NET_ADMIN + write access to those paths and drop privileges instead.
User=root
Environment=HAM_DATA_DIR=$DATA
Environment=HAM_CERT_DIR=$CERTS
Environment=HAM_HAPROXY_CFG=/etc/haproxy/haproxy.cfg
Environment=HAM_KEEPALIVED_CFG=/etc/keepalived/keepalived.conf
Environment=HAM_ACME_HOME=$ACME_HOME
Environment=HAM_LISTEN=$LISTEN
Environment=HAM_PORT=$PORT
ExecStart=/usr/bin/python3 $DEST/app.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$UNIT"
    systemctl daemon-reload
    systemctl enable haproxy-manager >/dev/null
    systemctl restart haproxy-manager
}

wait_for_ui() {
    local i
    for i in $(seq 1 30); do
        if curl -fs -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    warn "the UI did not answer on port $PORT within 30s -- check: journalctl -u haproxy-manager -n 50"
    return 1
}

summary() {
    local ip
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
    [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -n "$ip" ] || ip="<this-node>"

    echo
    printf '%s>> haproxy-manager is running at http://%s:%s%s\n' "$C_B" "$ip" "$PORT" "$C_0"
    echo
    if [ -n "${API_KEY:-}" ]; then
        printf '   API key for this node: %s%s%s\n' "$C_B" "$API_KEY" "$C_0"
        echo "   Paste it into the sidebar field to use the UI. Also saved at $DATA/api-key.txt."
    elif [ "${HAD_KEY:-0}" = "1" ]; then
        echo "   API key: unchanged (already set on this node)."
    else
        warn "No API key is set -- anyone who can reach port $PORT controls this node."
        echo "   Set one under High Availability > Sync > This node."
    fi
    [ "$ACME_OK" = "1" ] || warn "acme.sh is missing -- certificate issuance will fail until it is installed."
    cat <<EOF

   Next steps:
     1. High Availability > Sync: set/confirm the API key on THIS node (do the same on the peer).
     2. High Availability > Keepalived: enable, set interface/VRID/priority and the shared VIP.
     3. Add Real Servers, Backend Pools and Public Services; bind services to the VIP.
     4. ACME: add an Account + Challenge Type, then a Certificate, and click Issue.
     5. Point the ACTIVE node's Sync > Peer URL at the passive node and push.

   Put the UI behind TLS or restrict who can reach port $PORT -- the API key is a bearer token.

   Service:  systemctl status haproxy-manager
   Logs:     journalctl -u haproxy-manager -f
EOF
}

main() {
    parse_args "$@"
    preflight
    install_packages
    fetch_source
    install_acme
    install_app
    configure_system
    seed_api_key
    install_service
    wait_for_ui || true
    summary
}

main "$@"
