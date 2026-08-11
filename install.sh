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
# Run it on every node. When it is already installed it offers to
# update or remove it; --update / --uninstall pick one without asking. An update
# preserves config.json, issued certificates and node-local settings.
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
MODE=""            # install | update | uninstall (empty => decide at runtime)
MODE_FROM_FLAG=0   # the mode was chosen on the command line, not by prompting
PURGE=0            # with uninstall: also delete configuration and certificates
ASSUME_YES=0
PORT_SET=0; LISTEN_SET=0
[ "${HAM_PORT+set}" = "set" ]   && PORT_SET=1
[ "${HAM_LISTEN+set}" = "set" ] && LISTEN_SET=1

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
HAProxy Cluster Manager installer (Debian-based distributions)

  curl -fsSL https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/install.sh | sudo bash
  sudo ./install.sh

Options (or the equivalent environment variable):
  --repo    <owner/name>   HAM_REPO       GitHub repository        (avandeputte/haproxy-manager)
  --ref     <branch|tag>   HAM_REF        branch or tag            (main)
  --port    <port>         HAM_PORT       UI/API port              (8080)
  --listen  <address>      HAM_LISTEN     UI/API bind address      (0.0.0.0)
  --dest    <dir>          HAM_DEST       install directory        (/opt/haproxy-manager)
  --admin-user <name>      HAM_ADMIN_USER      UI login name       (admin)
  --admin-password <pw>    HAM_ADMIN_PASSWORD  UI password (random if unset)
  --api-key <key>          HAM_API_KEY    API key for peer sync (random if unset)
  --no-api-key                            do not set an API key
  --skip-acme              HAM_SKIP_ACME  do not install acme.sh
  --tarball <url|path>     HAM_TARBALL    install from this tarball instead of GitHub
                           GITHUB_TOKEN   token for a private repository

When haproxy-manager is already installed you are asked what to do. To decide up
front:
  --update                 reinstall the app over the existing install
  --uninstall              remove the service and the app, keep config + certs
  --purge                  uninstall and also delete config.json and certificates
  -y, --yes                do not ask for confirmation
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
            --port)       PORT="${2:?--port needs a value}"; PORT_SET=1; shift 2 ;;
            --listen)     LISTEN="${2:?--listen needs a value}"; LISTEN_SET=1; shift 2 ;;
            --update|--upgrade) MODE=update; MODE_FROM_FLAG=1; shift ;;
            --uninstall|--remove) MODE=uninstall; MODE_FROM_FLAG=1; shift ;;
            --purge)      MODE=uninstall; PURGE=1; MODE_FROM_FLAG=1; shift ;;
            -y|--yes)     ASSUME_YES=1; shift ;;
            --dest)       DEST="${2:?--dest needs a value}"; shift 2 ;;
            --tarball)    TARBALL="${2:?--tarball needs a value}"; shift 2 ;;
            --api-key)    HAM_API_KEY="${2:?--api-key needs a value}"; shift 2 ;;
            --no-api-key) HAM_API_KEY=""; shift ;;
            --admin-user) HAM_ADMIN_USER="${2:?--admin-user needs a value}"; shift 2 ;;
            --admin-password) HAM_ADMIN_PASSWORD="${2:?--admin-password needs a value}"; shift 2 ;;
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
# existing installation: update or remove
# --------------------------------------------------------------------------

detect_install() {
    INSTALLED=0
    if [ -f "$UNIT" ] || [ -f "$DEST/app.py" ]; then
        INSTALLED=1
    fi
    [ "$INSTALLED" = "1" ] || return 0

    # Keep the port/address the node already runs on unless asked otherwise.
    # (if/then, not `a && b`: a function ending on a false && list would abort
    # the script under `set -e`.)
    local cur
    cur="$(sed -n 's/^Environment=HAM_PORT=//p' "$UNIT" 2>/dev/null | tail -1)"
    if [ -n "$cur" ] && [ "$PORT_SET" = "0" ]; then PORT="$cur"; fi
    cur="$(sed -n 's/^Environment=HAM_LISTEN=//p' "$UNIT" 2>/dev/null | tail -1)"
    if [ -n "$cur" ] && [ "$LISTEN_SET" = "0" ]; then LISTEN="$cur"; fi
    return 0
}

describe_install() {
    local state
    state="$(systemctl is-active haproxy-manager 2>/dev/null || true)"
    printf '%s>>%s haproxy-manager is already installed\n' "$C_B" "$C_0"
    echo "     location: $DEST"
    echo "     service:  haproxy-manager.service (${state:-unknown})"
    echo "     address:  http://$(hostname -I 2>/dev/null | awk '{print $1}'):$PORT"
    echo "     data:     $DATA$([ -e "$DATA/config.json" ] && echo " (config.json present)")"
}

have_tty() {
    # A terminal to ask on. Not `[ -r /dev/tty ]`: the device node is readable
    # by permission even where opening it fails (ENXIO), e.g. under `docker exec`
    # or in a cron job -- only an actual open tells the truth.
    ( exec 3</dev/tty ) 2>/dev/null
}

confirm() {
    # $1 = question. Reads the terminal, not stdin: stdin is the script itself
    # when this is piped from curl.
    [ "$ASSUME_YES" = "1" ] && return 0
    if ! have_tty; then
        # An explicit --uninstall/--purge on the command line is the consent;
        # there is no way to ask, so proceed rather than silently doing nothing.
        if [ "$MODE_FROM_FLAG" = "1" ]; then
            warn "No terminal to confirm on -- proceeding as requested on the command line."
            return 0
        fi
        return 1
    fi
    local a
    printf '%s?? %s [y/N] %s' "$C_Y" "$1" "$C_0"
    read -r a < /dev/tty || return 1
    case "$a" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

choose_mode() {
    [ -n "$MODE" ] && return 0
    if [ "$INSTALLED" = "0" ]; then MODE=install; return 0; fi

    echo
    describe_install
    if ! have_tty; then
        MODE=update
        echo
        warn "No terminal to ask on -- updating in place."
        warn "   Re-run with --uninstall (or --purge) to remove it instead."
        return 0
    fi
    cat <<EOF

   [U] Update    reinstall the app, keep configuration and certificates
   [R] Remove    stop and delete the service and the app, keep $DATA
   [P] Purge     remove everything, including config.json and certificates
   [C] Cancel

EOF
    local a
    printf '%s?? %s' "$C_Y" "What would you like to do? [U/r/p/c] $C_0"
    read -r a < /dev/tty || a=""
    case "$a" in
        ""|[uU]*) MODE=update ;;
        [rR]*)    MODE=uninstall ;;
        [pP]*)    MODE=uninstall; PURGE=1 ;;
        *)        log "Cancelled -- nothing was changed."; exit 0 ;;
    esac
}

do_uninstall() {
    if [ "$INSTALLED" = "0" ]; then
        log "haproxy-manager is not installed -- nothing to remove."
        exit 0
    fi

    echo
    echo "   The following will be removed:"
    echo "     - haproxy-manager.service (stopped and disabled)"
    echo "     - $DEST"
    echo "     - /etc/sysctl.d/60-haproxy-manager.conf"
    if [ "$PURGE" = "1" ]; then
        echo "     - $DATA  (config.json, login, API key -- ALL settings)"
        echo "     - $CERTS (deployed certificate PEMs)"
    else
        echo "   Kept: $DATA and $CERTS (use --purge to delete those too)."
    fi
    echo "   Kept: the haproxy and keepalived packages, their generated configs,"
    echo "         and acme.sh in $ACME_HOME."
    echo
    if ! confirm "Remove haproxy-manager?"; then
        log "Cancelled -- nothing was changed."
        exit 0
    fi

    log "Stopping and disabling the service"
    systemctl disable --now haproxy-manager >/dev/null 2>&1 || true
    rm -f "$UNIT"
    systemctl daemon-reload
    systemctl reset-failed haproxy-manager >/dev/null 2>&1 || true

    log "Removing $DEST"
    rm -rf "$DEST"
    rm -f /etc/sysctl.d/60-haproxy-manager.conf
    sysctl -q --system >/dev/null 2>&1 || true

    if [ "$PURGE" = "1" ]; then
        log "Purging $DATA and $CERTS"
        rm -rf "$DATA" "$CERTS"
    fi

    echo
    printf '%s>> HAProxy Cluster Manager removed.%s\n' "$C_B" "$C_0"
    if [ "$PURGE" = "0" ]; then
        echo "   Your settings are still in $DATA -- reinstalling picks them up again."
    fi
    echo "   HAProxy and Keepalived were left running with their current configuration."
    echo "   To remove them too: apt-get purge haproxy keepalived"
    exit 0
}

# --------------------------------------------------------------------------
# steps
# --------------------------------------------------------------------------

install_packages() {
    log "Installing packages (haproxy, keepalived, python3-flask, python3-waitress, ...)"
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a          # keep Ubuntu's needrestart from prompting
    apt-get update -q
    apt-get install -y --no-install-recommends \
        python3 python3-flask python3-requests python3-waitress \
        haproxy keepalived \
        openssl ca-certificates curl socat iproute2 procps tar
}

# curl, but patient: retry a few times, and try IPv4 on a second pass. A
# transient DNS failure should not end an installation -- glibc caches nothing,
# so the next attempt is a genuinely fresh try.
fetch() {
    local url="$1" out="$2"
    local -a auth=()
    [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
    local -a base=(-fsSL --connect-timeout 15 --max-time 300
                   --retry 3 --retry-delay 2 --retry-connrefused)
    # --retry-all-errors is curl >= 7.71; older curl fails on the unknown flag
    if curl --help all 2>/dev/null | grep -q -- --retry-all-errors; then
        base+=(--retry-all-errors)
    fi
    curl "${base[@]}" "${auth[@]}" "$url" -o "$out" && return 0
    warn "retrying over IPv4 only"
    curl -4 "${base[@]}" "${auth[@]}" "$url" -o "$out" && return 0
    return 1
}

# The install needs three files. Fetching them one by one from the raw host
# avoids codeload.github.com entirely, which is a separate name to resolve.
fetch_individual_files() {
    local raw="https://raw.githubusercontent.com/$REPO/$REF"
    log "Falling back to fetching the individual files from raw.githubusercontent.com"
    mkdir -p "$TMPDIR_/src/static"
    fetch "$raw/app.py" "$TMPDIR_/src/app.py" || return 1
    fetch "$raw/static/index.html" "$TMPDIR_/src/static/index.html" || return 1
    # Cosmetic, so a failure here must not stop an installation.
    for asset in icon.svg logo.svg favicon.svg favicon.ico apple-touch-icon.png; do
        fetch "$raw/static/$asset" "$TMPDIR_/src/static/$asset" || true
    done
    fetch "$raw/VERSION" "$TMPDIR_/src/VERSION" || true       # optional
    fetch "$raw/install.sh" "$TMPDIR_/src/install.sh" || true  # optional
    [ -s "$TMPDIR_/src/app.py" ] && [ -s "$TMPDIR_/src/static/index.html" ] || return 1
    SRC="$TMPDIR_/src"
    return 0
}

# Printed when every route failed: what to check, in the order worth checking.
download_hint() {
    local host="codeload.github.com"
    local dns="" res=""
    if getent hosts "$host" >/dev/null 2>&1; then
        dns="resolves now (so this was probably a passing failure -- try again)"
    else
        dns="does not resolve from this node"
    fi
    res="$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | head -3 | tr '\n' ' ')"
    cat <<EOF
$host $dns
   nameservers: ${res:-none in /etc/resolv.conf}
   Check:  getent hosts $host
           cat /etc/resolv.conf
   DNS answers are not cached by the C library, so a resolver that is briefly
   unavailable fails every lookup for as long as it is down. If this node is
   also a cluster member, check the Logs page for a Keepalived restart at the
   same moment -- a VIP moving can interrupt the route to the resolver.
   Offline install:  git clone the repository and run ./install.sh from it,
                     or pass --tarball /path/to/archive.tar.gz
EOF
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
        if ! fetch "$url" "$tgz"; then
            # The tarball host is a second name to resolve, and resolution
            # failures are not cached or retried by the C library: one bad
            # moment and the whole install stops. Fall back to fetching the
            # handful of files we actually need, from a different host.
            warn "could not download the archive from ${url#https://}"
            if fetch_individual_files; then
                return 0
            fi
            die "download failed: $url
   $(download_hint)"
        fi
    fi

    mkdir -p "$TMPDIR_/src"
    tar -xzf "$tgz" -C "$TMPDIR_/src" --strip-components=1 || die "could not unpack the downloaded archive"
    SRC="$TMPDIR_/src"

    [ -f "$SRC/app.py" ] && [ -f "$SRC/static/index.html" ] \
        || die "archive does not contain app.py and static/index.html -- wrong --repo/--ref?"
    return 0
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
    # Keep a copy of the installer beside the app, so uninstalling and updating
    # work without fetching anything -- useful exactly when the network is the
    # problem.
    [ -f "$SRC/install.sh" ] && install -m 0755 "$SRC/install.sh" "$DEST/install.sh"
    # Everything in static/, not just the page: it also carries the icons.
    for f in "$SRC"/static/*; do
        [ -f "$f" ] && install -m 0644 "$f" "$DEST/static/$(basename "$f")"
    done
    # The app reads its own version from this file and compares it with GitHub.
    if [ -f "$SRC/VERSION" ]; then
        install -m 0644 "$SRC/VERSION" "$DEST/VERSION"
        log "Installed version $(cat "$SRC/VERSION")"
    fi
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

seed_credentials() {
    API_KEY=""; HAD_KEY=0; ADMIN_PW=""; ADMIN_USER=""

    # -- API key: for the peer and for scripted API access, not for people.
    #    Only ever seeded on a fresh install; an existing one is left alone.
    if [ -e "$DATA/config.json" ]; then
        python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("local",{}).get("api_key") else 1)' \
            "$DATA/config.json" 2>/dev/null && HAD_KEY=1
    else
        if [ "${HAM_API_KEY+set}" = "set" ]; then
            API_KEY="$HAM_API_KEY"                 # may be empty => no API key
        else
            API_KEY="$(openssl rand -hex 24)"
        fi
        if [ -n "$API_KEY" ]; then
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
        fi
    fi

    # -- UI login. Also covers upgrades from a version that only had an API key.
    ADMIN_USER="$(HAM_DATA_DIR="$DATA" python3 "$DEST/app.py" show-admin 2>/dev/null || true)"
    if [ -n "$ADMIN_USER" ]; then
        return 0                                    # an administrator already exists
    fi
    ADMIN_USER="${HAM_ADMIN_USER:-admin}"
    if [ -n "${HAM_ADMIN_PASSWORD:-}" ]; then
        ADMIN_PW="$HAM_ADMIN_PASSWORD"
    else
        ADMIN_PW="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | cut -c1-20)"
    fi
    # Piped, not passed as an argument: arguments are visible in the process list.
    if printf '%s' "$ADMIN_PW" | HAM_DATA_DIR="$DATA" python3 "$DEST/app.py" set-admin "$ADMIN_USER" - >/dev/null; then
        log "Created the administrator login for user '$ADMIN_USER'"
        { printf 'username: %s\npassword: %s\n' "$ADMIN_USER" "$ADMIN_PW"; } > "$DATA/admin-credentials.txt"
        chmod 0600 "$DATA/admin-credentials.txt"
    else
        ADMIN_PW=""
        warn "Could not create the administrator login -- the UI will ask you to create one on first visit."
    fi
    return 0
}

install_service() {
    log "Installing systemd service"
    cat > "$UNIT" <<EOF
[Unit]
Description=HAProxy Cluster Manager web UI
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
# Hang detection. The app pings systemd only when a real request to its own
# listener succeeds, so a process whose worker threads are all blocked -- alive,
# but answering nothing -- stops pinging and gets restarted. NotifyAccess must
# be set explicitly: for Type=simple it defaults to none, and the pings would
# be discarded.
NotifyAccess=main
WatchdogSec=90

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
    printf '%s>> HAProxy Cluster Manager is running at http://%s:%s%s\n' "$C_B" "$ip" "$PORT" "$C_0"
    echo
    if [ -n "${ADMIN_PW:-}" ]; then
        printf '   Sign in with   username %s%s%s\n' "$C_B" "${ADMIN_USER:-admin}" "$C_0"
        printf '                  password %s%s%s\n' "$C_B" "$ADMIN_PW" "$C_0"
        echo "   Also saved at $DATA/admin-credentials.txt -- change it under System > Administrator login."
    elif [ -n "${ADMIN_USER:-}" ]; then
        echo "   Sign in as '$ADMIN_USER' (password unchanged)."
    else
        warn "No administrator is configured -- the UI will ask you to create one on first visit."
    fi
    echo
    if [ -n "${API_KEY:-}" ]; then
        printf '   API key (peer sync / scripts): %s%s%s\n' "$C_B" "$API_KEY" "$C_0"
        echo "   Also saved at $DATA/api-key.txt. People sign in with the login above instead."
    elif [ "${HAD_KEY:-0}" = "1" ]; then
        echo "   API key: unchanged (already set on this node)."
    else
        warn "No API key is set -- the peer cannot push configuration to this node."
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
    detect_install
    choose_mode
    [ "$MODE" = "uninstall" ] && do_uninstall
    [ "$MODE" = "update" ] && log "Updating the existing installation"
    install_packages
    fetch_source
    install_acme
    install_app
    configure_system
    seed_credentials
    install_service
    wait_for_ui || true
    summary
}

main "$@"
