#!/usr/bin/env bash
# The scripts root: where the engine looks for install/haproxy-manager-install.sh.
# Set here so the one-liner needs no environment variable; still overridable.
export COMMUNITY_SCRIPTS_URL="${COMMUNITY_SCRIPTS_URL:-https://raw.githubusercontent.com/avandeputte/haproxy-manager/main/proxmox}"
_cs_boot="${COMMUNITY_SCRIPTS_CORE_DIR:-$(dirname "${BASH_SOURCE[0]}")/../../core}/core/build.func"
source "$_cs_boot" 2>/dev/null || source <(curl -fsSL "${COMMUNITY_SCRIPTS_CORE_URL:-https://raw.githubusercontent.com/community-scripts/core/main}/core/build.func")
# Copyright (c) 2021-2026 community-scripts ORG -- Core engine and script template (MIT)
# Copyright (c) 2026 Alex Van de Putte (avandeputte)
# License: MIT | https://github.com/community-scripts/core/blob/main/LICENSE
# Source: https://github.com/avandeputte/haproxy-manager
#
# Builds a Proxmox VE LXC running HAProxy Cluster Manager, using the
# community-scripts engine. Self-hosted here until the project meets the
# community-scripts listing criteria; see proxmox/README.md.

APP="HAProxy-Manager"
var_tags="${var_tags:-proxy;loadbalancer;haproxy;keepalived}"
var_cpu="${var_cpu:-1}"
var_ram="${var_ram:-1024}"
var_disk="${var_disk:-4}"
var_os="${var_os:-debian}"
var_version="${var_version:-13}"
var_unprivileged="${var_unprivileged:-1}"
var_arm64="${var_arm64:-yes}"

header_info "$APP"
variables
color
catch_errors

function update_script() {
  header_info
  check_container_storage
  check_container_resources

  if [[ ! -f /opt/haproxy-manager/app.py ]]; then
    msg_error "No ${APP} Installation Found!"
    exit
  fi

  # "latest" to GitHub is the newest release that is not a pre-release, so a
  # node that has ticked "Also offer beta versions" (Settings > Updates)
  # would never see a beta from here. For such a node the newest release of
  # all is taken, betas included -- a stable release still outranks the
  # betas before it -- and named to the helpers, which fetch a tag as
  # readily as "latest".
  WANT="latest"
  if python3 -c 'import json,sys; c=json.load(open("/var/lib/haproxy-manager/config.json")); sys.exit(0 if c.get("local",{}).get("updates",{}).get("beta") else 1)' 2>/dev/null; then
    TAG=$(curl -fsSL "https://api.github.com/repos/avandeputte/haproxy-manager/releases?per_page=30" 2>/dev/null | python3 -c '
import json, re, sys
def key(tag):
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)(?:-beta\.(\d+))?$", tag)
    if not m:
        return (0,)
    return (int(m[1]), int(m[2]), int(m[3]), int(m[4]) if m[4] else 10**9)
tags = [r["tag_name"] for r in json.load(sys.stdin) if not r.get("draft")]
print(max(tags, key=key) if tags else "")' 2>/dev/null)
    if [[ -n "$TAG" ]]; then
      WANT="$TAG"
      msg_info "Betas are offered on this node: looking at ${TAG}"
    fi
  fi
  PIN=""; [[ "$WANT" != "latest" ]] && PIN="$WANT"
  if check_for_gh_release "haproxy-manager" "avandeputte/haproxy-manager" "$PIN"; then
    msg_info "Stopping Service"
    systemctl stop haproxy-manager
    msg_ok "Stopped Service"

    fetch_and_deploy_gh_release "haproxy-manager" "avandeputte/haproxy-manager" "binary" "$WANT" "/opt/haproxy-manager" "haproxy-manager_*_all.deb"

    msg_info "Starting Service"
    systemctl daemon-reload
    systemctl start haproxy-manager
    msg_ok "Started Service"
    msg_ok "Updated successfully!"
  fi
  exit
}

start
build_container
description

msg_ok "Completed Successfully!\n"
echo -e "${CREATING}${GN}${APP} setup has been successfully initialized!${CL}"
echo -e "${INFO}${YW} Access it using the following URL:${CL}"
echo -e "${TAB}${GATEWAY}${BGN}http://${IP}:8080${CL}"
echo -e "${INFO}${YW} Credentials (also in /root/haproxy-manager.creds in the container):${CL}"
echo -e "${TAB}${DGN}$(pct exec "$CTID" -- cat /root/haproxy-manager.creds)${CL}"
