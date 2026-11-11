#!/usr/bin/env bash
# Every front-end check, in the order that fails fastest.
set -e
cd "$(dirname "$0")/../.."
for t in undefined-names module-graph navigate routing pages certificates-banner managed-objects dialogs recipes table-sorting table-sorting-dom account-gear webui-blurb admin-sync overwrite config-diff update-peers sparkline stats-refresh theme access mobile history localtime login-2fa maintenance oauth ratelimit proxy-protocol language wizard-sections beta-channel large-configs lists-errorpages rules-wizard condition-wizard crowdsec npm-parity custom-ca adcs challenge-alias mcp i18n; do
    printf '\n== %s ==\n' "$t"
    node "tools/uitests/$t.mjs"
done
printf '\n== i18n-check ==\n'
node tools/i18n-check.mjs
