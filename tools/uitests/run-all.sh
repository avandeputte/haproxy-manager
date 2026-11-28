#!/usr/bin/env bash
# Every front-end check, in the order that fails fastest.
#
# Most of these need a real DOM, and without one each skips itself with a line
# saying so and exits 0 -- which made a run with no linkedom look green while
# checking nothing. Three bugs shipped that way. So a DOM has to be there
# before anything runs, and a test that prints the skip line fails the run.
#
#     npm i linkedom            # anywhere
#     LINKEDOM=/path/to/node_modules/linkedom/esm/index.js tools/uitests/run-all.sh
set -e
cd "$(dirname "$0")/../.."
if ! node --input-type=module -e 'await import(process.env.LINKEDOM || "linkedom")' 2>/dev/null; then
    echo "no DOM available: npm i linkedom, or point LINKEDOM at node_modules/linkedom/esm/index.js" >&2
    exit 1
fi
for t in undefined-names module-graph navigate routing pages certificates-banner managed-objects dialogs recipes table-sorting table-sorting-dom account-gear webui-blurb admin-sync overwrite config-diff update-peers sparkline stats-refresh theme access mobile history localtime login-2fa twofactor-enrol maintenance oauth ratelimit proxy-protocol language wizard-sections beta-channel large-configs lists-errorpages rules-wizard condition-wizard crowdsec cloudflare cloudflare-countries npm-parity custom-ca adcs challenge-alias mcp escaped-cells service-edit-redirect page-guard fewer-requests field-parity i18n; do
    printf '\n== %s ==\n' "$t"
    out=$(node "tools/uitests/$t.mjs" 2>&1) || { printf '%s\n' "$out"; exit 1; }
    printf '%s\n' "$out"
    if grep -q 'skipped: no DOM available' <<<"$out"; then
        echo "$t skipped its DOM checks, which is a failure here" >&2
        exit 1
    fi
done
printf '\n== i18n-check ==\n'
node tools/i18n-check.mjs
