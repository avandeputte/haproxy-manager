#!/usr/bin/env bash
# Every front-end check, in the order that fails fastest.
set -e
cd "$(dirname "$0")/../.."
for t in undefined-names module-graph navigate pages certificates-banner managed-objects dialogs recipes table-sorting table-sorting-dom account-gear; do
    printf '\n== %s ==\n' "$t"
    node "tools/uitests/$t.mjs"
done
