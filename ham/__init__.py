"""The application, split by subject.

app.py is the entry point -- the command line, the background threads and
the server. Everything it serves lives here, one module per subject.

The import rule is worth knowing before changing anything: base, config,
util and validate are foundations and are imported by name. Every other
module addresses its siblings by module (`from . import cluster`, then
`cluster.sync_push(...)`), because feature modules depend on each other in
both directions and a qualified name is what keeps that legal.

Importing this package registers every route on `app`; nothing else here
has an import-time side effect.
"""

from .base import app, log, VERSION
from . import (
    config,
    util,
    auth,
    access,
    qr,
    twofactor,
    validate,
    crud,
    haproxy,
    history,
    keepalived,
    metrics,
    apply,
    acme,
    notify,
    watchdog,
    sync,
    setup,
    peering,
    probe,
    vrrp,
    cluster,
    stats,
    traffic,
    logs,
    updates,
    wizard,
    dnsapi,
    webui,
    recipes,
    backup,
    static,
)

# Imported for their side effect -- defining routes on `app` -- and named
# here so that is deliberate rather than something a tidy-up removes.
__all__ = [
    "app", "log", "VERSION", "config", "util", "auth", "access", "twofactor",
    "qr", "validate",
    "crud", "haproxy", "history", "keepalived", "metrics", "apply", "acme", "notify",
    "watchdog",
    "sync", "setup", "peering", "probe", "vrrp", "cluster", "stats", "traffic", "logs",
    "updates", "wizard", "dnsapi", "webui", "recipes", "backup", "static"
]
