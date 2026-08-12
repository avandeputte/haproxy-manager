"""The shared foundation: paths, tunables, logging, the Flask app."""

import logging
import logging.handlers
import os
import sys
import threading
from pathlib import Path

from flask import Flask

try:
    import requests as _requests
except ImportError:  # sync push disabled until python3-requests is installed
    _requests = None

DATA_DIR = Path(os.environ.get("HAM_DATA_DIR", "/var/lib/haproxy-manager"))
CONF_PATH = DATA_DIR / "config.json"
CERT_DIR = Path(os.environ.get("HAM_CERT_DIR", "/etc/haproxy/certs"))
HAPROXY_CFG = Path(os.environ.get("HAM_HAPROXY_CFG", "/etc/haproxy/haproxy.cfg"))
KEEPALIVED_CFG = Path(os.environ.get("HAM_KEEPALIVED_CFG", "/etc/keepalived/keepalived.conf"))
ACME_HOME = Path(os.environ.get("HAM_ACME_HOME", str(Path.home() / ".acme.sh")))
ACME_SH = os.environ.get("HAM_ACME_SH", str(ACME_HOME / "acme.sh"))
# One directory up: this module lives in ham/, the files it points at sit
# beside app.py.
ROOT_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT_DIR / "static"
STATS_SOCK = Path(os.environ.get("HAM_STATS_SOCK", "/run/haproxy/admin.sock"))

# Where the daily update check looks, and what a one-click update installs.
UPDATE_REPO = os.environ.get("HAM_REPO", "avandeputte/haproxy-manager")
UPDATE_REF = os.environ.get("HAM_REF", "main")
UPDATE_CHECK_HOURS = 24
# Overridable so a fork, a private mirror or a test rig can be pointed at.
VERSION_URL = os.environ.get(
    "HAM_VERSION_URL", "https://raw.githubusercontent.com/%s/%s/VERSION" % (UPDATE_REPO, UPDATE_REF))
INSTALL_URL = os.environ.get(
    "HAM_INSTALL_URL", "https://raw.githubusercontent.com/%s/%s/install.sh" % (UPDATE_REPO, UPDATE_REF))


def _read_version():
    """The VERSION file shipped next to app.py is the single source of truth."""
    try:
        return (ROOT_DIR / "VERSION").read_text().strip() or "0"
    except OSError:
        return "0"


VERSION = _read_version()


# --------------------------------------------------------------------------
# logging
# --------------------------------------------------------------------------

LOG_PATH = Path(os.environ.get("HAM_LOG_FILE", str(DATA_DIR / "haproxy-manager.log")))
LOG_MAX_BYTES = 4 * 1024 * 1024
log = logging.getLogger("haproxy-manager")


def setup_logging():
    """Log to a rotating file and to stdout, so both the journal and the log
    viewer see the same lines."""
    if log.handlers:
        return
    log.setLevel(logging.DEBUG if os.environ.get("HAM_DEBUG") else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S%z")
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(LOG_PATH, maxBytes=LOG_MAX_BYTES, backupCount=3)
        fh.setFormatter(fmt)
        log.addHandler(fh)
        os.chmod(LOG_PATH, 0o600)          # it records who signed in from where
    except OSError:
        pass                               # stdout alone is better than nothing
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    log.propagate = False       # the root logger would print every line twice


setup_logging()

LISTEN = os.environ.get("HAM_LISTEN", "0.0.0.0")
PORT = int(os.environ.get("HAM_PORT", "8080"))
THREADS = max(4, int(os.environ.get("HAM_THREADS", "16")))
# How long to wait on another node before calling it unreachable, as
# (connect, read). requests applies a bare number to BOTH phases, so a plain
# timeout=6 can take 12 seconds against a node that accepts the connection and
# then stops answering -- which is exactly what a node busy in an Apply does.
PEER_CONNECT_TIMEOUT = float(os.environ.get("HAM_PEER_CONNECT_TIMEOUT", "3"))
PEER_READ_TIMEOUT = float(os.environ.get("HAM_PEER_READ_TIMEOUT", "5"))
PEER_TIMEOUT = (PEER_CONNECT_TIMEOUT, PEER_READ_TIMEOUT)
# A push is a whole configuration and the far side applies it, so it gets a
# much longer read budget than a health poll -- but the same connect budget.
PUSH_READ_TIMEOUT = float(os.environ.get("HAM_PUSH_READ_TIMEOUT", "90"))
# Node health is collected in the background by the watchdog and served from
# that snapshot, so a page load never waits on the network. If the snapshot is
# older than this the request collects it inline instead -- the refresher has
# stopped, and stale health is worse than a slow page.
CLUSTER_POLL_SECONDS = float(os.environ.get("HAM_CLUSTER_POLL", "15"))
CLUSTER_SNAPSHOT_MAX_AGE = float(os.environ.get("HAM_CLUSTER_MAX_AGE", "60"))
# How long a liveness probe may take before the service counts as unresponsive.
WATCHDOG_PROBE_TIMEOUT = float(os.environ.get("HAM_WATCHDOG_PROBE_TIMEOUT", "5"))
WATCHDOG_SELF_TIMEOUT = float(os.environ.get("HAM_WATCHDOG_SELF_TIMEOUT", "10"))
DRY_RUN = os.environ.get("HAM_DRY_RUN") == "1"

app = Flask(__name__, static_folder=None)
# A request body is read into memory before a handler sees it. The largest
# legitimate one is a sync payload carrying certificates, which is well under
# a megabyte; anything past this is refused with 413 rather than buffered.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
_lock = threading.RLock()

# --------------------------------------------------------------------------
# config store
