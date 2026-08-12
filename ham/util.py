"""Small helpers used all over."""

from datetime import datetime
from datetime import timezone
import os
import re
import subprocess

from .base import CERT_DIR, DRY_RUN

# --------------------------------------------------------------------------

def run(cmd, env=None, timeout=600):
    """Run a command, return (rc, combined output)."""
    if DRY_RUN and cmd[0] in ("systemctl", "keepalived"):
        return 0, "[dry-run] " + " ".join(cmd)
    # Children must not inherit NOTIFY_SOCKET. With NotifyAccess=main, systemd
    # logs "Got notification message from PID ..., but reception only permitted
    # for main PID ..." for every helper that touches it -- one line of noise
    # per subprocess, and this app runs a lot of them.
    child_env = dict(env if env is not None else os.environ)
    child_env.pop("NOTIFY_SOCKET", None)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=child_env, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, "command not found: " + cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "timed out: " + " ".join(cmd)


def _sec(name):
    """Sanitize a user-supplied name for use in generated configs/filenames."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", (name or "").strip()) or "unnamed"


def _by_id(items):
    return {i["id"]: i for i in items if "id" in i}


def cert_path(cert):
    return CERT_DIR / (_sec(cert.get("name")) + ".pem")


# Certificates count as "expiring" this many days before notAfter.
EXPIRY_WARN_DAYS = 15


def cert_details(p):
    """Inspect a deployed PEM.

    Distinguishes a real certificate from the self-signed placeholder that
    Apply drops in before the first issuance -- otherwise "deployed" says yes
    for a certificate that was never actually issued.
    """
    info = {"deployed": False, "status": "missing", "file": str(p),
            "expires": None, "expires_iso": None, "days_left": None,
            "issuer": None, "subject": None, "self_signed": False}
    if not p.exists():
        return info
    info["deployed"] = True

    rc, out = run(["openssl", "x509", "-noout", "-enddate", "-issuer", "-subject", "-in", str(p)])
    if rc != 0:
        info["status"] = "unreadable"
        return info

    def _grab(field):
        m = re.search(r"^%s=(.+)$" % field, out, re.M)
        return m.group(1).strip() if m else None

    info["issuer"] = _grab("issuer")
    info["subject"] = _grab("subject")
    info["self_signed"] = bool(info["issuer"]) and info["issuer"] == info["subject"]
    info["expires"] = _grab("notAfter")

    if info["expires"]:
        try:
            exp = datetime.strptime(info["expires"], "%b %d %H:%M:%S %Y %Z")
            exp = exp.replace(tzinfo=timezone.utc)
            info["expires_iso"] = exp.isoformat(timespec="seconds")
            info["days_left"] = int((exp - datetime.now(timezone.utc)).total_seconds() // 86400)
        except ValueError:
            pass

    if info["self_signed"]:
        info["status"] = "placeholder"
    elif info["days_left"] is None:
        info["status"] = "unknown"
    elif info["days_left"] < 0:
        info["status"] = "expired"
    elif info["days_left"] <= EXPIRY_WARN_DAYS:
        info["status"] = "expiring"
    else:
        info["status"] = "valid"
    return info


def parse_domains(cert):
    return [d.strip() for d in re.split(r"[\s,]+", cert.get("domains", "")) if d.strip()]


# --------------------------------------------------------------------------
# auth
