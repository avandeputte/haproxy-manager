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


def rule_cond_ids(rule):
    """Every condition a rule tests, whichever half of the test it is in.

    Since 2.0 a rule holds two lists: `any_of`, of which one must match, and
    `conditions`, which must all match. Anything that asks "which conditions
    does this rule use" -- ownership, deletion, the ACLs a listener declares --
    wants both, and reading one list is how a condition in the other would be
    deleted from under a rule still testing it.
    """
    out = []
    for cid in (rule or {}).get("any_of") or []:
        if cid not in out:
            out.append(cid)
    for cid in (rule or {}).get("conditions") or []:
        if cid not in out:
            out.append(cid)
    return out


def cert_path(cert):
    return CERT_DIR / (_sec(cert.get("name")) + ".pem")


# Certificates count as "expiring" this many days before notAfter.
EXPIRY_WARN_DAYS = 15

# What openssl said about each file, by path, with the stamp it was read at.
# The Services page asks once per service -- 62 services sharing one wildcard
# certificate were 124 openssl runs, 5.7 seconds on a small machine (#16) --
# and a certificate file only changes when it is issued again, which changes
# its stamp. The days left are worked out on every call, not kept.
_CERT_READS = {}


def _read_cert(p):
    """Issuer, subject, notAfter and the names a PEM covers; None if unreadable."""
    try:
        st = p.stat()
    except OSError:
        return None
    stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
    hit = _CERT_READS.get(str(p))
    if hit and hit[0] == stamp:
        return hit[1]

    rc, out = run(["openssl", "x509", "-noout", "-enddate", "-issuer", "-subject",
                   "-ext", "subjectAltName", "-in", str(p)])
    if rc != 0:
        return None

    def _grab(field):
        m = re.search(r"^%s=(.+)$" % field, out, re.M)
        return m.group(1).strip() if m else None

    read = {"issuer": _grab("issuer"), "subject": _grab("subject"),
            "expires": _grab("notAfter")}
    # The names the file actually covers, which is not the same thing as the
    # names the certificate record lists. Adding a name to the record does not
    # change what was issued: until it is issued again, the file covers what it
    # covered before, and a browser asking for the new name is told the
    # certificate is for something else.
    san = out.split("Subject Alternative Name", 1)[1] if "Subject Alternative Name" in out else ""
    names = sorted({m.strip().lower() for m in re.findall(r"DNS:([^,\s]+)", san)})
    if not names:
        cn = re.search(r"CN\s*=\s*([^,/]+)", read["subject"] or "")
        if cn:
            names = [cn.group(1).strip().lower()]
    read["names"] = names
    read["self_signed"] = bool(read["issuer"]) and read["issuer"] == read["subject"]
    _CERT_READS[str(p)] = (stamp, read)
    return read


def cert_details(p):
    """Inspect a deployed PEM.

    Distinguishes a real certificate from the self-signed placeholder that
    Apply drops in before the first issuance -- otherwise "deployed" says yes
    for a certificate that was never actually issued.
    """
    info = {"deployed": False, "status": "missing", "file": str(p),
            "expires": None, "expires_iso": None, "days_left": None,
            "issuer": None, "subject": None, "self_signed": False, "names": []}
    if not p.exists():
        return info
    info["deployed"] = True

    read = _read_cert(p)
    if read is None:
        info["status"] = "unreadable"
        return info
    info.update(read, names=list(read["names"]))

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
