"""Turning one URL and one target into objects."""

from urllib.parse import urlsplit

from .util import _sec, parse_domains

# --------------------------------------------------------------------------

def _split_url(raw, what, default_scheme="http", allow=("http", "https", "tcp")):
    """Parse a user-typed URL into scheme/host/port/path (and an optional name).

    Targets may carry an explicit server name: galera1=192.168.1.81:3306.
    """
    raw = (raw or "").strip()
    if not raw:
        return None, "%s is required" % what
    label = ""
    # A target may carry both, as pve1=https://10.0.0.1:8006. Looking for the
    # "=" only after the scheme missed that form; what actually distinguishes a
    # name from an "=" inside a URL is whether anything precedes the scheme.
    if "=" in raw and "://" not in raw.split("=")[0]:
        label, raw = raw.split("=", 1)
        label, raw = label.strip(), raw.strip()
    if "://" not in raw:
        raw = default_scheme + "://" + raw   # be forgiving: 192.168.1.100:1781
    parts = urlsplit(raw)
    if parts.scheme not in allow:
        return None, "%s must be one of %s" % (what, ", ".join(s + "://" for s in allow))
    if not parts.hostname:
        return None, "%s has no host name" % what
    try:
        port = parts.port
    except ValueError:
        return None, "%s has an invalid port" % what
    if not port:
        if parts.scheme == "tcp":
            return None, "%s needs an explicit port, e.g. tcp://0.0.0.0:3306" % what
        port = 443 if parts.scheme == "https" else 80
    path = parts.path or ""
    if path in ("/", ""):
        path = ""
    return {"scheme": parts.scheme, "host": parts.hostname, "port": port,
            "path": path, "label": label}, None


def _uniq_name(existing, base):
    base = _sec(base)
    if base not in existing:
        return base
    n = 2
    while "%s-%d" % (base, n) in existing:
        n += 1
    return "%s-%d" % (base, n)


def _find(items, pred):
    for it in items:
        if pred(it):
            return it
    return None


def _bind_ports(fe):
    ports = set()
    for line in (fe.get("binds") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        hostport = line.split()[0]
        if ":" in hostport:
            tail = hostport.rsplit(":", 1)[1]
            if tail.isdigit():
                ports.add(int(tail))
    return ports


WIZARD_MARK = "created by the publish wizard"


def domain_covers(pattern, host):
    """Does a certificate domain entry cover this host name?

    Wildcards follow what browsers accept (RFC 6125): the wildcard is only the
    leftmost label and matches exactly one label, so *.example.com covers
    a.example.com but neither example.com nor a.b.example.com.
    """
    pattern = (pattern or "").strip().strip(".").lower()
    host = (host or "").strip().strip(".").lower()
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not suffix or not host.endswith("." + suffix):
            return False
        label = host[:-(len(suffix) + 1)]
        return bool(label) and "." not in label
    return False


def cert_for_host(certificates, host):
    """The best existing certificate for a host: (cert, "exact"|"wildcard") or (None, None).

    An exact name wins over a wildcard that would also cover it.
    """
    wildcard = None
    for c in certificates:
        for d in parse_domains(c):
            if d.strip().lower() == (host or "").strip().lower():
                return c, "exact"
            if d.strip().startswith("*.") and domain_covers(d, host) and wildcard is None:
                wildcard = c
    return (wildcard, "wildcard") if wildcard else (None, None)


# --------------------------------------------------------------------------
# acme.sh DNS hooks: what exists, and what each one needs
