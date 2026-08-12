"""Live statistics from HAProxy's admin socket."""

from datetime import datetime
from datetime import timezone
from flask import jsonify
import socket

from .base import STATS_SOCK, app

# --------------------------------------------------------------------------

def _socket_command(cmd):
    """Send one command to the HAProxy stats socket and return its output."""
    if not STATS_SOCK.exists():
        return None, ("HAProxy is not running, or its stats socket is missing at %s. "
                      "Press Apply once -- the generated configuration creates it." % STATS_SOCK)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(str(STATS_SOCK))
            s.sendall((cmd + "\n").encode())
            chunks = []
            while True:
                buf = s.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
        return b"".join(chunks).decode("utf-8", "replace"), None
    except OSError as e:
        return None, "could not talk to the HAProxy stats socket: %s" % e


# Columns worth showing; the socket reports about a hundred.
_STAT_KEEP = ("status", "weight", "act", "bck", "scur", "smax", "slim", "stot",
              "bin", "bout", "qcur", "qmax", "ereq", "econ", "eresp", "dreq", "dresp",
              "wretr", "wredis", "chkfail", "chkdown", "lastchg", "downtime",
              "check_status", "check_code", "check_duration", "rate", "rate_max",
              "lastsess", "addr", "mode", "algo")


def haproxy_stats():
    text, err = _socket_command("show stat")
    if err:
        return {"ok": False, "error": err}
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines or not lines[0].startswith("#"):
        return {"ok": False, "error": "unexpected output from the stats socket"}

    header = [h.strip() for h in lines[0].lstrip("# ").split(",")]
    frontends, backends, order = [], {}, []
    for line in lines[1:]:
        row = dict(zip(header, line.split(",")))
        px, sv = row.get("pxname", ""), row.get("svname", "")
        if not px or not sv:
            continue
        keep = {k: row.get(k, "") for k in _STAT_KEEP}
        keep["proxy"] = px
        keep["name"] = sv
        if sv == "FRONTEND":
            frontends.append(keep)
        elif sv == "BACKEND":
            backends.setdefault(px, {"proxy": px, "servers": []}).update(keep)
            if px not in order:
                order.append(px)
        else:
            backends.setdefault(px, {"proxy": px, "servers": []})["servers"].append(keep)
            if px not in order:
                order.append(px)

    for be in backends.values():
        # "no check" means health checking is off, and HAProxy still routes to
        # the server -- counting it as down would misreport a working pool.
        up = sum(1 for s in be["servers"]
                 if s.get("status", "").startswith("UP") or s.get("status") == "no check")
        be["servers_up"] = up
        be["servers_total"] = len(be["servers"])
    return {"ok": True, "frontends": frontends,
            "backends": [backends[p] for p in order],
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds")}


@app.get("/api/stats")
def api_stats():
    return jsonify(haproxy_stats())


# --------------------------------------------------------------------------
# log collection
