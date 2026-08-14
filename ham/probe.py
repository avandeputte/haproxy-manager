"""Ask for the published names the way a visitor would.

Every other check here looks at a piece: the backends' health checks watch the
servers, the watchdog watches the processes, the tracking script watches the
admin socket. All of them can be green while https://app.example.com answers
nobody -- DNS pointing at the wrong machine, another host claiming the
address, a listener that lost its certificate. The only test that catches the
whole chain is the one a browser performs: resolve the name, connect, ask.

Only the node holding the virtual IP probes, once a minute, in a thread of its
own -- a probe waits on timeouts, and the watchdog round must not.
"""

from datetime import datetime
from datetime import timezone
from flask import jsonify
import http.client
import socket
import ssl
import threading
import time

from .base import app, log
from .config import load_config, merged
from .util import _by_id, _sec
from . import auth, notify, wizard

PROBE_SECONDS = 60
TIMEOUT = 5

_state = {"at": 0.0, "results": [], "busy": False}
_state_lock = threading.Lock()

# What the probes themselves put through HAProxy, per pool, since the traffic
# history last asked. The probes go through the whole chain on purpose -- that
# is what makes them honest -- but it means HAProxy counts them like anyone
# else's requests, and a service nobody visits then shows a steady line of
# traffic that is only this app talking to itself. The history subtracts it.
_generated = {}


def _count_self(pool, status):
    """One request of ours reached HAProxy and was counted against this pool."""
    if not pool:
        return
    with _state_lock:
        row = _generated.setdefault(pool, {"req": 0, "e4": 0, "e5": 0})
        row["req"] += 1
        if status is not None and 400 <= status < 500:
            row["e4"] += 1              # the 401 a sign-in answers with
        elif status is not None and status >= 500:
            row["e5"] += 1


def drain_generated():
    """Hand over the per-pool counts and start again, for traffic.record()."""
    with _state_lock:
        out = _generated.copy()
        _generated.clear()
    return out


def published_urls(cfg):
    """What a visitor could ask for, derived from the objects that serve it.

    One entry per public URL: several names on one service are several ways in,
    and any one of them failing is worth knowing about. This node's own UI
    service is included -- its name not answering is precisely the failure
    that is invisible from inside.
    """
    cfg = merged(cfg)
    hp = cfg["haproxy"]
    conds = _by_id(hp["conditions"])
    rules = _by_id(hp["rules"])
    backends = _by_id(hp["backends"])
    out, seen = [], set()
    for fe in hp["frontends"]:
        if not fe.get("enabled", True):
            continue
        ports = sorted(wizard._bind_ports(fe))
        if fe.get("mode") == "tcp":
            pool = backends.get(fe.get("default_backend"))
            if not pool or not pool.get("enabled", True) or not ports:
                continue
            bind_host = (fe.get("binds") or "").split(":")[0].strip()
            host = bind_host if bind_host and bind_host != "0.0.0.0" else "127.0.0.1"
            key = ("tcp", host, ports[0])
            if key not in seen:
                seen.add(key)
                out.append({"kind": "tcp", "url": "tcp://%s:%d" % (host, ports[0]),
                            "host": host, "port": ports[0],
                            "pool": "be_" + _sec(pool.get("name") or "")})
            continue
        scheme = "https" if fe.get("ssl_enabled") else "http"
        default = 443 if scheme == "https" else 80
        port = ports[0] if ports else default
        for rid in fe.get("rules") or []:
            rule = rules.get(rid)
            if not rule or rule.get("type") != "use_backend":
                continue
            pool = backends.get(rule.get("backend"))
            if not pool or not pool.get("enabled", True):
                continue
            path = ""
            hosts = []
            for cid in rule.get("conditions") or []:
                c = conds.get(cid)
                if not c:
                    continue
                if c.get("type") == "host_matches" and c.get("value"):
                    hosts.append(c["value"])
                elif c.get("type") == "path_starts_with" and c.get("value"):
                    path = c["value"]
            for host in hosts:
                key = (scheme, host, port, path)
                if key in seen:
                    continue
                seen.add(key)
                shown = "" if port == default else ":%d" % port
                out.append({"kind": scheme, "url": "%s://%s%s%s" % (scheme, host, shown, path or ""),
                            "host": host, "port": port, "path": path or "/",
                            "pool": "be_" + _sec(pool.get("name") or "")})
    return out


def probe_one(entry):
    """One request, the way a browser would make it. Returns what happened.

    Three answers: "ok" -- it resolved, connected and spoke; "warn" -- it
    answers but something a visitor would see is wrong, like a certificate
    that does not verify; "down" -- no answer at all. An HTTP error status is
    still an answer: a 503 means the listener is fine and the pool is not,
    which the health-check alerts already report on their own.
    """
    host, port = entry["host"], entry["port"]
    began = time.time()
    result = dict(entry, state="down", note="", resolved="", ms=0, status=None)

    def done(state, note, status=None):
        result.update(state=state, note=note, status=status,
                      ms=int((time.time() - began) * 1000))
        return result

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        result["resolved"] = infos[0][4][0]
    except OSError as e:
        return done("down", "the name does not resolve: %s" % e)

    if entry["kind"] == "tcp":
        try:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                return done("ok", "accepts connections")
        except OSError as e:
            return done("down", "no answer on port %d: %s" % (port, e))

    tls_note = ""
    if entry["kind"] == "https":
        try:
            conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT,
                                               context=ssl.create_default_context())
            conn.request("GET", entry.get("path") or "/",
                         headers={"Host": host, "User-Agent": "haproxy-manager-probe"})
            status = conn.getresponse().status
            conn.close()
            return done("ok", "answers %d" % status, status)
        except ssl.SSLError as e:
            # It speaks TLS but the certificate does not pass: expired, the
            # wrong name, or an issuer this machine does not trust. A visitor
            # gets a warning page, so this is worth a warning here -- but
            # still worth asking whether anything answers behind it.
            tls_note = getattr(e, "reason", None) or str(e)
        except OSError as e:
            return done("down", "no answer: %s" % e)
        try:
            unverified = ssl.create_default_context()
            unverified.check_hostname = False
            unverified.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT,
                                               context=unverified)
            conn.request("GET", entry.get("path") or "/", headers={"Host": host})
            status = conn.getresponse().status
            conn.close()
            return done("warn", "answers %d, but the certificate does not verify: %s"
                        % (status, tls_note), status)
        except OSError as e:
            return done("down", "no answer: %s" % e)

    try:
        conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
        conn.request("GET", entry.get("path") or "/",
                     headers={"Host": host, "User-Agent": "haproxy-manager-probe"})
        status = conn.getresponse().status
        conn.close()
        return done("ok", "answers %d" % status, status)
    except OSError as e:
        return done("down", "no answer: %s" % e)


SEVERITY = {"down": "error", "warn": "warning"}


def _tell(cfg, result):
    state = result["state"]
    label = result["url"]
    if state == "ok":
        notify.notify_transition(
            "url:" + label, "ok", "service",
            "%s answers again" % label,
            "Probed from the active node: %s." % (result["note"] or "it answers"),
            "info", cfg)
    else:
        notify.notify_transition(
            "url:" + label, state, "service",
            "%s is not answering" % label if state == "down"
            else "%s has a certificate problem" % label,
            "Probed from the active node, the way a browser would ask.\n\n"
            "  %s\n  resolved to %s\n\nEvery internal check can be healthy while "
            "this fails: it is the whole path -- DNS, the address, the listener, "
            "the certificate -- that answers here." % (result["note"],
                                                       result["resolved"] or "nothing"),
            SEVERITY[state], cfg)


def _run(cfg, entries):
    results = []
    for entry in entries:
        r = probe_one(entry)
        results.append(r)
        # A response means the request went through HAProxy and was counted
        # against the pool; a TCP connect that was accepted is a session. A
        # name that never resolved or connected reached nothing to count.
        if r.get("status") is not None or (entry["kind"] == "tcp" and r["state"] == "ok"):
            _count_self(entry.get("pool"), r.get("status"))
        try:
            _tell(cfg, r)
        except Exception:
            log.exception("probe: reporting %s failed", r["url"])
    with _state_lock:
        _state["results"] = results
        _state["at"] = time.time()
        _state["busy"] = False
    bad = [r for r in results if r["state"] != "ok"]
    if bad:
        log.info("probe: %d of %d published URLs are not answering cleanly: %s",
                 len(bad), len(results), ", ".join(r["url"] for r in bad))


def poll(cfg):
    """Called every watchdog round; probes once a minute, from the active node.

    A passive node's answer would be about the wrong machine -- the names
    resolve to the virtual IP, which it does not hold. The work happens in its
    own thread because a dead service is worth a five-second timeout, and the
    watchdog round is not.
    """
    if not (cfg["local"].get("watchdog") or {}).get("probe_urls", True):
        return
    if auth.node_role(cfg)[0] == "passive":
        return
    with _state_lock:
        if _state["busy"] or time.time() - _state["at"] < PROBE_SECONDS:
            return
        _state["busy"] = True
    entries = published_urls(cfg)
    if not entries:
        with _state_lock:
            _state["busy"] = False
            _state["at"] = time.time()
        return
    threading.Thread(target=_run, args=(cfg, entries), daemon=True,
                     name="url-probe").start()


@app.get("/api/probes")
def api_probes():
    """The last round of URL probes, and when it ran."""
    cfg = load_config()
    with _state_lock:
        results = list(_state["results"])
        at = _state["at"]
    return jsonify({
        "ok": True,
        "enabled": bool((cfg["local"].get("watchdog") or {}).get("probe_urls", True)),
        "probing": auth.node_role(cfg)[0] != "passive",
        "at": datetime.fromtimestamp(at, timezone.utc).isoformat(timespec="seconds") if at else None,
        "age": int(time.time() - at) if at else None,
        "results": results,
    })
