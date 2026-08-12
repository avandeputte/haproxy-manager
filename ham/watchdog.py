"""Restarting what has stopped answering."""

from datetime import datetime
from datetime import timezone
from flask import jsonify
from flask import request
import json
import os
import re
import shutil
import socket
import threading
import time
import urllib.parse
import urllib.request

from .base import (CLUSTER_POLL_SECONDS, HAPROXY_CFG, KEEPALIVED_CFG, PORT, 
    STATS_SOCK, WATCHDOG_PROBE_TIMEOUT, WATCHDOG_SELF_TIMEOUT, _lock, app, log)
from .config import load_config, save_config
from .util import run
from . import apply, cluster, notify, sync, vrrp, webui

#
# `systemctl is-active` answers "is the process there", which is not the
# question. A process that has stopped answering looks perfectly healthy by
# that measure, and it is the failure that actually takes a site down. So each
# service gets a liveness probe that requires it to *do* something, and a
# restart is a considered action: never against a configuration that cannot
# work, and never more than a few times in a window.
# --------------------------------------------------------------------------

WATCHDOG_UNITS = ("haproxy", "keepalived")
_watchdog = {
    "enabled": False,
    "running": False,
    "last_run": "",
    "services": {},        # unit -> {state, detail, since, restarts, gave_up}
    "events": [],          # most recent first, capped
    "self": {"ok": True, "detail": "", "ms": 0},
}
_watchdog_lock = threading.Lock()
# Only one round may run at a time. The background timer and the "Check now"
# button would otherwise both find the same dead service and restart it twice,
# spending two of its restart budget on one fault.
_watchdog_round_lock = threading.Lock()
_restart_history = {}      # unit -> [epoch, ...]


def _wd_event(unit, message, level="info"):
    entry = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "unit": unit, "message": message, "level": level}
    with _watchdog_lock:
        _watchdog["events"].insert(0, entry)
        del _watchdog["events"][40:]
    {"info": log.info, "warning": log.warning, "error": log.error}[level](
        "watchdog: %s: %s", unit, message)


def service_state(unit):
    """active / inactive / failed / activating / unknown."""
    rc, out = run(["systemctl", "is-active", unit], timeout=15)
    word = (out or "").strip().splitlines()[-1] if out.strip() else ""
    if word in ("active", "inactive", "failed", "activating", "deactivating", "unknown"):
        return word
    return "active" if rc == 0 else "unknown"


def unit_wanted(unit):
    """Whether the operator wants this unit running at all.

    A masked or disabled unit is a deliberate "leave this alone" -- someone
    taking a node out of service for maintenance should not have the watchdog
    start it behind them.
    """
    rc, out = run(["systemctl", "is-enabled", unit], timeout=15)
    word = (out or "").strip().splitlines()[-1] if out.strip() else ""
    if word in ("masked", "disabled"):
        return False, word
    return True, word or "enabled"


def probe_haproxy(cfg):
    """Alive is not enough: make HAProxy answer on its stats socket.

    A process wedged on a lock, out of file descriptors or stuck in a bad
    reload still shows as active. `show info` requires it to accept a
    connection and produce a reply, which is what "serving" means here.
    """
    state = service_state("haproxy")
    if state in ("inactive", "failed"):
        return "down", "the service is %s" % state
    if state == "activating":
        return "starting", "the service is still starting"
    if not STATS_SOCK.exists():
        # Only a fault once a configuration has been applied -- a fresh node
        # legitimately has no socket yet.
        if not HAPROXY_CFG.exists():
            return "idle", "nothing has been applied yet"
        return "hung", "the stats socket %s is missing" % STATS_SOCK
    started = time.time()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sk:
            sk.settimeout(WATCHDOG_PROBE_TIMEOUT)
            sk.connect(str(STATS_SOCK))
            sk.sendall(b"show info\n")
            data = sk.recv(4096)
    except socket.timeout:
        return "hung", ("it did not answer on its stats socket within %gs"
                        % WATCHDOG_PROBE_TIMEOUT)
    except OSError as e:
        return "hung", "its stats socket could not be used: %s" % e
    if b"Process_num" not in data and b"Name:" not in data:
        return "hung", "its stats socket gave an answer that was not recognisable"
    return "ok", "answered in %d ms" % int((time.time() - started) * 1000)


def probe_keepalived(cfg):
    """Keepalived exposes no query interface, so this is deliberately modest:
    it reports whether the service is running when the cluster wants it."""
    if not vrrp.keepalived_wanted(cfg):
        return "disabled", "this node is not running Keepalived"
    if not KEEPALIVED_CFG.exists():
        return "idle", "no configuration has been written yet"
    state = service_state("keepalived")
    if state in ("inactive", "failed"):
        return "down", "the service is %s" % state
    if state == "activating":
        return "starting", "the service is still starting"
    return "ok", "running"


def _why_rejected(out):
    """The lines that say what is wrong, not a blind tail of the output.

    Daemons print their version and paths before the complaint, so cutting the
    last N characters lands mid-sentence in the preamble.
    """
    lines = [ln.strip() for ln in (out or "").splitlines()
             if "ALERT" in ln or "error" in ln.lower() or "cannot" in ln.lower()]
    text = " ".join(lines) if lines else (out or "").strip()
    # PIDs change every run; without dropping them the same fault looks new
    # each round and would be reported over and over.
    text = re.sub(r"\(\d+\)\s*:\s*", "", text)
    return text[:280]


def config_is_usable(unit):
    """Would a restart even help? Restarting against a configuration the
    daemon rejects is a loop that hides the real fault."""
    if unit == "haproxy":
        if not HAPROXY_CFG.exists():
            return False, "there is no %s to start from" % HAPROXY_CFG
        rc, out = run(["haproxy", "-c", "-f", str(HAPROXY_CFG)], timeout=30)
        if rc == 127:
            return True, ""                      # cannot check; let it try
        if rc != 0:
            return False, "its configuration does not validate: %s" % _why_rejected(out)
    if unit == "keepalived":
        if not KEEPALIVED_CFG.exists():
            return False, "there is no %s to start from" % KEEPALIVED_CFG
        rc, out = run(["keepalived", "-t", "-f", str(KEEPALIVED_CFG)], timeout=30)
        if rc not in (0, 127):
            return False, "its configuration does not validate: %s" % _why_rejected(out)
    return True, ""


def _restart_allowed(unit, limit, window):
    now = time.time()
    hist = [t for t in _restart_history.get(unit, []) if now - t < window]
    _restart_history[unit] = hist
    return len(hist) < limit, len(hist)


def watchdog_round(cfg=None):
    """One pass. Returns the per-service report it also stores."""
    with _watchdog_round_lock:
        return _watchdog_round_locked(cfg)


def _watchdog_round_locked(cfg=None):
    cfg = cfg or load_config()
    wd = cfg["local"].get("watchdog") or {}
    limit = int(wd.get("max_restarts") or 3)
    window = int(wd.get("window") or 900)
    report = {}

    for unit, probe in (("haproxy", probe_haproxy), ("keepalived", probe_keepalived)):
        if not wd.get(unit, True):
            report[unit] = {"state": "unwatched", "detail": "not supervised by the watchdog"}
            continue
        try:
            state, detail = probe(cfg)
        except Exception as e:                    # a broken probe must not stop the loop
            log.exception("watchdog: the %s probe failed", unit)
            report[unit] = {"state": "unknown", "detail": "the probe itself failed: %s" % e}
            continue
        entry = {"state": state, "detail": detail,
                 "checked": datetime.now(timezone.utc).isoformat(timespec="seconds")}

        if state == "starting":
            report[unit] = entry
            continue                              # give it a round to come up
        if state in ("down", "hung"):
            wanted, how = unit_wanted(unit)
            if not wanted:
                entry["action"] = "none"
                entry["blocked"] = "the %s service is %s -- left alone deliberately" % (unit, how)
                report[unit] = entry
                continue
            usable, why = config_is_usable(unit)
            if not usable:
                entry["action"] = "none"
                entry["blocked"] = why
                prev = _watchdog["services"].get(unit, {})
                if prev.get("blocked") != why:     # say it once, not every round
                    _wd_event(unit, "%s and will not be restarted, because %s"
                              % ("is not running" if state == "down" else "is not responding", why),
                              "error")
                notify.notify_transition(
                    "watchdog:" + unit, "blocked:" + why[:60], "watchdog",
                    "%s is down and cannot be restarted" % unit,
                    "%s is not running, and the watchdog will not restart it because %s"
                    % (unit, why), "error", cfg)
            else:
                allowed, used = _restart_allowed(unit, limit, window)
                if not allowed:
                    entry["action"] = "gave up"
                    entry["gave_up"] = True
                    prev = _watchdog["services"].get(unit, {})
                    if not prev.get("gave_up"):
                        _wd_event(unit, "restarted %d times in %d minutes without staying "
                                        "healthy -- leaving it alone so the fault is visible"
                                  % (used, window // 60), "error")
                        notify.notify_transition(
                            "watchdog:" + unit, "gave-up", "watchdog",
                            "%s keeps failing -- the watchdog has stopped restarting it" % unit,
                            "%s was restarted %d times in %d minutes and did not stay healthy, "
                            "so the watchdog has stopped trying.\n\nIt needs looking at by hand."
                            % (unit, used, window // 60), "error", cfg)
                else:
                    _restart_history.setdefault(unit, []).append(time.time())
                    _wd_event(unit, "%s -- restarting it (%s)"
                              % ("is not running" if state == "down" else "is not responding",
                                 detail), "warning")
                    rc, out = run(["systemctl", "restart", unit], timeout=60)
                    entry["action"] = "restarted"
                    # Judge by the probe, not by the exit status. Restarting a
                    # stopped process makes some service managers report an
                    # abnormal termination even though the daemon came back
                    # fine, and "the restart failed" next to a working service
                    # is worse than no message at all.
                    time.sleep(2)                  # let it come up before re-probing
                    after, adetail = probe(cfg)
                    entry["state"], entry["detail"] = after, adetail
                    if after in ("ok", "starting", "idle", "disabled"):
                        _wd_event(unit, "restarted; it is now %s (%s)" % (after, adetail), "info")
                        notify.notify_transition(
                            "watchdog:" + unit, "restarted", "watchdog",
                            "%s was restarted" % unit,
                            "%s stopped %s and the watchdog restarted it.\n\n"
                            "It is answering again now (%s)."
                            % (unit, "running" if state == "down" else "responding", adetail),
                            "warning", cfg)
                    else:
                        entry["restart_error"] = out.strip()[:300] if rc != 0 else ""
                        notify.notify_transition(
                            "watchdog:" + unit, "failed", "watchdog",
                            "%s is down and will not come back" % unit,
                            "%s is %s and a restart did not fix it.\n\n%s\n\n"
                            "Traffic through this node is affected."
                            % (unit, after, adetail), "error", cfg)
                        _wd_event(unit, "restarted but it is still %s (%s)%s"
                                  % (after, adetail,
                                     "; the service manager said: " + out.strip()[:150]
                                     if rc != 0 else ""), "error")
        elif state == "ok":
            _restart_history.pop(unit, None)       # healthy again: forget the history
            notify.notify_transition("watchdog:" + unit, "ok", "watchdog",
                              "%s is healthy again" % unit,
                              "%s is answering normally again (%s)." % (unit, detail),
                              "info", cfg)
        report[unit] = entry

    with _watchdog_lock:
        _watchdog["services"] = report
        _watchdog["last_run"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return report


def probe_self():
    """Ask this process to serve a real request.

    A thread checking a flag proves nothing: the failure worth catching is a
    worker pool with every thread blocked, where the process is healthy and
    the UI answers nothing. Only a request that goes through the socket and
    out of the WSGI server tests that.
    """
    started = time.time()
    url = "http://127.0.0.1:%d/api/whoami" % PORT
    try:
        with urllib.request.urlopen(url, timeout=WATCHDOG_SELF_TIMEOUT) as r:
            ok = r.status == 200
        return ok, ("" if ok else "the UI answered HTTP %s" % r.status), \
            int((time.time() - started) * 1000)
    except Exception as e:
        return False, "the UI did not answer: %s" % str(e)[:120], \
            int((time.time() - started) * 1000)


def sd_notify(message):
    """Talk to systemd without a dependency on python3-systemd."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):                       # abstract namespace
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sk:
            sk.connect(addr)
            sk.sendall(message.encode())
        return True
    except OSError:
        return False


_webui_restored_at = [0.0]


def _restore_webui_if_lost():
    """Put the management UI back when it stops answering on a name it should.

    The service is made of ordinary objects and anything that edits the
    configuration can change them. Losing a host rule takes the node off that
    address with nothing to see: the settings still say what was configured.

    Rebuilt at most twice an hour. If it goes again inside that, something is
    actively removing it and rebuilding on a loop would reload HAProxy every
    round while hiding the cause -- so it is reported and left alone.
    """
    cfg = load_config()
    missing = webui.webui_missing_hosts(cfg)
    if not missing:
        return
    if time.time() - _webui_restored_at[0] < 1800:
        log.error("the management UI is not answering for %s again, %d seconds after it "
                  "was put back -- something is removing it, so it is left as it is",
                  ", ".join(missing), int(time.time() - _webui_restored_at[0]))
        return
    with _lock:
        cfg = load_config()
        put_back = webui.restore_webui(cfg)
        if not put_back:
            return
        save_config(cfg)
    _webui_restored_at[0] = time.time()
    notify.notify("webui", "The management UI stopped answering on %s" % ", ".join(put_back),
                  "%s answers for that address again. It is built from ordinary HAProxy "
                  "objects, and something editing the configuration removed one of them; "
                  "the service has been rebuilt and applied."
                  % socket.gethostname(), "warning", cfg)
    res = apply.do_apply(load_config())
    log.warning("management UI restored for %s; apply: %s",
                ", ".join(put_back), "ok" if res.get("ok") else res.get("error"))


_addr_checked = [0.0]
ADDRESS_CHECK_SECONDS = 300


def probe_duplicate_addresses():
    """Is another machine on this network answering for one of our addresses?

    A cluster that moves addresses between machines is exactly where this goes
    wrong, and when it does nothing above the network can see it: the address
    is configured here, the socket is listening here, and a client reaches
    whichever machine won the last ARP exchange. The symptom is a name that
    works from one place and not another, or works until something re-ARPs --
    which looks like anything except two machines claiming one address.

    arping -D asks the network who claims an address without claiming it, so a
    reply can only come from somebody else. It is not always installed; then
    there is nothing to report, rather than a false all-clear.
    """
    if not shutil.which("arping"):
        return []
    found = []
    for iface in apply.node_interfaces():
        if iface["name"] == "lo" or not iface.get("up"):
            continue
        for cidr in iface.get("addresses") or []:
            ip = cidr.split("/")[0]
            if ":" in ip or ip.startswith("127."):
                continue          # ARP is IPv4, and loopback answers itself
            rc, out = run(["arping", "-D", "-q", "-c", "2", "-w", "3",
                           "-I", iface["name"], ip], timeout=15)
            # iputils-arping exits 1 when somebody else answers for it.
            if rc == 1:
                found.append({"address": ip, "interface": iface["name"],
                              "detail": out.strip()[-200:]})
    return found


def _check_addresses(cfg):
    """Every few minutes, not every round: each address takes a few seconds."""
    if time.time() - _addr_checked[0] < ADDRESS_CHECK_SECONDS:
        return
    _addr_checked[0] = time.time()
    try:
        dupes = probe_duplicate_addresses()
    except Exception:
        log.exception("watchdog: checking for duplicate addresses failed")
        return
    with _watchdog_lock:
        _watchdog["duplicate_addresses"] = dupes
    for d in dupes:
        log.error("another machine on %s answers for %s -- traffic for this node "
                  "reaches whichever of them won the last ARP exchange",
                  d["interface"], d["address"])
    seen = {d["address"] for d in dupes}
    for d in dupes:
        notify.notify_transition(
            "address:" + d["address"], "duplicate", "cluster",
            "Another machine is using %s" % d["address"],
            "%s answers for %s on %s as well as this node. Traffic for that address "
            "reaches whichever machine won the last ARP exchange, so this node will "
            "appear to work from some places and not others, and to come and go for "
            "no visible reason. Nothing here can fix it: one of the two has to stop "
            "using the address."
            % ("Another machine", d["address"], d["interface"]), "error", cfg)
    for old_addr in [a for a in _watchdog.get("_addr_seen") or [] if a not in seen]:
        notify.notify_transition("address:" + old_addr, "ok", "cluster",
                                 "%s is this node's alone again" % old_addr,
                                 "Nothing else on the network answers for it now.",
                                 "info", cfg)
    _watchdog["_addr_seen"] = sorted(seen)


def _watchdog_loop():
    """Supervise the services, and let systemd supervise us.

    The WATCHDOG=1 ping is deliberately gated on probe_self(): if this process
    stops serving, the ping stops, and systemd restarts it. Pinging
    unconditionally would tell systemd everything is fine from inside a
    process that answers nothing.
    """
    # systemd publishes its deadline in WATCHDOG_USEC. Ping at no less than
    # half of it, whatever the configured interval says, or a slow round would
    # look like a hang and systemd would restart a perfectly healthy process.
    deadline = 0.0
    try:
        deadline = int(os.environ.get("WATCHDOG_USEC", "0")) / 1000000.0
    except ValueError:
        pass
    # The listener is started after this thread, so wait for it before judging
    # anything. Reporting "the UI does not answer" while it is still coming up
    # would be wrong, and on systemd it would withhold the first ping.
    for _ in range(60):
        ok, _detail, _ms = probe_self()
        if ok:
            break
        time.sleep(1)
    else:
        log.error("watchdog: the UI was not answering on 127.0.0.1:%d a minute after start", PORT)
    if sd_notify("READY=1") and deadline:
        log.info("watchdog: systemd is supervising this process, deadline %gs", deadline)
    while True:
        cfg = load_config()
        wd = cfg["local"].get("watchdog") or {}
        interval = max(5, int(wd.get("interval") or 20))
        if deadline:
            interval = min(interval, max(2.0, deadline / 2.0))
        enabled = bool(wd.get("enabled", True))
        _watchdog["enabled"] = enabled

        ok, detail, ms = probe_self()
        with _watchdog_lock:
            _watchdog["self"] = {"ok": ok, "detail": detail, "ms": ms}
        if ok:
            sd_notify("WATCHDOG=1")
        else:
            # No ping: if systemd is watching, it will restart us. Say why
            # first, so the reason survives the restart in the log.
            log.error("watchdog: this node's own UI is not answering (%s) -- "
                      "not pinging systemd, so it will be restarted if WatchdogSec is set",
                      detail)

        if enabled:
            _watchdog["running"] = True
            try:
                watchdog_round(cfg)
            except Exception:
                log.exception("watchdog: the round failed")
            try:
                _restore_webui_if_lost()
            except Exception:
                log.exception("watchdog: checking the management UI service failed")
            _check_addresses(cfg)
        else:
            _watchdog["running"] = False

        # Collect every node's health here, on a schedule, so the UI reads a
        # snapshot instead of fanning out to the cluster on every page load.
        if cfg["local"]["sync"].get("peers") and \
                time.time() - cluster._cluster_cache["at"] >= CLUSTER_POLL_SECONDS:
            try:
                snap = cluster.cluster_snapshot(cfg)
            except Exception:
                log.exception("watchdog: collecting node health failed")
            else:
                # The health just collected says which nodes hold an older
                # configuration, so bringing them up to date costs nothing
                # extra. A node that was unreachable when a change was applied
                # is caught here rather than staying behind until someone
                # notices.
                try:
                    sync.reconcile(cfg, snap.get("nodes") or [])
                except Exception:
                    log.exception("watchdog: bringing the other nodes up to date failed")

        time.sleep(interval)


@app.get("/api/watchdog")
def api_watchdog():
    cfg = load_config()
    with _watchdog_lock:
        state = json.loads(json.dumps(_watchdog))
    state["settings"] = cfg["local"].get("watchdog") or {}
    state["systemd"] = bool(os.environ.get("NOTIFY_SOCKET"))
    state["arping"] = bool(shutil.which("arping"))
    state.pop("_addr_seen", None)
    return jsonify(state)


@app.put("/api/watchdog")
def api_watchdog_settings():
    body = request.get_json(force=True, silent=True) or {}
    keys = ("enabled", "interval", "haproxy", "keepalived", "max_restarts", "window")
    with _lock:
        cfg = load_config()
        wd = cfg["local"].setdefault("watchdog", {})
        for k in keys:
            if k not in body:
                continue
            if k in ("interval", "max_restarts", "window"):
                try:
                    wd[k] = max(1, int(body[k]))
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "error":
                                    "%s must be a whole number" % k}), 400
            else:
                wd[k] = bool(body[k])
        wd["interval"] = max(5, int(wd.get("interval") or 20))
        save_config(cfg)
    log.info("watchdog settings changed: %s", json.dumps(wd, sort_keys=True))
    return jsonify({"ok": True, "settings": wd})


@app.post("/api/watchdog/check")
def api_watchdog_check():
    """Run a round now, so the page does not have to wait for the timer."""
    return jsonify({"ok": True, "services": watchdog_round()})


# --------------------------------------------------------------------------
# node sync: one active node holds the virtual IP, any number stand ready
