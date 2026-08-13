"""Email, Pushover and webhook notifications."""

from datetime import datetime
from datetime import timezone
from flask import jsonify
from flask import request
import json
import re
import socket
import threading
import time
import uuid

from .base import PEER_CONNECT_TIMEOUT, VERSION, _lock, _requests, app, log
from .config import DEFAULT_CONFIG, load_config, save_config
from . import wizard

#
# SMTP and Pushover are built in and need nothing beyond the standard library
# and requests, which are already here. A generic webhook covers anything else:
# it posts JSON, so a small script can forward it wherever it is wanted.
#
# The hard part is not sending: it is not sending too much. The watchdog runs
# every twenty seconds, so anything that reports a *condition* would arrive
# hundreds of times a day. Alerts therefore fire on transitions, and an
# unresolved problem is repeated only on a slow timer.
# --------------------------------------------------------------------------

SEVERITY = {"info": 0, "warning": 1, "error": 2}
_notify_state = {}          # key -> {"state":..., "since":..., "last_sent":...}
_notify_lock = threading.Lock()
_notify_log = []            # recent attempts, newest first, for the UI


def _note_attempt(dest, ok, detail):
    entry = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "destination": dest, "ok": ok, "detail": detail[:300]}
    with _notify_lock:
        _notify_log.insert(0, entry)
        del _notify_log[30:]


def send_smtp(d, subject, body):
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = d.get("from") or d.get("username") or "haproxy-manager@localhost"
    to = [x.strip() for x in re.split(r"[,;\s]+", d.get("to") or "") if x.strip()]
    if not to:
        raise ValueError("no recipient address is set")
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.set_content(body)
    host = d.get("host") or "localhost"
    port = int(d.get("port") or (465 if d.get("security") == "ssl" else 587))
    timeout = float(d.get("timeout") or 20)
    if d.get("security") == "ssl":
        srv = smtplib.SMTP_SSL(host, port, timeout=timeout)
    else:
        srv = smtplib.SMTP(host, port, timeout=timeout)
    try:
        srv.ehlo()
        if d.get("security") == "starttls":
            srv.starttls()
            srv.ehlo()
        if d.get("username"):
            srv.login(d["username"], d.get("password") or "")
        srv.send_message(msg)
    finally:
        try:
            srv.quit()
        except Exception:
            pass


def send_pushover(d, subject, body, severity):
    if _requests is None:
        raise RuntimeError("python3-requests is not installed on this node")
    data = {"token": d.get("token") or "", "user": d.get("user") or "",
            "title": subject[:250], "message": body[:1024],
            # -1 quiet, 0 normal, 1 high. Emergency (2) needs acknowledgement
            # parameters, so it is deliberately not used.
            "priority": {"info": -1, "warning": 0, "error": 1}.get(severity, 0)}
    if d.get("device"):
        data["device"] = d["device"]
    r = _requests.post("https://api.pushover.net/1/messages.json", data=data,
                       timeout=(PEER_CONNECT_TIMEOUT, 15))
    if r.status_code != 200:
        raise RuntimeError("Pushover replied HTTP %s: %s" % (r.status_code, r.text[:200]))


def send_webhook(d, subject, body, severity, event):
    if _requests is None:
        raise RuntimeError("python3-requests is not installed on this node")
    payload = {"subject": subject, "message": body, "severity": severity,
               "event": event, "node": socket.gethostname(),
               "time": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    headers = {"Content-Type": "application/json"}
    for line in (d.get("headers") or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    r = _requests.post(d.get("url") or "", json=payload, headers=headers,
                       timeout=(PEER_CONNECT_TIMEOUT, 15),
                       verify=bool(d.get("verify_tls", True)))
    if r.status_code >= 300:
        raise RuntimeError("the endpoint replied HTTP %s: %s" % (r.status_code, r.text[:200]))


def send_to(dest, subject, body, severity="warning", event=""):
    """Deliver to one destination. Raises with a readable reason."""
    kind = (dest.get("type") or "").lower()
    if kind == "smtp":
        send_smtp(dest, subject, body)
    elif kind == "pushover":
        send_pushover(dest, subject, body, severity)
    elif kind == "webhook":
        send_webhook(dest, subject, body, severity, event)
    else:
        raise ValueError("unknown destination type %r -- expected smtp, pushover "
                         "or webhook" % kind)


def notify(event, subject, body, severity="warning", cfg=None, force=False):
    """Send to every enabled destination. Never raises: a failing mail server
    must not take down the thing that noticed the problem.

    force is for the second half of a pair: something recovered that was
    already reported as broken. Recoveries are informational, and the severity
    floor defaults to warning, so without this someone would be told what
    broke and never that it came back -- which is worse than not being told at
    all, because it leaves them believing it is still broken.
    """
    cfg = cfg or load_config()
    n = cfg.get("notify") or {}
    if not n.get("enabled", True):
        return {"sent": 0, "skipped": "notifications are switched off"}
    if not force and \
            SEVERITY.get(severity, 1) < SEVERITY.get(n.get("min_severity", "warning"), 1):
        return {"sent": 0, "skipped": "below the configured severity"}
    if event and not (n.get("events") or {}).get(event, True):
        return {"sent": 0, "skipped": "the %s category is switched off" % event}
    dests = [d for d in (n.get("destinations") or []) if d.get("enabled", True)]
    if not dests:
        return {"sent": 0, "skipped": "no destinations are configured"}

    host = socket.gethostname()
    full = "%s\n\n-- \nHAProxy Cluster Manager %s on %s" % (body, VERSION, host)
    sent = 0
    for d in dests:
        name = d.get("name") or d.get("type") or "?"
        try:
            send_to(d, "[%s] %s" % (host, subject), full, severity, event)
            sent += 1
            _note_attempt(name, True, "sent")
            log.info("notified %s: %s", name, subject)
        except Exception as e:
            _note_attempt(name, False, str(e))
            log.error("could not notify %s: %s", name, str(e)[:200])
    return {"sent": sent, "destinations": len(dests)}


def notify_transition(key, state, event, subject, body, severity="warning", cfg=None):
    """Alert when something *changes*, not while it stays broken.

    Reporting a condition on every watchdog round would send hundreds of
    messages a day. This sends when the state changes, and then only again
    after repeat_hours if it has not recovered.
    """
    cfg = cfg or load_config()
    n = cfg.get("notify") or {}
    repeat = float(n.get("repeat_hours") or 6) * 3600
    now = time.time()
    with _notify_lock:
        prev = _notify_state.get(key) or {}
        changed = prev.get("state") != state
        stale = (now - prev.get("last_sent", 0)) > repeat
        if not changed and not (stale and state != "ok"):
            _notify_state[key] = dict(prev, state=state)
            return {"sent": 0, "skipped": "no change"}
        # Was the thing this closes actually reported? A recovery for an alert
        # nobody received is noise.
        closing = state == "ok" and prev.get("state") not in (None, "ok") \
            and prev.get("sent")
        _notify_state[key] = {"state": state, "since": prev.get("since", now)
                              if not changed else now, "last_sent": now,
                              "sent": False}
    res = notify(event, subject, body, severity, cfg, force=bool(closing))
    with _notify_lock:
        st = _notify_state.get(key)
        if st is not None:
            st["sent"] = bool(res.get("sent"))
    return res


@app.get("/api/notify")
def api_notify_get():
    cfg = load_config()
    n = json.loads(json.dumps(cfg.get("notify") or {}))
    # Never hand secrets back to the browser; say only whether they are set.
    for d in n.get("destinations") or []:
        for secret in ("password", "token", "user"):
            if secret in d:
                d["has_" + secret] = bool((d.get(secret) or "").strip())
                d.pop(secret)
    with _notify_lock:
        recent = list(_notify_log)
    return jsonify({"ok": True, "settings": n, "recent": recent})


@app.put("/api/notify")
def api_notify_put():
    body = request.get_json(force=True, silent=True) or {}
    with _lock:
        cfg = load_config()
        n = cfg.setdefault("notify", json.loads(json.dumps(DEFAULT_CONFIG["notify"])))
        if "enabled" in body:
            n["enabled"] = bool(body["enabled"])
        if body.get("min_severity") in SEVERITY:
            n["min_severity"] = body["min_severity"]
        if "repeat_hours" in body:
            try:
                n["repeat_hours"] = max(0.25, float(body["repeat_hours"]))
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "repeat_hours must be a number"}), 400
        if isinstance(body.get("events"), dict):
            for k, v in body["events"].items():
                n.setdefault("events", {})[k] = bool(v)
        if isinstance(body.get("destinations"), list):
            existing = {d.get("id"): d for d in (n.get("destinations") or [])}
            out = []
            for d in body["destinations"]:
                if not isinstance(d, dict):
                    continue
                cur = dict(existing.get(d.get("id")) or {})
                cur.update({k: v for k, v in d.items()
                            if not (k in ("password", "token", "user")
                                    and not str(v or "").strip())})
                # a blank secret means "keep the stored one", never "clear it"
                cur["id"] = cur.get("id") or str(uuid.uuid4())
                out.append(cur)
            n["destinations"] = out
        save_config(cfg)
    log.info("notification settings changed (%d destination(s))",
             len(n.get("destinations") or []))
    return jsonify({"ok": True})


@app.post("/api/notify/test")
def api_notify_test():
    """Send a real message to one destination, so it is proven before it is
    needed. Uses the stored secrets when the browser sends blanks."""
    body = request.get_json(force=True, silent=True) or {}
    cfg = load_config()
    dest = None
    if body.get("id"):
        dest = wizard._find(cfg.get("notify", {}).get("destinations") or [],
                     lambda d: d.get("id") == body["id"])
    if dest is None:
        return jsonify({"ok": False, "error": "save the destination first, then test it"}), 400
    try:
        send_to(dest, "[%s] Test message" % socket.gethostname(),
                "This is a test from HAProxy Cluster Manager %s on %s.\n\n"
                "If you are reading it, alerts will reach you here."
                % (VERSION, socket.gethostname()),
                "info", "test")
    except Exception as e:
        _note_attempt(dest.get("name") or dest.get("type"), False, str(e))
        log.warning("test notification to %s failed: %s", dest.get("name"), str(e)[:200])
        return jsonify({"ok": False, "error": str(e)[:400]})
    _note_attempt(dest.get("name") or dest.get("type"), True, "test message sent")
    return jsonify({"ok": True, "message": "Sent. Check that it arrived."})


# --------------------------------------------------------------------------
# watchdog
