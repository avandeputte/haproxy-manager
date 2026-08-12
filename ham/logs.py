"""Reading and merging the four log sources."""

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from flask import Response
from flask import jsonify
from flask import request
import os
import shutil
import time

from .base import ACME_HOME, LOG_PATH, app, log
from .config import load_config
from .util import run

#
# Four programs write logs four different ways, and where they land depends on
# how haproxy-manager was installed. On a systemd host HAProxy and Keepalived
# log through syslog into the journal; in the container there is no journal, so
# a collector tees /dev/log to a file. Each reader below therefore tries the
# journal first and falls back to files, and every reader returns the same
# shape so the viewer can merge them into one timeline.
# --------------------------------------------------------------------------

SYSLOG_FILES = ["/var/log/ham-syslog.log", "/var/log/haproxy.log",
                "/var/log/syslog", "/var/log/messages"]
MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
# syslog severities 0-7; anything at warning or worse is worth colouring
SYSLOG_LEVELS = ["ERROR", "ERROR", "ERROR", "ERROR",
                 "WARNING", "INFO", "INFO", "DEBUG"]


def _tail(path, lines):
    """Last `lines` lines of a file, read from the end so a large log is cheap."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    want = min(size, max(4096, lines * 400))
    try:
        with open(path, "rb") as fh:
            fh.seek(size - want)
            data = fh.read()
    except OSError:
        return []
    if want < size:
        data = data.split(b"\n", 1)[-1]        # drop the partial first line
    return data.decode("utf-8", "replace").splitlines()[-lines:]


def _epoch(dt):
    return dt.replace(tzinfo=dt.tzinfo or timezone.utc).timestamp()


def _level_of(text):
    up = text.upper()
    for word in ("CRITICAL", "ALERT", "EMERG", "FATAL"):
        if word in up:
            return "ERROR"
    if "ERROR" in up or "ERR:" in up or "FAILED" in up or "FAILURE" in up:
        return "ERROR"
    if "WARNING" in up or "WARN " in up or "WARN:" in up:
        return "WARNING"
    if "DEBUG" in up:
        return "DEBUG"
    return "INFO"


def _entry(ts, source, level, text):
    return {"ts": ts, "source": source, "level": level, "text": text.rstrip()}


def _parse_syslog_date(token_month, token_day, token_time):
    """Classic syslog stamps carry no year; assume the most recent one."""
    try:
        now = datetime.now()
        dt = datetime(now.year, MONTHS[token_month], int(token_day),
                      *[int(x) for x in token_time.split(":")])
        if dt > now + timedelta(days=1):        # December log read in January
            dt = dt.replace(year=now.year - 1)
        return dt.astimezone().timestamp()
    except (KeyError, ValueError):
        return None


def read_manager_log(lines):
    """Our own log: '2026-08-10T12:00:00+0000 INFO message'."""
    out = []
    for line in _tail(str(LOG_PATH), lines):
        stamp, level, text = None, None, line
        parts = line.split(" ", 2)
        if len(parts) == 3 and "T" in parts[0]:
            try:
                stamp = _epoch(datetime.strptime(parts[0], "%Y-%m-%dT%H:%M:%S%z"))
                level, text = parts[1], parts[2]
            except ValueError:
                stamp = None
        if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            level, text = _level_of(line), line
        out.append(_entry(stamp, "manager", "ERROR" if level == "CRITICAL" else level, text))
    return out


def read_journal(unit, source, lines):
    """journalctl, when there is a journal to read."""
    if not shutil.which("journalctl"):
        return None
    rc, out = run(["journalctl", "-u", unit, "-n", str(lines),
                   "-o", "short-iso", "--no-pager"], timeout=20)
    if rc != 0:
        return None
    entries = []
    for line in out.splitlines():
        if not line or line.startswith("-- "):   # "-- No entries --", boot markers
            continue
        stamp, text = None, line
        head = line.split(" ", 1)
        if len(head) == 2:
            try:
                stamp = _epoch(datetime.strptime(head[0], "%Y-%m-%dT%H:%M:%S%z"))
                # strip the hostname, keep 'unit[pid]: message'
                rest = head[1].split(" ", 1)
                text = rest[1] if len(rest) == 2 else head[1]
            except ValueError:
                pass
        entries.append(_entry(stamp, source, _level_of(text), text))
    return entries


def parse_syslog_line(line):
    """Split one syslog line into (timestamp, program, message, level).

    Two shapes have to work. Datagrams read straight off /dev/log keep their
    '<134>' priority prefix and carry no hostname; lines written by a syslog
    daemon drop the priority and add one. Rather than guess by position, find
    the field that ends in ':' -- that is the program -- and treat whatever
    precedes it as the hostname.
    """
    level = None
    if line.startswith("<") and ">" in line[:6]:
        pri, _, line = line[1:].partition(">")
        if pri.isdigit():
            level = SYSLOG_LEVELS[int(pri) % 8]
    parts = line.split(None, 3)
    if len(parts) < 4 or parts[0] not in MONTHS:
        return None, "", line, level
    stamp = _parse_syslog_date(parts[0], parts[1], parts[2])
    rest = parts[3]
    prog, message = "", rest
    for i, tok in enumerate(rest.split(None, 2)[:2]):
        if tok.endswith(":"):
            prog = tok[:-1].split("[")[0]       # 'haproxy[1234]:' -> 'haproxy'
            message = rest.split(None, i + 1)[i + 1] if len(rest.split(None, i + 1)) > i + 1 else ""
            break
    return stamp, prog, "%s: %s" % (prog, message) if prog else message, level


def read_syslog_files(match, source, lines):
    """Fallback for hosts without a journal, and for the container's collector.

    /var/log/syslog holds every program's output, so filtering on the program
    field (not the whole line) keeps a HAProxy message that happens to mention
    keepalived out of the Keepalived view.
    """
    needle = match.lower()
    entries = []
    for path in SYSLOG_FILES:
        if not os.path.exists(path):
            continue
        for line in _tail(path, lines * 6):
            stamp, prog, text, level = parse_syslog_line(line)
            if needle not in (prog or line).lower():
                continue
            entries.append(_entry(stamp, source, level or _level_of(text), text))
        if entries:
            break                               # first file that has anything wins
    return entries[-lines:]


def read_service_log(unit, match, source, lines):
    entries = read_journal(unit, source, lines)
    if entries:
        return entries
    return read_syslog_files(match, source, lines)


def read_acme_log(lines):
    """acme.sh's own log, plus the outcome of each issuance we ran."""
    entries = []
    for line in _tail(str(ACME_HOME / "acme.sh.log"), lines):
        stamp, text = None, line
        if line.startswith("["):
            head, _, rest = line[1:].partition("]")
            for fmt in ("%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y"):
                try:
                    stamp = _epoch(datetime.strptime(head.strip(), fmt))
                    text = rest.strip()
                    break
                except ValueError:
                    continue
        entries.append(_entry(stamp, "acme", _level_of(text), text))
    # issuance results are kept in _meta by record_issue(); surface them here so
    # a failed renewal is visible even when acme.sh wrote nothing useful
    cfg = load_config()
    names = {c.get("id"): c.get("name", "?") for c in cfg["acme"].get("certificates", [])}
    for cid, rec in (cfg.get("_meta", {}).get("issue_log") or {}).items():
        stamp = None
        try:
            stamp = _epoch(datetime.fromisoformat(rec.get("time", "")))
        except ValueError:
            pass
        ok = rec.get("ok")
        entries.append(_entry(
            stamp, "acme", "INFO" if ok else "ERROR",
            "certificate %s: %s in %ss%s" % (
                names.get(cid, cid), "issued" if ok else "failed",
                rec.get("seconds", "?"),
                "" if ok else " -- " + (rec.get("error") or "no detail"))))
    return entries


LOG_SOURCES = [
    ("manager", "Web UI", lambda n: read_manager_log(n)),
    ("haproxy", "HAProxy", lambda n: read_service_log("haproxy", "haproxy", "haproxy", n)),
    ("acme", "acme.sh", lambda n: read_acme_log(n)),
    ("keepalived", "Keepalived",
     lambda n: read_service_log("keepalived", "Keepalived", "keepalived", n)),
]
LEVEL_ORDER = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}


def collect_logs(sources, lines, query="", min_level="DEBUG"):
    wanted = [s for s in LOG_SOURCES if s[0] in sources]
    entries, failed = [], []
    for key, _label, reader in wanted:
        try:
            entries.extend(reader(lines) or [])
        except Exception as exc:                # one unreadable source must not
            failed.append("%s: %s" % (key, exc))  # blank the whole viewer
            log.exception("could not read the %s log", key)
    floor = LEVEL_ORDER.get(min_level, 0)
    if floor:
        entries = [e for e in entries if LEVEL_ORDER.get(e["level"], 1) >= floor]
    if query:
        needle = query.lower()
        entries = [e for e in entries if needle in e["text"].lower()]
    # entries with no parsable timestamp sort to the end of their source rather
    # than to 1970, which would bury them
    fallback = max([e["ts"] for e in entries if e["ts"]] or [time.time()])
    entries.sort(key=lambda e: e["ts"] if e["ts"] else fallback)
    return entries[-lines:], failed


@app.get("/api/logs")
def api_logs():
    args = request.args
    sources = [s for s in (args.get("sources") or "").split(",") if s]
    if not sources:
        sources = [s[0] for s in LOG_SOURCES]
    try:
        lines = max(1, min(2000, int(args.get("lines", "300"))))
    except ValueError:
        lines = 300
    entries, failed = collect_logs(sources, lines, args.get("q", "").strip(),
                                   (args.get("level") or "DEBUG").upper())
    if args.get("format") == "text":
        body = "\n".join(
            "%s  %-10s %-7s %s" % (
                datetime.fromtimestamp(e["ts"], timezone.utc).isoformat(timespec="seconds")
                if e["ts"] else "-" * 25, e["source"], e["level"], e["text"])
            for e in entries)
        return Response(body + "\n", mimetype="text/plain", headers={
            "Content-Disposition": "attachment; filename=haproxy-manager-logs.txt"})
    return jsonify({"ok": True, "entries": entries, "failed": failed,
                    "sources": [{"key": k, "label": lab} for k, lab, _ in LOG_SOURCES]})


# --------------------------------------------------------------------------
# version and one-click update
