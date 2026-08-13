"""Export and import."""

from datetime import datetime
from datetime import timezone
from flask import jsonify
from flask import request
import copy
import json
import socket
import uuid

from .base import _lock, app
from .config import (DEFAULT_CONFIG, VALID_COLLECTIONS, _merge_defaults, load_config, 
    save_config)
from . import haproxy, keepalived

# --------------------------------------------------------------------------

BACKUP_FORMAT = 1


def _download(text, filename, mime="text/plain"):
    return app.response_class(text, mimetype=mime, headers={
        "Content-Disposition": 'attachment; filename="%s"' % filename,
        "Cache-Control": "no-store",
    })


@app.get("/api/export/haproxy.cfg")
def api_export_haproxy():
    """The haproxy.cfg this configuration renders to, as a download."""
    return _download(haproxy.render_haproxy(load_config()), "haproxy.cfg")


@app.get("/api/export/keepalived.conf")
def api_export_keepalived():
    cfg = load_config()
    if not cfg["local"]["keepalived"].get("enabled"):
        return _download("# Keepalived is disabled on this node.\n", "keepalived.conf")
    return _download(keepalived.render_keepalived(cfg), "keepalived.conf")


@app.get("/api/export/config")
def api_export_config():
    """Everything the UI manages, as a restorable JSON backup.

    Node-local settings (Keepalived, sync target, API key, login) and the
    private keys under the certificate directory are deliberately left out: a
    backup should be safe to copy around, and node-local settings differ per
    node by design.

    Service users and groups are included, without their passwords, so the
    services that admit them restore intact. Each restored user has to be
    given a password again before they can sign in.
    """
    cfg = load_config()
    users = [{k: v for k, v in u.items() if k != "hash"}
             for u in (cfg.get("access") or {}).get("users") or []]
    payload = {
        "format": BACKUP_FORMAT,
        "exported": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": socket.gethostname(),
        "config": {"haproxy": cfg["haproxy"], "acme": cfg["acme"],
                   "access": {"users": users,
                              "groups": (cfg.get("access") or {}).get("groups") or []}},
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return _download(json.dumps(payload, indent=2) + "\n",
                     "haproxy-manager-%s-%s.json" % (socket.gethostname(), stamp),
                     "application/json")


def _count_objects(section):
    return {k: len(v) for k, v in section.items() if isinstance(v, list)}


@app.post("/api/import/config")
def api_import_config():
    """Restore a backup. Replaces the shared objects, keeps node-local settings.

    Nothing is applied: the caller reviews the result and presses Apply.
    """
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "the file is not valid JSON"}), 400

    incoming = body.get("config") if isinstance(body.get("config"), dict) else body
    if not isinstance(incoming, dict) or not any(k in incoming for k in ("haproxy", "acme")):
        return jsonify({"ok": False, "error":
                        "not a haproxy-manager backup -- expected a \"haproxy\" or \"acme\" section"}), 400
    fmt = body.get("format", BACKUP_FORMAT)
    if isinstance(fmt, int) and fmt > BACKUP_FORMAT:
        return jsonify({"ok": False, "error":
                        "this backup was written by a newer version (format %s)" % fmt}), 400

    with _lock:
        cfg = load_config()
        restored = {}
        for section in ("haproxy", "acme"):
            part = incoming.get(section)
            if not isinstance(part, dict):
                continue
            for coll in VALID_COLLECTIONS[section]:
                if coll in part and not isinstance(part[coll], list):
                    return jsonify({"ok": False, "error":
                                    "%s/%s should be a list" % (section, coll)}), 400
            cfg[section] = _merge_defaults(copy.deepcopy(part), DEFAULT_CONFIG[section])
            restored[section] = _count_objects(cfg[section])
        part = incoming.get("access")
        if isinstance(part, dict):
            # A backup carries no passwords. A user who is already here keeps
            # the one this node has -- restoring a backup should not log
            # everybody out of the services they can currently reach.
            had = {u.get("id"): u.get("hash") for u in (cfg.get("access") or {}).get("users") or []}
            users = []
            for u in part.get("users") or []:
                if not isinstance(u, dict):
                    continue
                u = dict(u)
                u.setdefault("id", str(uuid.uuid4()))
                u["hash"] = had.get(u["id"], "")
                users.append(u)
            groups = [g for g in part.get("groups") or [] if isinstance(g, dict)]
            for g in groups:
                g.setdefault("id", str(uuid.uuid4()))
            cfg["access"] = {"users": users, "groups": groups}
            restored["access"] = _count_objects(cfg["access"])
        # Anything without an id would be invisible to the CRUD endpoints.
        for section in ("haproxy", "acme"):
            for coll in VALID_COLLECTIONS[section]:
                for item in cfg[section].get(coll, []):
                    if not item.get("id"):
                        item["id"] = str(uuid.uuid4())
        save_config(cfg)

    return jsonify({"ok": True, "restored": restored, "source": body.get("source", ""),
                    "exported": body.get("exported", ""),
                    "note": "Review the imported objects, then press Apply."})


# --------------------------------------------------------------------------
# static
