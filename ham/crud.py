"""The generic collection and item routes."""

from flask import abort
from flask import jsonify
from flask import request
import uuid

import copy

from .base import _lock, app
from .config import VALID_COLLECTIONS, load_config, merged, save_config
from .util import _by_id, _sec
from .validate import check_setting_types
from . import apply, haproxy

# --------------------------------------------------------------------------

def service_owned(cfg):
    """Which HAProxy objects exist because a service was published.

    Derived from what the services actually reference rather than from a mark
    written at creation time: a mark goes stale the moment something is edited
    or rebuilt, and this cannot. Returns {object id: service name}.
    """
    hp = cfg["haproxy"]
    rules, backends = _by_id(hp["rules"]), _by_id(hp["backends"])
    owned = {}

    def claim(oid, name):
        if oid and oid not in owned:
            owned[oid] = name

    for fe in hp.get("frontends") or []:
        for rid in (fe.get("rules") or []):
            rule = rules.get(rid)
            if not rule or rule.get("type") != "use_backend":
                continue
            pool = backends.get(rule.get("backend"))
            if not pool:
                continue
            name = pool.get("name") or rule.get("name") or "a service"
            claim(rule.get("id"), name)
            claim(pool.get("id"), name)
            for cid in (rule.get("conditions") or []):
                claim(cid, name)
            for sid in (pool.get("servers") or []):
                claim(sid, name)
            if pool.get("healthcheck"):
                claim(pool["healthcheck"], name)
    # a TCP service is a listener with a default backend and no rule at all
    for fe in hp.get("frontends") or []:
        pool = backends.get(fe.get("default_backend"))
        if not pool:
            continue
        name = pool.get("name") or fe.get("name") or "a service"
        claim(fe.get("id"), name)
        claim(pool.get("id"), name)
        for sid in (pool.get("servers") or []):
            claim(sid, name)
        if pool.get("healthcheck"):
            claim(pool["healthcheck"], name)
    return owned


@app.route("/api/<sec>/<col>", methods=["GET", "POST", "PUT"])
def collection(sec, col):
    if col == "settings":
        if sec not in ("haproxy", "acme"):
            abort(404)
        if request.method == "GET":
            return jsonify(load_config()[sec]["settings"])
        proposed = request.get_json(force=True) or {}
        bad = check_setting_types(sec, proposed)
        if bad:
            return jsonify({"error": "These settings were not saved.\n\n" + bad}), 400
        # validated outside the lock: it runs haproxy -c, which is slow
        ok, message = apply.check_rendered(apply.draft_with(sec, proposed))
        if not ok:
            return jsonify({"error": "These settings were not saved -- they do not produce a "
                                     "working configuration.\n\n" + message}), 400
        with _lock:
            cfg = load_config()
            cfg[sec]["settings"].update(proposed)
            save_config(cfg)
            return jsonify(cfg[sec]["settings"])
    if sec not in VALID_COLLECTIONS or col not in VALID_COLLECTIONS[sec]:
        abort(404)
    if request.method == "GET":
        stored = load_config()
        # The advanced pages list everything this node serves, its own objects
        # included -- leaving them out would make the configuration look
        # incomplete next to the generated haproxy.cfg. They are marked, and
        # editing one is refused with a pointer to where it is managed.
        mine = {i.get("id") for coll in ((stored["local"].get(sec) or {}).values())
                if isinstance(coll, list) for i in coll}
        items = merged(stored)[sec][col]
        if sec == "haproxy":
            # Say which of these a published service is responsible for, so the
            # advanced pages can warn before someone edits one by hand.
            owned = service_owned(merged(stored))
            items = [dict(i, managed_by=owned[i["id"]]) if i.get("id") in owned else i
                     for i in items]
        items = [dict(i, node_local=True) if i.get("id") in mine else i for i in items]
        return jsonify(items)
    if request.method == "POST":
        item = request.get_json(force=True) or {}
        if not item.get("name"):
            return jsonify({"error": "name is required"}), 400
        with _lock:
            cfg = load_config()
            item["id"] = str(uuid.uuid4())
            cfg[sec][col].append(item)
            save_config(cfg)
        return jsonify(item)
    abort(405)


@app.route("/api/<sec>/<col>/<iid>", methods=["PUT", "DELETE"])
def collection_item(sec, col, iid):
    if sec not in VALID_COLLECTIONS or col not in VALID_COLLECTIONS[sec]:
        abort(404)
    with _lock:
        cfg = load_config()
        mine = (cfg["local"].get(sec) or {}).get(col) or []
        for x in mine:
            if x.get("id") == iid:
                return jsonify({"error":
                                "\"%s\" is part of this node's web UI service and is managed from "
                                "Settings > Web UI access. Change it there, or turn it off."
                                % x.get("name", iid)}), 409
        items = cfg[sec][col]
        for i, x in enumerate(items):
            if x.get("id") != iid:
                continue
            if request.method == "PUT":
                data = request.get_json(force=True) or {}
                data["id"] = iid
                items[i] = data
                save_config(cfg)
                return jsonify(data)
            items.pop(i)
            save_config(cfg)
            return jsonify({"ok": True})
    abort(404)


@app.route("/api/local", methods=["GET", "PUT"])
def local_settings():
    if request.method == "GET":
        return jsonify(load_config()["local"])
    body = request.get_json(force=True) or {}
    with _lock:
        cfg = load_config()
        for key in ("keepalived", "sync"):
            if isinstance(body.get(key), dict):
                cfg["local"][key].update(body[key])
        for key in ("api_key", "node_url"):
            if key in body:
                cfg["local"][key] = body[key].strip() if isinstance(body[key], str) else body[key]
        save_config(cfg)
        return jsonify(cfg["local"])


def _paragraphs(text):
    """The rendered file as blocks, keyed by their first line."""
    out = {}
    for block in text.split("\n\n"):
        block = block.strip("\n")
        if block:
            out[block.splitlines()[0]] = block
    return out


def _object_token(col, item):
    """The text this object is recognisable by in the rendered file."""
    name = _sec(item.get("name") or "")
    return {"frontends": "frontend fe_" + name,
            "backends": "backend be_" + name,
            "servers": "server " + name + " ",
            "conditions": "acl_" + name}.get(col, "\x00never")


@app.post("/api/haproxy/preview-object")
def api_preview_object():
    """The haproxy.cfg this one object becomes, with the form's values in it.

    The editor shows this beside the fields, recomputed from what is typed
    rather than from what was saved -- a preview of the past would answer a
    question nobody asked. The blocks returned are the ones this object
    changes or appears in; an edit is easiest to trust when you can read
    exactly what it writes.
    """
    body = request.get_json(force=True, silent=True) or {}
    col = body.get("col")
    item = body.get("item") or {}
    if col not in VALID_COLLECTIONS["haproxy"]:
        abort(404)
    base_cfg = load_config()
    draft = copy.deepcopy(base_cfg)

    def apply_item(cfg):
        iid = item.get("id")
        for where in (cfg["haproxy"].get(col) or [],
                      (cfg["local"].get("haproxy") or {}).get(col) or []):
            for i, existing in enumerate(where):
                if iid and existing.get("id") == iid:
                    where[i] = dict(existing, **item)
                    return
        row = dict(item)
        row.setdefault("id", "preview")
        cfg["haproxy"].setdefault(col, []).append(row)

    apply_item(draft)
    try:
        base = _paragraphs(haproxy.render_haproxy(base_cfg))
        now = _paragraphs(haproxy.render_haproxy(draft))
    except Exception as e:
        return jsonify({"ok": False, "error": "this does not render: %s" % e}), 400

    token = _object_token(col, item)
    blocks = [block for head, block in now.items()
              if base.get(head) != block or token in block]
    if not blocks:
        blocks = [block for block in now.values() if token in block]
    return jsonify({"ok": True,
                    "text": "\n\n".join(blocks),
                    "note": "" if blocks else
                            "This object renders nothing on its own yet -- a condition or "
                            "server appears once a rule or pool uses it."})


# --------------------------------------------------------------------------
# haproxy.cfg renderer
