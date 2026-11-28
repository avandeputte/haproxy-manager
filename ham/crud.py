"""The generic collection and item routes."""

from flask import abort
from flask import jsonify
from flask import request
import uuid

import copy

from .base import _lock, app, log
from .config import VALID_COLLECTIONS, load_config, merged, save_config
from .util import _by_id, _sec, rule_cond_ids
from . import validate
from .validate import check_pool, check_setting_types
from . import access, acme, apply, errorpages, haproxy, mcp, oauth, updates, vrrp

# The collections whose objects the rendered file names by their name made a
# token: two names that become the same token are one ACL declared twice --
# which HAProxy reads as one ACL with both sets of patterns, so every rule
# testing either matches both -- or two backends, listeners or certificate
# files of one name, which fail the check or overwrite each other.
NAMED_ONCE = {("haproxy", "conditions"): "condition", ("haproxy", "backends"): "Backend Pool",
              ("haproxy", "frontends"): "Public Service", ("acme", "certificates"): "certificate"}
# The collections a condition's fit with its listener's mode depends on.
MODE_BOUND = ("conditions", "rules", "frontends", "backends")


def _check_name(sec, col, cfg, item):
    """Refuse a name another object of the kind already renders under."""
    what = NAMED_ONCE.get((sec, col))
    if not what:
        return
    mine = _sec(item.get("name"))
    for other in merged(cfg)[sec][col]:
        if other.get("id") != item.get("id") and _sec(other.get("name")) == mine:
            raise ValueError("the %s \"%s\" is already there%s: two of one name would be written "
                             "as one, so pick another"
                             % (what, other.get("name", ""),
                                "" if other.get("name") == item.get("name")
                                else " and \"%s\" becomes the same name in haproxy.cfg" % item.get("name", "")))


def _with(cfg, col, item):
    """The shared configuration with this object in it, as a save would leave it."""
    draft = copy.deepcopy(cfg)
    where = draft["haproxy"][col]
    for i, existing in enumerate(where):
        if item.get("id") and existing.get("id") == item["id"]:
            where[i] = item
            return draft
    where.append(dict(item, id=item.get("id") or "proposed"))
    return draft


def _check_mode_fit(col, cfg, item):
    """Refuse a save that puts a condition where it can never match: an
    HTTP test on a TCP listener, the TLS name on an HTTP one. Only what this
    save adds is held against it; a clash already stored is reported where
    it was made, not on every object saved afterwards."""
    if col not in MODE_BOUND:
        return
    before = set(validate.mode_clashes(merged(cfg)["haproxy"]))
    new = [c for c in validate.mode_clashes(merged(_with(cfg, col, item))["haproxy"]) if c not in before]
    if new:
        raise ValueError("\n".join(new))


def _check_item(sec, col, cfg, item):
    """What a collection refuses before storing it. Raises ValueError with why."""
    if sec == "acme" and col == "accounts":
        acme.check_account(item)
    if sec == "acme" and col == "challenges":
        acme.check_challenge(item, cfg)
    if sec == "acme" and col == "certificates":
        acme.check_certificate(cfg, item)
    _check_name(sec, col, cfg, item)
    if sec != "haproxy":
        return
    if col == "backends":
        check_pool(item)
        oauth.validate_pool_oauth(cfg, item)
    elif col == "servers":
        validate.check_server(item)
    elif col == "healthchecks":
        validate.check_healthcheck(item)
    elif col == "frontends":
        validate.check_frontend(item)
    elif col == "conditions":
        validate.check_condition(item)
    elif col == "rules":
        validate.check_rule(item)
    elif col == "addresslists":
        access.check_list(item)
    elif col == "errorpages":
        errorpages.check(item)
    _check_mode_fit(col, cfg, item)


def _after_save(sec, col, cfg):
    """Error pages live on disk as well as in the configuration, and go there
    the moment they change: haproxy -c reads the files, and a settings check
    made before the next Apply has to find them."""
    if sec == "haproxy" and col == "errorpages":
        try:
            errorpages.write_files(cfg)
        except OSError as e:
            log.warning("the error pages could not be written: %s", e)

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
            try:
                _check_item(sec, col, cfg, item)
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
            item["id"] = str(uuid.uuid4())
            cfg[sec][col].append(item)
            save_config(cfg)
            _after_save(sec, col, cfg)
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
                data["id"] = iid        # before the check: some ask what else uses this
                try:
                    _check_item(sec, col, cfg, data)
                except ValueError as e:
                    return jsonify({"error": str(e)}), 400
                items[i] = data
                save_config(cfg)
                _after_save(sec, col, cfg)
                return jsonify(data)
            # A condition a rule still tests cannot go: the rule would render
            # without it -- a deny for everyone, a route for everything.
            if sec == "haproxy" and col == "conditions":
                users = [r.get("name") or "?" for r in merged(cfg)["haproxy"]["rules"]
                         if iid in rule_cond_ids(r)]
                if users:
                    return jsonify({"error": "\"%s\" is still tested by %s. Take it off the rule "
                                             "first, or delete the rule."
                                             % (x.get("name", iid), ", ".join(users))}), 409
            items.pop(i)
            save_config(cfg)
            _after_save(sec, col, cfg)
            return jsonify({"ok": True})
    abort(404)


def _local_unredacted(body, stored):
    """The incoming node settings with every [redacted] value put back from
    what is stored, so what GET handed out can be sent back unchanged.

    Peers are matched by id, not position: the list may have been reordered
    or shortened between the read and the write, and the key of one node must
    never end up on another's entry.
    """
    peers = (body.get("sync") or {}).get("peers") if isinstance(body.get("sync"), dict) else None
    if isinstance(peers, list):
        known = {p.get("id"): p for p in (stored.get("sync") or {}).get("peers") or []
                 if isinstance(p, dict)}
        for p in peers:
            if isinstance(p, dict) and p.get("api_key") == mcp.REDACTED:
                p["api_key"] = (known.get(p.get("id")) or {}).get("api_key", "")
    return mcp.unredact(body, stored)


@app.route("/api/local", methods=["GET", "PUT"])
def local_settings():
    # This node's own settings carry its credentials: the API key the other
    # nodes present, the secret that signs every session cookie, the password
    # digest and the second factor, the MCP token, the keys held for each
    # peer. None of them has a reader here -- the UI edits these through their
    # own routes and the peers only ever write -- so they go out as [redacted],
    # the same mark the MCP server uses, and come back in unchanged.
    if request.method == "GET":
        return jsonify(mcp.redact(load_config()["local"]))
    body = request.get_json(force=True) or {}
    # The keepalived interface and addresses land in a file root runs; a
    # value that is not one word is refused here, the same as setup does.
    bad = vrrp.validate_local_update(body)
    if bad:
        return jsonify({"ok": False, "error": bad}), 400
    with _lock:
        cfg = load_config()
        body = _local_unredacted(body, cfg["local"])
        for key in ("keepalived", "sync"):
            if isinstance(body.get(key), dict):
                cfg["local"][key].update(body[key])
        for key in ("api_key", "node_url"):
            if key in body:
                cfg["local"][key] = body[key].strip() if isinstance(body[key], str) else body[key]
        save_config(cfg)
    # Until 2.4.1 the beta tick was saved here, as this node's own. It is the
    # cluster's now; whatever still asks for it this way gets the same thing.
    if isinstance(body.get("updates"), dict) and "beta" in body["updates"]:
        try:
            updates.set_beta(body["updates"]["beta"])
        except updates.Refused as e:
            return jsonify({"error": str(e)}), 409
    return jsonify(mcp.redact(load_config()["local"]))


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
            "conditions": "acl_" + name,
            "errorpages": "/" + name + "-"}.get(col, "\x00never")


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
    out = {"ok": True,
           "text": "\n\n".join(blocks),
           "note": "" if blocks else
                   "This object renders nothing on its own yet -- a condition or "
                   "server appears once a rule or pool uses it."}
    if body.get("check"):          # haproxy -c on the whole file with it in, as a save would
        ok, message = apply.check_rendered(draft)
        out["validation"] = {"ok": ok, "message": message}
    return jsonify(out)
