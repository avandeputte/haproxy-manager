"""The recipe files on disk."""

from flask import jsonify
from flask import request
import copy
import json
import re

from .base import STATIC_DIR, _lock, app, log
from .config import load_config, save_config
from . import apply, dnsapi, haproxy, wizard

#
# The wizard asks for a dozen settings, and for most well-known services there
# is one right answer for nearly all of them: which port, whether it is TCP or
# HTTP, how to tell a working server from a broken one. A recipe fills those in
# and leaves the two things only the operator knows -- the name to publish and
# the servers behind it.
#
# One JSON file per recipe in static/recipes/, read when asked for rather than
# compiled in: a new one is a file to drop in, and a local one is not lost on
# upgrade the way an edit to this file would be. A broken file is skipped and
# logged, because one bad recipe should not empty the list.
# --------------------------------------------------------------------------

RECIPE_DIR = STATIC_DIR / "recipes"


def load_recipes():
    """Every recipe on disk, ordered for the picker."""
    out = []
    for path in sorted(RECIPE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except (ValueError, OSError) as e:
            log.warning("ignoring recipe %s: %s", path.name, e)
            continue
        if not isinstance(data, dict) or not data.get("name") or \
                not isinstance(data.get("fields"), dict):
            log.warning("ignoring recipe %s: it needs a name and a fields object",
                        path.name)
            continue
        data["id"] = path.stem          # the filename is the identity
        data.setdefault("category", "Other")
        data.setdefault("summary", "")
        data.setdefault("notes", "")
        out.append(data)
    # Category order is deliberate rather than alphabetical -- the generic ones
    # first, the specialist ones last. Inside a category the list is long
    # enough that the only useful order is the one you can predict, so it is
    # sorted by name. Case is folded so "phpMyAdmin" lands under p rather than
    # ahead of every capitalised name.
    rank = {"Web": 0, "Databases": 1, "Applications": 2, "Infrastructure": 3}
    out.sort(key=lambda r: (rank.get(r["category"], 9), r["name"].casefold()))
    return out


@app.get("/api/recipes")
def api_recipes():
    recipes = load_recipes()
    if not recipes:
        log.warning("no recipes found in %s", RECIPE_DIR)
    return jsonify({"ok": True, "recipes": recipes, "directory": str(RECIPE_DIR)})


@app.post("/api/wizard/publish")
def api_wizard_publish():
    body = request.get_json(force=True, silent=True) or {}
    raw_urls = [u for u in re.split(r"[\s,]+", body.get("url") or "") if u]
    if not raw_urls:
        return jsonify({"ok": False, "error": "The public URL is required"}), 400
    pubs = []
    for raw in raw_urls:
        p, err = wizard._split_url(raw, "The public URL \"%s\"" % raw, default_scheme="https")
        if err:
            return jsonify({"ok": False, "error": err}), 400
        pubs.append(p)
    pub = pubs[0]
    if len(pubs) > 1:
        if any(p["scheme"] != pub["scheme"] for p in pubs):
            return jsonify({"ok": False, "error":
                            "every URL on one service must use the same scheme"}), 400
        if any(p["port"] != pub["port"] for p in pubs):
            return jsonify({"ok": False, "error":
                            "every URL on one service must use the same port"}), 400
        if pub["scheme"] == "tcp":
            return jsonify({"ok": False, "error":
                            "a tcp:// service is one listening port, so it takes one URL"}), 400
        if any(p["path"] for p in pubs):
            return jsonify({"ok": False, "error":
                            "URLs with a path cannot be combined on one service: a host and a path "
                            "must both match, while several host names are alternatives. Publish "
                            "the path as its own service."}), 400
        seen = set()
        for p in pubs:
            if p["host"].lower() in seen:
                return jsonify({"ok": False, "error": "%s is listed twice" % p["host"]}), 400
            seen.add(p["host"].lower())

    raw_targets = [t for t in re.split(r"[\s,]+", body.get("target") or "") if t]
    if not raw_targets:
        return jsonify({"ok": False, "error": "The target address is required"}), 400
    tgts = []
    for raw in raw_targets:
        # A tcp:// service forwards raw TCP, so its targets default to tcp too.
        t, err = wizard._split_url(raw, "The target address \"%s\"" % raw,
                            default_scheme="tcp" if pub["scheme"] == "tcp" else "http")
        if err:
            return jsonify({"ok": False, "error": err}), 400
        tgts.append(t)

    dry_run = bool(body.get("dry_run"))
    with _lock:
        cfg = load_config()
        draft = copy.deepcopy(cfg)
        try:
            acts, warns = dnsapi.wizard_publish(
                draft, pubs, tgts,
                name=body.get("name"),
                want_cert=body.get("certificate", True),
                account=body.get("account") or None,
                challenge=body.get("challenge") or None,
                http_redirect=body.get("http_redirect", True),
                health=body.get("health") or None,
                certificate_id=body.get("certificate_id") or None,
                new_certificate=bool(body.get("new_certificate")),
                service_id=(body.get("service_id") or "").strip() or None,
                balance=body.get("balance") or None,
                persistence=body.get("persistence") or None,
                stick_size=body.get("stick_size") or None,
                stick_expire=body.get("stick_expire") or None,
                stick_type=body.get("stick_type") or None,
                log_health_checks=bool(body.get("log_health_checks")),
                check_port=body.get("check_port") or None,
                timeout_connect=body.get("timeout_connect") or None,
                timeout_server=body.get("timeout_server") or None,
                auth=body.get("auth") if isinstance(body.get("auth"), dict) else None,
            )
        except ValueError as e:                     # a rejected request, not a crash
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception as e:                      # a malformed draft must not corrupt the store
            return jsonify({"ok": False, "error": "could not build the configuration: %s" % e}), 400

        summary = {"ok": True, "actions": acts, "warnings": warns, "dry_run": dry_run,
                   "public": "%s://%s%s" % (pub["scheme"], pub["host"], pub["path"]),
                   "target": ", ".join("%s://%s:%d" % (t["scheme"], t["host"], t["port"]) for t in tgts)}
        try:
            summary["preview"] = haproxy.render_haproxy(draft)
        except Exception as e:
            return jsonify({"ok": False, "error": "the resulting configuration is not renderable: %s" % e}), 400
        if dry_run:
            return jsonify(summary)
        save_config(draft)

    if body.get("apply"):
        summary["applied"] = apply.do_apply()
    return jsonify(summary)


# --------------------------------------------------------------------------
# export / import
