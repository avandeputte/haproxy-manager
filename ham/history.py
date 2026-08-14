"""The shared configuration as it was, and the way back to it.

The snapshots themselves are written by save_config, because that is the one
place every change passes through. What lives here is reading them: the list,
the difference between then and now, and putting one back.
"""

from flask import jsonify
import json

from .base import _lock, app, log
from .config import (DEFAULT_CONFIG, _history_files, _merge_defaults, load_config,
    save_config, shared_fingerprint, shared_objects, shared_view)

# The sections a snapshot holds, and the order they are shown in.
SECTIONS = ("haproxy", "acme", "access", "cluster", "notify")


def _read(name):
    for p in _history_files():
        if p.name == name:
            try:
                return json.loads(p.read_text())
            except (OSError, ValueError):
                return None
    return None


def _counts(view):
    out = {}
    for section in SECTIONS:
        body = view.get(section)
        if not isinstance(body, dict):
            continue
        for coll, items in body.items():
            if isinstance(items, list) and items:
                out["%s.%s" % (section, coll)] = len(items)
    return out


def _object_index(view):
    """Every object in a snapshot: {section.coll: {id: (name, fp)}}."""
    return {coll: {row[0]: (row[1], row[2]) for row in rows}
            for coll, rows in shared_objects({s: view.get(s, {}) for s in SECTIONS},
                                             limit=100000).items()}


def diff_views(then, now):
    """What stands between two states, object by object.

    The same three answers the cluster page gives about two nodes: an object
    only here, an object only there, and an object in both whose contents
    differ. Settings blocks are compared as a whole -- they have no ids.
    """
    a, b = _object_index(then), _object_index(now)
    out = []
    for coll in sorted(set(a) | set(b)):
        rows = []
        xs, ys = a.get(coll, {}), b.get(coll, {})
        for oid in xs:
            if oid not in ys:
                rows.append({"name": xs[oid][0], "state": "removed"})
            elif xs[oid][1] != ys[oid][1]:
                rows.append({"name": ys[oid][0], "state": "changed"})
        rows.extend({"name": ys[oid][0], "state": "added"}
                    for oid in ys if oid not in xs)
        if rows:
            out.append({"part": coll, "objects": sorted(rows, key=lambda r: r["name"])})
    for section in SECTIONS:
        for key in ("settings",):
            xs = (then.get(section) or {}).get(key)
            ys = (now.get(section) or {}).get(key)
            if isinstance(xs, dict) and isinstance(ys, dict) and xs != ys:
                changed = sorted(k for k in set(xs) | set(ys) if xs.get(k) != ys.get(k))
                out.append({"part": "%s.%s" % (section, key),
                            "objects": [{"name": k, "state": "changed"} for k in changed]})
        if section in ("cluster", "notify"):
            xs, ys = then.get(section), now.get(section)
            if isinstance(xs, dict) and isinstance(ys, dict) and xs != ys:
                changed = sorted(k for k in set(xs) | set(ys)
                                 if xs.get(k) != ys.get(k) and not isinstance(xs.get(k), list))
                if changed:
                    out.append({"part": section,
                                "objects": [{"name": k, "state": "changed"} for k in changed]})
    return out


def _summary(parts):
    """One line per snapshot: which parts moved, and by how much."""
    bits = []
    for part in parts[:4]:
        by_state = {}
        for o in part["objects"]:
            by_state[o["state"]] = by_state.get(o["state"], 0) + 1
        detail = ", ".join("%d %s" % (n, state) for state, n in sorted(by_state.items()))
        bits.append("%s (%s)" % (part["part"], detail))
    if len(parts) > 4:
        bits.append("and %d more" % (len(parts) - 4))
    return "; ".join(bits)


@app.get("/api/history")
def api_history():
    """Newest first, with what each snapshot changed against the one before."""
    entries = []
    with _lock:
        current_fp = shared_fingerprint(load_config())
        previous = None
        for p in _history_files():
            try:
                d = json.loads(p.read_text())
            except (OSError, ValueError):
                continue
            view = d.get("view") or {}
            entry = {"id": p.name, "at": d.get("at"), "rev": d.get("rev"),
                     "fp": d.get("fp"), "counts": _counts(view),
                     "current": d.get("fp") == current_fp}
            # What this change touched, said in a line: enough to find the one
            # you are looking for without opening each diff.
            if previous is not None:
                entry["summary"] = _summary(diff_views(previous, view))
            previous = view
            entries.append(entry)
    entries.reverse()
    return jsonify({"ok": True, "snapshots": entries})


@app.get("/api/history/<name>/diff")
def api_history_diff(name):
    snap = _read(name)
    if not snap:
        return jsonify({"error": "no such snapshot"}), 404
    with _lock:
        now = shared_view(load_config())
    return jsonify({"ok": True, "at": snap.get("at"), "rev": snap.get("rev"),
                    "parts": diff_views(snap.get("view") or {}, now),
                    "note": "what Restore would undo: 'added' exists now and would be "
                            "removed, 'removed' would come back, 'changed' would revert"})


@app.post("/api/history/<name>/restore")
def api_history_restore(name):
    """Put a snapshot back, as a new change.

    The restored state gets the next revision rather than the old one, so to
    the rest of the cluster it is what it is: the newest configuration, which
    happens to have older contents. Nothing is applied -- the point of coming
    here is to look before leaping, so the caller reviews and presses Apply.
    """
    snap = _read(name)
    if not snap:
        return jsonify({"error": "no such snapshot"}), 404
    view = snap.get("view") or {}
    with _lock:
        cfg = load_config()
        if shared_fingerprint(cfg) == snap.get("fp"):
            return jsonify({"ok": True, "note": "This is already the current configuration.",
                            "changed": False})
        for section in SECTIONS:
            part = view.get(section)
            if isinstance(part, dict):
                cfg[section] = _merge_defaults(part, DEFAULT_CONFIG[section])
        save_config(cfg)
        rev = int(cfg["_meta"].get("shared_rev") or 0)
    log.info("restored the configuration of %s (revision %s) as revision %d",
             snap.get("at"), snap.get("rev"), rev)
    return jsonify({"ok": True, "changed": True, "rev": rev,
                    "note": "Restored as revision %d. Review the result, then press Apply "
                            "to serve it -- and it syncs to the other nodes like any "
                            "other change." % rev})
