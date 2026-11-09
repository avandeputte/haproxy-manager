"""The rule wizard: a rule built in one place, attached where it applies.

A rule made on the Rules page did nothing until the Public Service it was
meant for was opened and the rule ticked there, and the conditions it tests
had to exist first, made on a third page. This builds all of it from one
request -- the conditions typed inline, reused when an identical one exists;
the rule; its place on each listener -- and validates what results with
haproxy -c before anything is stored, so a rule that would not load is
refused with HAProxy's own words rather than found at the next Apply.
"""

from flask import jsonify
from flask import request
import copy
import uuid

from .base import _lock, app
from .config import load_config, save_config
from .util import _by_id, _sec, rule_cond_ids
from . import access, apply, dnsapi, haproxy, wizard
import ipaddress

MARK = "created by the rule wizard"

COND_TYPES = ("host_matches", "host_starts_with", "host_ends_with", "path_matches",
              "path_starts_with", "path_ends_with", "path_contains", "url_parameter",
              "http_header", "source_ip", "source_list", "ssl_sni", "custom")
ACTIONS = ("use_backend", "redirect_scheme_https", "redirect_location", "http_request_deny",
           "http_request_set_header", "http_request_del_header", "http_response_set_header",
           "tcp_request_content_accept", "tcp_request_content_reject", "custom")
# What each action needs typed, by the field the rule stores it in.
NEEDS = {"redirect_location": ("param1",), "http_request_set_header": ("param1", "param2"),
         "http_request_del_header": ("param1",), "http_response_set_header": ("param1", "param2"),
         "custom": ("param1",)}


def _spec(raw):
    """One condition as the form sends it, trimmed to what a condition holds."""
    if not isinstance(raw, dict):
        raise ValueError("a condition must be an object")
    if raw.get("id"):
        return {"id": str(raw["id"])}
    t = raw.get("type") or "host_matches"
    if t not in COND_TYPES:
        raise ValueError("\"%s\" is not a condition type" % t)
    spec = {"type": t, "value": (raw.get("value") or "").strip(),
            "param": (raw.get("param") or "").strip(), "list": raw.get("list") or "",
            "negate": bool(raw.get("negate"))}
    if t == "source_list":
        if not spec["list"]:
            raise ValueError("a source_list condition needs an address list")
    elif not spec["value"]:
        raise ValueError("a %s condition needs a value" % t)
    if t in ("http_header", "url_parameter") and not spec["param"]:
        raise ValueError("a %s condition needs the name of the %s"
                         % (t, "header" if t == "http_header" else "parameter"))
    if t == "source_ip":
        _good, bad = access.networks(spec["value"])
        if bad:
            raise ValueError("not a network: %s" % ", ".join(bad[:3]))
    return spec


def _same(cond, spec):
    return (cond.get("type") == spec["type"]
            and (cond.get("value") or "").strip() == spec["value"]
            and (cond.get("param") or "").strip() == spec["param"]
            and (cond.get("list") or "") == spec["list"]
            and bool(cond.get("negate")) == spec["negate"])


def _cond_name(cfg, spec):
    """A name that says what the condition tests, the way the publish wizard names its own."""
    t, v = spec["type"], spec["value"]
    first = v.split()[0] if v.split() else ""
    if t.startswith("host"):
        base = "host-" + (first.split(".")[0] if first else "any")
    elif t.startswith("path"):
        base = "path-" + (first.strip("/").replace("/", "-") or "root")
    elif t == "source_ip":
        base = "from-" + first.split("/")[0]
    elif t == "source_list":
        base = "from-" + (access.list_names(cfg, [spec["list"]]) or ["list"])[0]
    elif t == "http_header":
        base = "hdr-" + spec["param"]
    elif t == "url_parameter":
        base = "param-" + spec["param"]
    elif t == "ssl_sni":
        base = "sni-" + (first.split(".")[0] if first else "any")
    else:
        base = "acl-" + (first or "custom")
    if spec["negate"]:
        base = "not-" + base
    return _sec(base)[:40]


def _resolve(cfg, specs, acts):
    """The ids of these conditions: picked ones checked, typed ones reused or made."""
    hp = cfg["haproxy"]
    conds = _by_id(hp["conditions"])
    local = {c.get("id") for c in (cfg["local"].get("haproxy") or {}).get("conditions") or []}
    ids = []
    for raw in specs or []:
        spec = _spec(raw)
        if "id" in spec:
            if spec["id"] not in conds and spec["id"] not in local:
                raise ValueError("a condition that was picked no longer exists")
            if spec["id"] not in ids:
                ids.append(spec["id"])
            continue
        if spec["type"] == "source_list" and not access.known_lists(cfg, [spec["list"]]):
            raise ValueError("the address list picked no longer exists")
        found = wizard._find(hp["conditions"], lambda c: _same(c, spec))
        if found:
            acts.append({"action": "reused", "type": "Condition", "name": found["name"]})
        else:
            found = {"id": str(uuid.uuid4()),
                     "name": wizard._uniq_name({c["name"] for c in hp["conditions"]},
                                               _cond_name(cfg, spec)),
                     "type": spec["type"], "value": spec["value"], "param": spec["param"],
                     "negate": spec["negate"], "description": MARK}
            if spec["type"] == "source_list":
                found["list"] = spec["list"]
            hp["conditions"].append(found)
            acts.append({"action": "created", "type": "Condition", "name": found["name"]})
        if found["id"] not in ids:
            ids.append(found["id"])
    return ids


def build_rule(cfg, body):
    """Make the rule the request describes, in this configuration. Returns
    (rule, actions, warnings); raises ValueError for a request that cannot be
    honoured, before anything is changed that matters."""
    hp = cfg["haproxy"]
    acts, warns = [], []
    fes = _by_id(hp["frontends"])
    listeners = [l for l in (body.get("listeners") or []) if isinstance(l, str)]
    for lid in listeners:
        if lid not in fes:
            raise ValueError("a Public Service that was picked no longer exists")
    action = body.get("action") or {}
    atype = action.get("type") or "use_backend"
    if atype not in ACTIONS:
        raise ValueError("\"%s\" is not an action" % atype)
    test = "unless" if action.get("test") == "unless" else "if"
    backend = action.get("backend") or ""
    if atype == "use_backend":
        if backend not in _by_id(hp["backends"]):
            raise ValueError("routing needs a Backend Pool to route to")
    else:
        backend = ""
    p1 = haproxy._line_safe(action.get("param1") or "") if atype != "custom" else (action.get("param1") or "").strip()
    p2 = haproxy._line_safe(action.get("param2") or "")
    for need in NEEDS.get(atype, ()):
        if not (p1 if need == "param1" else p2):
            what = {"redirect_location": "a location to redirect to",
                    "http_request_set_header": "a header name and a value",
                    "http_request_del_header": "a header name",
                    "http_response_set_header": "a header name and a value",
                    "custom": "the line to add"}[atype]
            raise ValueError("this action needs %s" % what)

    rule = None
    if body.get("id"):
        rule = _by_id(hp["rules"]).get(body["id"])
        if rule is None:
            if body["id"] in {r.get("id") for r in (cfg["local"].get("haproxy") or {}).get("rules") or []}:
                raise ValueError("that rule is part of this node's web UI service and is managed "
                                 "from Settings > Web UI access")
            raise ValueError("the rule being edited no longer exists")
    previous = rule_cond_ids(rule) if rule else []

    any_of = _resolve(cfg, body.get("any_of"), acts)
    all_of = [c for c in _resolve(cfg, body.get("all_of"), acts) if c not in any_of]
    # A condition in both lists would be "A and A or B": kept in the all-of
    # list, where it means what was presumably meant.

    conds = _by_id(hp["conditions"])
    first = next((conds[c]["name"] for c in any_of + all_of if c in conds), "")
    name = (body.get("name") or "").strip()
    if not name:
        if atype == "use_backend":
            name = "to-" + _by_id(hp["backends"])[backend]["name"]
        else:
            verb = {"redirect_scheme_https": "https", "redirect_location": "redirect",
                    "http_request_deny": "deny", "http_request_set_header": "set",
                    "http_request_del_header": "unset", "http_response_set_header": "set",
                    "tcp_request_content_accept": "accept", "tcp_request_content_reject": "reject",
                    "custom": "rule"}[atype]
            name = verb + ("-" + first if first else "")
        if rule is None or rule.get("name") != name:
            name = wizard._uniq_name({r["name"] for r in hp["rules"] if r is not rule}, _sec(name))
    # Alternatives alone keep the shape every version renders the same: a
    # node still on 1.x reads only `conditions`, and a rule with its
    # alternatives under any_of would apply there without any of them.
    if any_of and not all_of:
        shape = {"any_of": [], "conditions": any_of, "operator": "or"}
    else:
        shape = {"any_of": any_of, "conditions": all_of, "operator": "and"}
    fields = dict({"name": name, "type": atype, "test": test, "backend": backend,
                   "param1": p1, "param2": p2}, **shape)
    if rule:
        rule.update(fields)
        acts.append({"action": "updated", "type": "Rule", "name": rule["name"]})
    else:
        rule = dict({"id": str(uuid.uuid4())}, **fields)
        hp["rules"].append(rule)
        acts.append({"action": "created", "type": "Rule", "name": rule["name"]})

    # Where it applies: attached to the listeners picked, placed by how
    # specific it is, and taken off the ones no longer picked.
    for fe in hp["frontends"]:
        has = rule["id"] in (fe.get("rules") or [])
        want = fe["id"] in listeners
        if want and not has:
            fe["rules"] = dnsapi._place_rule(hp, fe.get("rules") or [], rule)
            acts.append({"action": "attached", "type": "Public Service", "name": fe["name"]})
        elif has and not want:
            fe["rules"] = [r for r in fe["rules"] if r != rule["id"]]
            acts.append({"action": "detached", "type": "Public Service", "name": fe["name"]})
        if want and (fe.get("mode") or "http") == "tcp" and atype.startswith("http") or \
                want and (fe.get("mode") or "http") == "tcp" and atype == "redirect_scheme_https":
            warns.append("\"%s\" forwards raw TCP, and an HTTP action cannot act on that: "
                         "the rule is attached, and HAProxy may refuse it." % fe["name"])
    if not listeners:
        warns.append("This rule is attached to no Public Service, so it does nothing yet. "
                     "Pick one under \"On\", or tick the rule on the service later.")

    # Conditions this wizard made for the rule and the rule no longer tests,
    # when nothing else does either. A condition made by hand is left alone:
    # it may be waiting for another rule.
    used = {c for r in hp["rules"] for c in rule_cond_ids(r)}
    for cid in previous:
        if cid in used:
            continue
        gone = conds.get(cid)
        if gone and gone.get("description") == MARK:
            hp["conditions"] = [c for c in hp["conditions"] if c.get("id") != cid]
            acts.append({"action": "removed", "type": "Condition", "name": gone.get("name")})
    return rule, acts, warns


def _blocks_for(text, cfg, listeners):
    """The frontend blocks of the rendered file for these listeners."""
    names = {"frontend fe_" + _sec(f["name"]) for f in cfg["haproxy"]["frontends"]
             if f["id"] in listeners}
    out = []
    for block in text.split("\n\n"):
        if block.strip() and block.strip().splitlines()[0] in names:
            out.append(block.strip("\n"))
    return "\n\n".join(out)


@app.post("/api/wizard/rule")
def api_wizard_rule():
    """Build a rule; with dry_run, only say what would happen and whether
    HAProxy would accept the result."""
    body = request.get_json(force=True, silent=True) or {}
    dry_run = bool(body.get("dry_run"))
    with _lock:
        cfg = load_config()
        draft = copy.deepcopy(cfg)
        try:
            rule, acts, warns = build_rule(draft, body)
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception as e:                      # a malformed draft must not corrupt the store
            return jsonify({"ok": False, "error": "could not build the rule: %s" % e}), 400
        summary = {"ok": True, "actions": acts, "warnings": warns, "dry_run": dry_run,
                   "rule": {"id": rule["id"], "name": rule["name"]}}
        try:
            text = haproxy.render_haproxy(draft)
        except Exception as e:
            return jsonify({"ok": False, "error": "the resulting configuration is not renderable: %s" % e}), 400
        summary["preview"] = _blocks_for(text, draft, body.get("listeners") or []) or text
        # The point of previewing: HAProxy's verdict on the result, before it
        # is stored. A rule it refuses is refused here, with its reason.
        ok, message = apply.check_rendered(draft)
        summary["validation"] = {"ok": ok, "message": message}
        if not ok and not dry_run:
            return jsonify({"ok": False, "error": "HAProxy would not load this rule, so it was "
                            "not saved.\n\n" + message, "validation": summary["validation"],
                            "preview": summary["preview"]}), 400
        if dry_run:
            return jsonify(summary)
        save_config(draft)
    if body.get("apply"):
        summary["applied"] = apply.do_apply()
    return jsonify(summary)


# --------------------------------------------------------------------------
# the condition wizard

def matches(cfg, spec, sample):
    """Would this condition hold for a sample request? True, False, or None
    for a raw ACL, which only HAProxy can judge.

    The sample is what the form offers: a host, a path, a source address, a
    header or parameter value. Each type reads the part it tests, the way
    the rendered ACL does: hosts without their port and case-blind, paths
    as given, addresses against the networks.
    """
    t = spec["type"]
    patterns = spec["value"].split()
    host = (sample.get("host") or "").strip().lower()
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    path = (sample.get("path") or "").strip()
    if t == "host_matches":
        hit = any(host == v.lower() or (v.startswith("*.") and host.endswith(v[1:].lower())
                                        and "." not in host[:-len(v) + 1])
                  for v in patterns)
    elif t == "host_starts_with":
        hit = any(host.startswith(v.lower()) for v in patterns)
    elif t == "host_ends_with":
        hit = any(host.endswith(v.lower()) for v in patterns)
    elif t == "ssl_sni":
        hit = (sample.get("host") or "").strip().lower() in {v.lower() for v in patterns}
    elif t == "path_matches":
        hit = path in patterns
    elif t == "path_starts_with":
        hit = any(path.startswith(v) for v in patterns)
    elif t == "path_ends_with":
        hit = any(path.endswith(v) for v in patterns)
    elif t == "path_contains":
        hit = any(v in path for v in patterns)
    elif t in ("http_header", "url_parameter"):
        got = (sample.get("header" if t == "http_header" else "param") or "").strip().lower()
        hit = got in {v.lower() for v in patterns}
    elif t in ("source_ip", "source_list"):
        nets = access.list_networks(cfg, [spec["list"]])[0] if t == "source_list" else access.networks(spec["value"])[0]
        try:
            addr = ipaddress.ip_address((sample.get("src") or "").strip())
        except ValueError:
            return None
        hit = any(addr in ipaddress.ip_network(n) for n in nets)
    else:
        return None
    return (not hit) if spec["negate"] else hit


def acl_line(cfg, cond):
    """The acl line(s) this condition renders to, as a listener would declare them."""
    if cond.get("type") == "source_list":
        nets, _bad = access.list_networks(cfg, [cond.get("list")])
        return "\n".join(haproxy._src_acl("acl_" + _sec(cond["name"]), nets))
    expr = haproxy._line_safe(haproxy.COND_MAP.get(cond.get("type", "custom"), haproxy.COND_MAP["custom"])(cond))
    return "acl acl_%s %s" % (_sec(cond["name"]), expr)


@app.post("/api/wizard/condition")
def api_wizard_condition():
    """Build a condition; with dry_run, say what it renders to, whether HAProxy
    accepts it, and whether it would match the sample request given."""
    body = request.get_json(force=True, silent=True) or {}
    dry_run = bool(body.get("dry_run"))
    with _lock:
        cfg = load_config()
        draft = copy.deepcopy(cfg)
        hp = draft["haproxy"]
        try:
            spec = _spec({k: body.get(k) for k in ("type", "value", "param", "list", "negate")})
            if spec["type"] == "source_list" and not access.known_lists(cfg, [spec["list"]]):
                raise ValueError("the address list picked no longer exists")
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        acts = []
        cond = _by_id(hp["conditions"]).get(body.get("id") or "")
        if body.get("id") and cond is None:
            return jsonify({"ok": False, "error": "the condition being edited no longer exists"}), 400
        if cond is None:
            cond = wizard._find(hp["conditions"], lambda c: _same(c, spec))
            if cond:
                acts.append({"action": "reused", "type": "Condition", "name": cond["name"]})
        name = (body.get("name") or "").strip()
        if cond is None:
            cond = {"id": str(uuid.uuid4()),
                    "name": wizard._uniq_name({c["name"] for c in hp["conditions"]}, _sec(name) if name else _cond_name(cfg, spec)),
                    "description": MARK}
            hp["conditions"].append(cond)
            acts.append({"action": "created", "type": "Condition", "name": cond["name"]})
        elif acts == []:
            if name and name != cond.get("name"):
                cond["name"] = wizard._uniq_name({c["name"] for c in hp["conditions"] if c is not cond}, _sec(name))
            acts.append({"action": "updated", "type": "Condition", "name": cond["name"]})
        cond.update({"type": spec["type"], "value": spec["value"], "param": spec["param"], "negate": spec["negate"]})
        if spec["type"] == "source_list":
            cond["list"] = spec["list"]
        else:
            cond.pop("list", None)
        summary = {"ok": True, "actions": acts, "dry_run": dry_run,
                   "condition": {"id": cond["id"], "name": cond["name"]},
                   "preview": acl_line(draft, cond),
                   "matches": matches(draft, spec, body.get("sample") or {}) if isinstance(body.get("sample"), dict) else None}
        # HAProxy's verdict, with the condition tested by a throwaway rule on
        # an HTTP listener in the draft, since a condition nothing tests
        # renders nothing for -c to read.
        probe = copy.deepcopy(draft)
        fe = next((f for f in probe["haproxy"]["frontends"] if (f.get("mode") or "http") == "http"), None)
        if fe is not None:
            probe["haproxy"]["rules"].append({"id": "probe", "name": "probe", "type": "http_request_deny",
                                              "test": "if", "any_of": [], "conditions": [cond["id"]]})
            fe["rules"] = list(fe.get("rules") or []) + ["probe"]
        ok, message = apply.check_rendered(probe)
        summary["validation"] = {"ok": ok, "message": message}
        if not ok and not dry_run:
            return jsonify({"ok": False, "error": "HAProxy would not load this condition, so it was not "
                            "saved.\n\n" + message, "validation": summary["validation"],
                            "preview": summary["preview"]}), 400
        if dry_run:
            return jsonify(summary)
        save_config(draft)
    return jsonify(summary)
