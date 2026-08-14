"""Publishing this management UI through HAProxy."""

from flask import abort
from flask import jsonify
from flask import request
from urllib.parse import urlsplit
import copy

from .base import LISTEN, PORT, _lock, app, log
from .config import WEBUI_NAME, is_webui_cert, load_config, merged, move_to_local, promote_local, save_config, webui_object_ids
from .util import _by_id, cert_details, cert_path
from . import access, apply, dnsapi, vrrp, wizard

# --------------------------------------------------------------------------



def webui_pubs(cfg, pub):
    """This node's own name, plus the shared one if it fits on the same listener.

    Both point at this node's local UI. On the node holding the virtual IP the
    shared name resolves there, so it always reaches whichever node is active,
    while the per-node names stay reachable individually.
    """
    pubs = [pub]
    shared = (cfg.get("cluster") or {}).get("ui_url") or ""
    if not shared:
        return pubs
    sp, err = wizard._split_url(shared, "The shared UI address", default_scheme="https",
                         allow=("http", "https"))
    if err or sp["host"].lower() == pub["host"].lower():
        # Both addresses the same: the node has no name of its own left, and
        # is reachable only through whichever node holds the virtual IP.
        return pubs
    if sp["scheme"] != pub["scheme"] or sp["port"] != pub["port"]:
        return pubs          # one listener cannot serve both; validated on save
    pubs.append(sp)
    return pubs


def build_webui(cfg, pub, mode="auto", http_redirect=True):
    """Create (or re-attach) this node's own UI service, and keep it this node's.

    The wizard edits what it can find in the shared collections, so this node's
    objects are put back there for the length of the call and moved out again
    at the end. Without that the wizard would find nothing, build a second set
    every time, and a node would gain another copy of its own UI service on
    every configuration it received.
    """
    promote_local(cfg)
    target = {"scheme": "http", "host": "127.0.0.1", "port": PORT, "path": "", "label": WEBUI_NAME}
    acts, warns = dnsapi.wizard_publish(cfg, webui_pubs(cfg, pub), [target], name=WEBUI_NAME,
                                 want_cert=(mode != "none"), new_certificate=(mode == "new"),
                                 http_redirect=http_redirect,
                                 health={"type": "http", "interval": "5s", "uri": "/", "status": "200"})
    # The wizard builds into the shared configuration like any other service.
    # Everything it built for this one then moves into this node's own, where
    # it cannot travel to the other nodes because it is not in what is sent.
    # A certificate that merely covers this host and was reused -- a wildcard --
    # was not built here and stays shared.
    mine = webui_object_ids(cfg)
    mine |= {c["id"] for c in cfg["acme"]["certificates"] if is_webui_cert(c)}
    move_to_local(cfg, mine)
    # Record which rule this node uses, here rather than only in the request
    # handler: this also runs when a configuration arrives from another node,
    # and a stale id would make the rule actually in use look like a leftover.
    local_hp = cfg["local"].get("haproxy") or {}
    pools = {b["id"] for b in local_hp.get("backends") or [] if b.get("name") == WEBUI_NAME}
    ours = [r for r in local_hp.get("rules") or [] if r.get("backend") in pools]
    if ours:
        best = max(ours, key=lambda r: len(r.get("conditions") or []))
        cfg["local"].setdefault("web_ui", {})["rule_id"] = best["id"]
    return acts, warns


def rebuild_webui(cfg):
    """Re-run the build from the stored setting, after a configuration arrives."""
    s = cfg["local"].get("web_ui") or {}
    if not (s.get("enabled") and s.get("url")):
        return
    pub, err = wizard._split_url(s["url"], "The web UI address", default_scheme="https",
                          allow=("http", "https"))
    if err:
        return
    # Never "new" here, whatever was chosen when the service was set up.
    # Asking for a new certificate is something a person does once, by pressing
    # Save; replaying it on every configuration that arrives would leave a node
    # with one more certificate for the same name after every sync.
    mode = s.get("certificate", "auto")
    build_webui(cfg, pub, "auto" if mode == "new" else mode, True)


def _webui_setting(cfg):
    """Node-local: each node publishes its own name for its own UI."""
    return cfg["local"].setdefault(
        "web_ui", {"enabled": False, "url": "", "certificate": "auto", "rule_id": ""})


def current_webui_hosts(cfg):
    """The host names the UI service is routed by, from the object graph."""
    hp = merged(cfg)["haproxy"]
    pools = {b["id"] for b in hp.get("backends") or [] if b.get("name") == WEBUI_NAME}
    conds = _by_id(hp.get("conditions") or [])
    out = set()
    for rule in hp.get("rules") or []:
        if rule.get("backend") not in pools:
            continue
        for cid in rule.get("conditions") or []:
            c = conds.get(cid) or {}
            if c.get("type") == "host_matches" and c.get("value"):
                out.add(c["value"].strip().lower())
    return out


def webui_address_checks(cfg):
    """Do the two addresses point where they have to?

    This node's own name must resolve to an address this node holds -- if it
    resolves anywhere else, nothing here can answer it however well HAProxy is
    running, and the failure looks exactly like the node being down. The shared
    name must resolve to the virtual IP, which is what makes it reach whichever
    node is active.
    """
    out = []
    s = cfg["local"].get("web_ui") or {}
    vips = vrrp.cluster_vips(cfg)
    if s.get("enabled") and s.get("url"):
        level, msg = vrrp.check_node_url(s["url"], vips)
        if level != "ok":
            out.append({"which": "This node's address", "level": level, "message": msg})
    shared = (cfg.get("cluster") or {}).get("ui_url") or ""
    if shared and vips:
        host = urlsplit(shared if "//" in shared else "//" + shared).hostname or ""
        ips = vrrp.resolve_host(host)
        if not ips:
            out.append({"which": "Shared address", "level": "warn",
                        "message": "%s does not resolve here." % host})
        elif not set(ips) & set(vips):
            out.append({"which": "Shared address", "level": "warn",
                        "message": "%s resolves to %s, which is not the virtual IP (%s). "
                                   "It will keep reaching whichever node that address "
                                   "belongs to rather than whichever node is active."
                                   % (host, ", ".join(ips), ", ".join(vips))})
    return out


def extra_ui_rules(cfg):
    """Rules routing to this node's UI service other than the one it uses.

    A leftover from when the service could be built twice: both rules point at
    the same pool, so nothing is broken and nothing is served twice -- HAProxy
    takes the first that matches -- but the Services page honestly shows one
    row per rule, and two rows for one service is a puzzle rather than
    information.

    Only rules whose pool is this node's UI service and which are this node's
    own are considered, so nothing a person made by hand is ever in the list.
    """
    all_of_it = merged(cfg)["haproxy"]
    pools = {b["id"] for b in all_of_it.get("backends") or [] if b.get("name") == WEBUI_NAME}
    mine = {r.get("id") for r in (cfg["local"].get("haproxy") or {}).get("rules") or []}
    ours = [r for r in all_of_it.get("rules") or []
            if r.get("backend") in pools and r.get("id") in mine]
    keep = (cfg["local"].get("web_ui") or {}).get("rule_id") or ""
    if keep not in {r.get("id") for r in ours}:
        # The recorded id names nothing here. Rather than call every rule a
        # leftover, keep the one testing the most host names -- the one built
        # for both this node's address and the shared one.
        keep = max(ours, key=lambda r: len(r.get("conditions") or []),
                   default={}).get("id", "")
    out = []
    for rule in ours:
        if rule.get("id") != keep:
            hosts = [c.get("value") for c in all_of_it.get("conditions") or []
                     if c.get("id") in (rule.get("conditions") or [])
                     and c.get("type") == "host_matches"]
            out.append({"id": rule.get("id"), "name": rule.get("name"), "hosts": hosts})
    return out


@app.post("/api/webui/tidy")
def api_webui_tidy():
    """Remove the leftover rules, on request rather than on sight.

    They are this node's own objects, they route to this node's own pool, and
    the one being kept is the one recorded in the setting -- so what goes is
    not a judgement about ownership. It is still asked for rather than done
    quietly: removing objects from a working configuration is exactly what
    should require somebody to have decided.
    """
    with _lock:
        cfg = load_config()
        extras = extra_ui_rules(cfg)
        if not extras:
            return jsonify({"ok": True, "removed": [], "note": "There was nothing to tidy."})
        promote_local(cfg)                       # where _remove_service_objects looks
        removed = []
        for rule in extras:
            removed += _remove_service_objects(cfg["haproxy"], rule["id"])
        s = cfg["local"].get("web_ui") or {}
        pub, err = wizard._split_url(s.get("url"), "x", default_scheme="https",
                                     allow=("http", "https"))
        if not err:
            # Rebuild afterwards, so anything the removal shared with the rule
            # that is being kept is put straight back.
            build_webui(cfg, pub, "auto" if s.get("certificate") == "new"
                        else s.get("certificate", "auto"), True)
        else:
            move_to_local(cfg, webui_object_ids(cfg))
        save_config(cfg)
    log.warning("removed %d leftover rule(s) for this node's own UI service", len(extras))
    res = apply.do_apply(load_config())
    return jsonify({"ok": True, "removed": removed,
                    "applied": {"ok": res.get("ok"), "error": res.get("error")},
                    "note": "Removed %d leftover rule%s." % (len(extras),
                                                             "" if len(extras) == 1 else "s")})


def webui_missing_hosts(cfg):
    """Addresses this node is configured to answer for and currently does not."""
    s = cfg["local"].get("web_ui") or {}
    if not (s.get("enabled") and s.get("url")):
        return []
    want = []
    for u in (s.get("url"), (cfg.get("cluster") or {}).get("ui_url")):
        pu, err = wizard._split_url(u, "x", default_scheme="https", allow=("http", "https"))
        if not err and pu.get("host"):
            want.append(pu["host"].lower())
    have = current_webui_hosts(cfg)
    return [h for h in want if h not in have]


def restore_webui(cfg):
    """Rebuild the UI service when an address it should answer for is not routed.

    The service is made of ordinary objects, and ordinary objects can be
    changed by anything that edits the configuration. When one of its host
    rules goes missing the symptom is that the node stops answering on that
    name -- with nothing to see, because every page still says what it was
    configured to be.

    Rebuilding is exactly what pressing Save on Web UI access does, so this
    cannot do anything that was not already a supported action. It returns the
    addresses it put back.
    """
    missing = webui_missing_hosts(cfg)
    if not missing:
        return []
    s = cfg["local"].get("web_ui") or {}
    pub, err = wizard._split_url(s.get("url"), "x", default_scheme="https",
                                 allow=("http", "https"))
    if err:
        return []
    mode = s.get("certificate", "auto")
    build_webui(cfg, pub, "auto" if mode == "new" else mode, True)
    still = webui_missing_hosts(cfg)
    if still:
        log.error("rebuilt the management UI service but %s is still not routed here; "
                  "something else is taking it out", ", ".join(still))
        return []
    log.warning("the management UI had stopped answering for %s -- rebuilt it",
                ", ".join(missing))
    return missing


@app.get("/api/webui")
def api_webui_get():
    cfg = load_config()
    s = _webui_setting(cfg)
    return jsonify({
        "enabled": bool(s.get("enabled")), "url": s.get("url", ""),
        "shared_url": (cfg.get("cluster") or {}).get("ui_url", ""),
        "certificate": s.get("certificate", "auto"), "rule_id": s.get("rule_id", ""),
        "port": PORT, "listen": LISTEN,
        "exposed_directly": LISTEN not in ("127.0.0.1", "localhost", "::1"),
        # What this node actually answers for right now, read from the objects
        # rather than from the setting that made them. The two can differ --
        # a name that was never published, or one that stopped being published
        # -- and the setting alone cannot show that.
        "hosts": sorted(current_webui_hosts(cfg)),
        # Where these names actually point. HAProxy answering on one address
        # and not another is not a proxy problem: it is a name resolving
        # somewhere this node is not.
        "address_checks": webui_address_checks(cfg),
        # Rules for this node's own UI beyond the one it uses -- why the
        # Services page can show the same address twice.
        "extra_rules": extra_ui_rules(cfg),
    })


@app.post("/api/webui")
def api_webui_set():
    """Publish (or withdraw) the management UI as a normal HAProxy service."""
    body = request.get_json(force=True, silent=True) or {}
    enabled = bool(body.get("enabled"))

    with _lock:
        cfg = load_config()
        s = _webui_setting(cfg)

        if not enabled:
            removed = []
            rid = s.get("rule_id")
            if rid:
                promote_local(cfg)      # where _remove_service_objects looks
                removed = _remove_service_objects(cfg["haproxy"], rid)
            s.update({"enabled": False, "rule_id": ""})
            save_config(cfg)
            return jsonify({"ok": True, "enabled": False, "removed": removed,
                            "note": "Press Apply to stop serving it."})

        pub, err = wizard._split_url(body.get("url"), "The web UI address",
                              default_scheme="https", allow=("http", "https"))
        if err:
            return jsonify({"ok": False, "error": err}), 400

        # The shared name is cluster-wide: every node answers for it, and the
        # one holding the virtual IP is the one reached. Both names sit on the
        # same listener, so they have to agree on scheme and port.
        shared_raw = (body.get("shared_url") or "").strip()
        shared = None
        if shared_raw:
            shared, serr = wizard._split_url(shared_raw, "The shared address",
                                      default_scheme="https", allow=("http", "https"))
            if serr:
                return jsonify({"ok": False, "error": serr}), 400
            if shared["host"].lower() == pub["host"].lower():
                return jsonify({"ok": False, "error":
                                "The shared address must differ from this node's own address."}), 400
            if shared["scheme"] != pub["scheme"] or shared["port"] != pub["port"]:
                return jsonify({"ok": False, "error":
                                "Both addresses are served by one listener, so they must use the "
                                "same scheme and port. This node's is %s://%s:%s."
                                % (pub["scheme"], pub["host"], pub["port"])}), 400
        cfg["cluster"]["ui_url"] = ("%s://%s" % (shared["scheme"], shared["host"])) if shared else ""

        # Refuse to take a host name that already points somewhere else.
        hp = cfg["haproxy"]
        conds = _by_id(hp["conditions"])
        for rule in hp["rules"]:
            if rule.get("type") != "use_backend" or rule.get("id") == s.get("rule_id"):
                continue
            hosts = [conds[c].get("value", "").lower() for c in (rule.get("conditions") or [])
                     if c in conds and conds[c].get("type") == "host_matches"]
            if pub["host"].lower() in hosts:
                pool = _by_id(hp["backends"]).get(rule.get("backend"))
                if not pool or pool.get("name") != WEBUI_NAME:
                    return jsonify({"ok": False, "error":
                                    "%s already points at the service \"%s\". Choose another host name "
                                    "for the UI, or remove that service first."
                                    % (pub["host"], pool["name"] if pool else rule.get("name", "?"))}), 409

        draft = copy.deepcopy(cfg)
        mode = body.get("certificate", "auto")
        try:
            acts, warns = build_webui(draft, pub, mode, bool(body.get("http_redirect", True)))
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

        pool = wizard._find(draft["haproxy"]["backends"], lambda b: b.get("name") == WEBUI_NAME)
        rule = wizard._find(draft["haproxy"]["rules"], lambda r: r.get("backend") == (pool or {}).get("id"))
        ws = _webui_setting(draft)
        ws.update({"enabled": True, "url": "%s://%s" % (pub["scheme"], pub["host"]),
                   "certificate": mode, "rule_id": (rule or {}).get("id", "")})

        if LISTEN not in ("127.0.0.1", "localhost", "::1"):
            warns.append("The UI still answers directly on %s:%d in plain HTTP. Once this works, set "
                         "HAM_LISTEN=127.0.0.1 in the service unit so only HAProxy can reach it."
                         % (LISTEN, PORT))
        if pub["scheme"] != "https":
            warns.append("This publishes the UI over plain HTTP: the password and session cookie "
                         "would cross the network in the clear.")
        save_config(draft)
        cfg = draft

    result = {"ok": True, "enabled": True, "actions": acts, "warnings": warns,
              "url": ws["url"], "note": "Press Apply to start serving it."}
    if body.get("apply"):
        result["applied"] = apply.do_apply()
    return jsonify(result)


@app.get("/api/services")
def api_services():
    """The published mappings, derived from the objects the wizard creates.

    A service is a use_backend rule whose conditions pin a host name; that is
    exactly what the wizard builds, and it also picks up equivalent rules made
    by hand on the Advanced pages.
    """
    stored = load_config()
    # Everything this node serves, its own objects included: the Services page
    # shows the management UI's service alongside the rest, marked as managed.
    cfg = merged(stored)
    local_ids = {i.get("id") for sec in ("haproxy", "acme")
                 for coll in ((stored["local"].get(sec) or {}).values())
                 if isinstance(coll, list) for i in coll}
    hp = cfg["haproxy"]
    conds, backends = _by_id(hp["conditions"]), _by_id(hp["backends"])
    servers, rules = _by_id(hp["servers"]), _by_id(hp["rules"])
    certs = _by_id(cfg["acme"]["certificates"])

    monitors = _by_id(hp["healthchecks"])

    def pool_settings(pool):
        """Everything the wizard would need to re-create this mapping unchanged."""
        if not pool:
            return {}
        first = next((servers[s] for s in (pool.get("servers") or []) if s in servers), {})
        m = monitors.get(pool.get("healthcheck")) if pool.get("healthcheck_enabled") else None
        return {
            "balance": pool.get("balance") or "roundrobin",
            "persistence": pool.get("persistence") or "none",
            "stick_type": pool.get("stick_type") or "ip",
            "stick_size": pool.get("stick_size") or "50k",
            "stick_expire": pool.get("stick_expire") or "30m",
            "log_health_checks": bool(pool.get("log_health_checks")),
            "notify_mode": pool.get("notify_mode") or "servers",
            "check_port": first.get("check_port") or "",
            "timeout_connect": pool.get("timeout_connect") or "",
            "timeout_server": pool.get("timeout_server") or "",
            # Whether visitors are asked to sign in, and who is let through.
            "auth": {"enabled": bool(pool.get("auth_enabled")),
                     "groups": list(pool.get("auth_groups") or []),
                     "group_names": access.group_names(cfg, pool.get("auth_groups")),
                     "realm": pool.get("auth_realm") or "",
                     "exempt": pool.get("auth_exempt_src") or ""},
            "allow_src": pool.get("allow_src") or "",
            "health": {"type": m.get("type") if m else "none",
                       "interval": (m or {}).get("interval") or "2s",
                       "uri": (m or {}).get("http_uri") or "/",
                       "status": (m or {}).get("expect_status") or "",
                       "user": (m or {}).get("db_user") or "",
                       "method": (m or {}).get("http_method") or "GET",
                       "version": (m or {}).get("http_version") or "",
                       "host": (m or {}).get("http_host") or ""},
        }

    def pool_targets(pool):
        out = []
        for sid in (pool.get("servers") if pool else []) or []:
            s = servers.get(sid)
            if s:
                out.append("%s://%s:%s" % ("https" if s.get("ssl") else "http",
                                           s.get("address"), s.get("port")))
        return out

    out = []
    for fe in hp["frontends"]:
        ports = sorted(wizard._bind_ports(fe))
        scheme = "https" if fe.get("ssl_enabled") else "http"

        # A TCP listener carries no host name: the port itself is the service.
        if fe.get("mode") == "tcp":
            pool = backends.get(fe.get("default_backend"))
            if not pool:
                continue
            bind = (fe.get("binds") or "").splitlines()[0].strip() if fe.get("binds") else ""
            out.append(dict(pool_settings(pool), **{
                "id": "fe:" + fe["id"],
                "url": "tcp://%s" % (bind or (":%d" % ports[0] if ports else "?")),
                "host": bind.rsplit(":", 1)[0] if ":" in bind else "", "path": "", "scheme": "tcp",
                "port": ports[0] if ports else None,
                "targets": [t.replace("http://", "tcp://") for t in pool_targets(pool)],
                "pool": pool["name"], "frontend": fe["name"], "frontend_id": fe["id"],
                "enabled": fe.get("enabled", True) and pool.get("enabled", True),
                "certificate": None, "certificate_id": None, "certificate_match": None,
                "certificate_status": None, "expires_iso": None, "days_left": None,
            }))
            continue

        for rid in fe.get("rules") or []:
            rule = rules.get(rid)
            if not rule or rule.get("type") != "use_backend":
                continue
            all_hosts, path = [], ""
            for cid in rule.get("conditions") or []:
                c = conds.get(cid)
                if not c:
                    continue
                if c.get("type") == "host_matches" and c.get("value"):
                    all_hosts.append(c["value"])
                elif c.get("type") == "path_starts_with":
                    path = c.get("value") or ""
            if not all_hosts:
                continue
            host = all_hosts[0]

            pool = backends.get(rule.get("backend"))
            targets = pool_targets(pool)
            default_port = 443 if scheme == "https" else 80
            shown_port = "" if (not ports or ports[0] == default_port) else ":%d" % ports[0]

            attached = [certs[cid] for cid in (fe.get("certificates") or []) if cid in certs]
            cert, match = wizard.cert_for_host(attached, host)
            uncovered = [h for h in all_hosts if not wizard.cert_for_host(attached, h)[0]]
            info = cert_details(cert_path(cert)) if cert else None

            out.append(dict(pool_settings(pool), **{
                "id": rule["id"],
                "managed": "web-ui" if rule.get("id") in local_ids else "",
                "url": "%s://%s%s%s" % (scheme, host, shown_port, path),
                "urls": ["%s://%s%s%s" % (scheme, h, shown_port, path) for h in all_hosts],
                "hosts": all_hosts,
                "certificate_uncovered": uncovered,
                "host": host, "path": path, "scheme": scheme,
                "port": ports[0] if ports else None,
                "targets": targets,
                "pool": pool["name"] if pool else None,
                "frontend": fe["name"], "frontend_id": fe["id"],
                "enabled": fe.get("enabled", True) and (pool.get("enabled", True) if pool else False),
                "certificate": cert["name"] if cert else None,
                "certificate_id": cert["id"] if cert else None,
                "certificate_match": match,          # "exact" or "wildcard"
                "certificate_status": info["status"] if info else None,
                "expires_iso": info["expires_iso"] if info else None,
                "days_left": info["days_left"] if info else None,
            }))
    return jsonify(out)


def _remove_service_objects(hp, rid):
    """Drop a use_backend rule and everything only it was using."""
    rule = _by_id(hp["rules"]).get(rid)
    if not rule:
        return []
    for fe in hp["frontends"]:
        if rid in (fe.get("rules") or []):
            fe["rules"] = [x for x in fe["rules"] if x != rid]
    hp["rules"] = [r for r in hp["rules"] if r.get("id") != rid]
    removed = [{"type": "Rule", "name": rule.get("name")}]

    still_used = {c for r in hp["rules"] for c in (r.get("conditions") or [])}
    for cid in rule.get("conditions") or []:
        if cid in still_used:
            continue
        cond = _by_id(hp["conditions"]).get(cid)
        if cond:
            hp["conditions"] = [c for c in hp["conditions"] if c.get("id") != cid]
            removed.append({"type": "Condition", "name": cond.get("name")})

    pool_id = rule.get("backend")
    pool = _by_id(hp["backends"]).get(pool_id)
    pool_used = any(r.get("backend") == pool_id for r in hp["rules"]) or \
        any(f.get("default_backend") == pool_id for f in hp["frontends"])
    if pool and not pool_used:
        server_ids = list(pool.get("servers") or [])
        hp["backends"] = [b for b in hp["backends"] if b.get("id") != pool_id]
        removed.append({"type": "Backend Pool", "name": pool.get("name")})
        in_use = {s for b in hp["backends"] for s in (b.get("servers") or [])}
        for sid in server_ids:
            if sid in in_use:
                continue
            srv = _by_id(hp["servers"]).get(sid)
            if srv:
                hp["servers"] = [s for s in hp["servers"] if s.get("id") != sid]
                removed.append({"type": "Real Server", "name": srv.get("name")})
    return removed


@app.delete("/api/services/<rid>")
def api_service_delete(rid):
    """Remove a mapping and every object it alone was using."""
    with _lock:
        cfg = load_config()
        hp = cfg["haproxy"]
        local_ids = {i.get("id") for sec in ("haproxy", "acme")
                     for coll in ((cfg["local"].get(sec) or {}).values())
                     if isinstance(coll, list) for i in coll}

        # "fe:<id>" is a TCP listener: the frontend itself is the service.
        if rid.startswith("fe:"):
            fe = _by_id(hp["frontends"]).get(rid[3:])
            if not fe:
                abort(404)
            pool_id = fe.get("default_backend")
            hp["frontends"] = [f for f in hp["frontends"] if f.get("id") != fe["id"]]
            removed = [{"type": "Public Service", "name": fe.get("name")}]
            pool = _by_id(hp["backends"]).get(pool_id)
            still_used = any(r.get("backend") == pool_id for r in hp["rules"]) or \
                any(f.get("default_backend") == pool_id for f in hp["frontends"])
            if pool and not still_used:
                server_ids = list(pool.get("servers") or [])
                hp["backends"] = [b for b in hp["backends"] if b.get("id") != pool_id]
                removed.append({"type": "Backend Pool", "name": pool.get("name")})
                dropped = []
                dnsapi._drop_orphan_wizard_servers(hp, server_ids, dropped)
                removed.extend({"type": d["type"], "name": d["name"]} for d in dropped)
            save_config(cfg)
            return jsonify({"ok": True, "removed": removed, "note": "Press Apply."})

        target = _by_id(hp["rules"]).get(rid)
        if not target:
            abort(404)
        if target.get("id") in local_ids:
            return jsonify({"ok": False, "error":
                            "This is the node's own web UI service. Turn it off under "
                            "Settings > Web UI access instead."}), 409
        removed = _remove_service_objects(hp, rid)
        save_config(cfg)
    return jsonify({"ok": True, "removed": removed,
                    "note": "Certificates and Public Services were left in place. Press Apply."})


# --------------------------------------------------------------------------
# recipes
