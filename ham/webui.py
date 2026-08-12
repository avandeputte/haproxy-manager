"""Publishing this management UI through HAProxy."""

from flask import abort
from flask import jsonify
from flask import request
import copy

from .base import LISTEN, PORT, _lock, app
from .config import LOCAL_ONLY, WEBUI_NAME, is_webui_cert, load_config, save_config
from .util import _by_id, cert_details, cert_path
from . import apply, dnsapi, wizard

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
        return pubs
    if sp["scheme"] != pub["scheme"] or sp["port"] != pub["port"]:
        return pubs          # one listener cannot serve both; validated on save
    pubs.append(sp)
    return pubs


def build_webui(cfg, pub, mode="auto", http_redirect=True):
    """Create (or re-attach) this node's own UI service and mark it node-local."""
    target = {"scheme": "http", "host": "127.0.0.1", "port": PORT, "path": "", "label": WEBUI_NAME}
    acts, warns = dnsapi.wizard_publish(cfg, webui_pubs(cfg, pub), [target], name=WEBUI_NAME,
                                 want_cert=(mode != "none"), new_certificate=(mode == "new"),
                                 http_redirect=http_redirect,
                                 health={"type": "http", "interval": "5s", "uri": "/", "status": "200"})
    hp = cfg["haproxy"]
    pool = wizard._find(hp["backends"], lambda b: b.get("name") == WEBUI_NAME)
    rule = wizard._find(hp["rules"], lambda r: r.get("backend") == (pool or {}).get("id"))
    ids = {(pool or {}).get("id"), (rule or {}).get("id"), (pool or {}).get("healthcheck")}
    ids |= set((pool or {}).get("servers") or [])
    ids |= set((rule or {}).get("conditions") or [])
    _tag_local(hp, {i for i in ids if i})
    # The certificate too. Every node needs one for its own name, so a
    # certificate left in the shared configuration travels to the others, which
    # keep it and add their own -- and no two nodes ever hold the same
    # configuration again. A certificate that merely covers this host and was
    # reused (a wildcard, say) is not ours to claim and is left alone.
    for cert in cfg["acme"]["certificates"]:
        if is_webui_cert(cert):
            cert[LOCAL_ONLY] = True
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


def _tag_local(hp, ids):
    """Mark the objects the web UI service is made of as node-local."""
    for coll in ("servers", "backends", "conditions", "rules", "healthchecks"):
        for item in hp.get(coll) or []:
            if item.get("id") in ids:
                item[LOCAL_ONLY] = True


def keep_local_only(mine, incoming, local_ids=None):
    """Put this node's own objects back after adopting a shared configuration.

    local_ids names everything this node owns alone across every section, so a
    listener under haproxy can be re-attached to a certificate under acme.
    """
    for coll, items in mine.items():
        if not isinstance(items, list):
            continue
        local = [i for i in items if i.get(LOCAL_ONLY)]
        if not local:
            continue
        have = {i.get("id") for i in incoming.get(coll) or []}
        incoming.setdefault(coll, []).extend(i for i in local if i.get("id") not in have)
    # re-attach them to whatever they were bound to
    # Match on name as well as id: each node created its own https-443, so the
    # same listener has a different id everywhere and an id-only match found
    # nothing -- which quietly dropped this node's UI rule from the listener.
    by_id = {f.get("id"): f for f in mine.get("frontends") or []}
    by_name = {f.get("name"): f for f in mine.get("frontends") or []}
    for fe in incoming.get("frontends") or []:
        was = by_id.get(fe.get("id")) or by_name.get(fe.get("name"))
        if not was:
            continue
        ids = local_ids if local_ids is not None else {
            i.get("id") for i in (mine.get("rules") or []) + (mine.get("certificates") or [])
            if i.get(LOCAL_ONLY)}
        for key in ("rules", "certificates"):
            extra = [x for x in (was.get(key) or []) if x in ids and x not in (fe.get(key) or [])]
            if extra:
                fe[key] = (fe.get(key) or []) + extra
    return incoming


def _webui_setting(cfg):
    """Node-local: each node publishes its own name for its own UI."""
    old = (cfg["haproxy"]["settings"].pop("web_ui", None) or {})   # migrate off the shared section
    cur = cfg["local"].setdefault(
        "web_ui", {"enabled": False, "url": "", "certificate": "auto", "rule_id": ""})
    for k, v in old.items():
        cur.setdefault(k, v)
    return cur


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
    cfg = load_config()
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
            "check_port": first.get("check_port") or "",
            "timeout_connect": pool.get("timeout_connect") or "",
            "timeout_server": pool.get("timeout_server") or "",
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
                "managed": "web-ui" if rule.get(LOCAL_ONLY) else "",
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
        if target.get(LOCAL_ONLY):
            return jsonify({"ok": False, "error":
                            "This is the node's own web UI service. Turn it off under "
                            "System > Web UI access instead."}), 409
        removed = _remove_service_objects(hp, rid)
        save_config(cfg)
    return jsonify({"ok": True, "removed": removed,
                    "note": "Certificates and Public Services were left in place. Press Apply."})


# --------------------------------------------------------------------------
# recipes
