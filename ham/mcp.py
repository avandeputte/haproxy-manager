"""An MCP server: this node's API as tools an assistant can call.

Model Context Protocol over its Streamable HTTP transport, in the part a tool
server needs: initialize, ping, tools/list and tools/call, answered as plain
JSON on POST /mcp. No streams, no package to install.

Every tool is a call to the node's own API, made in-process. So a tool
cannot do anything the UI could not: the same validation, the same `haproxy
-c` before a change is stored, the same passive-node lock, and a line in the
audit log naming the MCP client. The tools are a fixed list over fixed
routes -- the assistant cannot reach the login, the API key, peers or this
server's own settings.

Off until it is turned on under Settings > MCP server, and read-only until
changes are allowed there too. It answers only a token of its own, not the
API key: the key also authorises the other nodes, and a token handed to an
assistant should be revocable without touching the cluster. The token is kept
beside its hash, as the API key is, so the settings page can show it again
for setting up the next client; a request is checked against the hash.

In a cluster it behaves as one server. Its settings and token are copied to
every node, so a client pointed at the virtual IP keeps working through a
failover; and a change asked of a passive node is carried out on the node
holding the virtual IP -- forwarded over the peer link with the API key, the
way sync talks -- since that is where shared configuration is edited.
Reading stays on the node asked.
"""

from datetime import datetime
from datetime import timezone
import concurrent.futures
from flask import Response
from flask import jsonify
from flask import request
from urllib.parse import quote
from urllib.parse import urlsplit
import hashlib
import hmac
import json
import re
import secrets
import uuid

from .base import (PEER_CONNECT_TIMEOUT, PEER_READ_TIMEOUT, PUSH_READ_TIMEOUT, VERSION,
    _lock, _requests, app, log)
from .config import VALID_COLLECTIONS, load_config, save_config
from . import auth, peering, sync

PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
REDACTED = "[redacted]"
# Values an assistant has no use for and should never be sent: whatever it is
# shown leaves this machine for the model's provider.
SECRET_KEY_RE = re.compile(r"(passw|(^|_)pass$|secret|token|credential|private|salt|hash$|(^|_)key$|totp)", re.I)
MAX_TEXT = 200000            # characters of tool output; a log can be longer
_sessions = {}               # Mcp-Session-Id -> the client's name, for the log
INSTRUCTIONS = (
    "This server manages HAProxy on one haproxy-manager node. Changes made through it are "
    "stored but not live: HAProxy is rewritten and reloaded only by apply_changes, and "
    "get_status says whether anything is waiting (\"dirty\"). Prefer dry_run first where a "
    "tool offers it: it returns the configuration lines a change would produce and HAProxy's "
    "verdict on them, without storing anything. Values shown as [redacted] are secrets; "
    "send [redacted] back unchanged to keep the stored value. In a cluster, a change asked "
    "of a passive node is made on the node holding the virtual IP, and the answer says so.")
# What every node of a cluster holds the same of, so any of them answers the
# same client the same way.
SHARED_KEYS = ("enabled", "allow_writes", "token", "token_hash", "token_fp", "token_created")


def settings(cfg):
    return cfg["local"].get("mcp") or {}


def _token_hash(token):
    return hashlib.sha256((token or "").strip().encode()).hexdigest()


def shown_token(cfg):
    """The token, for showing again; "" when only its hash is known (made
    before tokens were kept) or the two disagree."""
    s = settings(cfg)
    token = s.get("token") or ""
    if token and hmac.compare_digest(s.get("token_hash") or "", _token_hash(token)):
        return token
    return ""


def token_matches(cfg, presented):
    stored = settings(cfg).get("token_hash") or ""
    if not stored or not (presented or "").strip():
        return False
    return hmac.compare_digest(stored, _token_hash(presented))


def redact(value):
    """A copy with every secret-looking value replaced, at any depth."""
    if isinstance(value, dict):
        return {k: (REDACTED if SECRET_KEY_RE.search(str(k)) and v not in ("", None, [], {})
                    and not isinstance(v, bool) else redact(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def unredact(sent, stored):
    """What was sent, with every [redacted] put back to what is stored, so an
    object read through MCP and written back does not lose its secrets."""
    if isinstance(sent, dict):
        stored = stored if isinstance(stored, dict) else {}
        return {k: (stored.get(k, "") if v == REDACTED else unredact(v, stored.get(k)))
                for k, v in sent.items()}
    if isinstance(sent, list):
        stored = stored if isinstance(stored, list) else []
        return [unredact(v, stored[i] if i < len(stored) else None) for i, v in enumerate(sent)]
    return sent


# --------------------------------------------------------------------------
# calling the node's own API

class Refused(Exception):
    """A tool call the server will not make, with the reason the client sees."""


class UnknownTool(Exception):
    pass


def _api(method, path, body=None, query=None):
    """One request to this node's API, as the MCP client. Returns
    (status, parsed JSON or text).

    Marked in the WSGI environ, which no HTTP client can set: the API's
    sign-in check lets it through and the audit line names the client."""
    environ = {"ham.mcp": getattr(request, "mcp_client", "") or "mcp",
               "REMOTE_ADDR": request.remote_addr or "127.0.0.1"}
    resp = app.test_client().open(path, method=method, json=body, query_string=query,
                                  environ_base=environ)
    if resp.is_json:
        return resp.status_code, resp.get_json(silent=True)
    return resp.status_code, resp.get_data(as_text=True)


def _ok(status, data):
    if status >= 400:
        msg = data.get("error") or data.get("message") if isinstance(data, dict) else str(data)
        raise Refused("%s (HTTP %d)%s" % (msg or "the request failed", status,
                                          "\n\n" + json.dumps(redact(data), indent=1)
                                          if isinstance(data, dict) and len(data) > 1 else ""))
    return data


def _get(path, query=None):
    return redact(_ok(*_api("GET", path, query=query)))


def _send(method, path, body=None):
    return redact(_ok(*_api(method, path, body=body)))


def _collection(args):
    col = str(args.get("collection") or "")
    sec, _, name = col.partition("/")
    if name not in VALID_COLLECTIONS.get(sec, ()):
        raise Refused("unknown collection %r; one of %s" % (col, ", ".join(COLLECTIONS)))
    return "/api/" + col


def _item_path(args):
    iid = str(args.get("id") or "").strip()
    if not iid:
        raise Refused("id is required")
    return _collection(args) + "/" + quote(iid, safe="")


# --------------------------------------------------------------------------
# the tools

COLLECTIONS = sorted("%s/%s" % (s, c) for s, cols in VALID_COLLECTIONS.items() for c in cols)
SETTINGS_READ = {"haproxy": "/api/haproxy/settings", "acme": "/api/acme/settings",
                 "cluster": "/api/cluster/settings", "crowdsec": "/api/crowdsec/settings",
                 "notify": "/api/notify", "watchdog": "/api/watchdog"}
SETTINGS_WRITE = {"haproxy": "/api/haproxy/settings", "acme": "/api/acme/settings"}
LOG_SOURCES = ("app", "haproxy", "keepalived", "acme", "crowdsec")


def _service_body(s):
    """The publish wizard's request that re-creates this service unchanged --
    the form the UI fills in when Edit is clicked -- so an edit through MCP
    changes what it names and nothing else."""
    h, a, o = s.get("health") or {}, s.get("auth") or {}, s.get("oauth") or {}
    body = {"service_id": s["id"], "url": "\n".join(s.get("urls") or [s.get("url") or ""]),
            "target": ", ".join(re.sub(r"^tcp://", "", t) if s.get("scheme") == "tcp" else t
                                for t in s.get("targets") or []),
            "name": s.get("pool") or "",
            "certificate": True, "http_redirect": True,
            "health": {k: h.get(k) for k in ("type", "interval", "uri", "status", "user",
                                              "method", "version", "host")},
            "auth": {"enabled": a.get("enabled"), "groups": a.get("groups") or [],
                     "realm": a.get("realm") or "", "exempt": a.get("exempt") or "",
                     "exempt_lists": a.get("exempt_lists") or []},
            "oauth": {"enabled": o.get("enabled"), "allow": "\n".join(o.get("allow") or []),
                      "forward": o.get("forward")}}
    for k in ("balance", "persistence", "stick_type", "stick_size", "stick_expire",
              "log_health_checks", "check_port", "proxy_protocol", "notify_mode",
              "timeout_connect", "timeout_server", "allow_src", "allow_lists", "error_pages",
              "rules", "hsts", "hsts_subdomains", "rate_limit", "rate_window", "certificate_id"):
        if k in s:
            body[k] = s[k]
    if s.get("redirect"):
        body["redirect"] = s["redirect"]
        body["target"] = ""
    return body


def _find_service(sid):
    services = _ok(*_api("GET", "/api/services"))
    sid = str(sid or "").strip()
    for s in services:
        if sid in (s.get("id"), s.get("pool"), s.get("url")) or sid in (s.get("urls") or []):
            return s
    raise Refused("no service %r: list_services shows their ids" % sid)


def t_publish(args):
    body = {k: v for k, v in args.items() if v is not None}
    if body.get("service_id"):
        base = _service_body(_find_service(body["service_id"]))
        if "redirect" in body and body["redirect"] is None:
            base.pop("redirect", None)
        if body.get("redirect"):
            base["target"] = ""
        for k in ("health", "auth", "oauth"):         # a partial object amends the current one
            if isinstance(body.get(k), dict):
                body[k] = dict(base.get(k) or {}, **body[k])
        body = dict(base, **body)
        body["service_id"] = base["service_id"]
    return _send("POST", "/api/wizard/publish", body)


def t_get_service(args):
    return redact(_find_service(args.get("id")))


def _preview_object(args, item):
    """A dry run of an object change: the haproxy.cfg blocks it writes, and
    haproxy -c on the whole file with it in. Stores nothing."""
    sec, _, col = _collection(args)[len("/api/"):].partition("/")
    if sec != "haproxy":
        raise Refused("dry_run shows what a haproxy/ object renders to; %s objects render "
                      "nothing to haproxy.cfg" % args.get("collection"))
    out = _ok(*_api("POST", "/api/haproxy/preview-object", {"col": col, "item": item, "check": True}))
    return redact({"lines": out.get("text", ""), "note": out.get("note", ""),
                   "validation": out.get("validation")})


def t_update_object(args):
    path = _item_path(args)
    item = args.get("item")
    if not isinstance(item, dict):
        raise Refused("item must be an object: the whole object, as list_objects shows it")
    stored = next((i for i in _ok(*_api("GET", _collection(args)))
                   if i.get("id") == args.get("id")), None)
    if stored is None:
        raise Refused("no %s with id %r" % (args.get("collection"), args.get("id")))
    item = unredact(item, stored)
    for k in ("managed_by", "node_local", "id"):       # annotations, not fields
        item.pop(k, None)
    if args.get("dry_run"):
        return _preview_object(args, dict(item, id=stored["id"]))
    return _send("PUT", path, item)


def t_create_object(args):
    item = args.get("item")
    if not isinstance(item, dict):
        raise Refused("item must be an object")
    if args.get("dry_run"):
        return _preview_object(args, item)
    return _send("POST", _collection(args), item)


def t_find_certificate(args):
    host = str(args.get("host") or "").strip()
    host = urlsplit(host).hostname or host if "://" in host else host
    return _get("/api/acme/cover", {"host": host})


def t_logs(args):
    q = {"lines": int(args.get("lines") or 200), "q": args.get("search") or "",
         "level": args.get("level") or "INFO"}
    if args.get("sources"):
        q["sources"] = ",".join(args["sources"])
    return _get("/api/logs", q)


def t_settings(args):
    sec = args.get("section")
    if sec not in SETTINGS_READ:
        raise Refused("section must be one of %s" % ", ".join(SETTINGS_READ))
    data = _get(SETTINGS_READ[sec])
    if sec == "watchdog" and isinstance(data, dict):
        data = data.get("settings", data)
    return data


def t_update_settings(args):
    sec = args.get("section")
    if sec not in SETTINGS_WRITE:
        raise Refused("section must be one of %s" % ", ".join(SETTINGS_WRITE))
    if not isinstance(args.get("values"), dict):
        raise Refused("values must be an object of the settings to change")
    return _send("PUT", SETTINGS_WRITE[sec], args["values"])


def t_haproxy_cfg(args):
    data = _ok(*_api("GET", "/api/preview"))
    return data.get("haproxy", "") if isinstance(data, dict) else data


def _id(args, what="id"):
    v = str(args.get(what) or "").strip()
    if not v:
        raise Refused("%s is required" % what)
    return quote(v, safe="")


def _schema(props=None, required=(), extra=False):
    s = {"type": "object", "properties": props or {}, "additionalProperties": extra}
    if required:
        s["required"] = list(required)
    return s


S, B, I = {"type": "string"}, {"type": "boolean"}, {"type": "integer"}
DRY = {"type": "boolean", "description": "Only show what would change and whether HAProxy "
                                         "accepts it; store nothing"}
COLL = {"type": "string", "enum": COLLECTIONS}
CONDITION = {"type": "object", "description": "An existing condition {id}, or a new one: "
             "{type, value, param?, list?, negate?}. type is host_matches, host_starts_with, "
             "host_ends_with, path_matches, path_starts_with, path_ends_with, path_contains, "
             "http_header (param: the header), url_parameter (param: the parameter), source_ip, "
             "source_list (list: an address list id), ssl_sni or custom (value: a raw ACL)."}


def tool(name, title, description, schema, fn, write=False, destructive=False):
    return {"name": name, "title": title, "description": description, "inputSchema": schema,
            "fn": fn, "write": write,
            "annotations": {"title": title, "readOnlyHint": not write,
                            "destructiveHint": destructive, "openWorldHint": False}}


TOOLS = [
    # ---- reading
    tool("get_status", "Node status",
         "This node: HAProxy and Keepalived state, cluster role and virtual IPs, whether there "
         "are unapplied changes (dirty), certificates with their expiry, CrowdSec, updates.",
         _schema(), lambda a: _get("/api/status", {"brief": "1"})),
    tool("list_services", "List services",
         "Every published service: public URLs, targets, health, certificate, sign-in, "
         "allow-lists, rules, HSTS, redirects, paused state.",
         _schema(), lambda a: _get("/api/services")),
    tool("get_service", "Get a service",
         "One service, by its id, pool name or public URL.",
         _schema({"id": S}, ["id"]), t_get_service),
    tool("list_objects", "List objects",
         "The advanced objects of one collection, as stored: haproxy/frontends (Public Services), "
         "haproxy/backends (Backend Pools), haproxy/servers, haproxy/rules, haproxy/conditions, "
         "haproxy/healthchecks, haproxy/addresslists, haproxy/errorpages, acme/certificates, "
         "acme/accounts, acme/challenges. managed_by names the service an object belongs to.",
         _schema({"collection": COLL}, ["collection"]),
         lambda a: _get(_collection(a))),
    tool("get_settings", "Get settings",
         "Settings of one section: haproxy (timeouts, maxconn, IPv6, unknown hosts...), acme, "
         "cluster (VRRP), crowdsec, notify, watchdog.",
         _schema({"section": {"type": "string", "enum": list(SETTINGS_READ)}}, ["section"]),
         t_settings),
    tool("get_haproxy_config", "Rendered haproxy.cfg",
         "The haproxy.cfg the stored configuration renders to: what apply_changes would write.",
         _schema(), t_haproxy_cfg),
    tool("check_config", "Check the configuration",
         "Run haproxy -c on what the stored configuration renders to, storing nothing.",
         _schema(), lambda a: _ok(*_api("POST", "/api/validate", {"section": "haproxy"}))),
    tool("get_stats", "Live statistics",
         "HAProxy's live counters per frontend, backend and server: state, sessions, rates, "
         "errors, check results.",
         _schema(), lambda a: _get("/api/stats")),
    tool("get_traffic", "Traffic history",
         "Requests, bytes and errors over time, for every pool or one.",
         _schema({"pool": {"type": "string", "description": "A Backend Pool name; all when left out"},
                  "minutes": {"type": "integer", "description": "How far back; default 60"}}),
         lambda a: _get("/api/traffic", {k: v for k, v in (("pool", a.get("pool")),
                                                            ("minutes", a.get("minutes") or 60)) if v})),
    tool("get_probes", "URL probes",
         "The latest check of every published URL from the outside: DNS, connection, "
         "certificate and status.",
         _schema(), lambda a: _get("/api/probes")),
    tool("get_logs", "Read logs",
         "Recent log lines, newest last.",
         _schema({"sources": {"type": "array", "items": {"type": "string", "enum": list(LOG_SOURCES)}},
                  "lines": {"type": "integer", "description": "1-2000, default 200"},
                  "search": {"type": "string", "description": "Only lines containing this"},
                  "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR"]}}),
         t_logs),
    tool("get_cluster", "Cluster health",
         "Every node in the cluster, as this one last saw it: reachable, version, role, "
         "whether it holds the same configuration.",
         _schema(), lambda a: _get("/api/cluster")),
    tool("list_history", "Configuration history",
         "Snapshots of the configuration taken before each change, newest first.",
         _schema(), lambda a: _get("/api/history")),
    tool("get_history_diff", "Compare with a snapshot",
         "What differs between a history snapshot and the configuration now.",
         _schema({"name": S}, ["name"]),
         lambda a: _get("/api/history/%s/diff" % _id(a, "name"))),
    tool("get_vip_status", "Why this node does or does not hold the virtual IP",
         "Keepalived on this node: its VRRP state and where that was read from, the virtual "
         "IPs and which it holds, the interface, keepalived -t on what Apply would write, and "
         "the journal's last lines. Ask each node for its own.",
         _schema(), lambda a: _get("/api/keepalived/status")),
    tool("check_certificate_setup", "Can this node get certificates",
         "Whether acme.sh is installed, runs and can store keys and certificates here, with "
         "the problem and the fix when it cannot. Worth asking before request_certificate.",
         _schema(), lambda a: _get("/api/acme/health")),
    tool("find_certificate", "Which certificate covers a host",
         "The configured certificate, if any, that already covers a host name -- exactly or by "
         "a wildcard -- with its status and days left. publish_service reuses it; when none "
         "covers the name, a new one is requested.",
         _schema({"host": {"type": "string", "description": "A host name or URL: app.example.com"}},
                 ["host"]), t_find_certificate),
    tool("list_recipes", "Service recipes",
         "Ready-made settings for common applications (health check, timeouts, headers, "
         "WebSockets...). Each recipe's fields can be passed to publish_service along with "
         "the url and target.",
         _schema(), lambda a: _get("/api/recipes")),
    tool("run_probes", "Probe the published URLs now",
         "Check every published URL the way a browser would -- DNS, connection, certificate, "
         "status -- now instead of at the next minute, and return the results, as get_probes "
         "does. Useful right after apply_changes. Runs on the node holding the virtual IP (or "
         "a standalone one); a passive node says so. Changes no configuration.",
         _schema(), lambda a: _send("POST", "/api/probes/run", {})),
    tool("get_certificate_log", "Certificate issue log",
         "acme.sh's output from the last time a certificate was issued or renewed.",
         _schema({"id": S}, ["id"]),
         lambda a: _get("/api/acme/log/%s" % _id(a))),

    # ---- changing
    tool("publish_service", "Publish or edit a service",
         "Publish a service -- a public URL forwarded to servers, or redirected -- creating its "
         "listener, pool, servers, health check and certificate together. With service_id it "
         "edits that service: fields left out keep their current values. Does not apply.",
         _schema({
             "url": {"type": "string", "description": "Public URL(s), one per line: "
                     "https://app.example.com, https://*.example.com, http://host:8080/path, "
                     "tcp://0.0.0.0:5432"},
             "target": {"type": "string", "description": "Server address(es), comma-separated: "
                        "10.0.0.5:80, https://10.0.0.6:8443"},
             "service_id": {"type": "string", "description": "Edit this service instead"},
             "name": {"type": "string", "description": "The Backend Pool name"},
             "redirect": {"type": ["object", "null"], "description": "Redirect instead of "
                          "forwarding: {to, code (301/302/307/308), keep_path}; null to forward again"},
             "certificate": {"type": "boolean", "description": "Attach a certificate (HTTPS)"},
             "new_certificate": B, "certificate_id": S, "account": S, "challenge": S,
             "http_redirect": {"type": "boolean", "description": "Also listen on 80 and send to HTTPS"},
             "hsts": B, "hsts_subdomains": B,
             "health": {"type": "object", "description": "{type: none|tcp|http|..., interval, uri, "
                        "status, method, host}"},
             "balance": {"type": "string", "enum": ["roundrobin", "leastconn", "source", "first"]},
             "persistence": {"type": "string", "enum": ["none", "source", "cookie"]},
             "timeout_connect": S, "timeout_server": S,
             "auth": {"type": "object", "description": "Ask visitors to sign in: {enabled, "
                      "groups: [group ids], realm, exempt, exempt_lists}"},
             "oauth": {"type": "object", "description": "Single sign-on: {enabled, allow, forward}"},
             "allow_src": {"type": "string", "description": "Only these networks, space-separated"},
             "allow_lists": {"type": "array", "items": S, "description": "Address list ids"},
             "error_pages": {"type": "array", "items": S, "description": "Error page ids"},
             "rules": {"type": "array", "items": S, "description": "Rule ids to apply to this pool"},
             "rate_limit": {"type": ["integer", "string"]}, "rate_window": I,
             "proxy_protocol": {"type": "string", "enum": ["", "v1", "v2"]},
             "notify_mode": {"type": "string", "enum": ["servers", "service", "off"]},
             "dry_run": DRY,
         }, extra=True), t_publish, write=True),
    tool("pause_service", "Pause or resume a service",
         "Put a service into maintenance (visitors get the maintenance answer) or take it out.",
         _schema({"id": S, "paused": B}, ["id", "paused"]),
         lambda a: _send("POST", "/api/services/%s/maintenance" % quote(_find_service(a.get("id"))["id"], safe=""),
                         {"on": bool(a.get("paused"))}),
         write=True),
    tool("delete_service", "Delete a service",
         "Remove a service and the objects only it used. Does not apply.",
         _schema({"id": S}, ["id"]),
         lambda a: _send("DELETE", "/api/services/%s" % quote(_find_service(a.get("id"))["id"], safe="")),
         write=True, destructive=True),
    tool("save_rule", "Create or edit a rule",
         "A rule: an action taken when its conditions hold, on the Public Services listed. "
         "Conditions in any_of are alternatives; all_of must all hold. With id it edits that rule.",
         _schema({
             "id": S, "name": S,
             "action": {"type": "object", "description": "{type, test: if|unless, backend, param1, "
                        "param2}. type: use_backend (backend: a pool id), redirect_scheme_https, "
                        "redirect_location (param1: where), http_request_deny, "
                        "http_request_set_header / http_response_set_header (param1 name, param2 "
                        "value), http_request_del_header (param1), tcp_request_content_accept, "
                        "tcp_request_content_reject, custom (param1: the line)"},
             "any_of": {"type": "array", "items": CONDITION},
             "all_of": {"type": "array", "items": CONDITION},
             "listeners": {"type": "array", "items": S, "description": "Public Service ids"},
             "dry_run": DRY,
         }, ["action"]),
         lambda a: _send("POST", "/api/wizard/rule", a), write=True),
    tool("save_condition", "Create or edit a condition",
         "A named condition rules can test. With id it edits that one. sample, a request "
         "{host, path, src, header, param}, is checked against it and the answer returned in "
         "matches.",
         _schema({"id": S, "name": S, "type": S, "value": S, "param": S, "list": S, "negate": B,
                  "sample": {"type": "object"}, "dry_run": DRY}, ["type"]),
         lambda a: _send("POST", "/api/wizard/condition", a),
         write=True),
    tool("request_certificate", "Request a certificate",
         "Create a certificate for these names and issue it through ACME.",
         _schema({"domains": {"type": "string", "description": "Names, comma- or space-separated; "
                              "*.example.com needs a DNS challenge"},
                  "account": S, "challenge": S, "dry_run": DRY}, ["domains"], extra=True),
         lambda a: _send("POST", "/api/wizard/certificate", a),
         write=True),
    tool("issue_certificate", "Issue or renew a certificate",
         "Run ACME for an existing certificate now; force renews one that is not due.",
         _schema({"id": S, "force": B}, ["id"]),
         lambda a: _send("POST", "/api/acme/issue/%s" % _id(a), {"force": bool(a.get("force"))}),
         write=True),
    tool("renew_certificates", "Renew the certificates that are due",
         "What the daily renewal does, now: every auto-renewing certificate that is due is "
         "renewed through ACME. Uploaded certificates are never renewed. Runs on the node "
         "holding the virtual IP.",
         _schema(), lambda a: _send("POST", "/api/acme/renew", {}), write=True),
    tool("create_object", "Create an object",
         "Add an object to a collection, with the fields list_objects shows. Prefer "
         "publish_service, save_rule and save_condition, which build the related objects too. "
         "dry_run (haproxy/ collections) returns the lines it renders to and HAProxy's verdict.",
         _schema({"collection": COLL, "item": {"type": "object"}, "dry_run": DRY},
                 ["collection", "item"]),
         t_create_object, write=True),
    tool("update_object", "Replace an object",
         "Replace an object with item, the whole object as list_objects shows it, changed. "
         "[redacted] values keep what is stored. dry_run (haproxy/ collections) returns the "
         "lines it renders to and HAProxy's verdict.",
         _schema({"collection": COLL, "id": S, "item": {"type": "object"}, "dry_run": DRY},
                 ["collection", "id", "item"]),
         t_update_object, write=True, destructive=True),
    tool("delete_object", "Delete an object",
         "Remove one object from a collection.",
         _schema({"collection": COLL, "id": S}, ["collection", "id"]),
         lambda a: _send("DELETE", _item_path(a)), write=True, destructive=True),
    tool("update_settings", "Change settings",
         "Change haproxy or acme settings; only the keys given change. Refused, and nothing "
         "stored, when HAProxy would not accept the result.",
         _schema({"section": {"type": "string", "enum": list(SETTINGS_WRITE)},
                  "values": {"type": "object"}}, ["section", "values"]),
         t_update_settings, write=True),
    tool("restore_history", "Restore a snapshot",
         "Put the configuration back to a history snapshot. Does not apply.",
         _schema({"name": S}, ["name"]),
         lambda a: _send("POST", "/api/history/%s/restore" % _id(a, "name"), {}),
         write=True, destructive=True),
    tool("apply_changes", "Apply",
         "Write haproxy.cfg from the stored configuration, validate it and reload HAProxy, then "
         "push to the other nodes. This is the step that makes changes live.",
         _schema(), lambda a: _send("POST", "/api/apply", {}), write=True, destructive=True),
]
BY_NAME = {t["name"]: t for t in TOOLS}


def _listing(t):
    return {k: t[k] for k in ("name", "title", "description", "inputSchema", "annotations")}


# --------------------------------------------------------------------------
# JSON-RPC

def _dry(t, args):
    """A dry run, from a tool that has one. A dry_run passed to any other tool
    is not one -- it would make the change -- so it opens nothing."""
    return bool(args.get("dry_run")) and "dry_run" in t["inputSchema"]["properties"]


def _call_tool(params):
    name = (params or {}).get("name")
    args = (params or {}).get("arguments") or {}
    t = BY_NAME.get(name)
    if t is None:
        raise UnknownTool(name)
    if not isinstance(args, dict):
        return _text("arguments must be an object", error=True)
    if t["write"] and not _dry(t, args) and not settings(load_config()).get("allow_writes"):
        return _text("Changes through MCP are turned off on this node: Settings > MCP server > "
                     "Allow changes. Reading works, and so does dry_run where a tool has it.",
                     error=True)
    if t["write"]:
        try:
            forwarded = _forward(name, args)
        except Refused as e:
            return _text(str(e), error=True)
        if forwarded is not None:
            return forwarded
    return _run(t, args)


def _run(t, args):
    shown = {k: v for k, v in args.items() if not SECRET_KEY_RE.search(k)}
    log.info("mcp %s: %s %s", request.mcp_client, t["name"], json.dumps(shown, sort_keys=True)[:200])
    try:
        out = t["fn"](args)
    except Refused as e:
        return _text(str(e), error=True)
    return _text(out if isinstance(out, str) else json.dumps(out, indent=1, ensure_ascii=False))


# --------------------------------------------------------------------------
# the cluster: changes go where the virtual IP is

def _active_peer(cfg):
    """The other node that says it holds the virtual IP, or None."""
    peers = sync.enabled_peers(cfg)
    if not peers or _requests is None:
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(peers))) as ex:
        found = list(ex.map(lambda p: (p, peering._query_peer(p, brief=True)), peers))
    return next((p for p, n in found if n.get("reachable") and n.get("vip_held")), None)


def _forward(name, args):
    """On a passive node, the tool result from the active one; None when this
    node is the one to make the change."""
    cfg = load_config()
    read_only, why = auth.readonly_state(cfg)
    if not read_only:
        return None
    peer = _active_peer(cfg)
    if peer is None:
        raise Refused("This node is passive, and no other node answered as the one holding the "
                      "virtual IP, so there is nowhere to make the change. " + why)
    url, who = (peer.get("url") or "").rstrip("/"), peer.get("name") or peer.get("url")
    try:
        r = _requests.post(url + "/api/mcp/forward",
                           json={"tool": name, "arguments": args, "client": request.mcp_client},
                           headers={"X-API-Key": peer.get("api_key", "")},
                           timeout=(PEER_CONNECT_TIMEOUT, PUSH_READ_TIMEOUT),
                           verify=bool(peer.get("verify_tls")))
        d = r.json()
    except Exception as e:
        raise Refused("This node is passive, and passing the change to %s, which holds the virtual "
                      "IP, failed: %s" % (who, peering.peer_error(e, url, PUSH_READ_TIMEOUT)))
    if r.status_code != 200 or not isinstance(d, dict) or "content" not in d:
        raise Refused("This node is passive, and %s, which holds the virtual IP, refused the change: "
                      "%s" % (who, (d or {}).get("error") or "HTTP %d" % r.status_code))
    log.info("mcp %s: %s forwarded to %s", request.mcp_client, name, who)
    note = {"type": "text", "text": "(made on %s, which holds the virtual IP; this node is passive)" % who}
    d["content"] = [note] + list(d.get("content") or [])
    return d


@app.post("/api/mcp/forward")
def api_mcp_forward():
    """Run a change a passive node's MCP server was asked for. Another node
    only: the API key is required, a session is not enough. Never forwarded
    again from here -- a node that cannot make the change says why."""
    cfg = load_config()
    if not auth.key_matches(cfg["local"].get("api_key"), request.headers.get("X-API-Key")):
        return jsonify({"ok": False, "error": "only another node, presenting this node's API key, "
                                              "can pass on an MCP call"}), 401
    if not settings(cfg).get("enabled"):
        return jsonify({"ok": False, "error": "the MCP server is off on this node too"}), 403
    body = request.get_json(force=True, silent=True) or {}
    t, args = BY_NAME.get(body.get("tool")), body.get("arguments")
    if t is None or not t["write"] or not isinstance(args, dict):
        return jsonify({"ok": False, "error": "not a change an MCP client can ask for"}), 400
    if not _dry(t, args) and not settings(cfg).get("allow_writes"):
        return jsonify(_text("Changes through MCP are turned off on the node holding the virtual "
                             "IP: Settings > MCP server > Allow changes.", error=True))
    client = re.sub(r"[^\w .@/:+-]", "", str(body.get("client") or "mcp:client"))[:60]
    request.mcp_client = "%s via %s" % (client, request.remote_addr)
    return jsonify(_run(t, args))


def push_settings(cfg):
    """Copy the MCP settings and token to every other node. [{ok, name, error}]"""
    rec = {k: settings(cfg).get(k) for k in SHARED_KEYS}
    out = []
    for peer in sync.enabled_peers(cfg):
        url, who = (peer.get("url") or "").rstrip("/"), peer.get("name") or peer.get("url")
        if _requests is None:
            out.append({"ok": False, "name": who, "error": "python3-requests is not installed"})
            continue
        try:
            r = _requests.post(url + "/api/mcp/receive", json={"mcp": rec},
                               headers={"X-API-Key": peer.get("api_key", "")},
                               timeout=(PEER_CONNECT_TIMEOUT, PEER_READ_TIMEOUT),
                               verify=bool(peer.get("verify_tls")))
            if r.status_code == 200:
                out.append({"ok": True, "name": who})
            else:
                try:
                    err = r.json().get("error")
                except Exception:
                    err = ""
                out.append({"ok": False, "name": who, "error": err or "HTTP %d" % r.status_code})
        except Exception as e:
            out.append({"ok": False, "name": who, "error": peering.peer_error(e, url, PEER_READ_TIMEOUT)})
    return out


@app.post("/api/mcp/receive")
def api_mcp_receive():
    """Take the MCP settings and token from another node."""
    cfg = load_config()
    if not auth.key_matches(cfg["local"].get("api_key"), request.headers.get("X-API-Key")):
        return jsonify({"ok": False, "error": "the MCP settings can only be set by a node "
                                              "presenting this node's API key"}), 401
    rec = (request.get_json(force=True, silent=True) or {}).get("mcp") or {}
    if not isinstance(rec, dict):
        return jsonify({"ok": False, "error": "that is not an MCP settings record"}), 400
    with _lock:
        cfg = load_config()
        s = cfg["local"].setdefault("mcp", {})
        if "token_hash" in rec and "token" not in rec:
            s.pop("token", None)             # a node that sends only the hash: the old token is gone
        for k in SHARED_KEYS:
            if k in rec:
                s[k] = bool(rec[k]) if k in ("enabled", "allow_writes") else str(rec[k] or "")
        save_config(cfg)
    log.info("mcp settings received from %s (token %s)", request.remote_addr, s.get("token_fp") or "none")
    return jsonify({"ok": True})


def _text(text, error=False):
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT] + "\n... cut at %d characters; ask for less" % MAX_TEXT
    return {"content": [{"type": "text", "text": text}], "isError": bool(error)}


def _handle(msg):
    """One JSON-RPC message; None for a notification."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
    if "id" not in msg:
        return None                          # notifications/initialized and friends
    mid, method, params = msg["id"], msg["method"], msg.get("params") or {}

    def result(r):
        return {"jsonrpc": "2.0", "id": mid, "result": r}

    if method == "initialize":
        asked = params.get("protocolVersion")
        return result({
            "protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "haproxy-manager", "title": "HAProxy Manager", "version": VERSION},
            "instructions": INSTRUCTIONS})
    if method == "ping":
        return result({})
    if method == "tools/list":
        return result({"tools": [_listing(t) for t in TOOLS]})
    if method == "tools/call":
        try:
            return result(_call_tool(params))
        except UnknownTool:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32602, "message": "unknown tool %r" % params.get("name")}}
        except Exception as e:               # a tool's crash is the tool's error, not the server's
            log.exception("mcp tool %s failed", params.get("name"))
            return result(_text("the tool failed: %s" % e, error=True))
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no method %r" % method}}


def _refuse(status, message, **headers):
    resp = jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": message}})
    resp.status_code = status
    for k, v in headers.items():
        resp.headers[k.replace("_", "-")] = v
    return resp


@app.route("/mcp", methods=["GET", "POST", "DELETE"])
def mcp_endpoint():
    cfg = load_config()
    if not settings(cfg).get("enabled"):
        return _refuse(403, "The MCP server is off on this node. Turn it on under Settings > MCP server.")
    # A browser page cannot be allowed to talk to this through a rebound DNS name.
    origin = request.headers.get("Origin")
    if origin and urlsplit(origin).netloc.lower() != (request.host or "").lower():
        return _refuse(403, "requests from another site are not accepted")
    presented = request.headers.get("Authorization", "")
    presented = presented[7:] if presented[:7].lower() == "bearer " else ""
    if not token_matches(cfg, presented):
        log.warning("mcp: refused a request without a valid token (%s)", request.remote_addr)
        return _refuse(401, "a valid MCP token is required: Authorization: Bearer <token>",
                       WWW_Authenticate='Bearer realm="haproxy-manager"')
    if request.method != "POST":
        # No server-to-client stream and no session to end: POST is the transport.
        return Response(status=405, headers={"Allow": "POST"})
    limit = app.config.get("MAX_CONTENT_LENGTH") or 0
    if limit and (request.content_length or 0) > limit:
        return _refuse(413, "the request body is too large")
    try:
        msg = json.loads(request.get_data(as_text=True) or "null")
    except ValueError:
        return jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}), 400

    sid = request.headers.get("Mcp-Session-Id") or ""
    if isinstance(msg, dict) and msg.get("method") == "initialize":
        info = (msg.get("params") or {}).get("clientInfo") or {}
        sid = uuid.uuid4().hex
        if len(_sessions) > 500:
            _sessions.clear()
        _sessions[sid] = re.sub(r"[^\w .@/+-]", "", str(info.get("name") or "client"))[:40] or "client"
        log.info("mcp: %s connected from %s", _sessions[sid], request.remote_addr)
    request.mcp_client = "mcp:" + _sessions.get(sid, "client")

    out = [r for r in map(_handle, msg) if r] if isinstance(msg, list) else _handle(msg)
    if not out:
        return Response(status=202)
    resp = Response(json.dumps(out), mimetype="application/json")
    if sid:
        resp.headers["Mcp-Session-Id"] = sid
    return resp


# --------------------------------------------------------------------------
# its settings, under Settings > MCP server

@app.get("/api/mcp")
def api_mcp():
    cfg = load_config()
    s = settings(cfg)
    return jsonify({"enabled": bool(s.get("enabled")), "allow_writes": bool(s.get("allow_writes")),
                    "has_token": bool(s.get("token_hash")), "token_fp": s.get("token_fp") or "",
                    "token_shown": bool(shown_token(cfg)),
                    "token_created": s.get("token_created") or "",
                    "tools": [{"name": t["name"], "title": t["title"], "write": t["write"]}
                              for t in TOOLS]})


@app.put("/api/mcp")
def api_mcp_settings():
    body = request.get_json(force=True, silent=True) or {}
    with _lock:
        cfg = load_config()
        s = cfg["local"].setdefault("mcp", {})
        for k in ("enabled", "allow_writes"):
            if k in body:
                s[k] = bool(body[k])
        save_config(cfg)
    log.info("mcp settings changed: enabled=%s allow_writes=%s", s.get("enabled"), s.get("allow_writes"))
    return jsonify({"ok": True, "pushed": push_settings(cfg)})


@app.get("/api/mcp/token")
def api_mcp_token_show():
    """The token again, to set up another client. The administrator's session
    can see it, as it can the API key; the MCP tools have no route to it."""
    cfg = load_config()
    token = shown_token(cfg)
    if not token:
        return jsonify({"ok": False, "error": "This token was made before tokens were kept, so it "
                                              "cannot be shown. Replace it to get one that can."}), 404
    log.info("mcp: the token was shown (%s)", settings(cfg).get("token_fp"))
    return jsonify({"ok": True, "token": token, "token_fp": settings(cfg).get("token_fp") or ""})


@app.post("/api/mcp/token")
def api_mcp_token():
    """A new token. The old one stops working the moment this returns."""
    token = "ham_mcp_" + secrets.token_urlsafe(32)
    with _lock:
        cfg = load_config()
        s = cfg["local"].setdefault("mcp", {})
        s["token"] = token
        s["token_hash"] = _token_hash(token)
        s["token_fp"] = s["token_hash"][:8]
        s["token_created"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        save_config(cfg)
    log.warning("mcp: a new token was created (%s); the previous one no longer works", s["token_fp"])
    return jsonify({"ok": True, "token": token, "token_fp": s["token_fp"], "pushed": push_settings(cfg)})
