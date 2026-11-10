#!/usr/bin/env python3
"""The MCP server at /mcp: off until turned on, its own token, read-only until
changes are allowed, secrets kept back, and a change asked of a passive node
made on the active one.

    python3 tools/test-mcp.py
"""
import json
import logging
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
# a data directory of its own, whatever the environment says: this test
# turns the MCP server on and writes services
os.environ["HAM_DATA_DIR"] = tempfile.mkdtemp(prefix="ham-mcp-")
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham import auth, mcp   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "mcp-test-key"
cfg["acme"]["challenges"] = [{"id": "ch1", "name": "cloudflare", "type": "dns-01",
                              "dns_provider": "dns_cf", "dns_credentials": "CF_Token=sekrit"}]
save_config(cfg)
K = {"X-API-Key": "mcp-test-key"}
lines = []
logging.getLogger("haproxy-manager").addHandler(
    type("H", (logging.Handler,), {"emit": lambda self, r: lines.append(r.getMessage())})())


SESSION = {}             # what a client sends back once initialized


def rpc(method, params=None, token=None, mid=1, headers=None):
    h = dict(SESSION, **(headers or {}))
    if token:
        h["Authorization"] = "Bearer " + token
    msg = {"jsonrpc": "2.0", "method": method}
    if mid is not None:
        msg["id"] = mid
    if params is not None:
        msg["params"] = params
    return client.post("/mcp", data=json.dumps(msg), content_type="application/json", headers=h)


def call(name, args=None, token=None):
    r = rpc("tools/call", {"name": name, "arguments": args or {}}, token=token)
    res = r.get_json()["result"]
    return res, "\n".join(c["text"] for c in res["content"])


# -- off, and its own token ----------------------------------------------------------
ok(rpc("initialize").status_code == 403, "off by default: /mcp refuses everything")
st = client.get("/api/mcp", headers=K).get_json()
ok(st["enabled"] is False and st["allow_writes"] is False and not st["has_token"],
   "and says so: off, read-only, no token")
client.put("/api/mcp", json={"enabled": True}, headers=K)
ok(rpc("initialize").status_code == 401, "on, but without a token nothing gets in")
ok(rpc("initialize", token="mcp-test-key").status_code == 401, "and the API key is not the token")
tok = client.post("/api/mcp/token", headers=K).get_json()["token"]
ok(tok.startswith("ham_mcp_") and tok != load_config()["local"]["mcp"]["token_hash"],
   "a token is made, and requests are checked against its hash")
r = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "claude-code", "version": "2"}}, token=tok)
init = r.get_json()["result"]
ok(r.status_code == 200 and init["protocolVersion"] == "2025-06-18"
   and init["capabilities"] == {"tools": {"listChanged": False}}
   and init["serverInfo"]["name"] == "haproxy-manager", "initialize: the version asked for, tools only")
ok("Ask the user before apply_changes" in init["instructions"],
   "and instructions that say to ask before Apply, a restore or a delete")
sid = r.headers.get("Mcp-Session-Id")
ok(bool(sid), "with a session id, so the log can name the client")
SESSION["Mcp-Session-Id"] = sid
ok(rpc("notifications/initialized", token=tok, mid=None).status_code == 202,
   "a notification is accepted with no body")
ok(client.get("/mcp", headers={"Authorization": "Bearer " + tok}).status_code == 405,
   "GET is not offered: there is no server stream")
ok(rpc("ping", token=tok, headers={"Origin": "http://evil.example"}).status_code == 403,
   "a request from another site's page is refused")
old = tok
tok = client.post("/api/mcp/token", headers=K).get_json()["token"]
ok(rpc("ping", token=old).status_code == 401 and rpc("ping", token=tok).status_code == 200,
   "a new token ends the old one")
shown = client.get("/api/mcp/token", headers=K).get_json()
ok(shown.get("token") == tok and client.get("/api/mcp", headers=K).get_json()["token_shown"],
   "the token can be shown again, to set up the next client")

# -- the tools ----------------------------------------------------------------------
tools = rpc("tools/list", token=tok).get_json()["result"]["tools"]
names = {t["name"]: t for t in tools}
ok({"get_status", "list_services", "list_objects", "get_logs", "get_haproxy_config",
    "publish_service", "save_rule", "save_condition", "apply_changes", "delete_service",
    "update_object", "restore_history"} <= set(names), "reading and changing tools are listed")
ok(names["get_status"]["annotations"]["readOnlyHint"] is True
   and names["apply_changes"]["annotations"]["destructiveHint"] is True
   and names["delete_service"]["annotations"]["destructiveHint"] is True,
   "marked read-only or destructive, so a client knows what to ask about")
ok(not any("download" in n or "upload" in n for n in names),
   "no tool hands over or takes in a private key")
ok(rpc("tools/call", {"name": "no_such"}, token=tok).get_json()["error"]["code"] == -32602,
   "an unknown tool is a protocol error")

res, text = call("get_status", token=tok)
ok(not res["isError"] and '"dirty"' in text, "get_status reads the node")
res, text = call("list_objects", {"collection": "acme/challenges"}, token=tok)
ok("sekrit" not in text and mcp.REDACTED in text and "dns_cf" in text,
   "secrets are kept back: DNS credentials come out as [redacted]")
res, text = call("list_objects", {"collection": "local/admin"}, token=tok)
ok(res["isError"], "only the configuration's collections, nothing else")

# -- read-only until allowed ----------------------------------------------------------
res, text = call("publish_service", {"url": "http://app.example.com", "target": "10.0.0.5:80"},
                 token=tok)
ok(res["isError"] and "Allow changes" in text, "changes are refused until they are allowed")
ok(not load_config()["haproxy"]["frontends"], "and nothing was stored")
res, text = call("publish_service", {"url": "http://app.example.com", "target": "10.0.0.5:80",
                                     "dry_run": True}, token=tok)
ok(not res["isError"] and "be_" in text and '"validation"' in text,
   "a dry run is allowed: it shows the lines and HAProxy's verdict")

save_config(dict(load_config(), haproxy=dict(load_config()["haproxy"],
     servers=[{"id": "s9", "name": "keep-me", "address": "10.0.0.9", "port": 80}])))
res, text = call("delete_object", {"collection": "haproxy/servers", "id": "s9", "dry_run": True},
                 token=tok)
ok(res["isError"] and any(x["id"] == "s9" for x in load_config()["haproxy"]["servers"]),
   "dry_run on a tool without one opens nothing: the server is still there")
res, text = call("update_settings", {"section": "haproxy", "values": {"maxconn": 1234},
                                     "dry_run": True}, token=tok)
ok(res["isError"] and load_config()["haproxy"]["settings"].get("maxconn") != 1234,
   "nor are settings changed under a dry_run they do not have")
res, text = call("create_object", {"collection": "haproxy/backends", "dry_run": True,
                                   "item": {"name": "drypool", "servers": ["s9"]}}, token=tok)
ok(not res["isError"] and "backend be_drypool" in text and "10.0.0.9:80" in text
   and '"haproxy -c accepts it"' in text
   and not any(x["name"] == "drypool" for x in load_config()["haproxy"]["backends"]),
   "create_object has a dry run: the lines and HAProxy's verdict, nothing stored: %s" % text[:200])
res, text = call("update_object", {"collection": "haproxy/servers", "id": "s9", "dry_run": True,
                                   "item": {"name": "keep-me", "address": "10.0.0.9", "port": 8081}},
                 token=tok)
ok(not res["isError"] and '"validation"' in text
   and next(x for x in load_config()["haproxy"]["servers"] if x["id"] == "s9")["port"] == 80,
   "so has update_object: %s" % text[:200])
res, text = call("create_object", {"collection": "acme/accounts", "dry_run": True,
                                   "item": {"name": "x", "email": "a@example.com"}}, token=tok)
ok(res["isError"] and not any(x.get("name") == "x" for x in load_config()["acme"]["accounts"]),
   "a dry run of an object haproxy.cfg does not show is refused, and nothing is stored")
res, text = call("renew_certificates", token=tok)
ok(res["isError"] and "Allow changes" in text, "renewing certificates is a change, refused while they are off")
for name, args, want in [("get_vip_status", {}, '"vrrp_state"'),
                         ("check_certificate_setup", {}, '"problem"'),
                         ("find_certificate", {"host": "https://app.example.com/x"}, '"covered": false'),
                         ("list_recipes", {}, '"recipes"'),
                         ("run_probes", {}, '"results"')]:
    res, text = call(name, args, token=tok)
    ok(not res["isError"] and want in text, "%s answers while changes are off: %s" % (name, text[:120]))
r = client.post("/api/mcp/forward", json={"tool": "delete_object", "arguments":
                {"collection": "haproxy/servers", "id": "s9", "dry_run": True}}, headers=K)
ok(r.get_json()["isError"] and any(x["id"] == "s9" for x in load_config()["haproxy"]["servers"]),
   "and the same holds for a call passed on from a passive node")

client.put("/api/mcp", json={"allow_writes": True}, headers=K)
lines.clear()
res, text = call("publish_service", {"url": "http://app.example.com", "target": "10.0.0.5:80",
                                     "name": "app"}, token=tok)
ok(not res["isError"], "allowed, a service is published")
ok(any(l.startswith("mcp:claude-code POST /api/wizard/publish") for l in lines),
   "and the audit line names the MCP client: %s" % [l for l in lines if "wizard" in l][:1])
svc = json.loads(call("get_service", {"id": "app"}, token=tok)[1])
res, text = call("publish_service", {"service_id": svc["id"], "hsts": True,
                                     "balance": "leastconn"}, token=tok)
after = json.loads(call("get_service", {"id": svc["id"]}, token=tok)[1])
ok(not res["isError"] and after["balance"] == "leastconn"
   and after["targets"] == svc["targets"] and after["urls"] == svc["urls"],
   "an edit changes what it names and keeps the rest: %s" % (text[:200] if res["isError"] else ""))
res, text = call("pause_service", {"id": "app", "paused": True}, token=tok)
ok(not res["isError"] and json.loads(call("get_service", {"id": "app"}, token=tok)[1])["maintenance"],
   "a service is paused by name")

ch = json.loads(call("list_objects", {"collection": "acme/challenges"}, token=tok)[1])[0]
ch["name"] = "cloudflare-renamed"
res, text = call("update_object", {"collection": "acme/challenges", "id": "ch1", "item": ch}, token=tok)
stored = load_config()["acme"]["challenges"][0]
ok(not res["isError"] and stored["name"] == "cloudflare-renamed"
   and stored["dns_credentials"] == "CF_Token=sekrit",
   "an object read and written back keeps its secret: [redacted] means unchanged")

res, text = call("save_condition", {"type": "path_starts_with", "value": "/api",
                                    "sample": {"path": "/api/v1"}, "dry_run": True}, token=tok)
ok(not res["isError"] and '"matches": true' in text, "a condition is tried against a request")
res, text = call("get_haproxy_config", token=tok)
ok("backend be_app" in text, "and the rendered haproxy.cfg can be read")

# -- a passive node passes changes to the active one ------------------------------------
real_ro, real_peer, real_req = auth.readonly_state, mcp._active_peer, mcp._requests
from flask import request as _rq   # noqa: E402
auth.readonly_state = lambda cfg: ((True, "passive") if _rq.path == "/mcp" else (False, ""))
mcp._active_peer = lambda cfg: {"name": "node-a", "url": "http://node-a", "api_key": "mcp-test-key"}


class FakeRequests:
    """The peer is this same app: the forward lands on /api/mcp/forward here."""
    @staticmethod
    def post(url, json=None, headers=None, **kw):
        r = client.post(url.replace("http://node-a", ""), json=json, headers=headers)
        return type("R", (), {"status_code": r.status_code, "json": lambda self: r.get_json()})()


mcp._requests = FakeRequests
lines.clear()
res, text = call("pause_service", {"id": "app", "paused": False}, token=tok)
ok(not res["isError"] and "made on node-a" in text, "on a passive node a change is made on node-a: %s" % text[:120])
ok(not json.loads(call("get_service", {"id": "app"}, token=tok)[1])["maintenance"], "and it took")
ok(any("mcp:claude-code via" in l and "maintenance" in l for l in lines),
   "the active node's audit line still names the client")
mcp._active_peer = lambda cfg: None
res, text = call("apply_changes", token=tok)
ok(res["isError"] and "no other node answered" in text, "with no active node, it says so")
res, text = call("get_status", token=tok)
ok(not res["isError"], "reading stays on the node asked")
real_role = auth.node_role
auth.node_role = lambda cfg: ("passive", [])
res, text = call("run_probes", token=tok)
ok(res["isError"] and "virtual IP" in text, "a passive node does not probe: the names lead elsewhere")
auth.node_role = real_role
auth.readonly_state, mcp._active_peer, mcp._requests = real_ro, real_peer, real_req

r = client.post("/api/mcp/forward", json={"tool": "apply_changes", "arguments": {}})
ok(r.status_code == 401, "only a node with the API key can pass a call on")
r = client.post("/api/mcp/receive", json={"mcp": {"enabled": True, "token_hash": "x" * 64}},
                headers={"X-API-Key": "wrong"})
ok(r.status_code == 401, "and only such a node can set the token")
ok(not any(tok in call(n, a, token=tok)[1] for n, a in
           [("get_status", {}), ("get_cluster", {}), ("get_settings", {"section": "haproxy"}),
            ("get_haproxy_config", {})]),
   "no tool shows the token it was called with")
keep = dict(load_config()["local"]["mcp"])
r = client.post("/api/mcp/receive", json={"mcp": {"token_hash": "f" * 64, "token_fp": "ffffffff"}}, headers=K)
ok(r.status_code == 200 and client.get("/api/mcp/token", headers=K).status_code == 404
   and not client.get("/api/mcp", headers=K).get_json()["token_shown"],
   "a hash from a node that does not send the token drops the one kept: it is not the token any more")
cfg = load_config()
cfg["local"]["mcp"] = keep
save_config(cfg)
ok(mcp.push_settings(load_config()) == [], "with no peers there is nothing to copy to")

# -- what is shown, and what is logged ------------------------------------------------------
from ham import acme, haproxy   # noqa: E402
client.put("/api/mcp", json={"allow_writes": True}, headers=K)
sample = ('    acl sso_valid var(txn.sso_msg),hmac(sha256,"c2lnbmluZy1rZXk="),hex,lower -m str x\n'
          'userlist ham_users\n    user alice password $6$salt$hashhashhash\n    stats auth admin:hunter2\n')
shown = mcp.redact_text(sample)
ok("c2lnbmluZy1rZXk=" not in shown and "$6$salt" not in shown and "hunter2" not in shown
   and "user alice password [redacted]" in shown and 'hmac(sha256,"[redacted]")' in shown,
   "configuration text loses the SSO signing key, the password hashes and the stats password")
ok(mcp.unredact(shown, sample) == sample and mcp.unredact("typed anew", sample) == "typed anew",
   "and such text written back untouched keeps what is stored")
real_render = haproxy.render_haproxy
haproxy.render_haproxy = lambda c: real_render(c) + "\n" + sample
res, text = call("get_haproxy_config", token=tok)
haproxy.render_haproxy = real_render
ok("c2lnbmluZy1rZXk=" not in text and "$6$salt" not in text and "userlist ham_users" in text,
   "get_haproxy_config shows the rendered file without them")
cfg = load_config()
cfg["acme"]["accounts"] = [{"id": "ac1", "name": "zero", "email": "", "ca": "zerossl",
                            "eab_kid": "kid-1", "eab_hmac": "hmac-sekrit"}]
cfg["notify"]["destinations"] = [{"id": "d1", "name": "hook", "type": "webhook", "enabled": True,
                                  "url": "https://hooks.example.com/T000/sekrit-path",
                                  "headers": "Authorization: Bearer sekrit-bearer"}]
save_config(cfg)
res, text = call("list_objects", {"collection": "acme/accounts"}, token=tok)
ok("hmac-sekrit" not in text and "kid-1" in text, "an account's EAB HMAC key is a secret too")
res, text = call("get_settings", {"section": "notify"}, token=tok)
ok("sekrit-path" not in text and "sekrit-bearer" not in text and "hooks.example.com" in text,
   "a webhook is shown by its host: its path and its headers are where the credential is")
del lines[:]
call("create_object", {"collection": "acme/challenges",
                       "item": {"name": "nested", "method": "dns01", "dns_provider": "dns_cf",
                                "dns_credentials": "CF_Token=nested-sekrit"}}, token=tok)
ok(any("create_object" in ln for ln in lines) and not any("nested-sekrit" in ln for ln in lines),
   "a credential inside item is not written to the log, which get_logs reads back")

# -- the tools do what their schemas say ------------------------------------------------------
listed = {t["name"]: t for t in rpc("tools/list", token=tok).get_json()["result"]["tools"]}
ok(listed["publish_service"]["inputSchema"]["properties"]["notify_mode"]["enum"] == ["servers", "outage", "off"],
   "notify_mode offers what the wizard takes")
ok("manager" in listed["get_logs"]["inputSchema"]["properties"]["sources"]["items"]["enum"],
   "get_logs offers the log viewer's own sources")
res, text = call("get_logs", {"sources": ["app"]}, token=tok)
ok(not res["isError"], "app is still understood as the manager's log")
res, text = call("get_logs", {"sources": ["nope"]}, token=tok)
ok(res["isError"] and "no log source nope" in text, "a source there is not is said to be none, not answered with nothing")
issued = []
real_issue = acme.acme_issue
acme.acme_issue = lambda c, cert, force=False: (issued.append(cert["name"]), {"ok": True})[1]
res, text = call("request_certificate", {"domains": "one.example.com", "account": "zero", "challenge": "ch1"}, token=tok)
made = [c for c in load_config()["acme"]["certificates"] if c.get("domains") == "one.example.com"]
ok(not res["isError"] and made and made[0]["account"] == "ac1" and made[0]["challenge"] == "ch1"
   and issued == [made[0]["name"]],
   "request_certificate takes an account by name and a challenge by id, and issues: %s" % text[:80])
res, text = call("request_certificate", {"domains": "two.example.com", "issue": False}, token=tok)
ok(res["isError"] and "say which ACME challenge type" in text,
   "with two challenge types and none named it asks which, rather than failing")
res, text = call("request_certificate", {"domains": "two.example.com", "account": "nobody", "challenge": "ch1"}, token=tok)
ok(res["isError"] and "no ACME account 'nobody'" in text, "an account there is not is said so")
res, text = call("request_certificate", {"domains": "two.example.com", "challenge": "ch1", "issue": False}, token=tok)
ok(not res["isError"] and len(issued) == 1, "the only account is used when none is named, and issue: false only creates")
acme.acme_issue = real_issue
call("publish_service", {"url": "http://moved.example.com", "redirect": {"to": "https://new.example.com"},
                         "certificate": False, "http_redirect": False}, token=tok)
svc = next(s for s in client.get("/api/services", headers=K).get_json() if s["pool"] == "moved")
res, text = call("publish_service", {"service_id": svc["id"], "redirect": None, "target": "10.0.0.9:80",
                                     "certificate": None, "name": None}, token=tok)
pool = next(b for b in load_config()["haproxy"]["backends"] if b["name"] == "moved")
ok(not res["isError"] and pool["redirect_to"] == "" and len(pool["servers"]) == 1,
   "redirect: null turns a redirecting service back into a forward: %s" % text[:80])
client.put("/api/mcp", json={"allow_writes": False}, headers=K)

# -- turned off again ---------------------------------------------------------------------
client.put("/api/mcp", json={"enabled": False}, headers=K)
ok(rpc("ping", token=tok).status_code == 403, "turned off, the token no longer opens anything")

print("\n%d failed" % len(fails) if fails else "\nan assistant gets the tools, not the keys")
sys.exit(1 if fails else 0)
