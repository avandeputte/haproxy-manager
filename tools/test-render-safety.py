#!/usr/bin/env python3
"""What is typed is what haproxy.cfg says -- pinned, with HAProxy's own verdict.

`haproxy -c` accepts a great many lines that do not mean what was typed: a
`#` in a redirect address comments out the condition after it, so every
host is redirected; two conditions whose names become one token are one ACL
with both pattern sets; a space in a server address is followed by a server
keyword; an accept ahead of a reject makes the reject dead text; a disabled
pool named by a rule fails the whole file. Each is pinned here at the seam
where it is refused or written safely, and every rendering claim is put to
the HAProxy in the image -- one of them to a running HAProxy, asked the way
a browser would ask.

    HAM_DATA_DIR=/tmp/x python3 tools/test-render-safety.py
"""
import copy
import http.client
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
_tmp = tempfile.mkdtemp(prefix="ham-safety-")
os.environ.setdefault("HAM_DATA_DIR", _tmp)
os.environ.setdefault("HAM_CERT_DIR", os.path.join(_tmp, "certs"))
os.environ["HAM_DRY_RUN"] = "1"

import ham   # noqa: E402
from ham import apply, haproxy, validate   # noqa: E402
from ham.config import DEFAULT_CONFIG, load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


def have_haproxy():
    try:
        return subprocess.run(["haproxy", "-v"], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


HAVE = have_haproxy()
if not HAVE:
    print("  ....  no haproxy here; HAProxy's verdict is not checked")


def accepted(cfg, what):
    """haproxy -c over what this configuration renders to, as one check."""
    if not HAVE:
        return
    rc, out, _text = apply._haproxy_check(cfg)
    ok(rc == 0, "haproxy -c accepts %s%s" % (what, "" if rc == 0 else ": " + out.strip().splitlines()[-1][:120]))


def block(text, head):
    """The paragraph of the rendered file that starts with this line."""
    for para in text.split("\n\n"):
        if para.strip().splitlines()[0] == head:
            return para
    return ""


def base():
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["acme"]["settings"]["haproxy_integration"] = False
    hp = cfg["haproxy"]
    hp["servers"] = [{"id": "s1", "name": "web", "address": "10.0.0.1", "port": "80", "enabled": True},
                     {"id": "s2", "name": "other", "address": "10.0.0.2", "port": "80", "enabled": True}]
    hp["backends"] = [{"id": "b1", "name": "shop", "mode": "http", "servers": ["s1"], "enabled": True},
                      {"id": "b2", "name": "admin", "mode": "http", "servers": ["s2"], "enabled": True}]
    hp["conditions"] = [{"id": "c1", "name": "host-shop", "type": "host_matches", "value": "shop.example.com"},
                        {"id": "c2", "name": "host-admin", "type": "host_matches", "value": "admin.example.com"}]
    hp["rules"] = [{"id": "r1", "name": "to-shop", "type": "use_backend", "backend": "b1", "conditions": ["c1"]},
                   {"id": "r2", "name": "to-admin", "type": "use_backend", "backend": "b2", "conditions": ["c2"]}]
    hp["frontends"] = [{"id": "f1", "name": "web", "mode": "http", "binds": "0.0.0.0:80",
                        "rules": ["r1", "r2"], "enabled": True}]
    return cfg


# -- a # or a % in a redirect address stays inside the address ----------------
cfg = base()
cfg["haproxy"]["rules"].insert(0, {"id": "r0", "name": "docs", "type": "redirect_location",
                                   "param1": "https://docs.example.com/page%20v2#top", "conditions": ["c1"]})
cfg["haproxy"]["rules"].insert(1, {"id": "r3", "name": "note", "type": "http_request_set_header",
                                   "param1": "X-Note", "param2": "value # not a comment", "conditions": ["c1"]})
cfg["haproxy"]["frontends"][0]["rules"] = ["r0", "r3", "r1", "r2"]
text = haproxy.render_haproxy(cfg)
fe = block(text, "frontend fe_web")
ok('    http-request redirect location "https://docs.example.com/page%%20v2#top" code 302 if acl_host-shop' in fe,
   "a redirect rule's address is written quoted and %-escaped, its condition intact after the #")
ok('    http-request set-header X-Note "value # not a comment" if acl_host-shop' in fe,
   "a header's value is written quoted, so a # in it stays a value")
accepted(cfg, "the quoted redirect and header")

if HAVE:
    # The proof is a running HAProxy: the host the rule names is redirected
    # to the address as typed, and another host on the same listener is not.
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cfg["haproxy"]["frontends"][0]["binds"] = "127.0.0.1:%d" % port
    stage = tempfile.mkdtemp(prefix="ham-live-")
    staged = apply._staged(cfg, haproxy.render_haproxy(cfg), stage)
    staged = staged.replace("/run/haproxy/admin.sock", os.path.join(stage, "admin.sock"))
    path = os.path.join(stage, "haproxy.cfg")
    pathlib.Path(path).write_text(staged)
    proc = subprocess.Popen(["haproxy", "-f", path, "-db"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)

    def get(host):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.request("GET", "/", headers={"Host": host})
        r = c.getresponse()
        return r.status, r.getheader("Location"), r.getheader("X-Note")

    try:
        if proc.poll() is not None:
            ok(False, "haproxy started on the rendered file: " + proc.stderr.read().decode()[-300:])
        status, where, note = get("shop.example.com")
        ok(status == 302 and where == "https://docs.example.com/page%20v2#top",
           "a running HAProxy redirects the host named to the address typed: %s %s" % (status, where))
        status, where, _note = get("admin.example.com")
        ok(status != 302 and where is None,
           "and another host on the same listener is not redirected: %s" % status)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    cfg["haproxy"]["frontends"][0]["binds"] = "0.0.0.0:80"

# -- a header name is one word; the forms refuse what would not be ---------
try:
    validate.check_rule({"type": "redirect_location", "param1": "https://a.example.com/x y"})
    ok(False, "a redirect address with a space is refused")
except ValueError as e:
    ok("spaces" in str(e), "a redirect address with a space is refused: " + str(e))
try:
    validate.check_rule({"type": "http_request_set_header", "param1": "X-Note #", "param2": "v"})
    ok(False, "a header name that is not one word is refused")
except ValueError as e:
    ok("header name" in str(e), "a header name that is not one word is refused: " + str(e))
try:
    validate.check_rule({"type": "http_request_set_header", "param1": "X-Note", "param2": "a\nb"})
    ok(False, "a header value with a line break is refused")
except ValueError as e:
    ok("line break" in str(e), "a header value with a line break is refused: " + str(e))
validate.check_rule({"type": "http_request_set_header", "param1": "X-Note", "param2": "value # fine %[src]"})
ok(True, "a header value with a # or a fetch in it is fine: it is quoted")
validate.check_rule({"type": "custom", "param1": "http-request deny if { path_beg /x } # raw"})
ok(True, "a custom rule is the raw-directive field and is left alone")

# -- two conditions of one token are two ACLs ---------------------------------
cfg = base()
cfg["haproxy"]["conditions"][1].update(name="host shop", value="admin.example.com")   # becomes host_shop
cfg["haproxy"]["conditions"][0].update(name="host_shop")
text = haproxy.render_haproxy(cfg)
fe = block(text, "frontend fe_web")
ok("acl acl_host_shop hdr(host)" in fe and "acl acl_host_shop_c2 hdr(host)" in fe,
   "two conditions whose names become one token are declared apart, the second told by its id")
ok("use_backend be_shop if acl_host_shop\n" in fe + "\n" and "use_backend be_admin if acl_host_shop_c2" in fe,
   "so each rule tests its own condition rather than both")
accepted(cfg, "the two ACLs")

ham.app.config["TESTING"] = True
client = ham.app.test_client()
stored = load_config()
stored["local"]["api_key"] = "safety-key"
stored["haproxy"].update(copy.deepcopy(base()["haproxy"]))
stored["acme"]["settings"]["haproxy_integration"] = False
save_config(stored)
H = {"X-API-Key": "safety-key"}


def post(col, item):
    return client.post("/api/haproxy/" + col, headers=H, json=item)


def put(col, iid, item):
    return client.put("/api/haproxy/%s/%s" % (col, iid), headers=H, json=item)


def wizard(which, body):
    return client.post("/api/wizard/" + which, headers=H, json=body)


r = post("conditions", {"name": "host_x", "type": "host_matches", "value": "x.example.com"})
ok(r.status_code == 200, "a condition of a new name is saved")
r = post("conditions", {"name": "host x", "type": "host_matches", "value": "y.example.com"})
ok(r.status_code == 400 and "same name in haproxy.cfg" in (r.get_json() or {}).get("error", ""),
   "a condition whose name becomes another's token is refused at save: " + str((r.get_json() or {}).get("error", ""))[:90])
r = post("conditions", {"name": "host-shop", "type": "host_matches", "value": "x.example.com"})
ok(r.status_code == 400 and "already there" in r.get_json()["error"], "and so is the same name again")
r = post("backends", {"name": "shop", "mode": "http", "servers": []})
ok(r.status_code == 400, "a pool of a name already taken is refused: two backends of one name fail the file")
r = post("frontends", {"name": "web", "mode": "http", "binds": "0.0.0.0:8080"})
ok(r.status_code == 400, "and a listener")
r = put("conditions", "c1", {"name": "host-shop", "type": "host_matches", "value": "shop.example.com"})
ok(r.status_code == 200, "an object saved under its own name is not its own duplicate")

# -- a TCP listener's reject comes before the accept it would otherwise follow --
cfg = base()
hp = cfg["haproxy"]
hp["backends"].append({"id": "b3", "name": "db", "mode": "tcp", "servers": ["s1"], "enabled": True})
hp["conditions"].append({"id": "c3", "name": "sni-bad", "type": "ssl_sni", "value": "bad.example.com"})
hp["rules"].append({"id": "r4", "name": "reject-bad", "type": "tcp_request_content_reject", "conditions": ["c3"]})
hp["frontends"].append({"id": "f2", "name": "tls", "mode": "tcp", "binds": "0.0.0.0:3306",
                        "rules": ["r4"], "default_backend": "b3", "enabled": True})
text = haproxy.render_haproxy(cfg)
tcp = block(text, "frontend fe_tls")
lines = [ln.strip() for ln in tcp.splitlines()]
delay, reject, accept = (lines.index("tcp-request inspect-delay 5s"),
                         lines.index("tcp-request content reject if acl_sni-bad"),
                         lines.index("tcp-request content accept if { req_ssl_hello_type 1 }"))
ok(delay < reject < accept,
   "the hello is waited for, the listener's own content rules decide, and the accept comes last")
accepted(cfg, "the TCP listener with an SNI reject")

# -- a bare-word field holds one word ------------------------------------------
for item, why in (({"address": "10.0.0.1 disabled", "port": 80}, "address"),
                  ({"address": "10.0.0.1", "port": "80 81"}, "port"),
                  ({"address": "10.0.0.1", "port": 80, "weight": "heavy"}, "weight"),
                  ({"address": "10.0.0.1", "port": 80, "check_port": "80#"}, "health check port"),
                  ({"address": "10.0.0.1#", "port": 80}, "address")):
    try:
        validate.check_server(item)
        ok(False, "a server with a bad %s is refused: %r" % (why, item))
    except ValueError as e:
        ok(why.split()[-1] in str(e), "a server with a bad %s is refused: %s" % (why, e))
for addr in ("10.0.0.1", "db.internal", "[2001:db8::1]", "2001:db8::1", "unix@/run/app.sock"):
    try:
        validate.check_server({"address": addr, "port": 80})
        ok(True, "an address of the form %s is fine" % addr)
    except ValueError as e:
        ok(False, "an address of the form %s is fine: %s" % (addr, e))
for item, why in (({"type": "http", "interval": "abc"}, "interval"),
                  ({"type": "http", "expect_status": "200 OK"}, "status"),
                  ({"type": "http", "http_host": "a b"}, "Host"),
                  ({"type": "http", "http_uri": "/x #"}, "URI"),
                  ({"type": "ping"}, "type")):
    try:
        validate.check_healthcheck(item)
        ok(False, "a monitor with a bad %s is refused: %r" % (why, item))
    except ValueError as e:
        ok(why in str(e), "a monitor with a bad %s is refused: %s" % (why, e))
validate.check_healthcheck({"type": "http", "interval": "2s", "expect_status": "200,204,300-399",
                            "http_host": "app.example.com:8443", "http_uri": "/health"})
ok(True, "a monitor with a status list and a Host with a port is fine")
for item, why in (({"balance": "roundrobin\n    http-request deny"}, "balance"),
                  ({"balance": "fastest"}, "balance"),
                  ({"cookie_name": "SRV ID"}, "cookie"),
                  ({"timeout_server": "abc"}, "timeout"),
                  ({"stick_size": "lots"}, "size"),
                  ({"mode": "udp"}, "mode")):
    try:
        validate.check_pool(item)
        ok(False, "a pool with a bad %s is refused: %r" % (why, item))
    except ValueError as e:
        ok(why in str(e), "a pool with a bad %s is refused: %s" % (why, e))
validate.check_pool({"balance": "hdr(X-Tenant)", "cookie_name": "SRVID", "timeout_server": "30s", "stick_size": "50k"})
ok(True, "a pool with an algorithm that takes an argument is fine")
bad = validate.check_setting_types("haproxy", {"ssl_min_ver": "TLSv1.2 foo", "stats_uri": "stats",
                                               "stats_bind": "127.0.0.1:8404 accept", "ssl_ciphers": "a b"})
ok(bad.count("\n") >= 3 and "ssl_min_ver" in bad and "stats_uri" in bad and "stats_bind" in bad and "ssl_ciphers" in bad,
   "the global settings that are one word each are refused with more: " + bad.replace("\n", " | ")[:160])
ok(validate.check_setting_types("haproxy", {"ssl_min_ver": "TLSv1.3", "stats_uri": "/stats", "ssl_ciphers":
                                            "ECDHE-ECDSA-AES128-GCM-SHA256:!aNULL"}) == "",
   "and the usual values pass")
try:
    validate.check_frontend({"mode": "http", "binds": "0.0.0.0:80\n0.0.0.0:443 # tls"})
    ok(False, "a bind line with a # is refused")
except ValueError as e:
    ok("#" in str(e), "a bind line with a # is refused: " + str(e))
try:
    validate.check_frontend({"mode": "http", "binds": "0.0.0.0:99999"})
    ok(False, "a bind port out of range is refused")
except ValueError as e:
    ok("65535" in str(e), "a bind port out of range is refused: " + str(e))
validate.check_frontend({"mode": "tcp", "binds": "0.0.0.0:3306\n192.0.2.10:3306 accept-proxy"})
ok(True, "bind lines with an option after the address are fine")

# through the API, where every page and the MCP server save
r = post("servers", {"name": "s", "address": "10.0.0.9", "port": "80 81"})
ok(r.status_code == 400 and "port" in r.get_json()["error"], "POST a server with a port that is not one: 400")
r = post("healthchecks", {"name": "h", "type": "http", "interval": "abc"})
ok(r.status_code == 400 and "interval" in r.get_json()["error"], "POST a monitor with an interval that is not a time: 400")
r = put("backends", "b1", dict(base()["haproxy"]["backends"][0], timeout_server="abc"))
ok(r.status_code == 400 and "timeout" in r.get_json()["error"], "PUT a pool with a timeout that is not one: 400")
r = post("frontends", {"name": "f", "mode": "http", "binds": "0.0.0.0:8443 #"})
ok(r.status_code == 400, "POST a listener with a # in a bind line: 400")
r = post("rules", {"name": "hdr", "type": "http_request_set_header", "param1": "X A", "param2": "v"})
ok(r.status_code == 400, "POST a rule whose header name is two words: 400")
r = post("conditions", {"name": "frag", "type": "path_starts_with", "value": "/a#b"})
ok(r.status_code == 400 and "#" in r.get_json()["error"], "POST a condition with a # in its value: 400")
r = post("conditions", {"name": "raw", "type": "custom", "value": "path_beg /a # raw"})
ok(r.status_code == 200, "a custom condition is the raw-ACL field and keeps its #")

# a value stored before the forms refused it is written as one word
cfg = base()
hp = cfg["haproxy"]
hp["servers"][0].update(address="10.0.0.1 disabled", port="80 81", weight="10 backup")
hp["healthchecks"] = [{"id": "h1", "name": "h", "type": "http", "interval": "2s\n    http-request deny",
                       "expect_status": "200 http-request deny", "http_host": "app.example.com:8443 #"}]
hp["backends"][0].update(healthcheck_enabled=True, healthcheck="h1", balance="roundrobin # x",
                         persistence="cookie", cookie_name="SRVID insert")
cfg["haproxy"]["settings"].update(ssl_min_ver="TLSv1.2\n    http-request deny", stats_enabled=True,
                                  stats_uri="/stats # x", maxconn="4000 x")
text = haproxy.render_haproxy(cfg)
be = block(text, "backend be_shop")
ok("    server web 10.0.0.1:80 check inter 2s weight 10 cookie web\n" in be + "\n"
   and "disabled" not in be and "backup" not in be,
   "a stored address, port and weight each become one word on the server line")
ok("http-request deny" not in text, "a line break in a bare-word field never becomes a directive")
ok("    balance roundrobin\n" in be and "    cookie SRVID insert indirect nocache\n" in be
   and "    http-check expect status 200\n" in be and "hdr Host app.example.com:8443\n" in be,
   "balance, cookie name, status and Host header are written as the one word each is")
ok("    maxconn 4000\n" in text and "    ssl-default-bind-options ssl-min-ver TLSv1.2\n" in text
   and "    stats uri /stats\n" in text, "and so are the global settings")
accepted(cfg, "the file with the stored oddities written safely")

# -- a disabled pool stays a backend ---------------------------------------
cfg = base()
cfg["haproxy"]["backends"][1]["enabled"] = False
cfg["haproxy"]["backends"].append({"id": "b3", "name": "db", "mode": "tcp", "servers": ["s1"], "enabled": False})
cfg["haproxy"]["frontends"][0]["default_backend"] = "b2"
cfg["haproxy"]["frontends"].append({"id": "f2", "name": "pg", "mode": "tcp", "binds": "0.0.0.0:5432",
                                    "default_backend": "b3", "enabled": True})
text = haproxy.render_haproxy(cfg)
be = block(text, "backend be_admin")
ok("    http-request return status 503\n" in be + "\n" and "server " not in be and "disabled" in be,
   "a disabled HTTP pool is a backend with no servers that answers 503, and says why")
ok("use_backend be_admin if acl_host-admin" in text and "default_backend be_admin" in text,
   "so the rule and the listener that name it still have something to name")
tcp = block(text, "backend be_db")
ok("    tcp-request content reject\n" in tcp + "\n" and "server " not in tcp,
   "a disabled TCP pool refuses every connection")
accepted(cfg, "a disabled pool named by a rule and a listener")

# -- a health check's Host header keeps its port ----------------------------
cfg = base()
cfg["haproxy"]["healthchecks"] = [{"id": "h1", "name": "h", "type": "http", "http_host": "app.example.com:8443",
                                   "http_uri": "/health", "http_version": "HTTP/1.1", "expect_status": "200"}]
cfg["haproxy"]["backends"][0].update(healthcheck_enabled=True, healthcheck="h1")
text = haproxy.render_haproxy(cfg)
ok("    http-check send meth GET uri /health ver HTTP/1.1 hdr Host app.example.com:8443\n" in text,
   "the Host header is sent as typed, port and all")
accepted(cfg, "the check with a Host header")

# -- a condition where it can never match --------------------------------
cfg = base()
hp = cfg["haproxy"]
hp["conditions"].append({"id": "c3", "name": "sni-shop", "type": "ssl_sni", "value": "shop.example.com"})
hp["rules"].append({"id": "r4", "name": "by-sni", "type": "use_backend", "backend": "b1", "conditions": ["c3"]})
hp["frontends"][0]["rules"].append("r4")
hp["backends"].append({"id": "b3", "name": "db", "mode": "tcp", "servers": ["s1"], "enabled": True})
hp["frontends"].append({"id": "f2", "name": "pg", "mode": "tcp", "binds": "0.0.0.0:5432",
                        "rules": ["r1"], "default_backend": "b3", "enabled": True})
text = haproxy.render_haproxy(cfg)
ok('# "sni-shop" tests the TLS server name in the raw hello, which an HTTP listener never sees' in block(text, "frontend fe_web"),
   "the TLS name tested on an HTTP listener is declared with a line saying it never matches")
ok('# "host-shop" tests the HTTP request, which this TCP listener never reads' in block(text, "frontend fe_pg"),
   "and a host tested on a TCP listener likewise")
accepted(cfg, "the mismatched conditions (HAProxy takes them, which is the problem)")
clashes = validate.mode_clashes(hp)
ok(len(clashes) == 2 and any("sni-shop" in c for c in clashes) and any("host-shop" in c for c in clashes),
   "mode_clashes names both: %s" % " / ".join(c[:60] for c in clashes))
stored = load_config()
stored["haproxy"]["backends"].append({"id": "b3", "name": "db", "mode": "tcp", "servers": ["s1"], "enabled": True})
save_config(stored)
r = post("frontends", {"name": "pg", "mode": "tcp", "binds": "0.0.0.0:5432", "rules": ["r1"], "default_backend": "b3"})
ok(r.status_code == 400 and "never match" in r.get_json()["error"],
   "a TCP listener given a rule that tests a host is refused: " + r.get_json()["error"][:80])
r = post("frontends", {"name": "pg", "mode": "tcp", "binds": "0.0.0.0:5432", "rules": [], "default_backend": "b3"})
ok(r.status_code == 200, "without the rule it is fine")
pg = r.get_json()["id"]
r = wizard("rule", {"listeners": [pg], "all_of": [{"type": "path_starts_with", "value": "/x"}],
                    "action": {"type": "tcp_request_content_reject"}})
ok(r.status_code == 400 and "never match" in r.get_json()["error"],
   "the rule wizard refuses a path test on a TCP listener: " + r.get_json()["error"][:80])
r = wizard("rule", {"listeners": [pg], "all_of": [{"type": "ssl_sni", "value": "bad.example.com"}],
                    "action": {"type": "tcp_request_content_reject"}})
ok(r.status_code == 200, "and takes the TLS name there, where it can be read")
r = wizard("rule", {"listeners": ["f1"], "all_of": [{"type": "ssl_sni", "value": "bad.example.com"}],
                    "action": {"type": "http_request_deny"}})
ok(r.status_code == 400 and "never match" in r.get_json()["error"],
   "but not on the HTTP listener: " + r.get_json()["error"][:80])
r = wizard("condition", {"type": "custom", "value": "always_true"})
ok(r.status_code == 200, "a condition nothing tests yet clashes with nothing")
r = wizard("condition", {"type": "host_matches", "value": "shop.example.com#x"})
ok(r.status_code == 400 and "#" in r.get_json()["error"], "the condition wizard refuses a # in a value too")

# -- a stick table that holds every client ---------------------------------
cfg = base()
cfg["haproxy"]["backends"][0].update(persistence="source", stick_type="ip", rate_limit=100, rate_window=10)
text = haproxy.render_haproxy(cfg)
be = block(text, "backend be_shop")
ok("    stick-table type ipv6 size 50k expire 30m store http_req_rate(10s)\n" in be + "\n" and "    stick on src\n" in be,
   "source persistence with a rate limit is keyed by ipv6, which holds IPv4 clients too")
accepted(cfg, "the ipv6 table with persistence and a counter")

print("\n" + ("%d failed" % len(fails) if fails else "what was typed is what HAProxy is told"))
sys.exit(1 if fails else 0)
