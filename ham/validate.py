"""Settings and object validation."""

import re


#
# `haproxy -c` is the authority on whether a configuration works, but it is
# lenient about types: `maxconn not-a-number` parses as zero and validates
# clean, silently capping the proxy at nothing. So the obviously-typed fields
# are checked here first, before anything is written.
#
# The same goes for every field that lands on a configuration line as a bare
# word. HAProxy reads `#` as the start of a comment and a space as the start
# of the next keyword, so a value holding either changes what the line means
# without failing the check: "10.0.0.1:80 disabled" is a server that is
# disabled, and a redirect to "/page#top" loses its condition. The renderer
# writes such fields defensively too, but a value is best refused where it is
# typed, with a reason, rather than quietly cut down later.
# --------------------------------------------------------------------------

NUMERIC_SETTINGS = {
    "haproxy": {"maxconn": (1, 2000000), "nbthread": (1, 256), "retries": (0, 100)},
    "acme": {"challenge_port": (1, 65535), "renew_hours": (1, 8760)},
}
TIME_SETTINGS = {"haproxy": ["timeout_client", "timeout_connect", "timeout_server",
                             "hard_stop_after", "timeout_tunnel"]}
DEFAULT_SITES = ("503", "404", "drop", "redirect")
TLS_VERSIONS = ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")

TIME_RE = re.compile(r"^\d+(us|ms|s|m|h|d)?$")
# A single configuration word: nothing that ends it early. Letters, digits
# and the punctuation an address, a cookie name or a cipher list is made of.
WORD_RE = re.compile(r"^[A-Za-z0-9_.:@/\[\]*!+=,\-]+$")
# An address as a server, a bind or a Host header carries it: a host name, an
# IPv4 or IPv6 address (bracketed or bare), a unix@ socket -- one word.
ADDRESS_RE = re.compile(r"^[A-Za-z0-9_.:@/\[\]*\-]+$")
HOST_PORT_RE = re.compile(r"^([A-Za-z0-9_.\-]+|\[[0-9A-Fa-f:.]+\])(:\d{1,5})?$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
STATUS_RE = re.compile(r"^\d{3}(-\d{3})?(,\d{3}(-\d{3})?)*$")
SIZE_RE = re.compile(r"^\d+[kKmMgG]?$")
# The first word of a `balance` line; the algorithms that take an argument
# -- hdr(name), rdp-cookie(name) -- or a modifier -- "uri whole" -- keep it.
BALANCES = ("roundrobin", "static-rr", "leastconn", "first", "source", "uri", "url_param",
            "hdr", "random", "rdp-cookie", "hash", "log-hash", "sticky")

COND_TYPES = ("host_matches", "host_starts_with", "host_ends_with", "path_matches",
              "path_starts_with", "path_ends_with", "path_contains", "url_parameter",
              "http_header", "source_ip", "source_list", "ssl_sni", "custom")
ACTIONS = ("use_backend", "redirect_scheme_https", "redirect_location", "http_request_deny",
           "http_request_set_header", "http_request_del_header", "http_response_set_header",
           "tcp_request_content_accept", "tcp_request_content_reject", "custom")
# What a condition reads, and the listener mode that has it to read. A Host
# header or a path exists once HTTP is parsed; the TLS server name is read
# from the raw hello, which an HTTP listener -- TLS already ended at its bind
# -- never has in front of it. Either on the wrong listener never matches,
# and HAProxy's check does not say so.
HTTP_ONLY_CONDS = ("host_matches", "host_starts_with", "host_ends_with", "path_matches",
                   "path_starts_with", "path_ends_with", "path_contains", "url_parameter",
                   "http_header")
TCP_ONLY_CONDS = ("ssl_sni",)
HEALTH_TYPES = ("tcp", "http", "ssl", "pgsql", "mysql", "none")
HTTP_VERSIONS = ("", "HTTP/1.0", "HTTP/1.1", "HTTP/2")


def plain_url(value):
    """An http(s) address with nothing in it that could end a directive:
    no space, no quote."""
    value = str(value or "").strip()
    return bool(re.match(r"^https?://\S+$", value)) and not any(q in value for q in "\"'")


def _text(value):
    return "" if value is None else str(value).strip()


def _has_control(value):
    return bool(re.search(r"[\x00-\x1f\x7f]", value))


def _refuse_breakers(what, value):
    """A value meant for one line, where a comment mark or a quote would
    change what the rest of the line means."""
    if _has_control(value):
        raise ValueError("%s cannot contain a line break or control character" % what)
    if "#" in value or "\"" in value or "'" in value:
        raise ValueError("%s cannot contain # or quotes: HAProxy reads # as the start of a "
                         "comment, and a quote as the start of a quoted string" % what)


def _word(what, value, pattern=WORD_RE):
    """One bare word, or empty. Raises with the field named."""
    value = _text(value)
    if value and not pattern.match(value):
        raise ValueError("%s must be a single word with no spaces, # or quotes, not %r" % (what, value))
    return value


def _whole(what, value, lo, hi, required=False):
    """A whole number in range, as int; None when empty and not required."""
    value = _text(value)
    if not value:
        if required:
            raise ValueError("%s is required" % what)
        return None
    try:
        n = int(value)
    except ValueError:
        raise ValueError("%s must be a whole number, not %r" % (what, value))
    if not lo <= n <= hi:
        raise ValueError("%s must be between %d and %d" % (what, lo, hi))
    return n


def _time(what, value):
    value = _text(value)
    if value and not TIME_RE.match(value):
        raise ValueError("%s must be a time such as 5s, 500 or 1m -- not %r" % (what, value))
    return value


def _choice(what, value, choices, empty_ok=True):
    value = _text(value)
    if not value and empty_ok:
        return value
    if value not in choices:
        raise ValueError("%s must be one of %s, not %r" % (what, ", ".join(c for c in choices if c), value))
    return value


def check_setting_types(sec, proposed):
    """Return a human-readable complaint, or "" when the values make sense."""
    problems = []
    for key, (lo, hi) in NUMERIC_SETTINGS.get(sec, {}).items():
        if key not in proposed:
            continue
        raw = proposed[key]
        if raw in ("", None):                  # empty means "use the default"
            continue
        try:
            val = int(str(raw).strip())
        except (TypeError, ValueError):
            problems.append("%s must be a whole number, not %r." % (key, raw))
            continue
        if not lo <= val <= hi:
            problems.append("%s must be between %d and %d." % (key, lo, hi))
    if sec == "haproxy" and "default_site" in proposed:
        if proposed["default_site"] not in DEFAULT_SITES:
            problems.append("default_site must be one of %s." % ", ".join(DEFAULT_SITES))
        elif proposed["default_site"] == "redirect" and \
                not plain_url(str(proposed.get("default_site_url") or "").strip()):
            problems.append("a redirect for unknown hosts needs an address starting with http:// or https://.")
    for key in TIME_SETTINGS.get(sec, []):
        raw = proposed.get(key)
        if raw in ("", None):
            continue
        if not TIME_RE.match(str(raw).strip()):
            problems.append("%s must be a time such as 50s, 5000 or 1m -- not %r." % (key, raw))
    if sec == "haproxy":
        # The single-word fields of the global and stats sections. Each lands
        # on its own line, where a second word would be read as a keyword.
        for key, check in (("ssl_min_ver", lambda v: _choice("ssl_min_ver", v, TLS_VERSIONS)),
                           ("ssl_ciphers", lambda v: _word("ssl_ciphers", v)),
                           ("stats_bind", lambda v: _word("stats_bind", v, ADDRESS_RE)),
                           ("stats_uri", lambda v: _word("stats_uri", v))):
            if key in proposed and proposed[key] not in ("", None):
                try:
                    check(proposed[key])
                except ValueError as e:
                    problems.append(str(e) + ".")
        if _text(proposed.get("stats_uri")) and not _text(proposed["stats_uri"]).startswith("/"):
            problems.append("stats_uri must start with /.")
    return "\n".join(problems)


# --------------------------------------------------------------------------
# Real Servers

def check_server(item):
    """Refuse a server whose line would not say what was typed.

    Raises ValueError with the reason. The address and the port become one
    word on the server line; anything after a space there is a server
    keyword -- "disabled", "backup" -- that HAProxy then honours.
    """
    address = _text(item.get("address"))
    if not address:
        raise ValueError("a server needs an address")
    if not ADDRESS_RE.match(address):
        raise ValueError("the address must be one host name or IP address, with no spaces, # or quotes")
    _whole("the port", item.get("port"), 1, 65535, required=True)
    _whole("the weight", item.get("weight"), 0, 256)
    _whole("the health check port", item.get("check_port"), 1, 65535)
    _choice("the PROXY protocol", item.get("proxy_protocol"), ("", "v1", "v2"))


# --------------------------------------------------------------------------
# Health Monitors

def check_healthcheck(item):
    """Refuse a monitor whose directives would not say what was typed.
    Raises ValueError with the reason."""
    _choice("the check type", item.get("type"), HEALTH_TYPES)
    _time("the check interval", item.get("interval"))
    _word("the HTTP method", item.get("http_method"), re.compile(r"^[A-Za-z]+$"))
    uri = _text(item.get("http_uri"))
    if uri:
        _refuse_breakers("the request URI", uri)
        if re.search(r"\s", uri):
            raise ValueError("the request URI cannot contain spaces")
    _choice("the HTTP version", item.get("http_version"), HTTP_VERSIONS)
    host = _text(item.get("http_host"))
    if host and not HOST_PORT_RE.match(host):
        raise ValueError("the Host header must be a host name, with a :port if needed, not %r" % host)
    status = _text(item.get("expect_status"))
    if status and not STATUS_RE.match(status):
        raise ValueError("the expected status must be a code such as 200, a range such as 200-399, "
                         "or several separated by commas -- not %r" % status)
    _word("the database user", item.get("db_user"), re.compile(r"^[A-Za-z0-9_.@\-]+$"))


# --------------------------------------------------------------------------
# Public Services

def check_frontend(item):
    """Refuse a listener whose bind lines would not say what was typed.
    Raises ValueError with the reason."""
    _choice("the mode", item.get("mode"), ("http", "tcp"))
    for line in str(item.get("binds") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        _refuse_breakers("a listen address", line)
        first = line.split()[0]
        if not ADDRESS_RE.match(first):
            raise ValueError("a listen address must be address:port, such as 0.0.0.0:443, not %r" % first)
        tail = first.rsplit(":", 1)[1] if ":" in first else ""
        if tail.isdigit() and not 1 <= int(tail) <= 65535:
            raise ValueError("the port in %r must be between 1 and 65535" % first)


# --------------------------------------------------------------------------
# Conditions and Rules

def check_condition(item):
    """Refuse a condition whose ACL would not test what was typed.

    Raises ValueError with the reason. The value is written straight after
    the fetch, so a `#` in it ends the pattern list and a quote starts a
    string; several values are separated by spaces on purpose, so those
    stay. A custom condition is the raw-ACL field and is left alone.
    """
    ctype = _choice("the condition type", item.get("type"), COND_TYPES) or "host_matches"
    value = _text(item.get("value"))
    if _has_control(value):
        raise ValueError("the value cannot contain a line break or control character")
    if ctype != "custom":
        _refuse_breakers("the value", value)
    if ctype in ("http_header", "url_parameter"):
        _word("the %s name" % ("header" if ctype == "http_header" else "parameter"),
              item.get("param"), re.compile(r"^[A-Za-z0-9_\-]+$"))
    if ctype == "source_ip" and value:
        from .access import networks   # here: access imports the app, which imports more than this module may
        _good, bad = networks(value)
        if bad:
            raise ValueError("not a network: %s" % ", ".join(bad[:3]))


def check_rule(item):
    """Refuse a rule whose line would not say what was typed.

    Raises ValueError with the reason. A header name is one word; a redirect
    location is one word too, and both the location and a header's value
    are written quoted, so a `#` in them is safe -- a line break is not.
    A custom rule is the raw-directive field and is left alone.
    """
    rtype = _choice("the action", item.get("type"), ACTIONS) or "use_backend"
    _choice("the test", item.get("test"), ("if", "unless"))
    if rtype == "custom":
        return
    p1, p2 = _text(item.get("param1")), _text(item.get("param2"))
    if _has_control(p1) or _has_control(p2):
        raise ValueError("a rule's values cannot contain a line break or control character")
    if rtype in ("http_request_set_header", "http_request_del_header", "http_response_set_header"):
        if not p1:
            raise ValueError("this action needs a header name")
        _word("the header name", p1, re.compile(r"^[A-Za-z0-9_\-]+$"))
    if rtype == "redirect_location":
        if not p1:
            raise ValueError("this action needs a location to redirect to")
        if re.search(r"\s", p1):
            raise ValueError("the location cannot contain spaces")


def mode_clashes(hp):
    """Conditions tested where they can never match: an HTTP-only test on a
    TCP listener, or the TLS name on an HTTP one. One sentence each, stable
    in order, so a save can tell what it adds from what was already there."""
    conds = {c.get("id"): c for c in hp.get("conditions") or []}
    rules = {r.get("id"): r for r in hp.get("rules") or []}
    out = []

    def look(mode, rule_ids, where):
        for rid in rule_ids or []:
            r = rules.get(rid)
            if not r:
                continue
            for cid in (r.get("any_of") or []) + (r.get("conditions") or []):
                c = conds.get(cid)
                if not c:
                    continue
                t = c.get("type", "custom")
                if mode == "tcp" and t in HTTP_ONLY_CONDS:
                    out.append("\"%s\" tests the HTTP request, which %s forwards raw TCP and never "
                               "reads; it would never match there" % (c.get("name", cid), where))
                elif mode == "http" and t in TCP_ONLY_CONDS:
                    out.append("\"%s\" tests the TLS server name in the raw hello, which %s -- an "
                               "HTTP listener -- never sees; it would never match there"
                               % (c.get("name", cid), where))

    for fe in hp.get("frontends") or []:
        look(fe.get("mode", "http"), fe.get("rules"), "the Public Service \"%s\"" % fe.get("name", "?"))
    for be in hp.get("backends") or []:
        look(be.get("mode", "http"), be.get("rules"), "the Backend Pool \"%s\"" % be.get("name", "?"))
    return out


# --------------------------------------------------------------------------
# Backend Pools

def check_pool(item):
    """Refuse a pool whose rate limit would not render, before it is stored.

    Raises ValueError with the reason. The renderer treats anything that is
    not a positive whole number as no limit, so a typo accepted here would
    save as a limit and serve as none -- the one outcome worse than an error.
    """
    rate, window = item.get("rate_limit"), item.get("rate_window")
    if rate not in ("", None):
        try:
            r = int(str(rate).strip())
        except (TypeError, ValueError):
            raise ValueError("the rate limit must be a whole number of requests per client")
        if r < 1:
            raise ValueError("the rate limit must be at least 1, or empty for no limit")
    if window not in ("", None):
        try:
            w = int(str(window).strip())
        except (TypeError, ValueError):
            raise ValueError("the rate window must be a whole number of seconds")
        if not 1 <= w <= 3600:
            raise ValueError("the rate window must be between 1 and 3600 seconds")
    # A redirect: the wizard checks these, the Backend Pools editor and the
    # API store what they are given, and the renderer writes it out.
    # Countries for Cloudflare: a code it would never see is a typo, and a
    # limit nobody can meet is the one outcome worse than an error.
    if item.get("cf_countries"):
        from .cloudflare import check_countries   # here: cloudflare imports more than this module may
        item["cf_countries"] = check_countries(item["cf_countries"])
    to = str(item.get("redirect_to") or "").strip()
    if to and not plain_url(to):
        raise ValueError("a redirect needs an address starting with http:// or https://")
    if item.get("redirect_code") not in ("", None):
        try:
            code = int(str(item["redirect_code"]).strip())
        except (TypeError, ValueError):
            code = 0
        if code not in (301, 302, 307, 308):
            raise ValueError("a redirect is answered with 301, 302, 307 or 308")
    # The fields that become one word, or one line, of the backend.
    _choice("the mode", item.get("mode"), ("http", "tcp"))
    balance = _text(item.get("balance"))
    if balance:
        _refuse_breakers("the balance algorithm", balance)
        if balance.split()[0].split("(")[0] not in BALANCES:
            raise ValueError("the balance algorithm must be one of %s, not %r" % (", ".join(BALANCES), balance))
    _choice("the persistence", item.get("persistence"), ("none", "cookie", "source"))
    _word("the cookie name", item.get("cookie_name"), TOKEN_RE)
    for key, what in (("timeout_connect", "the connect timeout"), ("timeout_server", "the server timeout"),
                      ("timeout_check", "the check timeout"), ("stick_expire", "the stick table expiry")):
        _time(what, item.get(key))
    size = _text(item.get("stick_size"))
    if size and not SIZE_RE.match(size):
        raise ValueError("the stick table size must be a number, with k, m or g if needed -- not %r" % size)
    _choice("the stick table type", item.get("stick_type"), ("ip", "ipv6"))
