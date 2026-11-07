"""Custom error pages: what HAProxy answers with when it cannot forward.

A page is part of the shared configuration, so it reaches every node the way
everything else does -- there is no second thing to synchronise. HAProxy,
though, reads an error page from a file, so each node writes its pages to
disk before it validates or applies a configuration that names them.

A page serves one or more status codes. HAProxy can only replace the
responses it generates itself, which is a fixed set (400 through 504 below);
a 404 from a server behind the proxy passes through untouched, since the
server's answer is the server's business. The whole response -- headers and
body -- has to fit HAProxy's buffer, 16 kB unless tuned, which rules out a
page with a large image embedded in it: link the image, or inline an SVG.
"""

import re

from .base import ERROR_DIR, log
from .util import _sec

# The responses HAProxy generates itself, and so the only ones a page can
# replace. The reason phrases are what the status line carries.
CODES = {
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 407: "Proxy Authentication Required",
    408: "Request Timeout", 410: "Gone", 413: "Payload Too Large",
    425: "Too Early", 429: "Too Many Requests",
    431: "Request Header Fields Too Large", 500: "Internal Server Error",
    501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable",
    504: "Gateway Timeout",
}

# tune.bufsize is 16384 by default and the response has to fit it whole,
# headers included, with room for HAProxy's own bookkeeping around it.
MAX_HTML = 14 * 1024

# What a page may say in place of the code and its reason phrase, so one
# page can stand for several codes.
PLACEHOLDERS = {"{error_code}": lambda code: str(code),
                "{error_message}": lambda code: CODES[code]}


def codes_of(page):
    """The status codes a page serves, as sorted ints.

    Raises ValueError for one HAProxy cannot replace.
    """
    out = []
    for tok in re.split(r"[\s,]+", str(page.get("codes") or "")):
        if not tok:
            continue
        try:
            code = int(tok)
        except ValueError:
            raise ValueError("\"%s\" is not a status code" % tok)
        if code not in CODES:
            raise ValueError("HAProxy cannot replace a %d: it only generates %s"
                             % (code, ", ".join(str(c) for c in sorted(CODES))))
        if code not in out:
            out.append(code)
    return sorted(out)


def check(item):
    """Refuse a page that would not render, before it is stored.

    Raises ValueError with the reason. HAProxy would refuse it at Apply too,
    but then every Apply fails until someone finds which page is at fault.
    """
    if not (item.get("name") or "").strip():
        raise ValueError("a page needs a name")
    if not codes_of(item):
        raise ValueError("a page needs at least one status code, e.g. 503")
    html = item.get("html") or ""
    if not html.strip():
        raise ValueError("the page is empty")
    if len(html.encode("utf-8")) > MAX_HTML:
        raise ValueError("the page is %d bytes and HAProxy's buffer holds %d: keep images "
                         "as links or inline SVG rather than embedding them"
                         % (len(html.encode("utf-8")), MAX_HTML))


def pages(cfg):
    return (cfg.get("haproxy") or {}).get("errorpages") or []


def body(page, code):
    """The page's HTML for this code, placeholders filled in."""
    html = page.get("html") or ""
    for key, fill in PLACEHOLDERS.items():
        html = html.replace(key, fill(code))
    return html.encode("utf-8")


def response(page, code):
    """The whole HTTP response HAProxy sends as it is, bytes for bytes."""
    html = body(page, code)
    head = ("HTTP/1.0 %d %s\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: close\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Length: %d\r\n\r\n" % (code, CODES[code], len(html)))
    return head.encode("ascii") + html


def path(page, code, kind="http"):
    """Where the page for this code is on disk: `.http` is the whole
    response, for errorfile; `.html` the body alone, for http-request return."""
    return ERROR_DIR / ("%s-%d.%s" % (_sec(page.get("name")), code, kind))


def files(cfg):
    """Every file the pages become: {path: bytes}."""
    out = {}
    for page in pages(cfg):
        try:
            codes = codes_of(page)
        except ValueError:
            continue                    # refused at the form; nothing to write
        for code in codes:
            out[path(page, code)] = response(page, code)
            out[path(page, code, "html")] = body(page, code)
    return out


def write_files(cfg):
    """Put the pages on disk as the configuration names them; say which changed.

    Files from a page that was renamed or deleted are removed -- the
    directory holds nothing but these, so anything else there is a leftover.
    Returns the names written or removed.
    """
    wanted = files(cfg)
    changed = []
    if wanted or ERROR_DIR.exists():
        ERROR_DIR.mkdir(parents=True, exist_ok=True)
    for p, content in wanted.items():
        try:
            if p.exists() and p.read_bytes() == content:
                continue
        except OSError:
            pass
        p.write_bytes(content)
        p.chmod(0o644)
        changed.append(p.name)
    if ERROR_DIR.exists():
        for p in ERROR_DIR.iterdir():
            if p.suffix in (".http", ".html") and p not in wanted:
                try:
                    p.unlink()
                    changed.append("removed " + p.name)
                except OSError as e:
                    log.warning("could not remove the stale error page %s: %s", p, e)
    return changed


def directives(selected):
    """The errorfile lines for these pages, in the order they are given.

    When two of them claim a code, the later wins, which is also what HAProxy
    does with two errorfile lines for one code.
    """
    out = []
    for page in selected:
        try:
            codes = codes_of(page)
        except ValueError:
            continue
        for code in codes:
            out.append("errorfile %d %s" % (code, path(page, code)))
    return out


def everywhere(cfg):
    """The pages that stand for every service."""
    return [p for p in pages(cfg) if p.get("everywhere", True)]


def chosen(cfg, ids):
    """The pages a pool picked for itself, in the order it picked them."""
    by_id = {p.get("id"): p for p in pages(cfg)}
    return [by_id[i] for i in (ids or []) if i in by_id]


def page_for(cfg, pool, code):
    """The page that answers this code for this pool, if any: the pool's own
    choice first, then what stands for every service; the last claim wins."""
    found = None
    for page in everywhere(cfg) + chosen(cfg, pool.get("error_pages")):
        try:
            if code in codes_of(page):
                found = page
        except ValueError:
            continue
    return found
