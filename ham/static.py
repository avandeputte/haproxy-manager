"""Serving index.html and the assets."""

from flask import Response
from flask import abort
from flask import send_from_directory
import base64
import hashlib
import re

from .base import STATIC_DIR, VERSION, app

# --------------------------------------------------------------------------

# Flask's own static route is switched off (static_folder=None), so this is the
# only way anything is served from disk. The UI is a directory of modules, so
# what may be served is decided by extension: send_from_directory refuses to
# escape STATIC_DIR, which makes the extension the whole policy. These answer
# without a session, because the sign-in page has to render before anyone can
# sign in.
STATIC_SUFFIXES = (".css", ".js", ".svg", ".png", ".ico")


def index_html():
    return (STATIC_DIR / "index.html").read_text().replace("__VERSION__", VERSION)


_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)
_policy = None


def content_security_policy():
    """What the page may load and run, for the Content-Security-Policy header.

    The UI loads nothing from anywhere else, so everything is 'self'. The one
    exception is the theme bootstrap, an inline script in index.html that has
    to run before the first paint; rather than allow inline scripts wholesale
    -- which would allow an injected one too -- its exact text is hashed, so
    only that script runs. The hash is taken from the page as served, and
    computed once: the page does not change while the service runs. Inline
    styles stay allowed; the UI sets them on the elements it builds, and a
    style can show something, not run it. A frame is refused outright, as
    X-Frame-Options says too for the browsers that read that instead.
    """
    global _policy
    if _policy is None:
        scripts = ["'self'"] + [
            "'sha256-%s'" % base64.b64encode(hashlib.sha256(m.group(1).encode()).digest()).decode()
            for m in _INLINE_SCRIPT.finditer(index_html())]
        _policy = ("default-src 'self'; script-src %s; style-src 'self' 'unsafe-inline'; "
                   "img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; "
                   "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
                   % " ".join(scripts))
    return _policy


@app.after_request
def _harden(resp):
    """The headers every answer carries, page and API alike.

    nosniff keeps a browser from running a JSON answer or an upload as a
    script because it guessed at the type; DENY and frame-ancestors keep the
    UI out of another site's frame, where a click could be steered onto Apply;
    same-origin keeps the page's address -- with whatever is in its hash --
    from being sent along to anywhere else.
    """
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Content-Security-Policy", content_security_policy())
    return resp


@app.get("/")
def index():
    """The page, with the version stamped into the asset URLs.

    A browser that kept yesterday's JavaScript would load a mixture of old and
    new modules, which fails in ways that look like nothing else. So the page
    itself is never cached, and everything it asks for lives under a path that
    contains the version -- change the version, change every URL, including the
    ones inside `import "./shell.js"`, because those resolve relative to the
    module that wrote them.
    """
    return Response(index_html(), mimetype="text/html", headers={
        "Cache-Control": "no-cache, must-revalidate",
    })


@app.get("/static/v/<ver>/<path:name>")
def static_versioned(ver, name):
    """Immutable: the URL changes whenever the version does."""
    if not name.endswith(STATIC_SUFFIXES):
        abort(404)
    resp = send_from_directory(STATIC_DIR, name)
    resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return resp


@app.get("/static/<path:name>")
def static_asset(name):
    """Unversioned, for things referenced from outside the page -- the icons a
    browser or a phone asks for by name. Revalidated rather than held."""
    if not name.endswith(STATIC_SUFFIXES):
        abort(404)
    return send_from_directory(STATIC_DIR, name, max_age=0, conditional=True)


@app.get("/favicon.ico")
def favicon():
    """Browsers ask for this whether or not the page links to it."""
    return send_from_directory(STATIC_DIR, "favicon.ico", max_age=86400)
