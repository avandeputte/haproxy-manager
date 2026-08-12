"""Serving index.html and the assets."""

from flask import Response
from flask import abort
from flask import send_from_directory

from .base import STATIC_DIR, VERSION, app

# --------------------------------------------------------------------------

# Flask's own static route is switched off (static_folder=None), so this is the
# only way anything is served from disk. The UI is a directory of modules, so
# what may be served is decided by extension: send_from_directory refuses to
# escape STATIC_DIR, which makes the extension the whole policy. These answer
# without a session, because the sign-in page has to render before anyone can
# sign in.
STATIC_SUFFIXES = (".css", ".js", ".svg", ".png", ".ico", ".map", ".woff2")


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
    html = (STATIC_DIR / "index.html").read_text().replace("__VERSION__", VERSION)
    return Response(html, mimetype="text/html", headers={
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
