#!/usr/bin/env python3
"""Check that the documentation still describes the code.

Documentation goes stale silently: a route is added, a default changes, an
option is removed, and the README keeps saying what used to be true. This
compares the checkable claims against the source and fails when they diverge.

    python3 tools/check-docs.py

It only checks what can be checked mechanically -- counts, names, defaults,
paths. Prose still needs reading.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# The application is app.py plus the ham package. Everything below asks
# questions of "the code" rather than of a particular file, so they are read as
# one -- which also means a module added to ham/ is covered without editing
# anything here.
SOURCES = [ROOT / "app.py"] + sorted((ROOT / "ham").glob("*.py"))
APP = "\n".join(p.read_text() for p in SOURCES)
INSTALL = (ROOT / "install.sh").read_text()
# refactoring.md is a working note that is deliberately not published, so
# it is excluded here too -- otherwise a claim would be satisfied locally
# by a file that does not exist in a fresh checkout.
DOCS = {p.name: p.read_text() for p in [ROOT / "README.md", *(ROOT / "docs").glob("*.md")]
        if p.name != "refactoring.md"}
ALL_DOCS = "\n".join(DOCS.values())

problems = []
checks = 0


def check(ok, what, detail=""):
    global checks
    checks += 1
    if not ok:
        problems.append("%s%s" % (what, (": " + detail) if detail else ""))


# -- routes ----------------------------------------------------------------
routes = re.findall(r'@app\.(?:route|get|post|put|delete)\("([^"]+)"', APP)
claimed = re.search(r"Of (\d+) routes", ALL_DOCS)
check(claimed is not None, "the route-count claim is missing from the docs")
if claimed:
    check(int(claimed.group(1)) == len(routes),
          "the documented route count is wrong",
          "docs say %s, the code has %d" % (claimed.group(1), len(routes)))

public = re.search(r"PUBLIC_PATHS = \{([^}]*)\}", APP)
check(public is not None, "PUBLIC_PATHS could not be found in app.py")
if public:
    names = re.findall(r'"([^"]+)"', public.group(1))
    check(len(names) == 3, "the number of unauthenticated paths changed",
          "now %s -- the security section says three" % (names,))
    for path in names:
        check(path in ALL_DOCS, "an unauthenticated path is undocumented", path)

# -- environment variables -------------------------------------------------
used = set(re.findall(r'HAM_[A-Z_]+', APP)) | set(re.findall(r'HAM_[A-Z_]+', INSTALL))
documented = set(re.findall(r'HAM_[A-Z_]+', ALL_DOCS))
for name in sorted(used - documented):
    check(False, "an environment variable is undocumented", name)
for name in sorted(documented - used):
    check(False, "the docs describe an environment variable the code ignores", name)

# -- defaults quoted in the docs -------------------------------------------
for const, env in [("THREADS", "HAM_THREADS"),
                   ("PEER_CONNECT_TIMEOUT", "HAM_PEER_CONNECT_TIMEOUT"),
                   ("PEER_READ_TIMEOUT", "HAM_PEER_READ_TIMEOUT"),
                   ("PUSH_READ_TIMEOUT", "HAM_PUSH_READ_TIMEOUT"),
                   ("CLUSTER_POLL_SECONDS", "HAM_CLUSTER_POLL"),
                   ("CLUSTER_SNAPSHOT_MAX_AGE", "HAM_CLUSTER_MAX_AGE"),
                   ("WATCHDOG_PROBE_TIMEOUT", "HAM_WATCHDOG_PROBE_TIMEOUT"),
                   ("WATCHDOG_SELF_TIMEOUT", "HAM_WATCHDOG_SELF_TIMEOUT"),
                   ("PORT", "HAM_PORT")]:
    m = re.search(r'%s = .*?os\.environ\.get\("%s", "([^"]+)"\)' % (const, env), APP)
    check(m is not None, "could not read the default for %s" % env)
    if not m:
        continue
    value = m.group(1)
    # the docs state defaults in a table cell: | `HAM_X` | `15` | ...
    row = re.search(r'\| `%s`[^|]*\| `?([^|`]+)`? *\|' % env, ALL_DOCS)
    if row:
        check(row.group(1).strip().strip("`") == value,
              "a documented default is wrong for %s" % env,
              "docs say %r, the code uses %r" % (row.group(1).strip(), value))

# -- installer flags -------------------------------------------------------
flags = set(re.findall(r'^\s+(--[a-z-]+)\)', INSTALL, re.M))
for flag in sorted(flags):
    check(flag in ALL_DOCS, "an installer flag is undocumented", flag)

# -- paths the docs promise ------------------------------------------------
for path in ["/var/lib/haproxy-manager/config.json", "/opt/haproxy-manager",
             "/etc/haproxy/haproxy.cfg", "/etc/keepalived/keepalived.conf"]:
    check(path in ALL_DOCS, "a path is missing from the docs", path)

# -- version consistency ---------------------------------------------------
# Three components, so the package filenames match VERSION exactly rather than
# being normalised to semver by the packager.
version = (ROOT / "VERSION").read_text().strip()
check(re.fullmatch(r"\d+\.\d+\.\d+", version) is not None,
      "VERSION is not three components", version)
for name, text in DOCS.items():
    for quoted in re.findall(r'haproxy-manager:(\d+\.\d+(?:\.\d+)?)', text):
        check(quoted == version, "%s pins an old image tag" % name,
              "says %s, VERSION is %s" % (quoted, version))
    # the documented package filenames are commands people paste
    for quoted in re.findall(r'haproxy-manager[_-](\d+\.\d+\.\d+)[_-]', text):
        check(quoted == version, "%s names an old package file" % name,
              "says %s, VERSION is %s" % (quoted, version))

# -- recipes ---------------------------------------------------------------
# Every recipe should be listed in the documentation, and every one should come
# with example servers -- the shape of the answer is half of what they are for.
#
# A recipe fills the wizard by field name, and a name the wizard does not have
# is skipped in silence -- the recipe simply does less than it says. So the
# names and the select values are checked against WIZ_FIELDS itself.
import json
wiz = (ROOT / "static" / "js" / "pages" / "services.js").read_text()
wiz = wiz[wiz.index("export const WIZ_FIELDS"):]
wiz = wiz[:wiz.index("\n];")]
WIZ_KEYS, WIZ_OPTIONS = set(), {}
for row in re.findall(r"\{k:\"(\w+)\"(.*?)\}", wiz, re.S):
    WIZ_KEYS.add(row[0])
    opts = re.search(r"o:\[(.*?)\]", row[1], re.S)
    if opts:
        WIZ_OPTIONS[row[0]] = set(re.findall(r"\"([^\"]*)\"", opts.group(1)))
check(len(WIZ_KEYS) > 15, "could not read WIZ_FIELDS out of services.js",
      "found %d" % len(WIZ_KEYS))

recipe_files = sorted((ROOT / "static" / "recipes").glob("*.json"))
check(len(recipe_files) > 0, "no recipes found in static/recipes")
for path in recipe_files:
    try:
        r = json.loads(path.read_text())
    except ValueError as e:
        check(False, "a recipe is not valid JSON", "%s: %s" % (path.name, e))
        continue
    rid = path.stem
    check(bool(r.get("name")), "a recipe has no name", rid)
    check(r.get("name", "") in ALL_DOCS, "a recipe is undocumented", r.get("name", rid))
    check(bool(r.get("summary")), "a recipe has no summary", rid)
    fields = r.get("fields") or {}
    check(bool(fields.get("target")), "a recipe has no example servers", rid)
    check(bool(fields.get("url")), "a recipe has no example address", rid)
    check("id" not in r, "a recipe repeats its id in the file; the filename is the id", rid)
    for k, v in fields.items():
        check(k in WIZ_KEYS, "a recipe sets a field the wizard does not have",
              "%s: %s" % (rid, k))
        if k in WIZ_OPTIONS:
            check(str(v) in WIZ_OPTIONS[k], "a recipe sets a value not in the list",
                  "%s: %s=%r, not one of %s"
                  % (rid, k, v, ", ".join(sorted(WIZ_OPTIONS[k]))))
    # An http check with a path but no interval inherits the 2s default, which
    # is far too eager for anything that renders a page to answer.
    if fields.get("health") == "http":
        check(bool(fields.get("health_interval")),
              "an http recipe does not say how often to check", rid)
    check("order" not in r, "a recipe still carries the removed order field", rid)

# The picker sorts by category, then by name; the documented table is meant to
# be the same list in the same order, so someone reading the docs and someone
# scrolling the dropdown are looking at the same thing.
RANK = {"Web": 0, "Databases": 1, "Applications": 2, "Infrastructure": 3}
by_name = {}
for path in recipe_files:
    try:
        r = json.loads(path.read_text())
    except ValueError:
        continue
    by_name[r.get("name", "")] = RANK.get(r.get("category", "Other"), 9)
conf = (ROOT / "docs" / "configuration.md").read_text()
table = conf[conf.index("**Web**\n\n| Recipe |"):conf.index("Every one carries example")]
listed = [m for m in re.findall(r"^\| (.+?) \| .* \|$", table, re.M)
          if m not in ("Recipe", "---")]
check(len(listed) == len(recipe_files),
      "the documented recipe table does not list every recipe",
      "%d rows, %d files" % (len(listed), len(recipe_files)))
expected = sorted(listed, key=lambda n: (by_name.get(n, 9), n.casefold()))
check(listed == expected, "the documented recipes are not in the picker's order",
      next((("%r comes before %r" % (a, b))
            for a, b in zip(listed, expected) if a != b), ""))

# -- menu paths the UI tells people to follow ------------------------------
# "Manage them under ACME > Certificates" stayed true-looking after
# Certificates moved to the top of the menu: both names still exist, only the
# hierarchy changed. So what is checked is the hierarchy -- a page at the top
# of the menu must not be described as living inside another page.
shell = (ROOT / "static" / "js" / "shell.js").read_text()
nav = shell[shell.index("export const NAV"):]
nav = nav[:nav.index("\n];")]
GROUPS = {"Advanced", "Settings", "HAProxy"}
for grp in re.findall(r'\["grp","([^"]+)"', nav):
    GROUPS.update(w.strip().title() for w in re.split(r"[·.]", grp) if w.strip())
PAGES = {m for m in re.findall(r'","([^"]+)"\]', nav)}
HEADINGS = set()
for js in sorted((ROOT / "static" / "js").rglob("*.js")):
    HEADINGS.update(h.strip() for h in re.findall(r"<h2>([^<&]+)</h2>", js.read_text()))
HEADINGS |= {"This node", "Other nodes"}      # cards whose heading carries markup


def _resolve(words, places, from_end):
    """The longest run of words that names a place, read from one end."""
    for n in range(len(words), 0, -1):
        part = " ".join(words[-n:] if from_end else words[:n])
        for cand in places:
            if part.lower() == cand.lower():
                return cand
    return None


# People say "ACME" for the page called "ACME Settings", so the first word of
# a page name counts as naming it -- otherwise the wording that prompted this
# check would not have been recognised as a menu path at all.
PARENTS = GROUPS | PAGES | {p.split()[0] for p in PAGES if " " in p}

SEP = r"\s*(?:&rsaquo;|&gt;|>|\u2192|\u203a)\s*"
PATH = re.compile(r"([A-Za-z' ]{3,40}?)" + SEP + r"([A-Za-z' ]{3,40})")
for src in (ROOT / "static" / "js", ROOT / "ham"):
    for f in sorted(src.rglob("*.js")) + sorted(src.rglob("*.py")):
        for left, right in PATH.findall(f.read_text()):
            parent = _resolve(left.split(), PARENTS, True)
            leaf = _resolve(right.split(), PAGES | HEADINGS | GROUPS, False)
            if not leaf or not parent:
                continue                    # not a menu path, just prose
            if leaf in PAGES and parent not in GROUPS:
                check(False, "the UI describes a page as living inside another page",
                      "%s says %r, but %r is at the top of the menu"
                      % (f.name, parent + " > " + leaf, leaf))

# The section called System is called Settings now.
for src in (ROOT / "static" / "js", ROOT / "ham"):
    for f in sorted(src.rglob("*.js")) + sorted(src.rglob("*.py")):
        for m in re.findall(r"System\s*(?:&rsaquo;|>|\u2192)\s*[A-Z]", f.read_text()):
            check(False, "the UI still calls the Settings section System", f.name)

# -- strings the state refactor could have damaged --------------------------
# Moving the shared variables into state.js rewrote every occurrence of their
# names, including ones inside strings: className="who" became
# className="state.who", which silently dropped the styling.
CLASS_OR_ID = re.compile(r"(?:className|id)\s*=\s*[\"']([^\"']*)[\"']")
for js in sorted((ROOT / "static" / "js").rglob("*.js")):
    text = js.read_text()
    for m in CLASS_OR_ID.finditer(text):
        check("state." not in m.group(1),
              "a class or id looks like the state refactor rewrote it",
              "%s in %s" % (m.group(1), js.name))

# -- cache busting ---------------------------------------------------------
# Assets are cached for a year, which is only safe while their URL carries the
# version. An unversioned stylesheet or module reference would be served stale
# after an upgrade, and a page loading a mixture of old and new modules fails
# in ways that look like nothing else.
index = (ROOT / "static" / "index.html").read_text()
for m in re.finditer(r'(?:href|src)="(/static/[^"]+\.(?:css|js))"', index):
    check(m.group(1).startswith("/static/v/__VERSION__/"),
          "an asset is referenced without the version in its path", m.group(1))
check('__VERSION__' in index, "index.html has no version placeholder to substitute")

# -- the static manifest ---------------------------------------------------
# install.sh's offline fallback fetches exactly what static/FILES lists, so a
# module missing from it would simply not be installed.
listed = set((ROOT / "static" / "FILES").read_text().split())
actual = {str(p.relative_to(ROOT / "static")) for p in (ROOT / "static").rglob("*")
          if p.is_file() and p.name != "FILES"}
for missing in sorted(actual - listed):
    check(False, "a static file is missing from static/FILES", missing)
for extra in sorted(listed - actual):
    check(False, "static/FILES lists a file that is not there", extra)

# The same for the package, and it matters more: a static file missing from the
# manifest loses an icon, a module missing from it means the app does not start.
listed = set((ROOT / "ham" / "FILES").read_text().split())
actual = {p.name for p in (ROOT / "ham").glob("*.py")}
for missing in sorted(actual - listed):
    check(False, "a module is missing from ham/FILES", missing)
for extra in sorted(listed - actual):
    check(False, "ham/FILES lists a module that is not there", extra)
check("__init__.py" in listed, "ham/FILES does not list __init__.py")

# `from . import cluster` then `cluster.sync_push(...)` only works while nothing
# nearer is called `cluster`. Python does not complain about the shadowing -- it
# quietly uses the local variable and fails somewhere else entirely -- so it is
# checked here. This is why the peers module is called `peering`.
import ast
for path in sorted((ROOT / "ham").glob("*.py")):
    tree = ast.parse(path.read_text())
    siblings = {a.name for n in tree.body
                if isinstance(n, ast.ImportFrom) and n.level == 1 and n.module is None
                for a in n.names}
    for fn in [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        bound = {a.arg for a in fn.args.args + fn.args.kwonlyargs}
        for n in ast.walk(fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                bound.add(n.id)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                bound |= {a.asname or a.name.split(".")[0] for a in n.names}
        for clash in sorted(bound & siblings):
            check(False, "a local variable hides an imported module",
                  "%s: %s() binds %r" % (path.name, fn.name, clash))
# Every module has to be imported for its routes to register, so one that
# nothing imports is dead weight that still ships.
init = (ROOT / "ham" / "__init__.py").read_text()
for mod in sorted(actual - {"__init__.py", "base.py"}):
    check(re.search(r"^\s+%s,$" % mod[:-3], init, re.M) is not None,
          "ham/__init__.py does not import a module, so its routes never register",
          mod)

# -- claims the code has outgrown ------------------------------------------
# The cluster was two nodes once. Wording that still says so is wrong, and
# nothing else here would catch it: it is prose, not a name or a number.
for phrase in ["active-passive pair", "active/passive pair", "the two nodes",
               "both nodes", "on BOTH nodes"]:
    for name, text in list(DOCS.items()) + [("app.py", APP), ("install.sh", INSTALL)]:
        check(phrase.lower() not in text.lower(),
              "wording that assumes exactly two nodes", "%r in %s" % (phrase, name))

# -- things that were removed must not linger ------------------------------
for gone in ["apprise", "HAM_VENV", "--with-apprise"]:
    for name, text in list(DOCS.items()) + [("app.py", APP), ("install.sh", INSTALL)]:
        check(gone.lower() not in text.lower(), "a removed feature is still mentioned",
              "%s in %s" % (gone, name))

print("checked %d claims" % checks)
if problems:
    print("\n%d problem(s):" % len(problems))
    for p in problems:
        print("  - %s" % p)
    sys.exit(1)
print("the documentation matches the code")
