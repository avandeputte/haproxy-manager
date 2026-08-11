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
APP = (ROOT / "app.py").read_text()
INSTALL = (ROOT / "install.sh").read_text()
DOCS = {p.name: p.read_text() for p in [ROOT / "README.md", *(ROOT / "docs").glob("*.md")]}
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
