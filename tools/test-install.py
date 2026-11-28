#!/usr/bin/env python3
"""What install.sh does about acme.sh, run against stand-ins.

    python3 tools/test-install.py

The installer's functions are sourced without its main, with curl, tar and
the unpacked acme.sh replaced by stand-ins that record what they were given.
Pinned here: an installed acme.sh older than the pinned release is updated,
one at or past it is kept; the tarball is unpacked in a directory mktemp
made, never a fixed name under /tmp; that directory is gone afterwards; and
the certificate directory ends up 0700 even when it was 0755 before.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
INSTALL = ROOT / "install.sh"
fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


r = subprocess.run(["bash", "-n", str(INSTALL)], capture_output=True, text=True)
ok(r.returncode == 0, "install.sh parses: %s" % (r.stderr.strip() or "ok"))

# install.sh ends in `main "$@"`; everything above it is functions and
# settings, which the harness sources and then calls one at a time.
FUNCS = INSTALL.read_text().rsplit('\nmain "$@"', 1)[0]

HARNESS = r'''
set -euo pipefail
%(funcs)s
# -- stand-ins: curl writes a fake tarball, tar unpacks a fake acme.sh that
# installs itself by copying into the home and recording where it ran from.
curl() {
    local out=""
    while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac; done
    echo "curl -> $out" >> "$LOG"
    printf 'tarball' > "$out"
}
tar() {
    local dir=""
    while [ $# -gt 0 ]; do case "$1" in -C) dir="$2"; shift 2 ;; *) shift ;; esac; done
    echo "tar -> $dir" >> "$LOG"
    cat > "$dir/acme.sh" <<EOF
#!/bin/sh
echo "acme.sh --install from \$(pwd) \$*" >> "$LOG"
mkdir -p "$ACME_HOME"
printf '#!/bin/sh\nVER=$ACME_VERSION\n' > "$ACME_HOME/acme.sh"
chmod 0755 "$ACME_HOME/acme.sh"
EOF
    chmod 0755 "$dir/acme.sh"
}
%(body)s
'''


def harness(body, env):
    full = dict(os.environ, **env)
    script = HARNESS % {"funcs": FUNCS, "body": body}
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=full)


def setup(have=None):
    d = tempfile.mkdtemp(prefix="ham-install-")
    home = os.path.join(d, "acme-home")
    if have is not None:
        os.makedirs(home)
        pathlib.Path(home, "acme.sh").write_text("#!/bin/sh\nVER=%s\n" % have)
        os.chmod(os.path.join(home, "acme.sh"), 0o755)
        pathlib.Path(home, "account.conf").write_text("ACCOUNT_EMAIL='a@example.com'\n")
    log = os.path.join(d, "log")
    return d, home, log


def log_of(path):
    try:
        return pathlib.Path(path).read_text()
    except OSError:
        return ""


print("installing acme.sh")
d, home, log = setup()
r = harness('install_acme; echo "ACME_TMP_=[$ACME_TMP_] ACME_OK=$ACME_OK"',
            {"HAM_ACME_HOME": home, "HAM_ACME_VERSION": "3.1.7", "LOG": log})
ok(r.returncode == 0 and "ACME_OK=1" in r.stdout, "a fresh install succeeds: %s" % (r.stderr.strip()[-120:] or r.stdout.strip()[-80:]))
unpacked = [l.split("-> ", 1)[1] for l in log_of(log).splitlines() if l.startswith("tar -> ")]
ok(unpacked and unpacked[0] != "/tmp/acme" and os.path.basename(unpacked[0]).startswith("tmp."),
   "the tarball is unpacked in a directory mktemp made, not /tmp/acme: %s" % (unpacked or "none"))
ok(unpacked and not os.path.exists(unpacked[0]), "and that directory is gone afterwards")
ok("ACME_TMP_=[]" in r.stdout, "nothing is left for the exit trap to clean")
ok(pathlib.Path(home, "acme.sh").read_text().endswith("VER=3.1.7\n"), "acme.sh 3.1.7 is in the home")

print("an acme.sh already there")
d, home, log = setup(have="3.0.9")
r = harness("install_acme", {"HAM_ACME_HOME": home, "HAM_ACME_VERSION": "3.1.7", "LOG": log})
ok(r.returncode == 0 and "Updating acme.sh 3.0.9" in r.stdout,
   "an acme.sh older than the pin is updated, and the installer says so: %s" % r.stdout.strip().splitlines()[-1:])
ok("acme.sh --install" in log_of(log) and pathlib.Path(home, "acme.sh").read_text().endswith("VER=3.1.7\n"),
   "it is now 3.1.7")
ok(pathlib.Path(home, "account.conf").read_text() == "ACCOUNT_EMAIL='a@example.com'\n",
   "and account.conf is as it was")
for have in ("3.1.7", "3.2.0", "3.1.10"):
    d, home, log = setup(have=have)
    r = harness("install_acme", {"HAM_ACME_HOME": home, "HAM_ACME_VERSION": "3.1.7", "LOG": log})
    ok(r.returncode == 0 and "already installed" in r.stdout and log_of(log) == "",
       "acme.sh %s is kept: nothing is fetched" % have)
d, home, log = setup(have="3.0.9")
r = harness("install_acme; install_acme", {"HAM_ACME_HOME": home, "HAM_ACME_VERSION": "3.1.7", "LOG": log})
ok(r.returncode == 0 and log_of(log).count("acme.sh --install") == 1 and "already installed" in r.stdout,
   "run twice, the second run has nothing to do")
d, home, log = setup()
r = harness("install_acme", {"HAM_ACME_HOME": home, "HAM_ACME_VERSION": "3.1.7", "HAM_SKIP_ACME": "1", "LOG": log})
ok(r.returncode == 0 and "Skipping" in r.stdout and log_of(log) == "", "--skip-acme still skips")

print("the certificate directory")
d = tempfile.mkdtemp(prefix="ham-install-")
for n in ("src/ham", "src/static", "certs", "data", "dest"):
    os.makedirs(os.path.join(d, n))
os.chmod(os.path.join(d, "certs"), 0o755)
pathlib.Path(d, "src", "app.py").write_text("# app\n")
pathlib.Path(d, "src", "ham", "__init__.py").write_text("# ham\n")
pathlib.Path(d, "src", "static", "index.html").write_text("<html></html>\n")
r = harness('SRC="%s/src"; install_app' % d,
            {"HAM_DEST": os.path.join(d, "dest"), "HAM_DATA_DIR": os.path.join(d, "data"),
             "HAM_CERT_DIR": os.path.join(d, "certs"), "LOG": os.path.join(d, "log")})
ok(r.returncode == 0, "install_app runs: %s" % (r.stderr.strip()[-120:] or "ok"))
ok(oct(os.stat(os.path.join(d, "certs")).st_mode & 0o777) == "0o700",
   "a certificate directory that was 0755 is 0700 afterwards")
ok(oct(os.stat(os.path.join(d, "data")).st_mode & 0o777) == "0o700", "and so is the data directory")

print()
print("FAILED: %d" % len(fails) if fails else "all passed")
sys.exit(1 if fails else 0)
