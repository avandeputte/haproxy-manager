"""Active Directory Certificate Services, through acme2certifier.

AD CS does not speak ACME. acme2certifier is an ACME server that passes
each request on to a CA that does not: for AD CS over MS-ICPR, the RPC
interface certreq uses, or through the CA's web enrollment pages. This
module runs it for the node: an ACME account with "adcs" as its CA holds
the CA's address, template and a service account, and when a certificate
is issued the node writes acme2certifier's configuration, starts it on
localhost, points acme.sh at it, and stops it again when acme.sh is done.

Nothing to supervise and no port to open: it runs for the minute an
issuance takes, on this node only, and two AD CS accounts simply take
turns. The image ships acme2certifier; a node installed from install.sh or
a package gets it on demand, as it gets the CrowdSec bouncer.
"""

from contextlib import contextmanager
from flask import jsonify
from flask import request
import configparser
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

from .base import A2C_DIR, A2C_PORT, A2C_STATE, DATA_DIR, app, log

# The release the image carries and a node installs on demand. The weekly
# upstream check (.github/workflows/upstream.yml) moves this, the Dockerfile's
# ARG and install.sh together; tools/check-docs.py holds them to one value.
A2C_VERSION = "0.46.4"
A2C_DEB = ("https://github.com/grindsa/acme2certifier/releases/download/%(v)s/"
           "acme2certifier_%(v)s-1_all.deb")
A2C_RPM = ("https://github.com/grindsa/acme2certifier/releases/download/%(v)s/"
           "acme2certifier-%(v)s-1.0.noarch.rpm")

METHODS = ("msicpr", "certsrv")
AUTH = {"msicpr": ("kerberos", "ntlm"), "certsrv": ("ntlm", "basic")}
HANDLER = {"msicpr": "acme2certifier.cahandlers.msicpr_ca_handler",
           "certsrv": "acme2certifier.cahandlers.mscertsrv_ca_handler"}
# What the account fields are called, with their defaults, in one place:
# the wizard creates an account from them and the editor shows them.
FIELDS = {"adcs_method": "msicpr", "adcs_host": "", "adcs_ca_name": "", "adcs_template": "WebServer",
          "adcs_domain": "", "adcs_dc": "", "adcs_user": "", "adcs_password": "", "adcs_auth": "",
          # Any acme2certifier setting the fields do not cover, as acme_srv.cfg
          # lines with their section headers, laid over the generated ones.
          "adcs_extra": ""}
# Sections the extra settings may not touch: the database is the node's.
EXTRA_KEEP_OUT = ("DBhandler",)

_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$")
# Something configparser can write and read back as one value.
_LINE = re.compile(r"^[^\x00-\x1f\x7f]*$")

# One acme2certifier at a time: it has the one port, and acme.sh keeps one
# account for it, so two issuances for AD CS wait for each other.
_serving = threading.Lock()


def is_adcs(acc):
    return (acc or {}).get("ca") == "adcs"


def auth_of(acc):
    """The authentication the account uses: what it says, or the method's first."""
    choices = AUTH.get(acc.get("adcs_method") or "msicpr", AUTH["msicpr"])
    return acc.get("adcs_auth") if acc.get("adcs_auth") in choices else choices[0]


def check_account(acc):
    """What an AD CS account refuses before it is stored. Raises ValueError with why."""
    method = acc.get("adcs_method") or "msicpr"
    if method not in METHODS:
        raise ValueError("unknown enrollment method %r: msicpr or certsrv" % method)
    if acc.get("adcs_auth") and acc["adcs_auth"] not in AUTH[method]:
        raise ValueError("%s enrollment authenticates with %s, not %s"
                         % ("MS-ICPR" if method == "msicpr" else "web",
                            " or ".join(AUTH[method]), acc["adcs_auth"]))
    host = (acc.get("adcs_host") or "").strip()
    if not _HOST.match(host):
        raise ValueError("an Active Directory account needs the name of the certification "
                         "authority's server, such as ca01.corp.example.lan")
    for key, what in (("adcs_template", "the certificate template, such as WebServer"),
                      ("adcs_user", "the user name of a service account allowed to enroll"),
                      ("adcs_password", "the service account's password")):
        if not (acc.get(key) or "").strip():
            raise ValueError("an Active Directory account needs %s" % what)
    if method == "msicpr" and not (acc.get("adcs_ca_name") or "").strip():
        raise ValueError("enrolling over MS-ICPR needs the certification authority's name, as "
                         "certutil shows it, such as Corp Issuing CA")
    if method == "msicpr" and auth_of(acc) == "kerberos" and not (acc.get("adcs_domain") or "").strip():
        raise ValueError("Kerberos needs the Active Directory domain, such as corp.example.lan")
    for key in FIELDS:
        if key != "adcs_extra" and not _LINE.match(acc.get(key) or ""):
            raise ValueError("%s must be one line" % key.replace("adcs_", "", 1).replace("_", " "))
    extra = _extra(acc)
    for sec in extra.sections():
        if sec in EXTRA_KEEP_OUT:
            raise ValueError("the extra acme2certifier settings may not set [%s]: the node keeps "
                             "acme2certifier's database itself" % sec)
    if method == "certsrv" and (acc.get("ca_bundle") or "").strip():
        from . import acme
        blocks = acme._pem_blocks(acc["ca_bundle"])
        if not blocks or any(kind != "CERTIFICATE" for kind, _ in blocks):
            raise ValueError("the CA certificate to trust must be one or more PEM "
                             "certificates (-----BEGIN CERTIFICATE-----)")


# --------------------------------------------------------------------------
# what acme2certifier is given

def _extra(acc):
    """The account's extra settings, parsed; raises ValueError when they are
    not acme_srv.cfg lines with section headers."""
    # With a default section no one names, a [DEFAULT] of the account's own
    # is an ordinary section here, and every section is handled alike.
    cp = configparser.ConfigParser(interpolation=None, default_section="\x00")
    text = acc.get("adcs_extra") or ""
    if not text.strip():
        return cp
    try:
        cp.read_string(text)
    except configparser.MissingSectionHeaderError:
        raise ValueError("the extra acme2certifier settings need their section headers, "
                         "such as [CAhandler] above timeout: 30")
    except configparser.Error as e:
        raise ValueError("the extra acme2certifier settings are not acme_srv.cfg lines: %s"
                         % str(e).splitlines()[0])
    return cp


def directory_url():
    return "http://127.0.0.1:%d/directory" % A2C_PORT


def config_text(acc, bundle_path=""):
    """acme2certifier's acme_srv.cfg for this account: the CA handler for AD CS,
    SQLite in the state directory, and nothing switched off."""
    method = acc.get("adcs_method") or "msicpr"
    auth = auth_of(acc)
    cp = configparser.ConfigParser(interpolation=None)
    cp["DEFAULT"] = {"debug": "False"}
    cp["Nonce"] = {"nonce_check_disable": "False"}
    # acme.sh on this node is its only client, and the account's e-mail
    # address may be empty: no contact, and no terms to accept.
    cp["Account"] = {"contact_check_disable": "True", "tos_check_disable": "True"}
    ca = {"handler_module": HANDLER[method],
          "host": (acc.get("adcs_host") or "").strip(),
          "user": (acc.get("adcs_user") or "").strip(),
          "password": acc.get("adcs_password") or "",
          "template": (acc.get("adcs_template") or "").strip()}
    if method == "msicpr":
        ca["ca_name"] = (acc.get("adcs_ca_name") or "").strip()
        ca["use_kerberos"] = "True" if auth == "kerberos" else "False"
        ca["timeout"] = "15"
        if (acc.get("adcs_domain") or "").strip():
            ca["target_domain"] = acc["adcs_domain"].strip()
        if (acc.get("adcs_dc") or "").strip():
            ca["domain_controller"] = acc["adcs_dc"].strip()
    else:
        ca["auth_method"] = auth
        if bundle_path:
            ca["ca_bundle"] = bundle_path
    cp["CAhandler"] = ca
    cp["Certificate"] = {"revocation_reason_check_disable": "False"}
    cp["Challenge"] = {"challenge_validation_disable": "False"}
    cp["Order"] = {"tnauthlist_support": "False"}
    # The account's own settings over the generated ones: a setting given
    # here replaces the one the fields produce, a new one is added.
    extra = _extra(acc)
    for sec in extra.sections():
        if sec in EXTRA_KEEP_OUT:
            continue
        if sec != configparser.DEFAULTSECT and not cp.has_section(sec):
            cp.add_section(sec)
        for key, value in extra.items(sec, raw=True):
            cp.set(sec, key, value)
    cp["DBhandler"] = {"handler": "wsgi", "dbfile": str(A2C_STATE / "acme_srv.db")}
    from io import StringIO
    out = StringIO()
    out.write("# Generated by haproxy-manager for one run of acme2certifier -- do not edit by hand.\n")
    cp.write(out)
    return out.getvalue()


def masked_config(acc):
    """The configuration as acme2certifier would get it, the password hidden."""
    text = config_text(acc, "<the CA certificate to trust, as a file>" if (acc.get("ca_bundle") or "").strip()
                       and (acc.get("adcs_method") or "msicpr") == "certsrv" else "")
    pw = acc.get("adcs_password") or ""
    return text.replace(pw, "********") if pw else text


@app.post("/api/acme/adcs/config")
def api_adcs_config():
    """What acme2certifier would be given for the account as typed."""
    acc = dict(request.get_json(force=True, silent=True) or {})
    acc["ca"] = "adcs"
    try:
        check_account(acc)
        return jsonify({"ok": True, "config": masked_config(acc)})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)})


def _write_private(path, text):
    """Written beside and moved into place with mode 0600: it holds a password."""
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix="." + path.name)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def write_config(acc):
    """The configuration on disk for a run: its path. The CA certificate to
    trust, when the account brings one for web enrollment, goes beside it."""
    bundle = ""
    if (acc.get("adcs_method") or "msicpr") == "certsrv" and (acc.get("ca_bundle") or "").strip():
        bundle = A2C_STATE / "ca-bundle.pem"
        _write_private(bundle, acc["ca_bundle"].strip() + "\n")
    path = A2C_STATE / "acme_srv.cfg"
    _write_private(path, config_text(acc, str(bundle) if bundle else ""))
    return path


def _env(cfg_path):
    env = dict(os.environ)
    env.pop("NOTIFY_SOCKET", None)
    env["ACME_SRV_CONFIGFILE"] = str(cfg_path)
    # Its output goes to a file and it is stopped with SIGTERM, which would
    # lose whatever python still had buffered: the lines that say why.
    env["PYTHONUNBUFFERED"] = "1"
    # The WSGI entry point sits in acme2certifier's directory, not on the
    # module path; the package itself is installed where python finds it.
    env["PYTHONPATH"] = str(A2C_DIR) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return env


def command():
    """What runs acme2certifier: waitress, which this app already runs under,
    serving the WSGI application on localhost only."""
    return [sys.executable, "-m", "waitress", "--listen=127.0.0.1:%d" % A2C_PORT,
            "--threads=4", "acme2certifier_wsgi:application"]


# --------------------------------------------------------------------------
# installed?

def installed():
    """acme2certifier, and for MS-ICPR the Impacket it enrolls through."""
    return (A2C_DIR / "acme2certifier_wsgi.py").is_file() and _module("acme2certifier")


def _module(name):
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def version():
    if not installed():
        return ""
    try:
        from importlib.metadata import version as v
        return v("acme2certifier")
    except Exception:
        return ""


def missing_for(acc):
    """Why this node cannot enroll for the account yet, or ""."""
    if not installed():
        return "acme2certifier is not installed on this node"
    if (acc.get("adcs_method") or "msicpr") == "msicpr" and not _module("impacket"):
        return "Impacket (python3-impacket) is not installed on this node; MS-ICPR enrolls through it"
    return ""


# --------------------------------------------------------------------------
# running it for one issuance

READY_WAIT = 60


def _ready():
    try:
        with urllib.request.urlopen(directory_url(), timeout=3) as r:
            body = json.loads(r.read(100000) or b"null")
        return isinstance(body, dict) and bool(body.get("newNonce"))
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _tail(path, n=300):
    """The end of acme2certifier's output: enough to hold the handler's own
    lines about a failed enrollment even when debug is on and every request
    is logged after them."""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-n:])


@contextmanager
def serving(acc, log_lines):
    """acme2certifier up for this account while the block runs; yields why
    it could not be started, or "". log_lines collects its output for the
    issue log."""
    if not is_adcs(acc):
        yield ""
        return
    why = missing_for(acc)
    if why:
        yield why
        return
    with _serving:
        A2C_STATE.mkdir(parents=True, exist_ok=True)
        os.chmod(A2C_STATE, 0o700)
        cfg_path = write_config(acc)
        out_path = A2C_STATE / "acme2certifier.log"
        proc = None
        try:
            with open(out_path, "w") as out:
                proc = subprocess.Popen(command(), cwd=str(A2C_DIR), env=_env(cfg_path),
                                        stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.time() + READY_WAIT
            while time.time() < deadline:
                if proc.poll() is not None:
                    break
                if _ready():
                    break
                time.sleep(0.3)
            if proc.poll() is not None or not _ready():
                log_lines.append(_tail(out_path))
                yield ("acme2certifier did not start for account %s: %s"
                       % (acc.get("name") or "", _tail(out_path, 3) or "no output"))
                return
            yield ""
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            log_lines.append(_tail(out_path))
            # The configuration holds the password; it is written for a run
            # and not left behind.
            for p in (cfg_path, A2C_STATE / "ca-bundle.pem"):
                try:
                    p.unlink()
                except OSError:
                    pass


def explain(log_text):
    """What acme2certifier's output says went wrong, in one line, for the
    issue result: the CA's refusal or the connection that failed."""
    # The specific line first -- a connection that failed, a refused login
    # -- and the handler's summary only when there is nothing better.
    for pat in (r"Failed to connect[^\n]*", r"Error resolving[^\n]*",
                r"(?:rpc_s_access_denied|STATUS_LOGON_FAILURE|KDC_ERR[A-Z_]*|STATUS_[A-Z_]+)[^\n]*",
                r"Could not get certificate from CA server[^\n]*", r"ERROR[^\n]*"):
        m = re.search(pat, log_text or "")
        if m:
            return m.group(0).strip()[:300]
    return ""


# --------------------------------------------------------------------------
# testing the connection to the CA

TEST_TOOL = "a2c-msicpr-connection-test"


@app.post("/api/acme/adcs/test")
def api_adcs_test():
    """Ask the CA for nothing more than a connection, with the account as
    typed: the CA's name, the service account, Kerberos or NTLM."""
    acc = dict(request.get_json(force=True, silent=True) or {})
    acc["ca"] = "adcs"
    try:
        check_account(acc)
    except ValueError as e:
        return jsonify({"ok": False, "message": str(e)})
    why = missing_for(acc)
    if why:
        return jsonify({"ok": False, "message": why})
    if (acc.get("adcs_method") or "msicpr") != "msicpr":
        return _test_certsrv(acc)
    tool = shutil.which(TEST_TOOL) or ("/usr/bin/" + TEST_TOOL)
    if not os.path.exists(tool):
        return jsonify({"ok": False, "message": "%s is not installed with acme2certifier here" % TEST_TOOL})
    with _serving:
        A2C_STATE.mkdir(parents=True, exist_ok=True)
        cfg_path = write_config(acc)
        try:
            p = subprocess.run([tool], capture_output=True, text=True, timeout=60, env=_env(cfg_path),
                               cwd=str(A2C_DIR))
            out = p.stdout + p.stderr
        except subprocess.TimeoutExpired:
            out = "timed out after 60 seconds"
        except OSError as e:
            out = str(e)
        finally:
            try:
                cfg_path.unlink()
            except OSError:
                pass
    lines = [l for l in out.splitlines() if l.strip() and not l.startswith(("CAhandler.", "Helper."))]
    failed = re.search(r"Failed|Error|error|denied|refused|not known|timed out", out)
    return jsonify({"ok": not failed, "message": "\n".join(lines[-6:])[:1500]
                    or ("the CA answered" if not failed else "no answer")})


def _test_certsrv(acc):
    """Web enrollment: whether /certsrv/ answers and takes the credentials."""
    import base64
    url = "https://%s/certsrv/" % acc["adcs_host"].strip()
    import ssl
    ctx = ssl.create_default_context()
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    if (acc.get("ca_bundle") or "").strip():
        ctx.load_verify_locations(cadata=acc["ca_bundle"])
    req = urllib.request.Request(url)
    if auth_of(acc) == "basic":
        token = base64.b64encode(("%s:%s" % (acc["adcs_user"], acc["adcs_password"])).encode()).decode()
        req.add_header("Authorization", "Basic " + token)
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            return jsonify({"ok": True, "message": "%s answers (HTTP %d)" % (url, r.status)})
    except urllib.error.HTTPError as e:
        if e.code == 401 and auth_of(acc) == "ntlm" and "NTLM" in (e.headers.get("WWW-Authenticate") or ""):
            return jsonify({"ok": True, "message": "%s answers and asks for NTLM, as the account expects" % url})
        if e.code == 401:
            return jsonify({"ok": False, "message": "%s refused the credentials (HTTP 401; it offers %s)"
                            % (url, e.headers.get("WWW-Authenticate") or "no authentication")})
        return jsonify({"ok": False, "message": "%s answered HTTP %d" % (url, e.code)})
    except urllib.error.URLError as e:
        import ssl as _ssl
        if isinstance(e.reason, _ssl.SSLCertVerificationError):
            return jsonify({"ok": False, "message": "this node does not trust the HTTPS certificate of %s: paste "
                            "the certificate of the CA that signed it into the account's CA certificate "
                            "to trust" % url})
        return jsonify({"ok": False, "message": "could not reach %s: %s" % (url, e.reason)})
    except (OSError, ValueError) as e:
        return jsonify({"ok": False, "message": "could not reach %s: %s" % (url, e)})


# --------------------------------------------------------------------------
# putting it on a node that lacks it

# When an install last failed, so a node that cannot reach GitHub is not made
# to try at every issuance.
TRIED = DATA_DIR / "acme2certifier-install-tried"
RETRY_AFTER = 6 * 3600
# Impacket's package brings example scripts -- secretsdump and the like --
# that scanners flag; they are not what enrollment uses, and the image leaves
# them out the same way.
DPKG_EXCLUDE = ("path-exclude /usr/bin/impacket-*\n"
                "path-exclude /usr/share/doc/python3-impacket/*\n")
APT_INSTALL = """set -e
export DEBIAN_FRONTEND=noninteractive
dpkg -s python3-impacket >/dev/null 2>&1 || printf '%%s' '%(exclude)s' > /etc/dpkg/dpkg.cfg.d/haproxy-manager-impacket
tmp=$(mktemp -d)
curl -fsSL --max-time 300 '%(deb)s' -o "$tmp/acme2certifier.deb"
apt-get -o DPkg::Lock::Timeout=120 -o Acquire::http::Timeout=30 -o Acquire::Retries=2 update -q
apt-get -o DPkg::Lock::Timeout=120 -o Acquire::http::Timeout=30 -o Acquire::Retries=2 install -y --no-install-recommends "$tmp/acme2certifier.deb" python3-impacket
rm -rf "$tmp"
""" % {"exclude": DPKG_EXCLUDE, "deb": A2C_DEB % {"v": A2C_VERSION}}
# The Enterprise Linux family: acme2certifier's own .rpm, whose dependencies
# come from EPEL, as this app's do.
RPM_INSTALL = """set -e
tmp=$(mktemp -d)
curl -fsSL --max-time 300 '%(rpm)s' -o "$tmp/acme2certifier.rpm"
if command -v dnf >/dev/null; then dnf install -y "$tmp/acme2certifier.rpm" python3-impacket; else yum install -y "$tmp/acme2certifier.rpm" python3-impacket; fi
rm -rf "$tmp"
""" % {"rpm": A2C_RPM % {"v": A2C_VERSION}}


def _tried_recently():
    try:
        return time.time() - float(TRIED.read_text().strip()) < RETRY_AFTER
    except (OSError, ValueError):
        return False


def last_failure():
    try:
        return TRIED.with_suffix(".log").read_text().strip()[-1500:]
    except OSError:
        return ""


def install():
    """Put acme2certifier on this node from its GitHub release: (ok, output)."""
    if installed():
        return True, "acme2certifier is already installed"
    if shutil.which("apt-get"):
        script = APT_INSTALL
    elif shutil.which("dnf") or shutil.which("yum"):
        script = RPM_INSTALL
    else:
        return False, ("this node has neither apt-get nor dnf; install acme2certifier %s and Impacket "
                       "by hand" % A2C_VERSION)
    from .crowdsec import _run_script
    rc, out = _run_script(script, timeout=900)
    if rc != 0 or not installed():
        return False, "the install did not finish:\n" + (out or "").strip()[-1500:]
    return True, "installed acme2certifier %s" % (version() or A2C_VERSION)


def ensure_installed():
    """Install it where an account needs it and it is missing: (ok, message).
    Never fatal, and a failure is not retried for a while."""
    if installed():
        return True, "installed"
    if _tried_recently():
        return False, "an install failed recently; not retried yet: " + last_failure()[-300:]
    ok, out = install()
    TRIED.parent.mkdir(parents=True, exist_ok=True)
    if ok:
        TRIED.unlink(missing_ok=True)
        TRIED.with_suffix(".log").unlink(missing_ok=True)
        log.info(out)
    else:
        TRIED.write_text(str(time.time()))
        TRIED.with_suffix(".log").write_text(out)
        log.warning("acme2certifier could not be installed: %s", out.strip()[-300:])
    return ok, out


def wanted(cfg):
    """Does any account on this node enroll with AD CS."""
    return any(is_adcs(a) for a in (cfg.get("acme") or {}).get("accounts") or [])


def startup():
    """At startup: a node that has an AD CS account gets acme2certifier if it
    lacks it, so the first renewal does not wait for the download."""
    try:
        from .config import load_config
        if wanted(load_config()):
            ensure_installed()
    except Exception:
        log.exception("acme2certifier at startup failed")


def summary(cfg):
    """For /api/acme/health: whether this node can enroll with AD CS."""
    out = {"wanted": wanted(cfg), "installed": installed(), "version": version(),
           "impacket": _module("impacket"), "port": A2C_PORT, "release": A2C_VERSION}
    if out["wanted"] and not out["installed"]:
        out["install_error"] = last_failure()
    return out


@app.post("/api/acme/adcs/install")
def api_adcs_install():
    """Install acme2certifier on this node now, rather than at the first issuance."""
    TRIED.unlink(missing_ok=True)
    ok, message = ensure_installed()
    from .config import load_config
    return jsonify({"ok": ok, "message": message, "adcs": summary(load_config())}), (200 if ok else 500)
