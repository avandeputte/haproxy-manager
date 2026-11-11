"""Certificates through acme.sh, and the renewal timer."""

from datetime import datetime
from datetime import timezone
from flask import Response
from flask import abort
from flask import jsonify
from flask import request
from pathlib import Path
import os
import tempfile
import time
import uuid

from .base import ACME_HOME, ACME_SH, CERT_DIR, _lock, app, log
from .config import load_config, merged, save_config
from .util import _by_id, cert_path, parse_domains, run

import re

# A provider credential variable is a plain shell identifier. Anything that
# could redirect a root process -- the loader variables, PATH, the shell's
# own hooks -- is refused even if it matches that shape.
_SAFE_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DANGEROUS_ENV = {"PATH", "IFS", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS",
                  "PS4", "PROMPT_COMMAND", "PYTHONPATH", "PERL5LIB"}
from . import adcs, auth, notify, sync

# A DNS alias target is a plain host name: it ends up on the command line of a
# root process, so nothing else is let through. Its last label starts with a
# letter, which an address or an option does not.
_ALIAS_NAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+"
                         r"[A-Za-z][A-Za-z0-9-]{0,61}[A-Za-z0-9]$")
# acme.sh's own word for "this domain is validated in its own zone", for a
# certificate where only some of the domains go through an alias.
NO_ALIAS = "no"
_ALIAS_PREFIX = "_acme-challenge."


def parse_challenge_alias(value):
    """The alias domains typed on a challenge type, as a list.

    One name per line (or separated by spaces or commas); an API client may
    send a list. A name is taken as it appears in a zone file too: a trailing
    dot is dropped, and so is a leading _acme-challenge. label, which acme.sh
    adds itself -- left in, the record would be made one label too deep.
    Raises ValueError with why when one is not a host name.
    """
    if isinstance(value, (list, tuple)) and all(isinstance(x, str) for x in value):
        value = " ".join(value)
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError("the challenge alias is one host name, or one per domain, not a %s"
                         % type(value).__name__)
    names = []
    for typed in re.split(r"[\s,]+", value.strip()):
        if not typed:
            continue
        n = typed[:-1] if typed.endswith(".") else typed
        if n.lower().startswith(_ALIAS_PREFIX):
            n = n[len(_ALIAS_PREFIX):]
        if n != NO_ALIAS and not _ALIAS_NAME.match(n):
            raise ValueError("%r is not a valid challenge alias domain" % typed)
        names.append(n)
    return names


def check_alias_count(ch, doms, cert_name=""):
    """One alias serves every domain of a certificate; several are paired
    with its domains by position, so there must be exactly as many. Raises
    ValueError when there are not; returns the aliases."""
    names = parse_challenge_alias(ch.get("challenge_alias"))
    if len(names) > 1 and len(names) != len(doms):
        raise ValueError("challenge type %s has %d alias domains but %s has %d domain names: "
                         "give one alias for all of them, or one per domain name, in order"
                         % (ch.get("name") or "", len(names),
                            ("certificate %s" % cert_name) if cert_name else "the certificate", len(doms)))
    return names


def check_challenge(item, cfg=None):
    """What a challenge type is refused for when it is saved: an alias that
    is not a host name, and a list of them that does not fit a certificate
    already using it -- that certificate's next renewal would fail."""
    if item.get("method") != "dns01":
        return                      # the alias is not used, and not shown
    names = parse_challenge_alias(item.get("challenge_alias"))
    item["challenge_alias"] = " ".join(names)
    if not cfg or not item.get("id"):
        return
    for cert in cfg["acme"]["certificates"]:
        if cert.get("challenge") == item["id"] and not is_custom(cert):
            check_alias_count(item, parse_domains(cert), cert.get("name") or "")


def check_certificate(cfg, item):
    """A certificate whose domain names no longer fit its challenge type's
    per-domain aliases is refused when saved, not at its next renewal."""
    if is_custom(item):
        return
    ch = _by_id(cfg["acme"]["challenges"]).get(item.get("challenge"))
    if not ch or ch.get("method") != "dns01":
        return
    try:
        parse_challenge_alias(ch.get("challenge_alias"))
    except ValueError:
        return                      # the challenge type's own fault, said when issuing
    check_alias_count(ch, parse_domains(item), item.get("name") or "")


def challenge_alias_args(ch, doms, cert_name=""):
    """acme.sh's --challenge-alias arguments for a DNS-01 challenge type.

    With the validation records CNAMEd to another zone (acme.sh's DNS alias
    mode), _acme-challenge.<domain> is answered in that zone instead. One alias
    applies to every domain on the certificate; otherwise there must be exactly
    one per domain, in the order the domains are listed -- acme.sh pairs them
    by position.
    """
    args = []
    for n in check_alias_count(ch, doms, cert_name):
        args += ["--challenge-alias", n]
    return args


# --------------------------------------------------------------------------

# The public CAs, by the short names acme.sh knows (its CA_NAMES). acme.sh
# takes a name it does not know for a directory URL, so a CA it drops has to
# go here too: Buypass stopped issuing on 31 October 2025 and left acme.sh in
# 3.1.2. The ones in EAB_REQUIRED will not register an account without it.
# Two more are not public CAs: "custom" is any ACME server by its directory
# URL, and "adcs" is Active Directory Certificate Services through the
# acme2certifier this node runs for it (see adcs.py).
CA_SERVERS = {
    "letsencrypt": "letsencrypt",
    "letsencrypt_test": "letsencrypt_test",
    "zerossl": "zerossl",
    "google": "google",
    "google_test": "google_test",
    "sslcom": "sslcom",
    "actalis": "actalis",
}
EAB_REQUIRED = {"google": "Google", "google_test": "Google", "sslcom": "SSL.com",
                "actalis": "Actalis"}
# The ones with no External Account Binding at all: Let's Encrypt has none,
# and AD CS is not reached over ACME. (ZeroSSL takes it, or makes its own
# from the e-mail address; a custom server may ask for it.)
NO_EAB = {"letsencrypt", "letsencrypt_test", "adcs"}
KEYLEN = {"ec-256": "ec-256", "ec-384": "ec-384", "rsa-2048": "2048", "rsa-4096": "4096"}


def _forget_ca_bundle():
    """Take a saved CA_BUNDLE out of acme.sh's account.conf.

    acme.sh saves --ca-bundle there after an issue, and reads account.conf
    after its command line, so a bundle saved for a custom CA would go on
    replacing the system's trust for every CA after it. Each run passes the
    bundle it needs instead.
    """
    conf = Path(ACME_HOME) / "account.conf"
    try:
        lines = conf.read_text().splitlines(keepends=True)
    except OSError:
        return
    keep = [l for l in lines if not re.match(r"\s*(export\s+)?CA_BUNDLE=", l)]
    if keep != lines:
        conf.write_text("".join(keep))


def acme_run(args, env_extra=None):
    if not Path(ACME_SH).exists():
        return 127, "acme.sh not found at %s -- run install.sh or set HAM_ACME_SH" % ACME_SH
    env = os.environ.copy()
    env.update(env_extra or {})
    _forget_ca_bundle()
    # --log makes acme.sh keep its own log in ACME_HOME, which is what the log
    # viewer reads back. Left at the default level: level 2 traces the DNS hook
    # calls, and those carry API credentials.
    return run([ACME_SH, "--home", str(ACME_HOME), "--log"] + args, env=env)


# --------------------------------------------------------------------------
# a certificate authority of your own: any ACME server, by its directory URL

SYSTEM_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                  "/etc/ssl/cert.pem")


def check_account(acc):
    """What an ACME account refuses before it is stored. Raises ValueError with why."""
    ca = acc.get("ca") or "letsencrypt"
    if ca in NO_EAB:
        # The editor hides the EAB rows for these, so what was typed for
        # another CA before switching must not stay behind, unseen: one of
        # the two is a key.
        for k in ("eab_kid", "eab_hmac"):
            if acc.get(k):
                acc[k] = ""
    if ca == "buypass":
        raise ValueError("Buypass stopped issuing certificates on 31 October 2025: "
                         "choose another certificate authority for this account")
    if ca not in ("custom", "adcs") and ca not in CA_SERVERS:
        raise ValueError("unknown certificate authority %r" % ca)
    if ca in EAB_REQUIRED and not (acc.get("eab_kid") or "").strip():
        raise ValueError("%s needs External Account Binding: fill in the EAB key ID and "
                         "HMAC key from your account with them" % EAB_REQUIRED[ca])
    if ca == "adcs":
        adcs.check_account(acc)
        return
    if ca != "custom":
        return
    url = (acc.get("server") or "").strip()
    if not re.match(r"^https?://[^\s/?#]+(/\S*)?$", url):
        raise ValueError("a custom certificate authority needs the address of its ACME "
                         "directory, such as https://ca.example.lan/directory")
    bundle = (acc.get("ca_bundle") or "").strip()
    if bundle:
        blocks = _pem_blocks(bundle)
        if not blocks or any(kind != "CERTIFICATE" for kind, _ in blocks):
            raise ValueError("the CA certificate to trust must be one or more PEM "
                             "certificates (-----BEGIN CERTIFICATE-----)")
        for _, block in blocks:
            rc, _ = _openssl_out(["x509", "-noout"], block)
            if rc != 0:
                raise ValueError("the CA certificate to trust is not a certificate "
                                 "openssl can read")


def _bundle_file(acc):
    """The system's trusted CAs plus the account's own, as a file for --ca-bundle.

    The system's are kept because the bundle is all curl trusts for the run,
    and a DNS hook calls its provider's public API in the same run.
    """
    import ssl
    system = ssl.get_default_verify_paths().cafile
    found = [p for p in ((system,) if system else ()) + SYSTEM_BUNDLES if Path(p).is_file()]
    text = Path(found[0]).read_text() if found else ""
    path = Path(ACME_HOME) / "ca-bundles" / ("%s.pem" % re.sub(r"[^A-Za-z0-9_-]", "_",
                                                              acc.get("id") or "account"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip("\n") + "\n" + acc["ca_bundle"].strip() + "\n")
    return path


def check_directory(acc):
    """Read a custom CA's ACME directory before acme.sh does. Returns why not, or "".

    acme.sh does not give up on a server it cannot reach or does not trust:
    it asks again for a nonce every 20 seconds until run() times it out ten
    minutes later, and says only that it timed out.
    """
    if acc.get("ca") != "custom":
        return ""
    import json
    import ssl
    import urllib.error
    import urllib.request
    url = (acc.get("server") or "").strip()
    ctx = ssl.create_default_context()
    # Python 3.13 adds RFC 5280 strictness that curl does not, and internal
    # CAs often lack an extension it wants; trust what acme.sh will trust.
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    if (acc.get("ca_bundle") or "").strip():
        ctx.load_verify_locations(cadata=acc["ca_bundle"])
    try:
        with urllib.request.urlopen(url, timeout=15, context=ctx) as r:
            body = json.loads(r.read(200000) or b"null")
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            return ("this node does not trust the HTTPS certificate of %s (%s). Paste the "
                    "certificate of the CA that signed it into the account's CA certificate "
                    "to trust." % (url, e.reason.verify_message or e.reason))
        if isinstance(e, urllib.error.HTTPError):
            return "%s answered HTTP %d: is that the address of the ACME directory?" % (url, e.code)
        return "could not reach the ACME server at %s: %s" % (url, e.reason)
    except (OSError, ValueError) as e:
        return "could not read an ACME directory at %s: %s" % (url, e)
    if not (isinstance(body, dict) and body.get("newNonce") and body.get("newAccount")):
        return "%s is not an ACME directory: it has no newNonce and newAccount" % url
    return ""


def server_args(acc):
    """--server, and --ca-bundle when the account brings one, for acme.sh."""
    if acc.get("ca") == "adcs":
        return ["--server", adcs.directory_url()]
    if acc.get("ca") != "custom":
        return ["--server", CA_SERVERS.get(acc.get("ca", "letsencrypt"), "letsencrypt")]
    args = ["--server", (acc.get("server") or "").strip()]
    if (acc.get("ca_bundle") or "").strip():
        args += ["--ca-bundle", str(_bundle_file(acc))]
    return args


def ensure_account(acc):
    args = ["--register-account", "-m", acc.get("email", "")] + server_args(acc)
    # An account stored before the EAB rows were hidden for these CAs may
    # still carry credentials meant for another one.
    if acc.get("eab_kid") and (acc.get("ca") or "letsencrypt") not in NO_EAB:
        args += ["--eab-kid", acc["eab_kid"], "--eab-hmac-key", acc.get("eab_hmac", "")]
    return acme_run(args)


def record_issue(cert, res, started):
    """Remember the outcome of an issuance attempt so the UI can show it.

    Kept in _meta rather than on the certificate itself: _meta is outside
    config_hash (so a renewal does not flag the configuration as changed) and
    outside the payload pushed to the peer.
    """
    cid = cert.get("id")
    if not cid:
        return
    with _lock:
        cur = load_config()
        cur["_meta"].setdefault("issue_log", {})[cid] = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "seconds": round(time.time() - started, 1),
            "ok": bool(res.get("ok")),
            "error": res.get("error") or "",
            "log": (res.get("log") or "")[-6000:],
        }
        save_config(cur)


def propagate_certificate(cfg, cert):
    """Send a freshly issued certificate to the other nodes.

    The deployed PEMs travel with a configuration push, so the other nodes get
    the file and reload. Without this a renewal only ever reached the node that
    performed it, and a failover served the old certificate.
    """
    peers = sync.enabled_peers(cfg)
    if not peers:
        return ""
    r = sync.sync_push(load_config())
    if r.get("ok"):
        return "sent to %d other node(s)" % len(peers)
    return "could not send it to the other nodes: %s" % r.get("error")


def is_custom(cert):
    """A certificate brought here rather than issued: nothing to renew."""
    return (cert or {}).get("source") == "custom"


def acme_issue(cfg, cert, force=False):
    started = time.time()
    res = _acme_issue(cfg, cert, force=force)
    try:
        record_issue(cert, res, started)
        if not res.get("ok"):
            log.error("certificate %s failed: %s", cert.get("name"), res.get("error"))
            notify.notify_transition(
                "cert:" + str(cert.get("id")), "failed", "certificates",
                "Certificate %s could not be issued" % cert.get("name"),
                "Issuing %s failed.\n\n%s\n\nDomains: %s\n\nUntil this succeeds the "
                "existing certificate stays in use, and it will eventually expire."
                % (cert.get("name"), res.get("error"), ", ".join(parse_domains(cert))),
                "error", cfg)
    except OSError:
        pass  # never fail an issuance because the log could not be written
    if res.get("ok") and not res.get("changed", True):
        # Not due: acme.sh kept the certificate it has and the deployed file
        # already is that one. Nothing to reload, announce or send.
        log.debug("certificate %s is not due; the deployed one is current", cert.get("name"))
    elif res.get("ok"):
        log.info("certificate issued: %s (%s)", cert.get("name"), ", ".join(parse_domains(cert)))
        notify.notify("certificates", "Certificate %s issued" % cert.get("name"),
               "The certificate %s was issued and deployed.\n\nDomains: %s"
               % (cert.get("name"), ", ".join(parse_domains(cert))), "info", cfg)
        note = propagate_certificate(cfg, cert)
        if note:
            res["propagated"] = note
    return res


def _acme_issue(cfg, cert, force=False):
    if is_custom(cert):
        # Whatever asked -- a button, the wizard, MCP -- an uploaded
        # certificate is not issued over: it would stay marked as uploaded,
        # and so never be renewed.
        return {"ok": False, "error": "this certificate was uploaded, not issued: "
                                      "upload a new one to replace it"}
    accounts = _by_id(cfg["acme"]["accounts"])
    challenges = _by_id(cfg["acme"]["challenges"])
    acc = accounts.get(cert.get("account"))
    ch = challenges.get(cert.get("challenge"))
    if not acc or not ch:
        return {"ok": False, "error": "certificate needs both an account and a challenge type"}
    doms = parse_domains(cert)
    if not doms:
        return {"ok": False, "error": "certificate has no domain names"}
    if ch.get("method") == "dns01":
        # Checked before anything is asked of the CA: an alias list that does
        # not fit is this node's own configuration, and saving refuses it, but
        # a restored or synced configuration has not been through that.
        try:
            challenge_alias_args(ch, doms, cert.get("name") or "")
        except ValueError as e:
            return {"ok": False, "error": str(e)}

    try:
        check_account(acc)
    except ValueError as e:
        return {"ok": False, "error": "ACME account %s: %s" % (acc.get("name") or "", e)}
    why = check_directory(acc)
    if why:
        return {"ok": False, "error": why}

    trace = []
    if adcs.is_adcs(acc) and not adcs.installed():
        # Every node gets acme2certifier when the service starts. Where that
        # failed, or is still running, this is the next try.
        ok, out = adcs.ensure_installed()
        trace.append(out)
        if not ok:
            return {"ok": False, "error": "acme2certifier is not installed on this node and could not "
                                          "be installed: %s" % out.strip()[-300:], "log": "\n".join(trace)}
    a2c_out = []
    with adcs.serving(acc, a2c_out) as why:
        if why:
            return {"ok": False, "error": why, "log": "\n".join(x for x in trace + a2c_out if x)}
        res = _acme_run_issue(cfg, cert, acc, ch, doms, force, trace)
    # acme2certifier's output is complete only now that it has stopped. Its
    # last lines go under acme.sh's in the log; the line that says what the
    # CA made of the request goes into the error.
    said = "\n".join(a2c_out)
    if said.strip():
        res["log"] = "%s\n\n--- acme2certifier ---\n%s" % (res.get("log") or "",
                                                           "\n".join(said.splitlines()[-40:]))
    if not res.get("ok") and "error" in res:
        why = adcs.explain(said)
        if why:
            res["error"] = "%s -- acme2certifier: %s" % (res["error"], why)
    return res


def _acme_run_issue(cfg, cert, acc, ch, doms, force, trace):
    """Register the account if need be, run acme.sh --issue, deploy the result."""
    rc, out = ensure_account(acc)
    trace.append(out)
    if rc != 0:
        return {"ok": False, "error": "ACME account registration failed", "log": "\n".join(trace)}

    args = ["--issue"] + server_args(acc)
    for d in doms:
        args += ["-d", d]
    args += ["--keylength", KEYLEN.get(cert.get("key_type", "ec-256"), "ec-256")]
    env = {}
    if ch.get("method") == "dns01":
        args += ["--dns", ch.get("dns_provider", "")]
        args += challenge_alias_args(ch, doms)
        for line in (ch.get("dns_credentials") or "").splitlines():
            if "=" not in line:
                continue
            kk, vv = line.split("=", 1)
            kk = kk.strip()
            # acme.sh's DNS hooks read their credentials from named variables,
            # so this whole line goes into the environment of a root process.
            # Restrict the NAME: a provider variable is a plain identifier, and
            # nothing here should be able to set PATH, IFS, or the dynamic
            # loader's hijack variables in that process.
            if not _SAFE_ENV.match(kk) or kk in _DANGEROUS_ENV \
                    or kk.startswith(("LD_", "DYLD_")):
                log.warning("ignoring a DNS credential line: %r is not a valid "
                            "provider variable name", kk)
                continue
            env[kk] = vv.strip()
    else:
        args += ["--standalone", "--httpport", str(cfg["acme"]["settings"].get("challenge_port", 9080))]
    if force:
        args += ["--force"]

    rc, out = acme_run(args, env)
    trace.append(out)
    if rc not in (0, 2):  # 2 = cert not yet due for renewal, treat as success
        return {"ok": False, "error": "issuance failed -- see log", "log": "\n".join(trace)}

    dep = deploy_cert(cfg, cert)
    trace.append(dep.get("log", ""))
    res = {"ok": dep["ok"], "changed": dep.get("changed", True), "log": "\n".join(x for x in trace if x)}
    if not dep["ok"]:
        res["error"] = dep.get("error")
    return res


def deploy_cert(cfg, cert):
    """Copy fullchain+key from acme.sh into a combined PEM HAProxy can load."""
    doms = parse_domains(cert)
    main = doms[0]
    with tempfile.TemporaryDirectory() as td:
        fc, key = Path(td) / "fullchain.pem", Path(td) / "key.pem"
        args = ["--install-cert", "-d", main, "--fullchain-file", str(fc), "--key-file", str(key)]
        if cert.get("key_type", "ec-256").startswith("ec"):
            args.append("--ecc")
        rc, out = acme_run(args)
        if rc != 0 or not fc.exists() or not key.exists():
            return {"ok": False, "error": "acme.sh --install-cert failed", "log": out}
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        p = cert_path(cert)
        pem = fc.read_text() + key.read_text()
        # A round asks acme.sh about every certificate, and one that is not
        # due comes back as it was. The file is compared rather than acme.sh's
        # exit code trusted, so a PEM that went missing or was replaced by a
        # placeholder is still put back.
        try:
            if p.read_text() == pem:
                return {"ok": True, "changed": False, "log": out.strip()}
        except OSError:
            pass
        p.write_text(pem)
        os.chmod(p, 0o600)
    auto = after_certificate_deployed(cfg, cert)
    return {"ok": True, "changed": True, "log": (out + ("\n" + auto if auto else "")).strip()}


def after_certificate_deployed(cfg, cert):
    """What always has to happen once a certificate lands on disk.

    HAProxy holds certificates in memory, so a new file changes nothing until
    it reloads -- this used to be an optional Automation, which meant a renewed
    certificate could sit on disk unserved. Sending it to the other nodes is
    handled by the caller.
    """
    rc, out = run(["systemctl", "reload-or-restart", "haproxy"])
    return "reloaded HAProxy" if rc == 0 else "HAProxy did not reload: %s" % out.strip()[:200]


@app.post("/api/acme/issue/<cid>")
def api_acme_issue(cid):
    cfg = load_config()
    # merged, so a node's own UI certificate -- moved into the local section --
    # can be issued from the button the Certificates page shows for it.
    cert = _by_id(merged(cfg)["acme"]["certificates"]).get(cid)
    if not cert:
        abort(404)
    if is_custom(cert):
        return jsonify({"ok": False, "error": "this certificate was uploaded, not issued: "
                                               "upload a new one to replace it"}), 400
    force = bool((request.get_json(silent=True) or {}).get("force"))
    return jsonify(acme_issue(cfg, cert, force=force))


@app.get("/api/acme/log/<cid>")
def api_acme_log(cid):
    """The acme.sh output of the last issue/renew attempt for one certificate."""
    entry = (load_config()["_meta"].get("issue_log") or {}).get(cid)
    if not entry:
        return jsonify({"ok": False, "error": "no issuance has been attempted for this certificate yet"})
    return jsonify({"ok": True, "entry": entry})


@app.post("/api/acme/renew")
def api_acme_renew():
    cfg = load_config()
    ok, why = renewal_runs_here(cfg)
    if not ok:
        return jsonify({"ok": False, "error": why}), 409
    results = {}
    for cert in merged(cfg)["acme"]["certificates"]:
        if cert.get("auto_renew", True) and not is_custom(cert):
            results[cert["name"]] = acme_issue(cfg, cert)
    return jsonify({"ok": all(r.get("ok") for r in results.values()) if results else True,
                    "results": results})


def renewal_runs_here(cfg):
    """Only the node serving traffic renews.

    Every node used to run this loop. HTTP-01 validation arrives at the virtual
    IP, so a passive node cannot answer it; with DNS-01 the nodes would instead
    race each other for the same certificate and burn the CA's rate limits.
    """
    role, _ = auth.node_role(cfg)
    if role == "passive":
        return False, "this node is passive; the node holding the virtual IP renews"
    return True, ""


# The renewal timer. It lives here rather than with the other background
# loops because it is the only state renewal keeps, and keeping it beside
# the code that decides whether renewal runs at all is what lets this
# module stand on its own.
_last_renew = time.time()


RETRY_AFTER = 3600


def renewal_due(cfg, cert, now=None):
    """Whether acme.sh's own schedule says this certificate is due, between rounds.

    The rounds run every renew_hours, a day by default. A CA of your own may
    issue certificates for a day (step-ca does by default), which acme.sh
    plans to renew an hour before they end, so a daily round can miss that
    hour; the 10-minute tick reads the plan instead. A failed attempt is not
    repeated for an hour, so a CA that is down is not asked every 10 minutes.
    """
    now = now or time.time()
    doms = parse_domains(cert)
    if not doms:
        return False
    # acme.sh keeps an EC certificate in <name>_ecc and an RSA one in <name>.
    # Only the folder of the key type this certificate has now: one issued as
    # EC and switched to RSA leaves the _ecc folder behind, with a plan that
    # is forever in the past.
    folder = doms[0] + ("_ecc" if cert.get("key_type", "ec-256").startswith("ec") else "")
    try:
        text = (Path(ACME_HOME) / folder / (doms[0] + ".conf")).read_text()
    except OSError:
        return False
    m = re.search(r"^Le_NextRenewTime='?(\d+)'?\s*$", text, re.M)
    if not m or int(m.group(1)) > now:
        return False
    last = (cfg.get("_meta", {}).get("issue_log") or {}).get(cert.get("id")) or {}
    if last and not last.get("ok"):
        try:
            at = datetime.fromisoformat(last["time"]).timestamp()
        except (KeyError, TypeError, ValueError):
            at = 0
        if now - at < RETRY_AFTER:
            return False
    return True


def _renew_loop():
    global _last_renew
    while True:
        time.sleep(600)
        try:
            cfg = load_config()
            st = cfg["acme"]["settings"]
            if not (st.get("enabled") and st.get("auto_renew")):
                continue
            ok, why = renewal_runs_here(cfg)
            if not ok:
                with _lock:
                    cur = load_config()
                    cur["_meta"]["renewal"] = {
                        "checked": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "ran": False, "reason": why}
                    save_config(cur)
                continue
            interval = max(1, int(st.get("renew_hours") or 24)) * 3600
            full = time.time() - _last_renew >= interval
            if full:
                _last_renew = time.time()
            for cert in merged(cfg)["acme"]["certificates"]:
                if cert.get("auto_renew", True) and not is_custom(cert) \
                        and (full or renewal_due(cfg, cert)):
                    acme_issue(cfg, cert)
        except Exception:
            # The loop must survive anything, but not silently: a renewal
            # loop that dies quietly is discovered as an expired certificate.
            log.exception("the renewal round failed; it runs again in 10 minutes")


# --------------------------------------------------------------------------
# certificates brought here: uploaded, and taken away again

PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.S)


def _pem_blocks(text):
    """(kind, block) for every PEM block in the text, in order."""
    return [(m.group(1), m.group(0)) for m in PEM_BLOCK.finditer(text or "")]


def _openssl_out(args, data):
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        os.chmod(path, 0o600)
        return run(["openssl"] + args + ["-in", path], timeout=30)
    finally:
        os.unlink(path)


def check_upload(cert_text, key_text, chain_text):
    """The combined PEM HAProxy reads, and the names it covers; raises
    ValueError with what is wrong."""
    certs = [b for k, b in _pem_blocks(cert_text) if k == "CERTIFICATE"]
    chain = [b for k, b in _pem_blocks(chain_text) if k == "CERTIFICATE"]
    keys = [(k, b) for k, b in _pem_blocks(key_text) if k.endswith("PRIVATE KEY")]
    if not certs:
        raise ValueError("no certificate found: paste the PEM, -----BEGIN CERTIFICATE----- and all")
    if not keys:
        raise ValueError("no private key found: paste the PEM, -----BEGIN PRIVATE KEY----- and all")
    if keys[0][0].startswith("ENCRYPTED"):
        raise ValueError("the private key is encrypted; HAProxy needs it without a passphrase")
    leaf, extra = certs[0], certs[1:] + chain
    rc, cert_pub = _openssl_out(["x509", "-noout", "-pubkey"], leaf)
    if rc != 0:
        raise ValueError("the certificate could not be read: %s" % cert_pub.strip()[-200:])
    rc, key_pub = _openssl_out(["pkey", "-pubout"], keys[0][1])
    if rc != 0:
        raise ValueError("the private key could not be read: %s" % key_pub.strip()[-200:])
    if cert_pub.strip() != key_pub.strip():
        raise ValueError("the private key does not belong to this certificate")
    rc, text = _openssl_out(["x509", "-noout", "-ext", "subjectAltName", "-subject"], leaf)
    names = re.findall(r"DNS:([^,\s]+)", text)
    if not names:
        m = re.search(r"CN\s*=\s*([^,/\n]+)", text)
        names = [m.group(1).strip()] if m else []
    pem = "\n".join([leaf] + extra + [keys[0][1]]) + "\n"
    return pem, names


@app.post("/api/acme/certificates/upload")
def api_certificate_upload():
    """A certificate issued elsewhere -- a commercial one, an internal CA's --
    stored like an issued one: a combined PEM in the certificate directory,
    sent to the other nodes with it, attached and matched by its names. It is
    never renewed here; uploading again replaces it."""
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    try:
        pem, names = check_upload(body.get("cert") or "", body.get("key") or "", body.get("chain") or "")
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    with _lock:
        cfg = load_config()
        certs = cfg["acme"]["certificates"]
        cert = _by_id(certs).get(body.get("id") or "")
        if body.get("id") and cert is None:
            return jsonify({"ok": False, "error": "the certificate being replaced no longer exists"}), 400
        if cert is not None and not is_custom(cert):
            return jsonify({"ok": False, "error": "%s is issued by ACME; upload under a new name"
                                                   % cert.get("name")}), 400
        if cert is None:
            if not name:
                return jsonify({"ok": False, "error": "the certificate needs a name"}), 400
            if any(c.get("name") == name for c in certs):
                return jsonify({"ok": False, "error": "a certificate named %s already exists" % name}), 400
            cert = {"id": str(uuid.uuid4()), "name": name}
            certs.append(cert)
        cert.update({"source": "custom", "domains": " ".join(names), "auto_renew": False})
        path = cert_path(cert)
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(CERT_DIR), prefix=".upload-")
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        save_config(cfg)
    log.info("certificate %s uploaded, covering %s", cert["name"], ", ".join(names) or "no names")
    sent = propagate_certificate(load_config(), cert)
    return jsonify({"ok": True, "certificate": {"id": cert["id"], "name": cert["name"]},
                    "names": names, "note": ("Apply to serve it." + (" " + sent if sent else ""))})


@app.get("/api/acme/certificates/<cid>/download")
def api_certificate_download(cid):
    """The certificate and its chain, or its private key, as files: to move a
    certificate to another server, or to keep a copy of an uploaded one."""
    cert = _by_id(merged(load_config())["acme"]["certificates"]).get(cid)
    if not cert:
        abort(404)
    try:
        blocks = _pem_blocks(cert_path(cert).read_text())
    except OSError:
        return jsonify({"ok": False, "error": "there is no file for this certificate yet"}), 404
    part = request.args.get("part") or "chain"
    if part == "key":
        body = "\n".join(b for k, b in blocks if k.endswith("PRIVATE KEY")) + "\n"
        filename = "%s.key" % cert["name"]
        log.warning("the private key of %s was downloaded", cert["name"])
    else:
        body = "\n".join(b for k, b in blocks if k == "CERTIFICATE") + "\n"
        filename = "%s.crt" % cert["name"]
    return Response(body, mimetype="application/x-pem-file",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % filename,
                             "Cache-Control": "no-store"})


# --------------------------------------------------------------------------
# notifications
