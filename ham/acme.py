"""Certificates through acme.sh, and the renewal timer."""

from datetime import datetime
from datetime import timezone
from flask import abort
from flask import jsonify
from flask import request
from pathlib import Path
import os
import tempfile
import time

from .base import ACME_HOME, ACME_SH, CERT_DIR, _lock, app, log
from .config import load_config, save_config
from .util import _by_id, cert_path, parse_domains, run
from . import auth, notify, sync

# --------------------------------------------------------------------------

CA_SERVERS = {
    "letsencrypt": "letsencrypt",
    "letsencrypt_test": "letsencrypt_test",
    "zerossl": "zerossl",
    "buypass": "buypass",
    "google": "google",
}
KEYLEN = {"ec-256": "ec-256", "ec-384": "ec-384", "rsa-2048": "2048", "rsa-4096": "4096"}


def acme_run(args, env_extra=None):
    if not Path(ACME_SH).exists():
        return 127, "acme.sh not found at %s -- run install.sh or set HAM_ACME_SH" % ACME_SH
    env = os.environ.copy()
    env.update(env_extra or {})
    # --log makes acme.sh keep its own log in ACME_HOME, which is what the log
    # viewer reads back. Left at the default level: level 2 traces the DNS hook
    # calls, and those carry API credentials.
    return run([ACME_SH, "--home", str(ACME_HOME), "--log"] + args, env=env)


def ensure_account(acc):
    args = ["--register-account", "-m", acc.get("email", ""),
            "--server", CA_SERVERS.get(acc.get("ca", "letsencrypt"), "letsencrypt")]
    if acc.get("eab_kid"):
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
    if res.get("ok"):
        log.info("certificate issued: %s (%s)", cert.get("name"), ", ".join(parse_domains(cert)))
        notify.notify("certificates", "Certificate %s issued" % cert.get("name"),
               "The certificate %s was issued and deployed.\n\nDomains: %s"
               % (cert.get("name"), ", ".join(parse_domains(cert))), "info", cfg)
        note = propagate_certificate(cfg, cert)
        if note:
            res["propagated"] = note
    return res


def _acme_issue(cfg, cert, force=False):
    accounts = _by_id(cfg["acme"]["accounts"])
    challenges = _by_id(cfg["acme"]["challenges"])
    acc = accounts.get(cert.get("account"))
    ch = challenges.get(cert.get("challenge"))
    if not acc or not ch:
        return {"ok": False, "error": "certificate needs both an account and a challenge type"}
    doms = parse_domains(cert)
    if not doms:
        return {"ok": False, "error": "certificate has no domain names"}

    trace = []
    rc, out = ensure_account(acc)
    trace.append(out)
    if rc != 0:
        return {"ok": False, "error": "ACME account registration failed", "log": "\n".join(trace)}

    args = ["--issue", "--server", CA_SERVERS.get(acc.get("ca", "letsencrypt"), "letsencrypt")]
    for d in doms:
        args += ["-d", d]
    args += ["--keylength", KEYLEN.get(cert.get("key_type", "ec-256"), "ec-256")]
    env = {}
    if ch.get("method") == "dns01":
        args += ["--dns", ch.get("dns_provider", "")]
        for line in (ch.get("dns_credentials") or "").splitlines():
            if "=" in line:
                kk, vv = line.split("=", 1)
                env[kk.strip()] = vv.strip()
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
    res = {"ok": dep["ok"], "log": "\n".join(x for x in trace if x)}
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
        p.write_text(fc.read_text() + key.read_text())
        os.chmod(p, 0o600)
    auto = after_certificate_deployed(cfg, cert)
    return {"ok": True, "log": (out + ("\n" + auto if auto else "")).strip()}


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
    cert = _by_id(cfg["acme"]["certificates"]).get(cid)
    if not cert:
        abort(404)
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
    for cert in cfg["acme"]["certificates"]:
        if cert.get("auto_renew", True):
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
            if time.time() - _last_renew >= interval:
                _last_renew = time.time()
                for cert in cfg["acme"]["certificates"]:
                    if cert.get("auto_renew", True):
                        acme_issue(cfg, cert)
        except Exception:
            pass


# --------------------------------------------------------------------------
# notifications
