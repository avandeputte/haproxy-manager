"""The acme.sh DNS hook catalogue."""

from flask import jsonify
from flask import request
from pathlib import Path
import copy
import json
import os
import re
import shutil
import uuid

from .base import ACME_HOME, ACME_SH, _lock, app
from .config import load_config, save_config
from .util import _by_id, _sec, cert_details, cert_path, parse_domains, rule_cond_ids, run
from . import access, acme, adcs, errorpages, validate, wizard, oauth
from .validate import plain_url as _plain_url

# --------------------------------------------------------------------------

_dnsapi_cache = {"stamp": None, "hooks": []}


def _parse_dnsapi(path):
    """Read one acme.sh dnsapi script's self-description.

    acme.sh 3.x embeds a machine-readable block in every hook:

        dns_cf_info='CloudFlare
        Site: CloudFlare.com
        Docs: github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cf
        Options:
         CF_Key API Key
         CF_Email Your account email
        OptionsAlt:
         CF_Token API Token
        '
    """
    hook = path.stem
    info = {"hook": hook, "title": hook, "site": "", "docs": "",
            "options": [], "options_alt": []}
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return info

    m = re.search(r"^dns_[A-Za-z0-9_]+_info='(.*?)'\s*$", text, re.S | re.M)
    if not m:
        # No description block: fall back to the variables the script reads.
        seen = []
        for v in re.findall(r'_readaccountconf_mutable\s+"?([A-Za-z][A-Za-z0-9_]*)"?', text):
            if v not in seen:
                seen.append(v)
        info["options"] = [{"name": v, "desc": "", "optional": False} for v in seen]
        return info

    block = m.group(1)

    # A few hooks declare their options as JSON instead of prose (dns_czechia).
    if block.lstrip().startswith("["):
        try:
            for entry in json.loads(block):
                info["options"].append({
                    "name": entry.get("name", ""),
                    "desc": entry.get("usage", ""),
                    "optional": str(entry.get("required", "1")) not in ("1", "true", "True"),
                })
            return info
        except (ValueError, AttributeError, TypeError):
            pass

    lines = block.splitlines()
    if lines:
        info["title"] = lines[0].strip() or hook

    # Section driven, not indentation driven, and tolerant of the three header
    # dialects in the wild: options flush left (dns_poweradmin), an "Optional:"
    # sub-heading (dns_hetznercloud), and a header with trailing prose
    # ("Options: For old API version v1", dns_selectel).
    meta_keys = ("site", "docs", "issues", "author", "domains")
    bucket, optional_here = None, False
    for line in lines[1:]:
        text_ = line.strip()
        if not text_:
            continue
        head = text_.split(":", 1)[0].strip().lower() if ":" in text_ else ""
        if head in ("options", "optionsalt"):
            bucket, optional_here = head, False
            continue
        if head == "optional":                 # sub-heading inside the options
            optional_here = True
            continue
        if head in meta_keys or text_.endswith(":"):   # metadata, or any other section
            if head in ("site", "docs"):
                info[head] = text_.split(": ", 1)[1].strip()
            bucket = None                      # stop collecting: Notes, Issues, ...
            continue
        if bucket:
            parts = text_.split(None, 1)
            desc = parts[1].strip() if len(parts) > 1 else ""
            entry = {"name": parts[0], "desc": desc,
                     "optional": optional_here or "optional" in desc.lower()}
            (info["options_alt"] if bucket == "optionsalt" else info["options"]).append(entry)
    return info


def dnsapi_hooks():
    """Every DNS hook the installed acme.sh provides, parsed and cached."""
    d = ACME_HOME / "dnsapi"
    try:
        stamp = d.stat().st_mtime
    except OSError:
        return []
    if _dnsapi_cache["stamp"] == stamp:
        return _dnsapi_cache["hooks"]
    hooks = [_parse_dnsapi(p) for p in sorted(d.glob("dns_*.sh"))]
    hooks.sort(key=lambda h: h["title"].lower())
    _dnsapi_cache.update(stamp=stamp, hooks=hooks)
    return hooks


@app.get("/api/acme/health")
def api_acme_health():
    """Whether this node can actually obtain a certificate.

    Existence is not enough: the file has to be runnable, its home has to be
    writable for account keys and issued certificates, and the tools it shells
    out to have to be there.
    """
    path = Path(ACME_SH)
    out = {"ok": False, "path": str(path), "home": str(ACME_HOME),
           "version": "", "problem": "", "hint": ""}

    if not path.exists():
        out["problem"] = "acme.sh is not installed at %s." % path
        out["hint"] = ("Re-run the installer on this node -- it installs acme.sh when it is "
                       "missing -- or point HAM_ACME_SH at an existing copy. Nodes installed "
                       "before this was fixed never got it: the old installer reported success "
                       "while acme.sh failed to install.")
        return jsonify(out)

    if not os.access(str(path), os.X_OK):
        out["problem"] = "%s is not executable." % path
        out["hint"] = "chmod +x %s" % path
        return jsonify(out)

    rc, text = run([str(path), "--home", str(ACME_HOME), "--version"], timeout=30)
    if rc != 0:
        out["problem"] = "acme.sh will not run: %s" % (text.strip()[:300] or "exit code %s" % rc)
        out["hint"] = "Check that bash and curl are installed, then re-run the installer."
        return jsonify(out)
    out["version"] = next((l.strip() for l in reversed(text.splitlines())
                           if l.strip().startswith("v")), text.strip()[:40])

    if not os.access(str(ACME_HOME), os.W_OK):
        out["problem"] = "%s is not writable, so account keys and certificates cannot be stored." % ACME_HOME
        out["hint"] = "Fix the ownership of that directory; the service runs as root."
        return jsonify(out)

    missing = [t for t in ("curl", "openssl") if not shutil.which(t)]
    if missing:
        out["problem"] = "acme.sh needs %s, which is not installed." % " and ".join(missing)
        out["hint"] = "apt-get install -y " + " ".join(missing)
        return jsonify(out)
    # Whether the node can enroll with Active Directory Certificate Services,
    # for the certificates page to say so when an account asks for it.
    out["adcs"] = adcs.summary(load_config())

    if not shutil.which("socat"):
        out["ok"] = True
        out["problem"] = ""
        out["warning"] = ("socat is not installed, so HTTP-01 validation with acme.sh's standalone "
                          "listener will fail. DNS-01 is unaffected.")
        return jsonify(out)

    out["ok"] = True
    return jsonify(out)


@app.get("/api/acme/dnsapi")
def api_acme_dnsapi():
    hooks = dnsapi_hooks()
    return jsonify({"ok": True, "count": len(hooks), "hooks": hooks,
                    "acme_home": str(ACME_HOME),
                    "note": "" if hooks else
                            "acme.sh was not found at %s, so its DNS hooks could not be listed. "
                            "Type the hook name by hand." % ACME_HOME})


@app.post("/api/wizard/certificate")
def api_wizard_certificate():
    """Request a certificate, creating the account and challenge type it needs.

    account/challenge are either {"id": "<existing>"} or a full object to
    create, so the whole thing is one round trip from the UI.
    """
    body = request.get_json(force=True, silent=True) or {}
    domains = [d for d in re.split(r"[\s,]+", body.get("domains") or "") if d]
    if not domains:
        return jsonify({"ok": False, "error": "at least one domain name is required"}), 400
    bad = [d for d in domains if not re.match(r"^\*?[A-Za-z0-9_.-]+$", d)]
    if bad:
        return jsonify({"ok": False, "error": "not a domain name: %s" % ", ".join(bad[:3])}), 400

    acts, warns = [], []
    dry_run = bool(body.get("dry_run"))

    with _lock:
        cfg = load_config()
        draft = copy.deepcopy(cfg)
        ac = draft["acme"]

        def pick(kind, spec, defaults, label_field="name"):
            """Reuse the referenced object, or create one from the given fields."""
            spec = spec or {}
            if not isinstance(spec, dict):
                raise ValueError("the %s must be {id} of an existing one, or the fields of a "
                                 "new one" % kind[:-1])
            if spec.get("id"):
                found = _by_id(ac[kind]).get(spec["id"])
                if not found:
                    raise ValueError("the selected %s no longer exists" % kind[:-1])
                acts.append({"action": "reused", "type": label_field and kind[:-1].title(),
                             "name": found.get("name", "")})
                return found
            obj = dict(defaults)
            obj.update({k: v for k, v in spec.items() if k != "id"})
            if not obj.get("name"):
                raise ValueError("a name is required for the new %s" % kind[:-1])
            if kind == "challenges":
                acme.check_challenge(obj)
            obj["id"] = str(uuid.uuid4())
            obj["name"] = wizard._uniq_name({x["name"] for x in ac[kind]}, obj["name"])
            ac[kind].append(obj)
            acts.append({"action": "created", "type": kind[:-1].title(), "name": obj["name"]})
            return obj

        try:
            account = pick("accounts", body.get("account"),
                           dict({"name": "", "email": "", "ca": "letsencrypt", "server": "",
                                 "ca_bundle": "", "eab_kid": "", "eab_hmac": ""}, **adcs.FIELDS))
            acme.check_account(account)
            challenge = pick("challenges", body.get("challenge"),
                             {"name": "", "method": "http01", "dns_provider": "", "dns_credentials": "",
                              "challenge_alias": ""})
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

        if not account.get("email"):
            warns.append("The ACME account has no e-mail address. Let's Encrypt accepts that, "
                         "but you will get no expiry warnings from them.")
        wildcards = [d for d in domains if d.startswith("*.")]
        if wildcards and challenge.get("method") != "dns01":
            warns.append("%s is a wildcard, and wildcards can only be validated with DNS-01. "
                         "Pick or create a DNS-01 challenge type." % wildcards[0])
        aliases = []
        if challenge.get("method") == "dns01":
            # Aliases given one per domain are paired with the names by
            # position, so a count that does not fit can never issue.
            try:
                aliases = acme.check_alias_count(challenge, domains)
            except ValueError as e:
                return jsonify({"ok": False, "error": str(e)}), 400
        if challenge.get("method") == "dns01" and not challenge.get("dns_provider"):
            warns.append("The DNS-01 challenge type has no DNS API hook set, so acme.sh cannot "
                         "create the validation record.")

        name = (body.get("name") or "").strip() or domains[0].replace("*.", "wildcard-")
        # An uploaded certificate for the same names is not this one: issuing
        # over it would leave an ACME certificate marked as uploaded, which
        # nothing renews. The new one is created beside it.
        existing = wizard._find(ac["certificates"], lambda c: not acme.is_custom(c)
                                and set(parse_domains(c)) == set(domains))
        if any(acme.is_custom(c) and set(parse_domains(c)) == set(domains) for c in ac["certificates"]):
            warns.append("An uploaded certificate already covers these names. This one is "
                         "issued beside it; delete the uploaded one once this is in use.")
        if existing:
            if len(aliases) > 1:
                # The same names in another order: the aliases follow the
                # order just typed, so the certificate has to as well.
                existing["domains"] = " ".join(domains)
            existing.update({"account": account["id"], "challenge": challenge["id"],
                             "key_type": body.get("key_type") or existing.get("key_type", "ec-256"),
                             "auto_renew": bool(body.get("auto_renew", True))})
            cert = existing
            acts.append({"action": "updated", "type": "Certificate", "name": cert["name"]})
        else:
            cert = {"id": str(uuid.uuid4()),
                    "name": wizard._uniq_name({c["name"] for c in ac["certificates"]}, name),
                    "domains": " ".join(domains),
                    "account": account["id"], "challenge": challenge["id"],
                    "key_type": body.get("key_type") or "ec-256",
                    "auto_renew": bool(body.get("auto_renew", True)),
                    }
            ac["certificates"].append(cert)
            acts.append({"action": "created", "type": "Certificate", "name": cert["name"]})

        summary = {"ok": True, "actions": acts, "warnings": warns, "dry_run": dry_run,
                   "domains": domains, "certificate": cert["name"], "certificate_id": cert["id"]}
        if dry_run:
            return jsonify(summary)
        save_config(draft)
        cfg = draft

    if body.get("issue"):
        summary["issued"] = acme.acme_issue(cfg, cert, force=bool(body.get("force")))
    return jsonify(summary)


@app.get("/api/acme/cover")
def api_acme_cover():
    """Which configured certificate, if any, already covers this host name."""
    host = (request.args.get("host") or "").strip()
    if not host:
        return jsonify({"ok": False, "error": "host is required"}), 400
    cfg = load_config()
    cert, how = wizard.cert_for_host(cfg["acme"]["certificates"], host)
    if not cert:
        return jsonify({"ok": True, "host": host, "covered": False})
    info = cert_details(cert_path(cert))
    return jsonify({"ok": True, "host": host, "covered": True, "how": how,
                    "id": cert["id"], "name": cert["name"],
                    "domains": parse_domains(cert), "status": info["status"],
                    "expires_iso": info["expires_iso"], "days_left": info["days_left"]})


def _drop_orphan_wizard_servers(hp, candidate_ids, acts):
    """Remove wizard-made Real Servers that no pool references any more.

    Hand-made servers are left alone even when unused -- someone may be keeping
    them on purpose, and the Real Servers page is where those belong.
    """
    referenced = {s for b in hp["backends"] for s in (b.get("servers") or [])}
    for sid in candidate_ids:
        if sid in referenced:
            continue
        srv = _by_id(hp["servers"]).get(sid)
        if srv and srv.get("description") == wizard.WIZARD_MARK:
            hp["servers"] = [s for s in hp["servers"] if s.get("id") != sid]
            acts.append({"action": "removed", "type": "Real Server", "name": srv.get("name")})


def _is_wildcard(hp, rule):
    """Does this rule route by a wildcard host name?"""
    conds = _by_id(hp["conditions"])
    return any((conds.get(c) or {}).get("type") == "host_matches"
               and any(v.startswith("*.") for v in (conds[c].get("value") or "").split())
               for c in rule_cond_ids(rule))


def _place_rule(hp, rule_ids, rule):
    """Position a rule among a frontend's rules by how specific it is.

    HAProxy takes the first matching use_backend, so a rule for
    host + /api must come before the host-only rule it refines -- otherwise
    the broader one swallows the traffic and the narrower one never fires.
    For the same reason a named host comes before a wildcard that would
    also match it: app.example.com before *.example.com.
    """
    rules = _by_id(hp["rules"])
    ids = [r for r in rule_ids if r != rule["id"]]
    mine = set(rule_cond_ids(rule))
    wild = _is_wildcard(hp, rule)
    for i, rid in enumerate(ids):
        other = rules.get(rid)
        if not other:
            continue
        if set(rule_cond_ids(other)) < mine or (not wild and _is_wildcard(hp, other)):
            return ids[:i] + [rule["id"]] + ids[i:]
    return ids + [rule["id"]]


def _label(host):
    """The first label of a host name, for naming: the one after the * of a
    wildcard, marked as one."""
    parts = host.split(".")
    if parts[0] == "*" and len(parts) > 1:
        return "wildcard-" + parts[1]
    return parts[0]


REDIRECT_CODES = (301, 302, 307, 308)


def wizard_publish(cfg, pubs, tgts, name=None, want_cert=True, account=None,
                   challenge=None, http_redirect=True, health=None,
                   certificate_id=None, new_certificate=False,
                   balance=None, persistence=None, stick_size=None, stick_expire=None,
                   stick_type=None, log_health_checks=False, check_port=None,
                   timeout_connect=None, timeout_server=None, service_id=None,
                   auth=None, oauth_opts=None, allow_src=None, notify_mode=None,
                   rate_limit=None, rate_window=None, proxy_protocol=None,
                   allow_lists=None, error_pages=None, rules=None,
                   hsts=None, hsts_subdomains=None, redirect=None):
    """Create (or update) everything needed to serve `pub` from `tgts`.

    Re-running for the same public host updates that mapping instead of adding
    a second one, so the wizard is safe to use as an editor.
    """
    hp, ac = cfg["haproxy"], cfg["acme"]
    acts, warns = [], []
    # None leaves the servers' setting alone (a caller that does not know the
    # field); "" turns it off.
    if proxy_protocol is not None and proxy_protocol not in ("", "v1", "v2"):
        raise ValueError("The PROXY protocol must be off, v1 or v2")
    # One service can answer for several host names and on several ports. The
    # names become one rule, and that rule goes into a listener for each port,
    # so every name answers on every port. The scheme is shared; the first URL
    # names things.
    pubs = pubs if isinstance(pubs, list) else [pubs]
    pub = pubs[0]
    hosts, ports = [], []
    for p in pubs:
        if p["host"].lower() not in {h.lower() for h in hosts}:
            hosts.append(p["host"])
        if p["port"] not in ports:
            ports.append(p["port"])

    def act(action, kind, nm):
        acts.append({"action": action, "type": kind, "name": nm})

    # What this service already consists of, when one is being edited. Editing
    # must change these objects, never leave them behind and build a second set.
    existing_rule = existing_fe = None
    if service_id:
        if service_id.startswith("fe:"):
            existing_fe = _by_id(hp["frontends"]).get(service_id[3:])
        else:
            existing_rule = _by_id(hp["rules"]).get(service_id)
    existing_pool = _by_id(hp["backends"]).get(
        (existing_rule or existing_fe or {}).get("backend")
        or (existing_fe or {}).get("default_backend") or "")
    existing_monitor = _by_id(hp["healthchecks"]).get((existing_pool or {}).get("healthcheck") or "")
    old_hosts = [c.get("value") for c in
                 (_by_id(hp["conditions"]).get(cid) for cid in rule_cond_ids(existing_rule))
                 if c and c.get("type") == "host_matches" and c.get("value")]

    is_tcp = pub["scheme"] == "tcp"
    if name and name.strip():
        base = name.strip()
    elif is_tcp:
        base = "tcp-%d" % pub["port"]
    else:
        base = _label(pub["host"]) + \
            ("-" + _sec(pub["path"].strip("/")).replace("/", "-") if pub["path"] else "")
    # A service that redirects somewhere else rather than forwarding: it has
    # no servers, and nothing to check.
    if redirect is not None:
        if is_tcp:
            raise ValueError("a tcp:// service forwards a port; it cannot redirect")
        to = str(redirect.get("to") or "").strip()
        if not _plain_url(to):
            raise ValueError("a redirect needs an address starting with http:// or https://")
        try:
            code = int(redirect.get("code") or 301)
        except (TypeError, ValueError):
            code = 0
        if code not in REDIRECT_CODES:
            raise ValueError("a redirect is answered with 301, 302, 307 or 308")
        redirect = {"to": to, "code": code, "keep_path": bool(redirect.get("keep_path", True))}
        tgts, health = [], {"type": "none"}

    # -- Real Servers -----------------------------------------------------
    # The targets given here ARE the pool's servers: publishing the same URL
    # again repoints it instead of quietly adding a second server behind it.
    srv_ids = []
    for t in tgts:
        # A target already claimed by an earlier entry cannot be claimed again:
        # two targets sharing one address:port would otherwise both resolve to
        # the same server, and the pool would list it twice -- which HAProxy
        # rejects as "another server named 'a' was already defined".
        label = (t.get("label") or "").strip()
        srv = None
        if label:
            # An explicitly named target names the server, so match on that
            # first: editing galera2's address should repoint galera2, not
            # invent a second server.
            srv = wizard._find(hp["servers"], lambda s: s.get("name") == label
                        and s["id"] not in srv_ids)
            if srv:
                srv["address"], srv["port"] = t["host"], t["port"]
                srv["ssl"] = t["scheme"] == "https"
        if srv is None:
            srv = wizard._find(hp["servers"], lambda s: s.get("address") == t["host"]
                        and str(s.get("port")) == str(t["port"])
                        and bool(s.get("ssl")) == (t["scheme"] == "https")
                        and s["id"] not in srv_ids)
        if srv:
            act("reused", "Real Server", srv["name"])
        else:
            default_name = base + "-srv" if len(tgts) == 1 else "%s-%s" % (base, t["host"])
            srv = {"id": str(uuid.uuid4()),
                   "name": wizard._uniq_name({s["name"] for s in hp["servers"]},
                                      t.get("label") or default_name),
                   "address": t["host"], "port": t["port"], "enabled": True,
                   "ssl": t["scheme"] == "https", "ssl_verify": False,
                   "description": wizard.WIZARD_MARK}
            hp["servers"].append(srv)
            act("created", "Real Server", srv["name"])
        if check_port:
            srv["check_port"] = check_port
        # Whether a server expects the PROXY line belongs to the port it
        # listens on, so a server shared with another service carries the same
        # setting there -- which is what that port needs either way.
        if proxy_protocol:
            srv["proxy_protocol"] = proxy_protocol
        elif proxy_protocol is not None:
            srv.pop("proxy_protocol", None)
        if srv["id"] not in srv_ids:
            srv_ids.append(srv["id"])

    pool_opts = {
        "mode": "tcp" if is_tcp else "http",
        "balance": balance or ("source" if is_tcp else "roundrobin"),
        "persistence": persistence or "none",
        "stick_size": stick_size or "50k",
        "stick_expire": stick_expire or "30m",
        "stick_type": stick_type if stick_type in ("ip", "ipv6") else "ip",
        "log_health_checks": bool(log_health_checks),
        "timeout_connect": timeout_connect or "",
        "timeout_server": timeout_server or "",
        # What losing a server means for this pool: news, or Tuesday. A
        # Patroni pool is designed to have one server passing, so "some are
        # down" is its healthy state and only a full outage is worth a word.
        "notify_mode": notify_mode if notify_mode in ("servers", "outage", "off") else "servers",
        "redirect_to": redirect["to"] if redirect else "",
        "redirect_code": redirect["code"] if redirect else 301,
        "redirect_keep_path": redirect["keep_path"] if redirect else True,
    }
    if redirect:
        pool_opts["notify_mode"] = "off"         # no servers to lose
    # HSTS, sent over HTTPS only. Silence leaves the pool as it is.
    if hsts is not None:
        pool_opts["hsts"] = bool(hsts) and not is_tcp
        pool_opts["hsts_subdomains"] = bool(hsts_subdomains) and bool(hsts) and not is_tcp
    # Who may reach it by source address. Same contract as auth: silence
    # leaves the pool as it is, an empty string switches it off. Refused here
    # when an entry does not parse -- at the form, where the typo can be
    # fixed, rather than at the renderer, which can only fail closed.
    if allow_src is not None:
        good, bad = access.networks(allow_src)
        if bad:
            raise ValueError("not a network: %s -- one address or CIDR per line, "
                             "e.g. 192.168.0.0/16" % ", ".join(bad[:3]))
        pool_opts["allow_src"] = "\n".join(good)
    # The named lists beside the typed networks. A list that no longer exists
    # is dropped here rather than stored as a reference to nothing.
    if allow_lists is not None:
        pool_opts["allow_lists"] = access.known_lists(cfg, allow_lists)
    # The pages this service wants for itself; one that no longer exists is
    # dropped rather than stored as a reference to nothing.
    if error_pages is not None:
        pool_opts["error_pages"] = errorpages.known_pages(cfg, error_pages)
    # Rules the service holds for itself. A routing rule is not one of them,
    # and one that no longer exists is dropped rather than stored.
    if rules is not None:
        known = {r["id"]: r for r in hp["rules"] if r.get("id")}
        pool_opts["rules"] = [r for r in rules if r in known and known[r].get("type") != "use_backend"]
    # A ceiling per client address. Silence leaves the pool as it is; an
    # empty limit switches it off. Refused here, where the typo can be fixed,
    # rather than saved and rendered as no limit at all.
    if rate_limit is not None:
        pool_opts["rate_limit"] = "" if str(rate_limit).strip() == "" else rate_limit
    if rate_window is not None:
        pool_opts["rate_window"] = "" if str(rate_window).strip() == "" else rate_window
    validate.check_pool(pool_opts)
    for k in ("rate_limit", "rate_window"):
        if pool_opts.get(k) not in ("", None):
            pool_opts[k] = int(str(pool_opts[k]).strip())
    # A sign-in in front of the service. Silence leaves whatever the pool has:
    # an edit that does not mention it must not switch it off.
    if auth is not None:
        want = bool(auth.get("enabled")) and not is_tcp
        if want and not access.users_with_passwords(cfg):
            raise ValueError("there is nobody to sign in yet -- add a user under "
                             "Access > Users first")
        known = {g["id"] for g in access.section(cfg)["groups"] if g.get("id")}
        missing = [g for g in (auth.get("groups") or []) if g not in known]
        if missing:
            raise ValueError("that group no longer exists")
        pool_opts["auth_enabled"] = want
        pool_opts["auth_groups"] = [g for g in (auth.get("groups") or [])] if want else []
        pool_opts["auth_realm"] = (auth.get("realm") or "").strip() if want else ""
        good, bad = access.networks(auth.get("exempt") or "")
        if bad:
            raise ValueError("not a network: %s -- one address or CIDR per line, "
                             "e.g. 192.168.0.0/16" % ", ".join(bad[:3]))
        pool_opts["auth_exempt_src"] = "\n".join(good) if want else ""
        pool_opts["auth_exempt_lists"] = access.known_lists(cfg, auth.get("exempt_lists")) if want else []
        if bool(auth.get("enabled")) and is_tcp:
            warns.append("A tcp:// service forwards a raw port, which carries no place to "
                         "put a sign-in, so it was not applied. Publish the service over "
                         "HTTPS to require one.")
    # A sign-in through the identity provider. Same contract again: silence
    # leaves the pool alone, enabled:false clears it. The shared gate does
    # the refusing, so the editor and this path cannot drift apart.
    if oauth_opts is not None:
        want = bool(oauth_opts.get("enabled")) and not is_tcp
        pool_opts["oauth_enabled"] = want
        pool_opts["oauth_allow"] = "\n".join(
            oauth.parse_allow(oauth_opts.get("allow"))[0]) if want else ""
        pool_opts["oauth_forward"] = bool(oauth_opts.get("forward")) and want
        if want and not oauth.ready(oauth.settings_of(cfg)):
            raise ValueError("single sign-on is not configured yet -- fill in the "
                             "provider under Access > Single sign-on first")
        if bool(oauth_opts.get("enabled")) and is_tcp:
            warns.append("A tcp:// service forwards a raw port, which carries no place "
                         "for a sign-in redirect, so OIDC was not applied.")
    oauth.validate_pool_oauth(cfg, pool_opts, existing_pool)

    # -- Health Monitor ---------------------------------------------------
    monitor = None
    if health is None and existing_monitor is not None:
        # An edit that says nothing about health checking leaves it alone,
        # rather than reading silence as "switch it off".
        monitor = existing_monitor
        htype = existing_monitor.get("type") or "none"
        act("reused", "Health Monitor", monitor["name"])
    else:
        htype = (health or {}).get("type") or "none"
    if monitor is None and htype != "none":
        want = {"type": htype,
                "interval": (health.get("interval") or "2s"),
                "http_method": (health.get("method") or "GET"),
                "http_uri": health.get("uri") or "/",
                "http_version": health.get("version") or "",
                "http_host": health.get("host") or "",
                "expect_status": str(health.get("status") or "") if htype == "http" else "",
                "db_user": health.get("user") or ("postgres" if htype == "pgsql" else "haproxy"),
                "mysql_post41": bool(health.get("post41", True))}
        # The monitor this service already has is the one to change -- unless
        # another pool shares it, in which case editing here must not alter
        # that one too.
        shared = existing_monitor is not None and any(
            b.get("healthcheck") == existing_monitor["id"] and b is not existing_pool
            for b in hp["backends"])
        monitor = None
        if existing_monitor is not None and not shared:
            changed = any(str(existing_monitor.get(k, "")) != str(v) for k, v in want.items())
            existing_monitor.update(want)
            monitor = existing_monitor
            act("updated" if changed else "reused", "Health Monitor", monitor["name"])
        if monitor is None:
            monitor = wizard._find(hp["healthchecks"], lambda m: all(
                str(m.get(k, "")) == str(v) for k, v in want.items() if k != "mysql_post41"))
        if monitor and monitor is not existing_monitor:
            act("reused", "Health Monitor", monitor["name"])
        if monitor is None:
            monitor = dict(want)
            monitor["id"] = str(uuid.uuid4())
            monitor["name"] = wizard._uniq_name({m["name"] for m in hp["healthchecks"]}, base + "-check")
            hp["healthchecks"].append(monitor)
            act("created", "Health Monitor", monitor["name"])
        if htype in ("pgsql", "mysql"):
            warns.append("A %s check expects the servers behind this service to speak that database "
                         "protocol. Point it at the database itself, not at a web server, or every "
                         "server will be marked down." % ("PostgreSQL" if htype == "pgsql" else "MySQL/MariaDB"))

    # A monitor this service alone was using, now switched off
    if htype == "none" and existing_monitor is not None:
        if not any(b.get("healthcheck") == existing_monitor["id"] and b is not existing_pool
                   for b in hp["backends"]):
            hp["healthchecks"] = [m for m in hp["healthchecks"] if m["id"] != existing_monitor["id"]]
            acts.append({"action": "removed", "type": "Health Monitor",
                         "name": existing_monitor.get("name")})

    # -- Backend Pool -----------------------------------------------------
    # The pool this service already uses, whatever it is called: matching by
    # name alone would strand it as soon as the name changed.
    pool = existing_pool or wizard._find(hp["backends"], lambda b: b.get("name") == _sec(base))
    if pool is not None and pool is existing_pool and pool.get("name") != _sec(base) and name:
        renamed = wizard._uniq_name({b["name"] for b in hp["backends"] if b is not pool}, base)
        acts.append({"action": "renamed", "type": "Backend Pool",
                     "name": "%s -> %s" % (pool["name"], renamed)})
        pool["name"] = renamed
    if pool:
        previous = list(pool.get("servers") or [])
        pool["servers"] = srv_ids
        pool["healthcheck_enabled"] = bool(monitor)
        pool["healthcheck"] = monitor["id"] if monitor else ""
        pool.update(pool_opts)
        act("updated" if previous != srv_ids else "reused", "Backend Pool", pool["name"])
        _drop_orphan_wizard_servers(hp, previous, acts)
    else:
        pool = {"id": str(uuid.uuid4()),
                "name": wizard._uniq_name({b["name"] for b in hp["backends"]}, base),
                "enabled": True, "servers": srv_ids,
                "healthcheck_enabled": bool(monitor),
                "healthcheck": monitor["id"] if monitor else ""}
        pool.update(pool_opts)
        hp["backends"].append(pool)
        act("created", "Backend Pool", pool["name"])

    # -- TCP: a listening port sent straight to the pool ------------------
    # TCP carries no host name, so a port serves exactly one pool: no
    # conditions, no rules, just bind + default_backend.
    if is_tcp:
        fe = None
        if service_id and service_id.startswith("fe:"):
            fe = _by_id(hp["frontends"]).get(service_id[3:])
            if fe:                       # the port may be what changed
                fe["binds"] = "%s:%d" % (pub["host"] or "0.0.0.0", pub["port"])
                clash = wizard._find(hp["frontends"], lambda f: f is not fe and pub["port"] in wizard._bind_ports(f))
                if clash:
                    raise ValueError("port %d is already used by \"%s\"" % (pub["port"], clash["name"]))
        fe = fe or wizard._find(hp["frontends"], lambda f: pub["port"] in wizard._bind_ports(f))
        if fe:
            if fe.get("mode") != "tcp":
                raise ValueError("port %d is already used by the HTTP service \"%s\"" % (pub["port"], fe["name"]))
            if fe.get("default_backend") and fe["default_backend"] != pool["id"]:
                other = _by_id(hp["backends"]).get(fe["default_backend"])
                raise ValueError("port %d already forwards to the pool \"%s\"; delete that service first"
                                 % (pub["port"], other["name"] if other else "?"))
            fe["default_backend"] = pool["id"]
            act("updated", "Public Service", fe["name"])
        else:
            fe = {"id": str(uuid.uuid4()),
                  "name": wizard._uniq_name({f["name"] for f in hp["frontends"]}, base + "-listener"),
                  "enabled": True, "mode": "tcp",
                  "binds": "%s:%d" % (pub["host"] or "0.0.0.0", pub["port"]),
                  "ssl_enabled": False, "certificates": [], "rules": [],
                  "default_backend": pool["id"], "custom": ""}
            hp["frontends"].append(fe)
            act("created", "Public Service", fe["name"])
        return acts, warns

    # -- Conditions: host, and a path prefix when the URL has one ---------
    host_ids, path_id = [], None
    for h in hosts:
        host_cond = wizard._find(hp["conditions"], lambda c: c.get("type") == "host_matches"
                          and (c.get("value") or "").lower() == h.lower())
        if host_cond:
            act("reused", "Condition", host_cond["name"])
        else:
            suffix = base if len(hosts) == 1 else _sec(_label(h))
            host_cond = {"id": str(uuid.uuid4()),
                         "name": wizard._uniq_name({c["name"] for c in hp["conditions"]}, "host-" + suffix),
                         "type": "host_matches", "value": h,
                         "description": "created by the publish wizard"}
            hp["conditions"].append(host_cond)
            act("created", "Condition", host_cond["name"])
        host_ids.append(host_cond["id"])

    if pub["path"]:
        pc = wizard._find(hp["conditions"], lambda c: c.get("type") == "path_starts_with"
                   and c.get("value") == pub["path"])
        if pc:
            act("reused", "Condition", pc["name"])
        else:
            pc = {"id": str(uuid.uuid4()),
                  "name": wizard._uniq_name({c["name"] for c in hp["conditions"]}, "path-" + base),
                  "type": "path_starts_with", "value": pub["path"],
                  "description": "created by the publish wizard"}
            hp["conditions"].append(pc)
            act("created", "Condition", pc["name"])
        path_id = pc["id"]
    cond_ids = host_ids + ([path_id] if path_id else [])

    # -- Rule -------------------------------------------------------------
    # When a service is being edited, follow its id: the conditions are derived
    # from the URL, so a changed URL no longer matches and would otherwise leave
    # the old mapping in place beside the new one.
    rule = None
    if service_id and not service_id.startswith("fe:"):
        rule = _by_id(hp["rules"]).get(service_id)
    if rule is None:
        rule = wizard._find(hp["rules"], lambda r: r.get("type") == "use_backend"
                     and set(rule_cond_ids(r)) == set(cond_ids))
    # What an operator added to the rule by hand -- an address list, a header
    # test -- is theirs and stays. The wizard's own conditions are the host
    # names and the path, told apart by type, and those it replaces. Until
    # 2.0 an edit rewrote the whole list, and a condition added on the Rules
    # page was gone the next time the service was saved.
    conds_by_id = _by_id(hp["conditions"])
    extras = [cid for cid in rule_cond_ids(rule)
              if (conds_by_id.get(cid) or {}).get("type") not in ("host_matches", "path_starts_with")]
    all_of = ([path_id] if path_id else []) + extras
    if len(host_ids) > 1 and all_of:
        # Several names, and something that must hold whichever of them was
        # asked for: any of the names, and all of the rest.
        shape = {"any_of": host_ids, "conditions": all_of, "operator": "and"}
    else:
        # One name, or names alone: the shape every version renders the same.
        shape = {"any_of": [], "conditions": host_ids + all_of,
                 "operator": "or" if len(host_ids) > 1 else "and"}
    if rule:
        previous_conds = rule_cond_ids(rule)
        rule.update(shape)
        rule["backend"] = pool["id"]
        act("updated", "Rule", rule["name"])
        # conditions the old URL needed and nothing else uses
        still_used = {c for r in hp["rules"] for c in rule_cond_ids(r)}
        for cid in previous_conds:
            if cid in still_used:
                continue
            gone = _by_id(hp["conditions"]).get(cid)
            if gone:
                hp["conditions"] = [c for c in hp["conditions"] if c.get("id") != cid]
                acts.append({"action": "removed", "type": "Condition", "name": gone.get("name")})
    else:
        rule = dict({"id": str(uuid.uuid4()),
                     "name": wizard._uniq_name({r["name"] for r in hp["rules"]}, "to-" + base),
                     "type": "use_backend", "test": "if", "backend": pool["id"]}, **shape)
        hp["rules"].append(rule)
        act("created", "Rule", rule["name"])

    # -- Certificate (https only; the object also gives Apply a placeholder)
    cert = None
    if pub["scheme"] == "https" and want_cert:
        how = None
        if certificate_id:
            cert = _by_id(ac["certificates"]).get(certificate_id)
            how = "chosen" if cert else None
        if not cert and not new_certificate:
            # a single certificate has to cover every name, or it is no use here
            cert, how = wizard.cert_for_host(ac["certificates"], pub["host"])
            if cert and not all(wizard.cert_for_host([cert], h)[0] for h in hosts):
                missing = [h for h in hosts if not wizard.cert_for_host([cert], h)[0]]
                extra = " ".join(parse_domains(cert) + missing)
                cert["domains"] = extra
                act("updated", "Certificate", "%s covers %s" % (cert["name"], ", ".join(missing)))
                how = "extended"
                # Listing a name is not covering it. The file on disk still
                # holds what was last issued, so until it is issued again the
                # new name is served the wrong certificate -- which looks like
                # the address being down.
                on_disk = cert_details(cert_path(cert))
                # Whatever is on disk was issued before this name was added, so
                # it does not cover it -- a placeholder no more than a real one.
                if on_disk["deployed"] and not set(m.lower() for m in missing) <= set(on_disk["names"]):
                    warns.append(
                        "%s was extended to cover %s, but the certificate on disk was "
                        "issued before that and does not. Press Issue on it, or those "
                        "names will be served the wrong certificate -- which looks "
                        "like the address being down."
                        % (cert["name"], ", ".join(missing)))
        if cert:
            act("reused", "Certificate", cert["name"] +
                (" (wildcard %s covers %s)" % (next((d for d in parse_domains(cert)
                                                     if wizard.domain_covers(d, pub["host"]) and d.startswith("*.")), ""),
                                               pub["host"]) if how == "wildcard" else ""))
        else:
            accounts, challenges = ac["accounts"], ac["challenges"]
            acc_id = account or (accounts[0]["id"] if len(accounts) == 1 else "")
            ch_id = challenge or (challenges[0]["id"] if len(challenges) == 1 else "")
            stale = None
            for old in old_hosts:
                if old.lower() == pub["host"].lower():
                    continue
                candidate = wizard._find(ac["certificates"], lambda c: parse_domains(c) == [old])
                if candidate and cert_details(cert_path(candidate))["status"] in ("missing", "placeholder"):
                    stale = candidate
                    break
            if stale is not None:
                # never issued, and for a name this service has stopped using
                stale["domains"] = " ".join(hosts)
                if acc_id:
                    stale["account"] = stale.get("account") or acc_id
                if ch_id:
                    stale["challenge"] = stale.get("challenge") or ch_id
                cert = stale
                act("updated", "Certificate", "%s -> %s" % (cert["name"], pub["host"]))
            else:
                cert = {"id": str(uuid.uuid4()),
                        "name": wizard._uniq_name({c["name"] for c in ac["certificates"]}, base),
                        "domains": " ".join(hosts), "account": acc_id, "challenge": ch_id,
                        "key_type": "ec-256", "auto_renew": True}
                ac["certificates"].append(cert)
                act("created", "Certificate", cert["name"])
                if old_hosts and old_hosts[0].lower() != pub["host"].lower():
                    warns.append("The certificate for %s was kept: it has been issued, so it is not "
                                 "repointed automatically. Remove it under Certificates if it is no "
                                 "longer wanted." % old_hosts[0])
            wild = [h for h in hosts if h.startswith("*.")]
            chosen_ch = _by_id(challenges).get(cert.get("challenge") or "")
            if wild and chosen_ch and chosen_ch.get("method") != "dns01":
                warns.append("A wildcard certificate (%s) can only be issued with a DNS challenge; "
                             "the one chosen is HTTP. Pick a DNS challenge type for it under "
                             "Certificates." % ", ".join(wild))
            if not acc_id or not ch_id:
                warns.append("The certificate has no %s yet, so it cannot be issued. Apply installs a "
                             "self-signed placeholder meanwhile; add one under ACME and press Issue."
                             % (" and ".join([x for x in ["ACME account" if not acc_id else "",
                                                          "challenge type" if not ch_id else ""] if x])))

    # -- Public Services (frontends), one per port -----------------------
    want_ssl = pub["scheme"] == "https"
    typed = {(p["host"].lower(), p["port"]) for p in pubs}
    also = [wizard.url_label(dict(pub, host=h, port=pt)) for pt in ports for h in hosts
            if (h.lower(), pt) not in typed]
    if also:
        warns.append("Every name on a service answers on each of its ports, so this also "
                     "serves %s." % ", ".join(also))
    serving = []
    for port in ports:
        fe = wizard._find(hp["frontends"], lambda f: port in wizard._bind_ports(f)
                   and f.get("mode") != "tcp" and bool(f.get("ssl_enabled")) == want_ssl)
        if fe:
            act("updated", "Public Service", fe["name"])
        else:
            clash = wizard._find(hp["frontends"], lambda f: port in wizard._bind_ports(f))
            if clash:
                raise ValueError("port %d is already used by \"%s\"" % (port, clash["name"]))
            fe = {"id": str(uuid.uuid4()),
                  "name": wizard._uniq_name({f["name"] for f in hp["frontends"]},
                                     ("https" if want_ssl else "http") + "-" + str(port)),
                  "enabled": True, "mode": "http", "binds": "0.0.0.0:%d" % port,
                  "ssl_enabled": want_ssl, "http2": want_ssl, "forwardfor": True,
                  "certificates": [], "rules": [], "custom": ""}
            hp["frontends"].append(fe)
            act("created", "Public Service", fe["name"])
        serving.append(fe["id"])
        fe["rules"] = _place_rule(hp, fe.get("rules") or [], rule)
        if cert and cert["id"] not in (fe.get("certificates") or []):
            fe.setdefault("certificates", []).append(cert["id"])
        if not fe.get("default_backend"):
            warns.append("Public Service \"%s\" has no default Backend Pool, so a request for any other "
                         "host gets what Unknown hosts says under Advanced \u00b7 HAProxy \u203a Settings."
                         % fe["name"])
    # Editing a service: the URLs on the form are all of them, so a port that
    # is no longer listed stops serving it. Without an edit (a publish that
    # happens to match an existing service's names) nothing is taken away --
    # that caller may not know the other ports, and they are live.
    if existing_rule is not None and existing_rule is rule:
        for f in hp["frontends"]:
            if f["id"] not in serving and rule["id"] in (f.get("rules") or []):
                f["rules"] = [x for x in f["rules"] if x != rule["id"]]
                act("updated", "Public Service", f["name"])

    # -- Optional :80 service that redirects to https ---------------------
    if want_ssl and http_redirect:
        red = wizard._find(hp["frontends"], lambda f: 80 in wizard._bind_ports(f) and not f.get("ssl_enabled"))
        if red:
            if not red.get("http_to_https"):
                red["http_to_https"] = True
                act("updated", "Public Service", red["name"])
            else:
                act("reused", "Public Service", red["name"])
        else:
            red = {"id": str(uuid.uuid4()),
                   "name": wizard._uniq_name({f["name"] for f in hp["frontends"]}, "http-redirect"),
                   "enabled": True, "mode": "http", "binds": "0.0.0.0:80",
                   "ssl_enabled": False, "forwardfor": True, "http_to_https": True,
                   "certificates": [], "rules": [], "custom": ""}
            hp["frontends"].append(red)
            act("created", "Public Service", red["name"])

    return acts, warns


# --------------------------------------------------------------------------
# front the management UI itself with HAProxy + a certificate
