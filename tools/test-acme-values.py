"""What acme.sh is never given: a value it would keep as shell code.

acme.sh stores the account e-mail, the DNS hook name and the domain names in
conf files of the form KEY='value' and runs those files as shell code later,
as root. A quote in any of them would run the rest. They are refused when
saved, and again before acme.sh runs, for a configuration that came by sync,
restore or an older version. (Reported in PR #41.)

    HAM_DATA_DIR=/tmp/x python3 tools/test-acme-values.py
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-acmevals-"))
os.environ["HAM_CERT_DIR"] = os.path.join(os.environ["HAM_DATA_DIR"], "certs")
os.environ["HAM_DRY_RUN"] = "1"

import ham   # noqa: E402
from ham import acme   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "vals-key"
save_config(cfg)
H = {"X-API-Key": "vals-key"}

QUOTE = "';touch${IFS}/tmp/pwn;'"

# -- saving: the challenge type's DNS hook
ch = {"name": "cf", "method": "dns01", "dns_provider": "dns_cf", "dns_credentials": "CF_Token=x"}
r = client.post("/api/acme/challenges", headers=H, json=ch)
ok(r.status_code == 200, "a DNS hook such as dns_cf is stored")
r = client.post("/api/acme/challenges", headers=H, json=dict(ch, name="sp", dns_provider=" dns_cf "))
ok(r.status_code == 200 and r.get_json().get("dns_provider") == "dns_cf",
   "spaces around a hook name are dropped")
for bad, why in (("dns_cf" + QUOTE, "a quote"), ("../../../../tmp/hook", "a path"),
                 ("dns_cf dns_aws", "a space"), ("$(id)", "a $")):
    r = client.post("/api/acme/challenges", headers=H, json=dict(ch, name="bad", dns_provider=bad))
    ok(r.status_code == 400 and "DNS API hook" in r.get_json().get("error", ""),
       "a DNS hook with %s is refused with 400" % why)
r = client.post("/api/acme/challenges", headers=H, json=dict(ch, name="empty", dns_provider=""))
ok(r.status_code == 200, "a DNS-01 challenge type with no hook yet still saves (the wizard warns)")
r = client.post("/api/acme/challenges", headers=H,
                json={"name": "http", "method": "http01", "dns_provider": "left" + QUOTE})
ok(r.status_code == 200, "an HTTP-01 challenge type does not use the hook, so it is not judged")

# every hook acme.sh ships has the allowed shape
from ham import dnsapi   # noqa: E402
names = [h["hook"] for h in dnsapi.dnsapi_hooks()]
if names:
    odd = [n for n in names if not acme._DNS_HOOK.match(n)]
    ok(not odd, "all %d hooks acme.sh ships pass (%s)" % (len(names), ", ".join(odd[:3]) or "none refused"))
else:
    print("  skip  acme.sh is not installed here, so its hook names are not checked")

# -- saving: the account's e-mail
acc = {"name": "le", "email": "me@example.com", "ca": "letsencrypt"}
for good in ("me@example.com", "first.last+acme@sub.example.co.uk", ""):
    r = client.post("/api/acme/accounts", headers=H, json=dict(acc, name="g", email=good))
    ok(r.status_code == 200, "the e-mail %r is stored" % good)
for bad, why in (("me@example.com" + QUOTE, "a quote"), ("me@example.com bob@x.org", "a space"),
                 ("$(id)@example.com", "a $"), ("me", "no @")):
    r = client.post("/api/acme/accounts", headers=H, json=dict(acc, name="b", email=bad))
    ok(r.status_code == 400 and "e-mail" in r.get_json().get("error", ""),
       "an e-mail with %s is refused with 400" % why)

# -- saving: the certificate's domain names
cfg = load_config()
cid = next(c["id"] for c in cfg["acme"]["challenges"] if c["name"] == "cf")
aid = cfg["acme"]["accounts"][0]["id"]
cert = {"name": "c", "account": aid, "challenge": cid, "key_type": "ec-256"}
for good in ("example.com *.example.com", "Host_1.lan", "2001:db8::1", "localhost"):
    r = client.post("/api/acme/certificates", headers=H, json=dict(cert, name="g", domains=good))
    ok(r.status_code == 200, "the domains %r are stored" % good)
for bad, why in (("a.example.com" + QUOTE, "a quote"), ("../../tmp/x", "a path"),
                 ("-x.example.com", "a leading dash"), ("--pre-hook", "an option"),
                 ("example.com.", "a trailing dot"), ("a..example.com", "an empty label")):
    r = client.post("/api/acme/certificates", headers=H, json=dict(cert, name="b", domains=bad))
    ok(r.status_code == 400 and "not a domain name" in r.get_json().get("error", ""),
       "domains with %s are refused with 400" % why)
r = client.post("/api/acme/certificates", headers=H,
                json={"name": "up", "source": "custom", "domains": "whatever" + QUOTE})
ok(r.status_code != 400 or "not a domain name" not in r.get_json().get("error", ""),
   "an uploaded certificate is not judged: its names never reach acme.sh")

# -- the certificate wizard
r = client.post("/api/wizard/certificate", headers=H,
                json={"domains": "../../tmp/x", "account": {"id": aid}, "challenge": {"id": cid},
                      "dry_run": True})
ok(r.status_code == 400 and "not a domain name" in r.get_json().get("error", ""),
   "the wizard refuses a domain that is a path")
r = client.post("/api/wizard/certificate", headers=H,
                json={"domains": "w.example.com", "account": {"id": aid}, "dry_run": True,
                      "challenge": {"name": "new", "method": "dns01", "dns_provider": "dns_cf" + QUOTE}})
ok(r.status_code == 400 and "DNS API hook" in r.get_json().get("error", ""),
   "the wizard refuses a new challenge type with a quote in its hook")
r = client.post("/api/wizard/certificate", headers=H,
                json={"domains": "w.example.com", "challenge": {"id": cid}, "dry_run": True,
                      "account": {"name": "new", "ca": "letsencrypt", "email": "x@example.com" + QUOTE}})
ok(r.status_code == 400 and "e-mail" in r.get_json().get("error", ""),
   "the wizard refuses a new account with a quote in its e-mail")

# -- issuing a configuration that never went through saving
seen = []
acme.acme_run = lambda args, env_extra=None: (seen.append(args) or (0, "ok"))
acme.deploy_cert = lambda cfg, cert: {"ok": True, "changed": True, "log": ""}
real_ensure = acme.ensure_account
acme.ensure_account = lambda acc: (seen.append(["--register-account"]) or (0, ""))


def issue(email="", hook="dns_cf", domains="a.example.com"):
    del seen[:]
    c = load_config()
    c["acme"]["accounts"] = [{"id": "a", "name": "a", "email": email, "ca": "letsencrypt"}]
    c["acme"]["challenges"] = [{"id": "c", "name": "c", "method": "dns01", "dns_provider": hook,
                                "dns_credentials": "CF_Token=x"}]
    k = {"id": "k", "name": "k", "domains": domains, "account": "a", "challenge": "c",
         "key_type": "ec-256"}
    return acme._acme_issue(c, k)


res = issue()
ok(res.get("ok") and any("--issue" in a for a in seen), "clean values issue as before")
for kw, word in ((dict(hook="dns_cf" + QUOTE), "DNS API hook"),
                 (dict(hook="../../../../tmp/hook"), "DNS API hook"),
                 (dict(email="me@example.com" + QUOTE), "e-mail"),
                 (dict(domains="a.example.com b.example.com" + QUOTE), "not a domain name"),
                 (dict(domains="../../tmp/x"), "not a domain name")):
    res = issue(**kw)
    ok(not res.get("ok") and word in (res.get("error") or "") and not seen,
       "a stored %s is refused before acme.sh runs at all" % next(iter(kw)))

print("\n" + ("acme.sh gets names, never shell code" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)
