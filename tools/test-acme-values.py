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
for n, good in enumerate(("example.com *.example.com", "Host_1.lan", "2001:db8::1", "localhost")):
    r = client.post("/api/acme/certificates", headers=H, json=dict(cert, name="g%d" % n, domains=good))
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

# -- saving: the DNS credentials. Each line is NAME=value, and the whole line
# goes into the environment of acme.sh, which takes its own settings from
# there: ACCOUNT_CONF_PATH names a file it sources as root. A name is taken
# only when the hook's script reads it; acme.sh's own are refused by name.
hooks_known = dnsapi.hook_variables("dns_cf")
if hooks_known:
    ok({"CF_Token", "CF_Key", "CF_Email", "CF_Account_ID"} <= hooks_known,
       "the variables dns_cf declares are read from its script: %s" % ", ".join(sorted(hooks_known)))
    r = client.post("/api/acme/challenges", headers=H,
                    json=dict(ch, name="cf-ok", dns_credentials="CF_Token=abc\nCF_Account_ID=def\n\n# a note\n"))
    ok(r.status_code == 200, "CF_Token and CF_Account_ID are stored for dns_cf; blank and # lines are fine")
    r = client.post("/api/acme/challenges", headers=H,
                    json=dict(ch, name="cf-other", dns_credentials="CF_Token=abc\nAWS_ACCESS_KEY_ID=x"))
    ok(r.status_code == 400 and "not a variable the dns_cf hook reads" in r.get_json().get("error", ""),
       "a variable dns_cf does not read is refused, naming the hook: %s" % r.get_json().get("error", "")[:80])
    # every hook acme.sh ships accepts every variable it declares
    refused = []
    for h in dnsapi.dnsapi_hooks():
        for name in dnsapi.hook_variables(h["hook"]) or ():
            if acme.dangerous_name(name) or not acme._SAFE_ENV.match(name):
                refused.append("%s:%s" % (h["hook"], name))
    ok(not refused, "no shipped hook declares a variable the refusals would take (%s)"
       % (", ".join(refused[:5]) or "none"))
else:
    print("  skip  acme.sh is not installed here, so the hooks' variables are not read")
for bad, why in (("ACCOUNT_CONF_PATH=/tmp/evil", "ACCOUNT_CONF_PATH, a file acme.sh sources"),
                 ("LE_CONFIG_HOME=/tmp", "LE_CONFIG_HOME"), ("HTTPS_INSECURE=1", "HTTPS_INSECURE"),
                 ("HTTP_HEADER=/etc/passwd", "HTTP_HEADER, a file acme.sh writes"),
                 ("LD_PRELOAD=/tmp/x.so", "LD_PRELOAD"), ("PATH=/tmp", "PATH"), ("DEBUG=3", "DEBUG"),
                 ("CF_Token=abc\nLOG_FILE=/etc/x", "LOG_FILE on a second line")):
    r = client.post("/api/acme/challenges", headers=H, json=dict(ch, name="bad", dns_credentials=bad))
    ok(r.status_code == 400 and "acme.sh or the shell acts on" in r.get_json().get("error", ""),
       "a credential line setting %s is refused with 400" % why)
for bad, why in (("CF Token=x", "a space in the name"), ("1CF=x", "a leading digit"),
                 ("CF_Token", "no = at all"), ("CF_Token=ab'c", "a quote in the value"),
                 ("CF_Token=ab\tc", "a control character in the value")):
    r = client.post("/api/acme/challenges", headers=H, json=dict(ch, name="bad", dns_credentials=bad))
    ok(r.status_code == 400, "a credential line with %s is refused with 400: %s"
       % (why, r.get_json().get("error", "")[:70]))
r = client.post("/api/acme/challenges", headers=H,
                json={"name": "http2", "method": "http01", "dns_credentials": "ACCOUNT_CONF_PATH=/tmp/evil"})
ok(r.status_code == 200, "an HTTP-01 challenge type does not use credentials, so they are not judged")
# without a hook script to ask, the refusals by name stand on their own
ok(acme.credential_names("dns_nosuchhook") is None, "an unknown hook has no variable list")
try:
    acme.credential_env({"method": "dns01", "dns_provider": "dns_nosuchhook",
                         "dns_credentials": "LE_CONFIG_HOME=/tmp"})
    ok(False, "LE_CONFIG_HOME is refused when the hook's variables are unknown")
except ValueError as e:
    ok("acts on" in str(e), "LE_CONFIG_HOME is refused when the hook's variables are unknown")
ok(acme.credential_env({"method": "dns01", "dns_provider": "dns_nosuchhook",
                        "dns_credentials": "MY_API_KEY=x"}) == {"MY_API_KEY": "x"},
   "and a plain name is taken, since there is nothing to check it against")
r = client.post("/api/wizard/certificate", headers=H,
                json={"domains": "w.example.com", "account": {"id": aid}, "dry_run": True,
                      "challenge": {"name": "new", "method": "dns01", "dns_provider": "dns_cf",
                                    "dns_credentials": "ACCOUNT_CONF_PATH=/tmp/evil"}})
ok(r.status_code == 400 and "ACCOUNT_CONF_PATH" in r.get_json().get("error", ""),
   "the wizard refuses a new challenge type with such a line")

# -- saving: an account's EAB key and custom CA address, kept by acme.sh as shell code too
for field, val, label in (("eab_kid", "kid'x", "a quote in the EAB key ID"),
                          ("eab_hmac", "hm\x01ac", "a control character in the EAB HMAC key"),
                          ("server", "https://ca.example.lan/dir'x", "a quote in the directory address")):
    body = {"name": "q", "ca": "custom", "server": "https://ca.example.lan/directory", "eab_kid": "k",
            "eab_hmac": "h"}
    body[field] = val
    r = client.post("/api/acme/accounts", headers=H, json=body)
    ok(r.status_code == 400 and "quote or a control character" in r.get_json().get("error", ""),
       "%s is refused with 400" % label)
r = client.post("/api/acme/accounts", headers=H, json={"name": "num", "ca": "custom", "server": 12})
ok(r.status_code == 400 and "must be text" in r.get_json().get("error", ""),
   "a number where text is expected is refused with 400, not a 500")

# -- issuing a configuration that never went through saving
seen = []
acme.acme_run = lambda args, env_extra=None: (seen.append(args) or (0, "ok"))
acme.deploy_cert = lambda cfg, cert: {"ok": True, "changed": True, "log": ""}
real_ensure = acme.ensure_account
acme.ensure_account = lambda acc: (seen.append(["--register-account"]) or (0, ""))


def issue(email="", hook="dns_cf", domains="a.example.com", creds="CF_Token=x"):
    del seen[:]
    c = load_config()
    c["acme"]["accounts"] = [{"id": "a", "name": "a", "email": email, "ca": "letsencrypt"}]
    c["acme"]["challenges"] = [{"id": "c", "name": "c", "method": "dns01", "dns_provider": hook,
                                "dns_credentials": creds}]
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
res = issue(creds="CF_Token=x\nACCOUNT_CONF_PATH=/tmp/evil")
ok(not res.get("ok") and "ACCOUNT_CONF_PATH" in (res.get("error") or "")
   and not any("--issue" in a for a in seen),
   "a stored credential line acme.sh acts on is refused before --issue runs")

print("\n" + ("acme.sh gets names, never shell code" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)
