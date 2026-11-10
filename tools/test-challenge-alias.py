#!/usr/bin/env python3
"""DNS alias mode: a challenge type's alias domain is validated when it is
saved and reaches acme.sh as --challenge-alias, once per alias.

    HAM_DATA_DIR=/tmp/x python3 tools/test-challenge-alias.py
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-alias-"))
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
cfg["local"]["api_key"] = "alias-key"
save_config(cfg)
H = {"X-API-Key": "alias-key"}

base = {"name": "cf", "method": "dns01", "dns_provider": "dns_cf", "dns_credentials": "CF_Token=x"}

r = client.post("/api/acme/challenges", headers=H, json=dict(base, challenge_alias="alias.example.net"))
ok(r.status_code == 200 and r.get_json().get("challenge_alias") == "alias.example.net",
   "a valid alias is stored on the challenge type")
r = client.post("/api/acme/challenges", headers=H, json=dict(base, name="bad", challenge_alias="x; reboot"))
ok(r.status_code == 400, "an alias that is not a host name is refused with 400")
r = client.post("/api/acme/challenges", headers=H, json=dict(base, name="none"))
ok(r.status_code == 200, "a challenge type without an alias still saves")

# the issue path hands the flag to acme.sh
seen = []
acme.acme_run = lambda args, env_extra=None: (seen.append(args) or (0, "ok"))
acme.deploy_cert = lambda cfg, cert: {"ok": True, "changed": True, "log": ""}
acme.ensure_account = lambda acc: (0, "")
cfg = load_config()
cfg["acme"]["accounts"] = [{"id": "a", "name": "a", "email": "", "ca": "letsencrypt"}]
cfg["acme"]["challenges"] = [{"id": "c", "name": "c", "method": "dns01", "dns_provider": "dns_cf",
                              "dns_credentials": "CF_Token=x", "challenge_alias": "alias.example.net"}]
cert = {"id": "k", "name": "k", "domains": "a.example.com *.example.com",
        "account": "a", "challenge": "c", "key_type": "ec-256"}
res = acme._acme_issue(cfg, cert)
args = seen[-1] if seen else []
ok(res.get("ok") and "--challenge-alias" in args
   and args[args.index("--challenge-alias") + 1] == "alias.example.net",
   "issuing passes --challenge-alias to acme.sh")
cfg["acme"]["challenges"][0]["challenge_alias"] = "a.net b.net c.net"
asked = []
acme.ensure_account = lambda acc: (asked.append(acc) or (0, ""))
seen.clear()
res = acme._acme_issue(cfg, cert)
ok(not res.get("ok") and "alias" in res.get("error", "") and not seen,
   "an alias count that fits no domain count fails before acme.sh runs")
ok(not asked, "and before the CA is asked to register the account")
cfg["acme"]["challenges"][0]["challenge_alias"] = 5
res = acme._acme_issue(cfg, cert)
ok(not res.get("ok") and "alias" in res.get("error", ""),
   "a stored alias that is not text fails the issuance with why, rather than raising")
cfg["acme"]["challenges"][0].update(method="http01", challenge_alias="alias.example.net")
seen.clear()
acme._acme_issue(cfg, cert)
ok(seen and "--challenge-alias" not in seen[-1], "HTTP-01 never gets an alias")



def refused(fn, *a):
    try:
        fn(*a)
    except ValueError:
        return True
    return False


print("the arguments")
ch = {"method": "dns01", "challenge_alias": "validation.example.net"}
ok(acme.challenge_alias_args(ch, ["a.example.com", "b.example.com"])
   == ["--challenge-alias", "validation.example.net"],
   "one alias applies to every domain on the certificate")
ch["challenge_alias"] = "x.example.net y.example.net"
ok(acme.challenge_alias_args(ch, ["a.example.com", "b.example.com"])
   == ["--challenge-alias", "x.example.net", "--challenge-alias", "y.example.net"],
   "one alias per domain is passed in order")
ok(acme.challenge_alias_args({"method": "dns01"}, ["a.example.com"]) == [],
   "no alias adds no argument")
ok(refused(acme.challenge_alias_args, {"challenge_alias": "a.net b.net"}, ["1.x.com", "2.x.com", "3.x.com"]),
   "an alias count that matches neither one nor the domain count is refused")
ok(acme.challenge_alias_args({"challenge_alias": "no alias.example.net"}, ["own.example.com", "ext.example.org"])
   == ["--challenge-alias", "no", "--challenge-alias", "alias.example.net"],
   "\"no\" in a position leaves that domain to its own zone, as acme.sh has it")

print("what counts as an alias")
P = acme.parse_challenge_alias
ok(P("alias.example.net.") == ["alias.example.net"], "a trailing dot, as in a zone file, is dropped")
ok(P("_acme-challenge.alias.example.net") == ["alias.example.net"],
   "a leading _acme-challenge. label is dropped: acme.sh adds it itself")
ok(P("a.example.net, b.example.net\nc.example.net") == ["a.example.net", "b.example.net", "c.example.net"],
   "spaces, commas and lines all separate")
ok(P(["a.example.net", "b.example.net"]) == ["a.example.net", "b.example.net"], "a list of names is taken as one")
ok(P(None) == [] and P("") == [], "nothing is nothing")
ok(P("_acme.validation.example.net") == ["_acme.validation.example.net"], "an underscore label is a host name here")
for bad in ("evil.net; rm -rf /", "--force", "nodots", "1.2.3.44", "a.--", "x.-y", "-x.example.net"):
    ok(refused(P, bad), "refused: %r" % bad)
for bad in (5, True, {"a": 1}, ["a.example.net", 5]):
    ok(refused(P, bad), "refused, with a reason rather than a crash: %r" % (bad,))

print("when a challenge type is saved")
for bad in (["a.example.net", 7], 5, True):
    r = client.post("/api/acme/challenges", headers=H, json=dict(base, name="typed", challenge_alias=bad))
    ok(r.status_code == 400, "an alias of the wrong type is a 400, not a 500: %r (%d)" % (bad, r.status_code))
r = client.post("/api/acme/challenges", headers=H,
                json=dict(base, name="listed", challenge_alias=["a.example.net", "b.example.net"]))
ok(r.status_code == 200 and r.get_json().get("challenge_alias") == "a.example.net b.example.net",
   "a list of names is stored as the text the editor shows")
r = client.post("/api/acme/challenges", headers=H,
                json=dict(base, name="pasted", challenge_alias="_acme-challenge.alias.example.net."))
ok(r.status_code == 200 and r.get_json().get("challenge_alias") == "alias.example.net",
   "a pasted record name is stored as the alias it means")
r = client.post("/api/acme/challenges", headers=H,
                json={"name": "web", "method": "http01", "challenge_alias": "oops typed"})
ok(r.status_code == 200, "HTTP-01 does not use the alias, so what is left in it is not checked")

print("aliases per domain, against the certificates that use them")
r = client.post("/api/acme/challenges", headers=H, json=dict(base, name="two", challenge_alias="x.example.net y.example.net"))
two = r.get_json()
r = client.post("/api/acme/challenges", headers=H, json=dict(base, name="one", challenge_alias="x.example.net"))
one = r.get_json()
cert2 = {"name": "pair", "domains": "a.example.com b.example.com", "account": "a", "challenge": two["id"]}
r = client.post("/api/acme/certificates", headers=H, json=cert2)
ok(r.status_code == 200, "two names on a challenge type with two aliases is saved")
pair = r.get_json()
r = client.put("/api/acme/certificates/" + pair["id"], headers=H, json=dict(cert2, domains="a.example.com b.example.com c.example.com"))
ok(r.status_code == 400 and "alias" in r.get_json().get("error", ""),
   "a third name on that certificate is refused when saved: %s" % (r.get_json().get("error") or "")[:80])
r = client.post("/api/acme/certificates", headers=H, json=dict(cert2, name="three", domains="a.example.com b.example.com c.example.com"))
ok(r.status_code == 400, "and so is a new certificate with three")
r = client.put("/api/acme/challenges/" + two["id"], headers=H, json=dict(base, name="two", challenge_alias="x.example.net y.example.net z.example.net"))
ok(r.status_code == 400 and "pair" in r.get_json().get("error", ""),
   "a third alias on a challenge type a two-name certificate uses is refused, naming the certificate")
r = client.put("/api/acme/challenges/" + two["id"], headers=H, json=dict(base, name="two", challenge_alias="x.example.net"))
ok(r.status_code == 200, "one alias for all of them is always fine")
r = client.put("/api/acme/certificates/" + pair["id"], headers=H, json=dict(cert2, domains="a.example.com b.example.com c.example.com"))
ok(r.status_code == 200, "and then the third name is too")
r = client.post("/api/acme/certificates", headers=H, json=dict(cert2, name="many", challenge=one["id"], domains="a.example.com b.example.com c.example.com"))
ok(r.status_code == 200, "any number of names goes with a single alias")

print("the certificate wizard")
W = {"issue": False, "account": {"name": "wiz", "email": "", "ca": "letsencrypt"}}
r = client.post("/api/wizard/certificate", headers=H, json=dict(
    W, dry_run=True, domains="w1.example.com w2.example.com w3.example.com",
    challenge=dict(base, name="wiz2", challenge_alias="x.example.net y.example.net")))
ok(r.status_code == 400 and "alias" in (r.get_json() or {}).get("error", ""),
   "three names and two aliases is refused in the preview already")
r = client.post("/api/wizard/certificate", headers=H, json=dict(
    W, dry_run=True, domains="w1.example.com", challenge={"name": "wiz-http", "method": "http01", "challenge_alias": "oops typed"}))
ok(r.status_code == 200, "an alias left over in an HTTP-01 challenge type does not stop the wizard")
r = client.post("/api/wizard/certificate", headers=H, json=dict(
    W, domains="w1.example.com w2.example.com",
    challenge=dict(base, name="wiz2", challenge_alias="alias1.example.net alias2.example.net")))
ok(r.status_code == 200, "two names and two aliases is created")
cid = r.get_json()["certificate_id"]
r = client.post("/api/wizard/certificate", headers=H, json=dict(
    W, domains="w2.example.com w1.example.com",
    challenge=dict(base, name="wiz3", challenge_alias="alias2.example.net alias1.example.net")))
stored = [c for c in load_config()["acme"]["certificates"] if c["id"] == cid][0]
ok(r.status_code == 200 and r.get_json()["certificate_id"] == cid and stored["domains"] == "w2.example.com w1.example.com",
   "the same names in another order: the certificate takes the order the aliases were typed for")

print()
print("challenge alias holds" if not fails else "%d failed" % len(fails))
sys.exit(1 if fails else 0)
