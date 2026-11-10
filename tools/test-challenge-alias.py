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
res = acme._acme_issue(cfg, cert)
ok(not res.get("ok") and "alias" in res.get("error", ""),
   "an alias count that fits no domain count fails before acme.sh runs")
cfg["acme"]["challenges"][0].update(method="http01", challenge_alias="alias.example.net")
seen.clear()
acme._acme_issue(cfg, cert)
ok(seen and "--challenge-alias" not in seen[-1], "HTTP-01 never gets an alias")

print()
print("challenge alias holds" if not fails else "%d failed" % len(fails))
sys.exit(1 if fails else 0)
