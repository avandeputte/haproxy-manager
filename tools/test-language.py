#!/usr/bin/env python3
"""The language pinned on the account, from the API's side.

    HAM_DATA_DIR=/tmp/x python3 tools/test-language.py

Empty means the browser's; otherwise it is a language the UI has a dictionary
for, and that is decided by the file being there, so nothing outside
static/js/i18n -- and nothing shaped like a path -- is ever stored. The
account dialog reads it back from whoami, which says nothing about it until
someone has signed in.
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-lang-"))
os.environ["HAM_DRY_RUN"] = "1"

import ham; ham   # noqa: E402  (route registration)
from ham.config import load_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
client.post("/api/setup", json={"username": "alex", "password": "language-pw1"})

who = client.get("/api/whoami").get_json()
ok(who.get("authenticated") and who.get("language") == "",
   "a new account follows the browser: %r" % who.get("language"))


def save(language):
    return client.post("/api/password", json={"username": "alex", "language": language})


r = save("nl")
ok(r.status_code == 200 and r.get_json().get("language") == "nl", "Dutch can be pinned")
ok(load_config()["local"]["admin"].get("language") == "nl", "and is stored with the account")
ok(client.get("/api/whoami").get_json().get("language") == "nl", "and whoami hands it back")

r = save("en")
ok(r.status_code == 200 and client.get("/api/whoami").get_json().get("language") == "en",
   "English can be pinned too -- it has no dictionary file, and is the point of the issue")

for bad in ("xx", "../../etc/passwd", "i18n", "DE", "de.js", 7, ["de"]):
    r = save(bad)
    ok(r.status_code == 400 and "unknown language" in r.get_json().get("error", ""),
       "%r is refused" % (bad,))
ok(load_config()["local"]["admin"].get("language") == "en", "and a refusal changes nothing")

r = client.post("/api/password", json={"username": "alex", "theme": "dark"})
ok(r.status_code == 200 and load_config()["local"]["admin"].get("language") == "en",
   "a save that does not mention it leaves it alone")

r = save("")
ok(r.status_code == 200 and client.get("/api/whoami").get_json().get("language") == "",
   "empty goes back to the browser's")

client.post("/api/logout", json={})
who = client.get("/api/whoami").get_json()
ok(not who.get("authenticated") and "language" not in who,
   "signed out, whoami does not say")

print("\n" + ("%d failed" % len(fails) if fails else "the account keeps the language it was given"))
sys.exit(1 if fails else 0)
