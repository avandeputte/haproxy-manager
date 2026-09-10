#!/usr/bin/env python3
"""The beta channel of the update check.

    HAM_DATA_DIR=/tmp/x python3 tools/test-updates.py

A beta is the VERSION file on another branch. The rules under test: the
ordering that puts 1.95.0-beta.1 above 1.94.1 and below 1.95.0; that the
beta branch is only read once asked for and never turns a failed read into a
failed check; that a beta seen while wanted is withdrawn the moment it is
not; and that an update names the branch it installs, and hands it on.
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
os.environ.setdefault("HAM_DATA_DIR", tempfile.mkdtemp(prefix="ham-upd-"))
os.environ["HAM_DRY_RUN"] = "1"
os.environ.pop("HAM_VERSION_URL", None)

import ham; ham   # noqa: E402
from ham import updates   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


# ---- the ordering --------------------------------------------------------
vt = updates.version_tuple
ok(vt("1.95.0-beta.1") > vt("1.94.1"), "a beta is newer than the release before it")
ok(vt("1.95.0") > vt("1.95.0-beta.1"), "and older than its own release")
ok(vt("1.95.0-beta.2") > vt("1.95.0-beta.1"), "betas of one release order by number")
ok(vt("1.95.0-rc.1") > vt("1.95.0-beta.9"), "a release candidate comes after every beta")
ok(vt("v1.95.0") == vt("1.95.0"), "a leading v is not a difference")
ok(vt("1.95") == vt("1.95.0") and vt("1.95") > vt("1.95.0-beta.1"), "missing components are zero, so 1.95 is the release 1.95.0")
ok(not updates.is_newer("1.94.1", "1.94.1"), "the same version is not newer")
R = updates.VERSION_RE
ok(all(R.match(v) for v in ("1.94.1", "v2.0", "1.95.0-beta.1", "1.95.0-rc.2", "1.95.0-beta")),
   "the version pattern takes releases and marked prereleases")
ok(not any(R.match(v) for v in ("1.95.0-nightly", "main", "1.95.0-beta.1; rm -rf /", "")),
   "and nothing else off the network")
ok(updates.is_prerelease("1.95.0-beta.1") and not updates.is_prerelease("1.95.0"),
   "a prerelease is told by its mark")

# ---- what the check reads, per branch ------------------------------------
served = {}
calls = []


def fake_read(url):
    calls.append(url)
    for ref, body in served.items():
        if ("ref=%s" % ref) in url or ("/%s/VERSION" % ref) in url:
            if isinstance(body, Exception):
                raise body
            return body
    raise OSError("HTTP Error 404: Not Found")


updates._read_version_url = fake_read
served.update({"main": "1.94.2", "beta": "1.95.0-beta.1"})
ok(updates.fetch_latest_version() == ("1.94.2", "main"), "not asked: the release, from main")
ok(not any("beta" in u for u in calls), "and the beta branch was not even read")
calls.clear()
ok(updates.fetch_latest_version(beta=True) == ("1.95.0-beta.1", "beta"),
   "asked: the newer beta, and the branch it is on")
served["beta"] = "1.94.0-beta.3"
ok(updates.fetch_latest_version(beta=True) == ("1.94.2", "main"),
   "a beta older than the release is not offered over it")
served["beta"] = OSError("HTTP Error 404: Not Found")
ok(updates.fetch_latest_version(beta=True) == ("1.94.2", "main"),
   "no beta branch means no beta, not a failed check")
served["beta"] = "something-else"
ok(updates.fetch_latest_version(beta=True) == ("1.94.2", "main"),
   "a beta branch whose VERSION is not one is ignored too")
served["main"] = OSError("HTTP Error 503")
served["beta"] = "1.95.0-beta.1"
try:
    updates.fetch_latest_version(beta=True)
    ok(False, "main unreadable is still a failed check")
except OSError:
    ok(True, "main unreadable is still a failed check, whatever the beta branch says")

# ---- through the API: the setting, the check, the offer ------------------
ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "upd-key"
save_config(cfg)
H = {"X-API-Key": "upd-key"}
served.update({"main": "1.94.2", "beta": "1.95.0-beta.1"})
updates.VERSION = "1.94.2"          # what this node runs, for the offer arithmetic

v = client.get("/api/version", headers=H).get_json()
ok(v.get("beta") is False and v.get("beta_ref") == "beta", "betas are off to begin with, and the branch is named")
client.post("/api/version/check", headers=H)
v = client.get("/api/version", headers=H).get_json()
ok(v["latest"] == "1.94.2" and v["available"] is False and v["latest_ref"] == "main",
   "a check with betas off finds the release: %s" % v["latest"])

r = client.put("/api/local", headers=H, json={"updates": {"beta": True}})
ok(r.status_code == 200 and r.get_json()["updates"]["beta"] is True, "the setting is saved")
ok(client.get("/api/local", headers=H).get_json()["updates"]["beta"] is True, "and read back")
client.post("/api/version/check", headers=H)
v = client.get("/api/version", headers=H).get_json()
ok(v["latest"] == "1.95.0-beta.1" and v["available"] is True and v["latest_is_beta"] is True
   and v["latest_ref"] == "beta", "with betas on the beta is offered, marked, with its branch")

client.put("/api/local", headers=H, json={"updates": {"beta": False}})
v = client.get("/api/version", headers=H).get_json()
ok(v["latest"] == "" and v["available"] is False and v["latest_ref"] == "main",
   "switching betas off withdraws the offer before any new check")

# ---- the update names its branch ----------------------------------------
sh = updates._update_shell("https://x/install.sh", "beta")
ok("--update --yes --ref beta" in sh, "the updater is told the branch")
ok("'" in updates._update_shell("https://x/install.sh", "a b"), "and a ref is quoted for the shell")
c = load_config()
ok(updates._update_ref(None, c) == "main", "no branch asked and nothing on offer: main")
ok(updates._update_ref("beta", c) == "beta", "the branch another node asked for is taken")
try:
    updates._update_ref("beta; rm -rf /", c)
    ok(False, "a ref that is not one is refused")
except ValueError:
    ok(True, "a ref that is not one is refused")
r = client.post("/api/update", headers=H, json={"ref": "$(evil)"})
ok(r.status_code == 400, "over the API too: %s" % r.get_json().get("error", ""))

print("\n" + ("%d failed" % len(fails) if fails else "a node can ask for betas, and only then gets them"))
sys.exit(1 if fails else 0)
