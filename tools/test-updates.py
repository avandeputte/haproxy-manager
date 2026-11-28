#!/usr/bin/env python3
"""The beta channel of the update check.

    HAM_DATA_DIR=/tmp/x python3 tools/test-updates.py

A beta is the VERSION file on another branch. The rules under test: the
ordering that puts 1.95.0-beta.1 above 1.94.1 and below 1.95.0; that the
beta branch is only read once asked for and never turns a failed read into a
failed check; that a beta seen while wanted is withdrawn the moment it is
not; that an update names the branch it installs, and hands it on; and that
asking for betas is the cluster's choice, made on the node holding the
virtual IP whichever node was asked (#39).
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
from ham import auth, sync, updates   # noqa: E402
from ham.config import config_hash, load_config, save_config, shared_view   # noqa: E402

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

c = load_config()
c["_meta"]["applied_hash"] = config_hash(c)          # a node with nothing waiting
save_config(c)
rev = load_config()["_meta"]["shared_rev"]
r = client.put("/api/version/beta", headers=H, json={"beta": True})
d = r.get_json()
ok(r.status_code == 200 and d["beta"] is True and d["changed"] is True and d["made_on"] == "" and d["here"] is True,
   "the choice is saved, on this node: %s" % d)
c = load_config()
ok(c["cluster"]["beta_updates"] is True and shared_view(c)["cluster"]["beta_updates"] is True,
   "in the shared configuration, where every node gets it")
ok(c["_meta"]["shared_rev"] == rev + 1, "as a new revision, so the other nodes are behind until they have it")
ok(c["_meta"]["applied_hash"] == config_hash(c), "and nothing is left waiting for an Apply")
ok(client.get("/api/version", headers=H).get_json()["beta"] is True, "and read back")
r = client.put("/api/version/beta", headers=H, json={"beta": True})
ok(r.get_json()["changed"] is False and load_config()["_meta"]["shared_rev"] == rev + 1,
   "asking again changes nothing")
ok(client.put("/api/version/beta", headers=H, json={"beta": "yes"}).status_code == 400,
   "anything but true or false is refused")
client.post("/api/version/check", headers=H)
v = client.get("/api/version", headers=H).get_json()
ok(v["latest"] == "1.95.0-beta.1" and v["available"] is True and v["latest_is_beta"] is True
   and v["latest_ref"] == "beta", "with betas on the beta is offered, marked, with its branch")

c = load_config()
c["haproxy"]["settings"]["maxconn"] = 4001             # something does wait now
save_config(c)
client.put("/api/version/beta", headers=H, json={"beta": False})
v = client.get("/api/version", headers=H).get_json()
ok(v["latest"] == "" and v["available"] is False and v["latest_ref"] == "main",
   "switching betas off withdraws the offer before any new check")
c = load_config()
ok(c["_meta"]["applied_hash"] != config_hash(c), "a change that was waiting for an Apply still is")
c["haproxy"]["settings"]["maxconn"] = 4000
save_config(c)

# what asked the old way, this node's own settings, gets the same thing
r = client.put("/api/local", headers=H, json={"updates": {"beta": True}})
ok(r.status_code == 200 and load_config()["cluster"]["beta_updates"] is True,
   "the tick sent the way it was before 2.4.1 is the cluster's too")
client.put("/api/local", headers=H, json={"updates": {"beta": False}})
ok(load_config()["cluster"]["beta_updates"] is False, "and so is the untick")

# ---- a package install takes the release's package ------------------------------------
import pathlib as _pl
_mark = _pl.Path(os.environ["HAM_DATA_DIR"]) / "dpkg-list"
updates.DPKG_LIST, updates.INSTALLER_UNIT = _mark, _pl.Path(os.environ["HAM_DATA_DIR"]) / "no-unit"
ok(updates.install_kind() == "", "neither mark: not an installer-managed node")
_mark.write_text("")
ok(updates.install_kind() == "deb", "dpkg's file list says a package install")
ok(updates.package_asset("2.0.0", "deb") == "haproxy-manager_2.0.0_all.deb"
   and updates.package_asset("2.0.0-beta.8", "deb") == "haproxy-manager_2.0.0.beta.8_all.deb"
   and updates.package_asset("2.0.0-beta.8", "rpm") == "haproxy-manager-2.0.0.beta.8-1.noarch.rpm",
   "the release asset is named as GitHub shows it: a beta's ~ as a dot")
sh = updates._package_shell("2.0.0-beta.8", "deb")
ok("releases/download/v2.0.0-beta.8/haproxy-manager_2.0.0.beta.8_all.deb" in sh and "apt-get" in sh
   and "DPkg::Lock::Timeout" in sh and "release may not be cut yet" in sh,
   "a deb node fetches the release's package and installs it with apt, and says so when there is none")
ok("dnf install" in updates._package_shell("2.0.0", "rpm"), "an rpm node with dnf")
ok("mktemp -d" in sh and "chmod 700" in sh and "/tmp/haproxy-manager" not in sh,
   "the package lands in a directory of its own that only root can read, not at a fixed name under /tmp")
ok("releases/download/v2.0.0-beta.8/SHA256SUMS" in sh and "sha256sum -c" in sh,
   "and is checked against the release's SHA256SUMS before it is installed")
ok("predates the checksum file" in updates._package_shell("2.0.0", "deb"),
   "a release from before the checksum file is installed with a warning when it has none")
new = updates._package_shell(updates.CHECKSUMS_SINCE, "deb")
ok("cannot be verified -- not installed" in new and "predates" not in new,
   "one from the release that introduced it on is refused without it")

# -- the shell itself, run against a release served from here ------------------------------
import hashlib   # noqa: E402
import http.server   # noqa: E402
import subprocess   # noqa: E402
import threading   # noqa: E402
from functools import partial   # noqa: E402

DATA = _pl.Path(os.environ["HAM_DATA_DIR"])
release = DATA / "release"
release.mkdir()
NEW, OLD = "9.9.9", "2.0.0"           # after and before the checksum file
for v in (NEW, OLD):
    (release / updates.package_asset(v, "deb")).write_bytes(("not really a package %s\n" % v).encode())
digest = hashlib.sha256((release / updates.package_asset(NEW, "deb")).read_bytes()).hexdigest()
SUMS = release / updates.CHECKSUMS_FILE
SUMS.write_text("%s  %s\n%s  %s\n" % ("0" * 64, updates.package_asset(NEW, "rpm"),
                                      digest, updates.package_asset(NEW, "deb")))
httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
                                        partial(http.server.SimpleHTTPRequestHandler, directory=str(release)))
threading.Thread(target=httpd.serve_forever, daemon=True).start()
real_asset_url = updates.release_asset_url
updates.release_asset_url = lambda version, name: "http://127.0.0.1:%d/%s" % (httpd.server_port, name)

# apt-get is stood in for by a script that records what it was handed
bindir = DATA / "bin"
bindir.mkdir()
record = DATA / "apt-get.record"
(bindir / "apt-get").write_text('#!/bin/sh\nfor a in "$@"; do :; done\n'
                                '{ echo "$a"; test -f "$a" && echo exists; stat -c %a "$(dirname "$a")"; } > "$RECORD"\n')
(bindir / "apt-get").chmod(0o755)
env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ.get("PATH", "")), RECORD=str(record))


def run_update(version):
    if record.exists():
        record.unlink()
    before = updates.UPDATE_LOG.read_text() if updates.UPDATE_LOG.exists() else ""
    rc = subprocess.run(["sh", "-c", updates._package_shell(version, "deb")], env=env, timeout=60).returncode
    log = updates.UPDATE_LOG.read_text()[len(before):]
    got = record.read_text().splitlines() if record.exists() else []
    return rc, log, got


rc, log, got = run_update(NEW)
ok(rc == 0 and "checksum verified" in log, "a package that matches SHA256SUMS is installed: rc %s, %r" % (rc, log.strip()))
ok(len(got) == 3 and got[1] == "exists" and got[2] == "700"
   and _pl.Path(got[0]).name == updates.package_asset(NEW, "deb") and _pl.Path(got[0]).parent != _pl.Path("/tmp"),
   "from a directory of its own, mode 700, under the name the release gave it: %s" % got)
ok(got and not _pl.Path(got[0]).parent.exists(), "and that directory is gone afterwards")

SUMS.write_text("%s  %s\n" % ("f" * 64, updates.package_asset(NEW, "deb")))
rc, log, got = run_update(NEW)
ok(rc != 0 and "does not match" in log and not got,
   "a package that does not match is not handed to apt: rc %s, %r" % (rc, log.strip()))

SUMS.unlink()
rc, log, got = run_update(NEW)
ok(rc != 0 and "cannot be verified" in log and not got,
   "a release from the checksum file on that lacks it is refused: rc %s, %r" % (rc, log.strip()))
rc, log, got = run_update(OLD)
ok(rc == 0 and "predates the checksum file" in log and len(got) == 3,
   "an older release without one is installed, and the log says it was not verified: %r" % log.strip())
httpd.shutdown()
updates.release_asset_url = real_asset_url
client.put("/api/version/beta", headers=H, json={"beta": True})
client.post("/api/version/check", headers=H)
c = load_config()
ok(updates._package_version(None, c) == "1.95.0-beta.1" and updates._package_version("beta", c) == "1.95.0-beta.1",
   "the version a package node installs is what the check found, for the ref on offer")
ok(updates._package_version("main", c) == "1.94.2", "another ref: that ref's VERSION, read now")
v = client.get("/api/version", headers=H).get_json()
ok(v["install_kind"] == "deb", "and the page is told how the node was installed")
client.put("/api/version/beta", headers=H, json={"beta": False})
_mark.unlink()

# ---- the update names its branch ----------------------------------------
sh = updates._update_shell("https://x/install.sh", "beta")
ok("--update --yes --ref beta" in sh, "the updater is told the branch")
ok("'" in updates._update_shell("https://x/install.sh", "a b"), "and a ref is quoted for the shell")
ok("| bash" not in sh and "-o \"$d\"/install.sh" in sh and "bash \"$d\"/install.sh" in sh,
   "the installer is downloaded to a file and run from it, not piped into bash")
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

# ---- a tick from before 2.4.1 was the node's own: it is handed to the cluster ----------
def own(record):
    c = load_config()
    c["local"]["updates"] = record
    c["cluster"]["beta_updates"] = False
    save_config(c)


own({"beta": True})
ok(not updates.wants_beta(load_config()), "a node's own tick is not what is read any more")
ok(updates.adopt_own_tick() is True and load_config()["cluster"]["beta_updates"] is True,
   "a ticked node hands its tick to the cluster")
ok(load_config()["local"]["updates"] == {"beta": True, "shared": True},
   "and its own record is from then on a copy, for what reads the file from outside")
client.put("/api/version/beta", headers=H, json={"beta": False})
ok(load_config()["local"]["updates"] == {"beta": False, "shared": True}, "the copy follows the cluster's choice")
ok(updates.adopt_own_tick() is True and load_config()["cluster"]["beta_updates"] is False,
   "and is never handed over a second time")
own({"beta": False})
ok(updates.adopt_own_tick() is True and load_config()["cluster"]["beta_updates"] is False
   and load_config()["local"]["updates"]["shared"] is True, "an unticked node has nothing to hand over")
import json as _json   # noqa: E402
from ham.base import CONF_PATH   # noqa: E402
stored = _json.loads(CONF_PATH.read_text())
stored["cluster"]["beta_updates"] = True            # as a 2.4.0 on this node would have taken it:
stored["local"]["updates"] = {"beta": False, "shared": True}   # without touching the copy
CONF_PATH.write_text(_json.dumps(stored))
rev = load_config()["_meta"]["shared_rev"]
ok(updates.adopt_own_tick() is True and load_config()["local"]["updates"] == {"beta": True, "shared": True},
   "a copy that fell behind the cluster's choice is put right")
ok(load_config()["cluster"]["beta_updates"] is True, "the choice itself is not touched by that")
client.put("/api/version/beta", headers=H, json={"beta": False})

# ---- a passive node passes the choice to the node holding the virtual IP ---------------
real_ro, real_peer, real_req, real_catch = auth.readonly_state, sync.active_peer, updates._requests, sync.catch_up
from flask import has_request_context, request as _rq   # noqa: E402
PASSIVE_WHY = "This node is passive."
# this one app plays both nodes: passive when asked by the page or by its own
# loop, the active one when the call arrives from the other node (forwarded)
auth.readonly_state = lambda cfg: ((False, "") if has_request_context() and (_rq.get_json(silent=True) or {}).get("forwarded")
                                   else (True, PASSIVE_WHY))
sync.active_peer = lambda cfg: {"name": "node-a", "url": "http://node-a", "api_key": "upd-key"}
caught = []
sync.catch_up = lambda cfg: caught.append(1)


class FakeRequests:
    """The peer is this same app: the choice lands on /api/version/beta here."""
    sent = []

    @classmethod
    def put(cls, url, json=None, headers=None, **kw):
        cls.sent.append((url, json))
        r = client.put(url.replace("http://node-a", ""), json=json, headers=headers)
        return type("R", (), {"status_code": r.status_code, "json": lambda self: r.get_json()})()


updates._requests = FakeRequests
checks = []
real_soon = updates._check_soon
updates._check_soon = lambda: checks.append(1)
r = client.put("/api/version/beta", headers=H, json={"beta": True})
d = r.get_json()
ok(r.status_code == 200 and d["made_on"] == "node-a" and d["changed"] is True, "on a passive node the choice is made on node-a: %s" % d)
ok(FakeRequests.sent[-1] == ("http://node-a/api/version/beta", {"beta": True, "forwarded": True}),
   "passed on once, marked as passed on")
ok(load_config()["cluster"]["beta_updates"] is True, "and it took there")
ok(caught == [1], "the passive node then takes the configuration back, rather than waiting for the next round")
ok(checks == [1], "and the node it was made on looks for the beta at once, with nobody at its page to ask")

own({"beta": True})
caught.clear()
ok(updates.adopt_own_tick() is True and load_config()["cluster"]["beta_updates"] is True,
   "a passive node's own tick from before 2.4.1 reaches the cluster the same way")

# the node asked to make it is passive too: it does not pass it on again
auth.readonly_state = lambda cfg: (True, PASSIVE_WHY)
r = client.put("/api/version/beta", headers=H, json={"beta": False, "forwarded": True})
ok(r.status_code == 409 and "virtual IP" in r.get_json()["error"], "a choice passed on is never passed on twice: %s" % r.get_json()["error"])

# nobody holds the virtual IP, or the node that does is from before 2.4.1
sync.active_peer = lambda cfg: None
r = client.put("/api/version/beta", headers=H, json={"beta": False})
ok(r.status_code == 409 and "no other node answered" in r.get_json()["error"], "with no active node, it says so")
own({"beta": True})
ok(updates.adopt_own_tick() is False and load_config()["local"]["updates"] == {"beta": True},
   "and a tick that could not be handed over is kept, to be tried again")
sync.active_peer = lambda cfg: {"name": "node-a", "url": "http://node-a", "api_key": "upd-key"}
FakeRequests.put = classmethod(lambda cls, url, **kw: type("R", (), {"status_code": 404, "json": lambda self: {}})())
r = client.put("/api/version/beta", headers=H, json={"beta": True})
ok(r.status_code == 409 and "Update it first" in r.get_json()["error"],
   "an active node from before 2.4.1 is named as the thing to update: %s" % r.get_json()["error"])
ok(updates.adopt_own_tick() is False, "and the tick waits for it")
auth.readonly_state, sync.active_peer, updates._requests, sync.catch_up = real_ro, real_peer, real_req, real_catch

# ---- the choice arriving from another node ---------------------------------------------
checks.clear()
updates._follow_the_cluster({"beta_updates": False}, {"beta_updates": True})
updates._follow_the_cluster({"beta_updates": True}, {"beta_updates": True, "vips": "10.0.0.9"})
updates._follow_the_cluster({}, {"beta_updates": False})
ok(checks == [1], "a node that receives a changed choice checks again at once, and only then")
ok(updates._follow_the_cluster in sync.after_receive, "and that is hooked to every configuration received")
updates._check_soon = real_soon

print("\n" + ("%d failed" % len(fails) if fails else "betas are asked for once, for every node"))
sys.exit(1 if fails else 0)
