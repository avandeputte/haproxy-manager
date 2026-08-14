"""Users and groups for the sign-in HAProxy can put in front of a service.

These are not accounts for this management UI. They are the credentials a
visitor is asked for when a published service requires one, and HAProxy checks
them itself from a userlist in the generated configuration -- the request never
reaches this application.

Passwords are stored the way HAProxy wants to read them: SHA-512 crypt, the
same format as /etc/shadow. Nothing here can recover one.
"""

from flask import jsonify, request
import hashlib
import ipaddress
import os
import re
import uuid

from .base import _lock, app
from .config import load_config, save_config
from .util import _sec

# The userlist every user and group is rendered into. One list is enough:
# membership is what a service tests, and a second list would only be a second
# place to look.
USERLIST = "ham_users"

# What HAProxy will accept as a user or group name in its configuration, and
# what a browser will send back: no spaces, nothing that would end the field.
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")

MIN_PASSWORD = 8


# --------------------------------------------------------------------------
# SHA-512 crypt
#
# Written out here rather than taken from the standard library because the
# crypt module is gone from Python 3.13, and rather than shelled out to
# openssl because a password that cannot be hashed is a user who cannot be
# created -- on a machine that happens not to have it. hashlib is enough.
#
# The algorithm is Ulrich Drepper's, the one behind $6$ hashes; the tests
# compare it against openssl passwd -6.

B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ROUNDS = 5000
SALT_CHARS = B64


def _b64_from_24bit(b2, b1, b0, n):
    w = (b2 << 16) | (b1 << 8) | b0
    return "".join(B64[(w >> (6 * i)) & 0x3F] for i in range(n))


def sha512_crypt(password, salt=None):
    """The $6$ hash of a password, as crypt(3) would produce it."""
    if salt is None:
        salt = "".join(SALT_CHARS[b % 64] for b in os.urandom(16))
    salt = str(salt)[:16]
    pw = password.encode("utf-8") if isinstance(password, str) else password
    sa = salt.encode("ascii")

    b = hashlib.sha512(pw + sa + pw).digest()
    a_ctx = hashlib.sha512(pw + sa)
    a_ctx.update(b * (len(pw) // 64))
    a_ctx.update(b[:len(pw) % 64])
    # The length of the password, one bit at a time from the bottom: a set bit
    # takes the digest, a clear one takes the password.
    n = len(pw)
    while n:
        a_ctx.update(b if n & 1 else pw)
        n >>= 1
    a = a_ctx.digest()

    dp = hashlib.sha512(pw * len(pw)).digest()
    p = (dp * (len(pw) // 64 + 1))[:len(pw)]
    ds = hashlib.sha512(sa * (16 + a[0])).digest()
    s = (ds * (len(sa) // 64 + 1))[:len(sa)]

    c = a
    for i in range(ROUNDS):
        ctx = hashlib.sha512()
        ctx.update(p if i & 1 else c)
        if i % 3:
            ctx.update(s)
        if i % 7:
            ctx.update(p)
        ctx.update(c if i & 1 else p)
        c = ctx.digest()

    # The output bytes are interleaved rather than taken in order: every third
    # byte, wrapping around the first 63, then the last one on its own.
    out = "".join(_b64_from_24bit(c[i * 22 % 63], c[(i * 22 + 21) % 63],
                                  c[(i * 22 + 42) % 63], 4) for i in range(21))
    out += _b64_from_24bit(0, 0, c[63], 2)
    return "$6$%s$%s" % (salt, out)


def verify(password, stored):
    """Does this password produce that hash? Used by the tests, not by HAProxy."""
    parts = str(stored or "").split("$")
    if len(parts) < 4 or parts[1] != "6":
        return False
    return sha512_crypt(password, parts[2]) == stored


# --------------------------------------------------------------------------

def section(cfg):
    """The users and groups, whatever an older configuration was missing."""
    sec = cfg.setdefault("access", {})
    sec.setdefault("users", [])
    sec.setdefault("groups", [])
    return sec


def group_names(cfg, ids):
    """The names of the groups these ids refer to, in the order they are given.

    Ids that name nothing are dropped: a group that was deleted must not turn
    into an ACL nothing can ever satisfy.
    """
    by_id = {g.get("id"): g for g in section(cfg)["groups"]}
    return [by_id[i]["name"] for i in (ids or []) if i in by_id and by_id[i].get("name")]


def users_with_passwords(cfg):
    """The users HAProxy can actually check: enabled, and with a hash."""
    return [u for u in section(cfg)["users"]
            if u.get("enabled", True) and u.get("hash")]


def render_userlist(cfg):
    """The userlist block, or nothing when there is nobody in it."""
    users = users_with_passwords(cfg)
    if not users:
        return []
    groups = section(cfg)["groups"]
    by_id = {g.get("id"): g for g in groups}
    lines = ["userlist %s" % USERLIST]
    for g in groups:
        if g.get("name"):
            lines.append("    group %s" % _sec(g["name"]))
    for u in users:
        mine = [_sec(by_id[i]["name"]) for i in (u.get("groups") or [])
                if i in by_id and by_id[i].get("name")]
        line = "    user %s password %s" % (_sec(u["username"]), u["hash"])
        if mine:
            line += " groups %s" % ",".join(mine)
        lines.append(line)
    lines.append("")
    return lines


def public(user):
    """A user as the UI sees it: everything except the hash."""
    out = {k: v for k, v in user.items() if k != "hash"}
    out["has_password"] = bool(user.get("hash"))
    return out


def _check_name(name, what):
    name = (name or "").strip()
    if not name:
        return None, "%s is required" % what
    if not NAME_RE.match(name):
        return None, ("%s must start with a letter or digit and hold only letters, "
                      "digits, dots, dashes, underscores or @ -- HAProxy reads it "
                      "from a configuration line, and a browser sends it back" % what)
    return name, None


def used_by(cfg, group_id):
    """The pools that let this group in, by name."""
    return [b.get("name") or "?" for b in cfg["haproxy"]["backends"]
            if group_id in (b.get("auth_groups") or [])]


# --------------------------------------------------------------------------
# source addresses

def networks(text):
    """The valid networks in a one-per-line list, and the entries that are not.

    An address without a prefix is one host. What is malformed is returned
    separately rather than silently dropped, so the caller can choose: the
    wizard refuses the input, and the renderer leaves the bad entry out --
    which only ever narrows who gets in, never widens it.
    """
    good, bad = [], []
    for token in re.split(r"[\s,]+", text or ""):
        if not token:
            continue
        try:
            good.append(str(ipaddress.ip_network(token, strict=False)))
        except ValueError:
            bad.append(token)
    return good, bad


# --------------------------------------------------------------------------
# users

@app.route("/api/access/users", methods=["GET", "POST"])
def api_access_users():
    with _lock:
        cfg = load_config()
        if request.method == "GET":
            return jsonify([public(u) for u in section(cfg)["users"]])
        body = request.get_json(force=True, silent=True) or {}
        name, err = _check_name(body.get("username") or body.get("name"), "The user name")
        if err:
            return jsonify({"error": err}), 400
        if any((u.get("username") or "").lower() == name.lower() for u in section(cfg)["users"]):
            return jsonify({"error": "there is already a user called \"%s\"" % name}), 400
        password = body.get("password") or ""
        if len(password) < MIN_PASSWORD:
            return jsonify({"error": "the password must be at least %d characters"
                                     % MIN_PASSWORD}), 400
        user = {"id": str(uuid.uuid4()), "username": name, "name": name,
                "enabled": bool(body.get("enabled", True)),
                "groups": [g for g in (body.get("groups") or []) if isinstance(g, str)],
                "description": (body.get("description") or "").strip(),
                "hash": sha512_crypt(password)}
        section(cfg)["users"].append(user)
        save_config(cfg)
        return jsonify(public(user))


@app.route("/api/access/users/<uid>", methods=["PUT", "DELETE"])
def api_access_user(uid):
    with _lock:
        cfg = load_config()
        users = section(cfg)["users"]
        for i, u in enumerate(users):
            if u.get("id") != uid:
                continue
            if request.method == "DELETE":
                users.pop(i)
                save_config(cfg)
                return jsonify({"ok": True})
            body = request.get_json(force=True, silent=True) or {}
            name, err = _check_name(body.get("username") or body.get("name") or u.get("username"),
                                    "The user name")
            if err:
                return jsonify({"error": err}), 400
            if any((o.get("username") or "").lower() == name.lower() and o.get("id") != uid
                   for o in users):
                return jsonify({"error": "there is already a user called \"%s\"" % name}), 400
            password = body.get("password") or ""
            if password and len(password) < MIN_PASSWORD:
                return jsonify({"error": "the password must be at least %d characters"
                                         % MIN_PASSWORD}), 400
            u["username"] = u["name"] = name
            u["enabled"] = bool(body.get("enabled", True))
            u["groups"] = [g for g in (body.get("groups") or []) if isinstance(g, str)]
            u["description"] = (body.get("description") or "").strip()
            # An empty password field leaves the password alone: it is the only
            # thing on this form nobody can read back, so it cannot be resent.
            if password:
                u["hash"] = sha512_crypt(password)
            save_config(cfg)
            return jsonify(public(u))
        return jsonify({"error": "no such user"}), 404


# --------------------------------------------------------------------------
# groups

@app.route("/api/access/groups", methods=["GET", "POST"])
def api_access_groups():
    with _lock:
        cfg = load_config()
        if request.method == "GET":
            return jsonify(section(cfg)["groups"])
        body = request.get_json(force=True, silent=True) or {}
        name, err = _check_name(body.get("name"), "The group name")
        if err:
            return jsonify({"error": err}), 400
        if any((g.get("name") or "").lower() == name.lower() for g in section(cfg)["groups"]):
            return jsonify({"error": "there is already a group called \"%s\"" % name}), 400
        group = {"id": str(uuid.uuid4()), "name": name,
                 "description": (body.get("description") or "").strip()}
        section(cfg)["groups"].append(group)
        save_config(cfg)
        return jsonify(group)


@app.route("/api/access/groups/<gid>", methods=["PUT", "DELETE"])
def api_access_group(gid):
    with _lock:
        cfg = load_config()
        groups = section(cfg)["groups"]
        for i, g in enumerate(groups):
            if g.get("id") != gid:
                continue
            if request.method == "DELETE":
                # Deleting a group a service depends on would quietly widen or
                # close that service, depending on which way HAProxy read what
                # was left. Say what is in the way instead.
                where = used_by(cfg, gid)
                if where:
                    return jsonify({"error":
                                    "\"%s\" is what lets people into %s. Change %s first."
                                    % (g.get("name"), ", ".join(where),
                                       "that service" if len(where) == 1 else "those services")}), 409
                groups.pop(i)
                for u in section(cfg)["users"]:
                    u["groups"] = [x for x in (u.get("groups") or []) if x != gid]
                save_config(cfg)
                return jsonify({"ok": True})
            body = request.get_json(force=True, silent=True) or {}
            name, err = _check_name(body.get("name"), "The group name")
            if err:
                return jsonify({"error": err}), 400
            if any((o.get("name") or "").lower() == name.lower() and o.get("id") != gid
                   for o in groups):
                return jsonify({"error": "there is already a group called \"%s\"" % name}), 400
            g["name"] = name
            g["description"] = (body.get("description") or "").strip()
            save_config(cfg)
            return jsonify(g)
        return jsonify({"error": "no such group"}), 404
