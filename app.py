#!/usr/bin/env python3
"""
HAProxy Cluster Manager -- a small self-hosted web UI for managing:

  * an HAProxy configuration: Public Services, Backend Pools, Real Servers,
    Conditions, Rules, Health Monitors and settings, published through a
    service wizard that creates and updates those objects together
  * Let's Encrypt (ACME) certificates via acme.sh: accounts, challenge types
    and certificates, renewed automatically by the node that holds the VIP and
    pushed to the others
  * a cluster of any number of nodes using Keepalived on a shared virtual IP,
    with push-based settings and certificate sync between them
  * a watchdog that restarts HAProxy and Keepalived when they stop answering,
    and notifications by email, Pushover or webhook when something needs a
    person

One JSON config store, no database. Everything HAProxy and Keepalived read is
generated from it and validated before it is written.

Requires: Flask, requests, waitress, haproxy, keepalived, openssl, acme.sh.
Runs as root -- it writes /etc/haproxy and /etc/keepalived and reloads services
through systemctl. Served by waitress as a single process with a thread pool;
see _serve() for why it must not be run with multiple worker processes.

Configuration lives in the UI. Environment overrides are documented in
docs/configuration.md; HAM_DRY_RUN=1 renders and validates without reloading
anything, which is how the tests run.
"""

from urllib.parse import urlsplit
import logging
import logging.handlers
import socket
import sys
import threading

from ham.base import (CONF_PATH, DATA_DIR, LISTEN, PORT, THREADS, VERSION, _lock, 
    app, log)
from ham.config import load_config, save_config
from ham.auth import key_fingerprint, set_admin
from ham.acme import _renew_loop
from ham.watchdog import _watchdog_loop
from ham.updates import _update_loop

def _cli(argv):
    """Small maintenance CLI so installers do not reimplement the hashing.

        app.py set-admin <username> <password>   create/replace the UI login
        app.py set-admin <username> -            read the password from stdin
        app.py show-admin                        print the configured username
        app.py set-api-key <key>                 set this node's API key
        app.py set-api-key -                     read it from stdin
        app.py keys                              print key fingerprints, for comparing nodes
    """
    cmd = argv[0]
    if cmd == "set-admin":
        if len(argv) != 3:
            print("usage: app.py set-admin <username> <password|->", file=sys.stderr)
            return 2
        # "-" keeps the password out of the process list.
        password = sys.stdin.read().rstrip("\n") if argv[2] == "-" else argv[2]
        if len(password) < 8:
            print("the password must be at least 8 characters", file=sys.stderr)
            return 1
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        cfg = load_config()
        set_admin(cfg, argv[1], password)
        save_config(cfg)
        print("administrator '%s' set" % cfg["local"]["admin"]["username"])
        return 0
    if cmd == "keys":
        cfg = load_config()
        loc = cfg["local"]
        print("node:      %s" % socket.gethostname())
        print("url:       %s" % (loc.get("node_url") or "(not set)"))
        print("api key:   %s  fingerprint %s"
              % ("(not set)" if not (loc.get("api_key") or "").strip() else "set",
                 key_fingerprint(loc.get("api_key")) or "-"))
        print("           other nodes must hold a key with THIS fingerprint for this node")
        peers = loc["sync"].get("peers") or []
        print("peers:     %d" % len(peers))
        seen = {}
        for p in peers:
            host = urlsplit(p.get("url") or "").hostname or "?"
            fp = key_fingerprint(p.get("api_key")) or "-"
            flags = []
            if fp != "-" and fp == key_fingerprint(loc.get("api_key")):
                flags.append("THIS NODE'S OWN KEY")
            if host in seen:
                flags.append("duplicate of %s" % seen[host])
            seen.setdefault(host, p.get("url"))
            if not p.get("enabled", True):
                flags.append("disabled")
            print("  %-28s %-34s fingerprint %s%s"
                  % (p.get("name", "?"), p.get("url", "?"), fp,
                     "   <-- " + ", ".join(flags) if flags else ""))
        return 0
    if cmd == "set-api-key":
        if len(argv) != 2:
            print("usage: app.py set-api-key <key|->", file=sys.stderr)
            return 2
        key = sys.stdin.read().strip() if argv[1] == "-" else argv[1]
        if not key:
            print("the key must not be empty", file=sys.stderr)
            return 2
        # Read, change, write -- never replace the file wholesale, which would
        # discard everything else on an existing installation.
        with _lock:
            cfg = load_config()
            cfg["local"]["api_key"] = key
            save_config(cfg)
        print(key_fingerprint(key))
        return 0
    if cmd == "show-admin":
        admin = load_config()["local"].get("admin") or {}
        print(admin.get("username", "") if admin.get("hash") else "")
        return 0
    print("unknown command: %s" % cmd, file=sys.stderr)
    return 2


def _serve():
    """Serve with waitress, a production WSGI server.

    Deliberately one process with a thread pool: this app keeps state in
    process globals -- the write lock that makes configuration changes atomic,
    the failed-sign-in counters and the renewal timer -- so a multi-process
    server would give each worker its own copy and reintroduce lost updates.
    Waitress is threaded within a single process, which is exactly right here.
    """
    try:
        from waitress import serve as waitress_serve
    except ImportError:
        log.warning("waitress is not installed; falling back to the development "
                    "server, which is not meant for production. Install it with "
                    "'apt-get install -y python3-waitress'.")
        app.run(host=LISTEN, port=PORT, threaded=True)
        return
    for name in ("waitress", "waitress.queue"):
        wl = logging.getLogger(name)
        wl.handlers = list(log.handlers)
        wl.setLevel(logging.INFO)
        wl.propagate = False
    log.info("haproxy-manager %s listening on %s:%s (waitress)", VERSION, LISTEN, PORT)
    waitress_serve(app, host=LISTEN, port=PORT, threads=THREADS,
                   ident="haproxy-manager", clear_untrusted_proxy_headers=True,
                   max_request_body_size=app.config["MAX_CONTENT_LENGTH"],
                   channel_timeout=120, asyncore_use_poll=True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(_cli(sys.argv[1:]))
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not CONF_PATH.exists():
        save_config(load_config())
    threading.Thread(target=_renew_loop, daemon=True).start()
    threading.Thread(target=_update_loop, daemon=True).start()
    threading.Thread(target=_watchdog_loop, daemon=True).start()
    _serve()
