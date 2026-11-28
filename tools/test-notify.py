#!/usr/bin/env python3
"""Notification destinations keep their secrets, and mail goes out over TLS
that is actually checked.

A webhook's extra headers are where its bearer token goes, so they are pinned
to come back from GET /api/notify redacted and to be restored when the
redacted text is saved again -- the other secrets (password, token, user)
already worked that way. The SMTP sender is pinned against a mail server with
a self-signed certificate: refused by default, accepted only when the
destination's Verify TLS is off. Both the SSL and the STARTTLS paths, since
each hands the context to smtplib in a different place.

    HAM_DATA_DIR=/tmp/x python3 tools/test-notify.py
"""
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
_tmp = tempfile.mkdtemp(prefix="ham-notify-")
os.environ["HAM_DATA_DIR"] = _tmp
os.environ["HAM_DRY_RUN"] = "1"

import ham   # noqa: E402
from ham import notify   # noqa: E402
from ham.config import load_config, save_config   # noqa: E402

fails = []


def ok(cond, msg):
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        fails.append(msg)


ham.app.config["TESTING"] = True
client = ham.app.test_client()
cfg = load_config()
cfg["local"]["api_key"] = "notify-test-key"
save_config(cfg)
client.environ_base["HTTP_X_API_KEY"] = "notify-test-key"

# -- a webhook's headers do not come back -------------------------------------
TOKEN = "Bearer sekrit-token-0123"
r = client.put("/api/notify", json={"destinations": [
    {"id": "w1", "type": "webhook", "name": "hook", "url": "https://hooks.example/x",
     "headers": "Authorization: %s\nX-Env: prod" % TOKEN}]})
assert r.status_code == 200, r.get_json()
got = client.get("/api/notify").get_json()["settings"]["destinations"][0]
ok("sekrit-token" not in str(got) and got["headers"] == "Authorization: [redacted]\nX-Env: [redacted]",
   "GET hands the header names back with every value marked [redacted]")


def stored_headers():
    return load_config()["notify"]["destinations"][0]["headers"]


client.put("/api/notify", json={"destinations": [got]})
ok(stored_headers() == "Authorization: %s\nX-Env: prod" % TOKEN,
   "saved back as it came, the stored values are kept")
client.put("/api/notify", json={"destinations": [
    dict(got, headers="Authorization: [redacted]\nX-Env: staging")]})
ok(stored_headers() == "Authorization: %s\nX-Env: staging" % TOKEN,
   "a header edited beside a redacted one takes its new value, the redacted one keeps its old")
client.put("/api/notify", json={"destinations": [
    dict(got, headers="Authorization: Bearer new-token\nX-New: [redacted]")]})
ok(stored_headers() == "Authorization: Bearer new-token",
   "a new value replaces the stored one; a redacted value for a name never stored is dropped")

# -- the mail server's certificate is checked ----------------------------------
# A mail server of our own on loopback, with a certificate nobody vouches for.
# It speaks just enough SMTP to tell a connection that got through TLS from one
# that did not: a greeting, an EHLO that offers STARTTLS, and a 421 for whatever
# comes after -- the test is about the handshake, not about delivering mail.
certdir = pathlib.Path(_tmp) / "fake-smtp"
certdir.mkdir()
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=fake-smtp", "-keyout", str(certdir / "key.pem"),
                "-out", str(certdir / "cert.pem")], check=True, capture_output=True)
server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_ctx.load_cert_chain(str(certdir / "cert.pem"), str(certdir / "key.pem"))


class FakeSMTP(threading.Thread):
    """One connection, then done. `saw` is every command line that arrived."""

    def __init__(self, implicit_tls):
        super().__init__(daemon=True)
        self.implicit_tls = implicit_tls
        self.saw = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.sock.settimeout(10)
        self.port = self.sock.getsockname()[1]
        self.start()

    def run(self):
        conn = None
        try:
            conn, _ = self.sock.accept()
            conn.settimeout(5)
            if self.implicit_tls:
                conn = server_ctx.wrap_socket(conn, server_side=True)
            conn.sendall(b"220 fake-smtp ESMTP\r\n")
            f = conn.makefile("rb")
            while True:
                line = f.readline().decode(errors="replace").strip()
                if not line:
                    return
                self.saw.append(line)
                verb = line.split()[0].upper()
                if verb == "EHLO":
                    conn.sendall(b"250-fake-smtp\r\n250 STARTTLS\r\n")
                elif verb == "STARTTLS":
                    conn.sendall(b"220 go ahead\r\n")
                    conn = server_ctx.wrap_socket(conn, server_side=True)
                    f = conn.makefile("rb")
                else:
                    conn.sendall(b"421 fake-smtp closing\r\n")
                    return
        except Exception:
            return          # a client that refused the certificate hangs up mid-handshake
        finally:
            for s in (conn, self.sock):
                try:
                    s.close()
                except Exception:
                    pass


def try_send(security, **extra):
    """(exception or None, the commands the server saw) for one delivery."""
    srv = FakeSMTP(implicit_tls=(security == "ssl"))
    dest = dict({"type": "smtp", "host": "127.0.0.1", "port": srv.port, "security": security,
                 "to": "ops@example.org", "timeout": 5}, **extra)
    try:
        notify.send_smtp(dest, "test", "body")
        err = None
    except Exception as e:
        err = e
    srv.join(5)
    return err, srv.saw


def talked_after_tls(saw, security):
    """Did any command reach the server through the TLS session? Through
    implicit TLS every command does; through STARTTLS the second EHLO is the
    first one that did."""
    ehlos = sum(1 for line in saw if line.upper().startswith("EHLO"))
    return ehlos >= 2 if security == "starttls" else len(saw) >= 1


for security in ("ssl", "starttls"):
    err, saw = try_send(security)
    ok(isinstance(err, ssl.SSLError) and not talked_after_tls(saw, security),
       "%s: a self-signed certificate is refused by default (%s)"
       % (security, type(err).__name__ if err else "no error"))
    err, saw = try_send(security, verify_tls=True)
    ok(isinstance(err, ssl.SSLError),
       "%s: and with Verify TLS on, explicitly" % security)
    err, saw = try_send(security, verify_tls=False)
    ok(err is not None and not isinstance(err, ssl.SSLError) and talked_after_tls(saw, security),
       "%s: with Verify TLS off the handshake completes and the conversation goes on (%s)"
       % (security, type(err).__name__ if err else "no error"))

print("\n" + ("%d failed" % len(fails) if fails
              else "notifications keep their secrets and their TLS"))
sys.exit(1 if fails else 0)
