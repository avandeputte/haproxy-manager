#!/usr/bin/env python3
"""Minimal syslog collector for the container image.

HAProxy and Keepalived can only log through syslog, and the image has no
syslog daemon and no journal. This binds /dev/log, echoes every message to
stdout (so `docker logs` works as before) and appends it to a file the UI's
log viewer can read back.

socat did the stdout half, but writes datagrams with no separator, so the
file came out as a single unreadable line. One message per line matters here.
"""
import os
import socket
import sys

SOCK = os.environ.get("HAM_SYSLOG_SOCKET", "/dev/log")
PATH = os.environ.get("HAM_SYSLOG_FILE", "/var/log/ham-syslog.log")
MAX_BYTES = int(os.environ.get("HAM_SYSLOG_MAX", str(8 * 1024 * 1024)))


def main():
    try:
        os.unlink(SOCK)
    except OSError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(SOCK)
    os.chmod(SOCK, 0o666)
    fh = open(PATH, "a", buffering=1, encoding="utf-8", errors="replace")
    written = os.path.getsize(PATH)
    while True:
        try:
            data = srv.recv(65535)
        except OSError:
            continue
        if not data:
            continue
        line = data.decode("utf-8", "replace").rstrip("\n\x00")
        if not line:
            continue
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        if written > MAX_BYTES:          # keep a container from filling its disk
            fh.close()
            os.replace(PATH, PATH + ".1")
            fh = open(PATH, "a", buffering=1, encoding="utf-8", errors="replace")
            written = 0
        fh.write(line + "\n")
        written += len(line) + 1


if __name__ == "__main__":
    main()
