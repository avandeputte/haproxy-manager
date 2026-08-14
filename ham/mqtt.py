"""An MQTT 3.1.1 client, just large enough for Home Assistant.

Vendored for the same reason as the password hashing and the QR encoder: one
broker, QoS 0, and a client library would be far larger than the code. What
this speaks is the 3.1.1 subset every broker accepts: CONNECT with
credentials and a will, PUBLISH with the retain flag, SUBSCRIBE for the
command topics, PINGREQ to hold the connection open, and DISCONNECT. The
will is the point of keeping the connection open at all -- the broker
publishes it the moment this process vanishes, which is the one message a
dead process cannot send for itself.
"""

import socket
import ssl
import threading
import time

from .base import log


def _varint(n):
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _string(s):
    b = s.encode("utf-8") if isinstance(s, str) else s
    return len(b).to_bytes(2, "big") + b


class Publisher:
    """One connection to one broker, reconnected as needed by the caller."""

    def __init__(self, host, port=1883, username="", password="", tls=False,
                 client_id="", will_topic="", will_payload="offline",
                 keepalive=60, timeout=5):
        self.host, self.port = host, int(port or 1883)
        self.username, self.password = username or "", password or ""
        self.tls = bool(tls)
        self.client_id = client_id or "haproxy-manager"
        self.will_topic, self.will_payload = will_topic, will_payload
        self.keepalive, self.timeout = int(keepalive), timeout
        self.sock = None
        self._last_io = 0.0
        # Publishes come from the watchdog round, commands are answered from
        # the reader thread; TCP is full duplex but writes must not interleave.
        self._write_lock = threading.Lock()
        self._buf = b""
        self._packet_id = 0

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.tls:
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)
        raw.settimeout(self.timeout)

        flags = 0x02                                    # clean session
        payload = _string(self.client_id)
        if self.will_topic:
            # QoS 0, retained: the broker holds "offline" so anyone asking
            # later still learns this node went away without saying goodbye.
            flags |= 0x04 | 0x20
            payload += _string(self.will_topic) + _string(self.will_payload)
        if self.username:
            flags |= 0x80
            payload += _string(self.username)
            if self.password:
                flags |= 0x40
                payload += _string(self.password)
        var = _string("MQTT") + bytes([4, flags]) + self.keepalive.to_bytes(2, "big")
        packet = bytes([0x10]) + _varint(len(var) + len(payload)) + var + payload
        raw.sendall(packet)

        ack = self._read_exact(raw, 4)
        if ack[0] != 0x20 or ack[3] != 0:
            reasons = {1: "the broker does not speak MQTT 3.1.1",
                       2: "the broker rejected the client id",
                       3: "the broker is not accepting connections",
                       4: "bad username or password",
                       5: "the broker refused authorisation"}
            raw.close()
            raise ConnectionError(reasons.get(ack[3], "CONNACK code %d" % ack[3]))
        self.sock = raw
        self._last_io = time.time()

    @staticmethod
    def _read_exact(sock, n):
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("the broker closed the connection")
            data += chunk
        return data

    def publish(self, topic, payload, retain=True):
        body = _string(topic) + (payload.encode("utf-8")
                                 if isinstance(payload, str) else payload)
        with self._write_lock:
            self.sock.sendall(bytes([0x30 | (1 if retain else 0)])
                              + _varint(len(body)) + body)
        self._last_io = time.time()

    def subscribe(self, topic_filter):
        """QoS 0. The SUBACK arrives on the reader like everything else."""
        self._packet_id = self._packet_id % 65535 + 1
        body = self._packet_id.to_bytes(2, "big") + _string(topic_filter) + b"\x00"
        with self._write_lock:
            self.sock.sendall(bytes([0x82]) + _varint(len(body)) + body)
        self._last_io = time.time()

    def read_frame(self, timeout=1.0):
        """One MQTT frame, or None on timeout: (packet type, payload bytes).

        Buffered, because TCP has no respect for frame boundaries.
        """
        deadline = time.time() + timeout
        while True:
            frame = self._parse_buffered()
            if frame:
                return frame
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            try:
                self.sock.settimeout(remaining)
                chunk = self.sock.recv(4096)
            except (TimeoutError, socket.timeout):
                return None
            finally:
                if self.sock:
                    self.sock.settimeout(self.timeout)
            if not chunk:
                raise ConnectionError("the broker closed the connection")
            self._buf += chunk

    def _parse_buffered(self):
        if len(self._buf) < 2:
            return None
        length, shift, i = 0, 0, 1
        while True:
            if i >= len(self._buf):
                return None
            byte = self._buf[i]
            length |= (byte & 0x7F) << shift
            i += 1
            if not byte & 0x80:
                break
            shift += 7
        if len(self._buf) < i + length:
            return None
        ptype, payload = self._buf[0], self._buf[i:i + length]
        self._buf = self._buf[i + length:]
        return ptype, payload

    @staticmethod
    def parse_publish(payload):
        """(topic, message) out of a QoS-0 PUBLISH frame's payload."""
        tlen = int.from_bytes(payload[:2], "big")
        return (payload[2:2 + tlen].decode("utf-8", "replace"),
                payload[2 + tlen:].decode("utf-8", "replace"))

    def ping_if_idle(self):
        """Hold the connection open, so the will stays armed. The PINGRESP is
        consumed by whoever reads frames -- the reader thread, or nobody."""
        if time.time() - self._last_io < self.keepalive / 2:
            return
        with self._write_lock:
            self.sock.sendall(b"\xc0\x00")
        self._last_io = time.time()

    def close(self, say_goodbye=True):
        if not self.sock:
            return
        try:
            if say_goodbye:
                self.sock.sendall(b"\xe0\x00")     # a clean DISCONNECT suppresses the will
            self.sock.close()
        except OSError:
            pass
        self.sock = None

    def __bool__(self):
        return self.sock is not None


def try_connect(settings, will_topic="", client_id=""):
    """A connected Publisher, or a readable reason why not."""
    pub = Publisher(settings.get("host") or "",
                    settings.get("port") or 1883,
                    settings.get("username") or "",
                    settings.get("password") or "",
                    tls=bool(settings.get("tls")),
                    client_id=client_id,
                    will_topic=will_topic)
    try:
        pub.connect()
        return pub, ""
    except (OSError, ConnectionError) as e:
        return None, str(e)
    except Exception as e:
        log.exception("mqtt: connecting to %s failed unexpectedly", settings.get("host"))
        return None, str(e)
