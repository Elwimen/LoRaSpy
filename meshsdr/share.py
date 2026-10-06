"""
Wire format between the process that owns the RTL-SDR (meshsdr.server) and the front-ends
attached to it (meshsdr.remote): a local Unix socket carrying length-prefixed messages.

    u32 length (LE) | u8 kind | payload
      kind 0 = JSON object (UTF-8)
      kind 1 = spectrum: u16 header length | JSON header | float32 dBFS bins

Only JSON and raw floats cross the socket (no pickle), and the socket is created user-only
(0600) in $XDG_RUNTIME_DIR, so nothing but the same user's processes can talk to it.

Server → client JSON messages (field "type"):
  hello   receivers, bands, tuner, FFT, stats — everything a front-end needs to draw itself
  event   one decoded frame, pre-rendered: summary, details, JSON line, LoRaTap record,
          plus text in the client's own --format when it asked for one
  stats   per-receiver counters, 2×/s
  config  enabled receivers / FFT size / window changed (by anybody)
  bye     the server is going away
Client → server (field "cmd"): hello, spectrum (fps + detectors), enable, fft.
"""

import json
import os
import socket
import struct
import tempfile

PROTOCOL_VERSION = 1
KIND_JSON = 0
KIND_SPECTRUM = 1
MAX_MESSAGE = 16 << 20


def default_socket_path() -> str:
    run = os.environ.get("XDG_RUNTIME_DIR")
    if run and os.path.isdir(run):
        return os.path.join(run, "loraspy.sock")
    uid = os.getuid() if hasattr(os, "getuid") else os.environ.get("USERNAME", "user")
    return os.path.join(tempfile.gettempdir(), f"loraspy-{uid}.sock")


def pack_json(obj: dict) -> bytes:
    body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
    return struct.pack("<IB", len(body), KIND_JSON) + body


def pack_spectrum(header: dict, db) -> bytes:
    h = json.dumps(header, separators=(",", ":")).encode()
    body = struct.pack("<H", len(h)) + h + db.astype("<f4").tobytes()
    return struct.pack("<IB", len(body), KIND_SPECTRUM) + body


def unpack_spectrum(body: bytes):
    import numpy as np

    (hlen,) = struct.unpack_from("<H", body)
    header = json.loads(body[2:2 + hlen])
    return header, np.frombuffer(body, dtype="<f4", offset=2 + hlen).astype(np.float64)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


def recv_message(sock: socket.socket) -> tuple[int, bytes]:
    n, kind = struct.unpack("<IB", _recv_exact(sock, 5))
    if n > MAX_MESSAGE:
        raise ConnectionError(f"message too large ({n} bytes)")
    return kind, _recv_exact(sock, n)


def server_alive(path: str, timeout: float = 0.5) -> bool:
    """True when something accepts connections on the socket (a stale file does not)."""
    if not os.path.exists(path):
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        return True
    except OSError:
        return False
    finally:
        s.close()
