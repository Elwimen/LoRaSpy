"""
Wireshark export: pcapng with link type LoRaTap (LINKTYPE_LORATAP = 270).

Each frame = LoRaTap v1 header + the raw LoRa payload, so Wireshark's built-in LoRaTap
dissector shows the radio metadata and hands sync word 0x34 to its LoRaWAN dissector.
Our Lua dissectors (tools/wireshark/loraspy.lua) register in the `loratap.syncword` table
for 0x2B (Meshtastic) and 0x12 (MeshCore).

What only LoRaSpy knows (decryption results) travels in the pcapng packet comment,
one line: "sdrmon1 key=value key=value ..." (values URL-quoted), e.g.
  sdrmon1 proto=meshtastic rx=LongFast crc=ok method=psk channel=LongFast plain=0801120548656c6c6f
The Lua side reads it through the `frame.comment` field.
"""

import struct
import time
from urllib.parse import quote

LINKTYPE_LORATAP = 270
LORATAP_V1_LEN = 35

# LoRaTap v1 flags (little-endian bitfield order of the reference struct)
FLAG_IQ_INVERTED = 0x02
FLAG_CRC_OK = 0x08
FLAG_CRC_BAD = 0x10
FLAG_NO_CRC = 0x20


def _rssi_byte(dbm) -> int:
    return 0 if dbm is None else max(0, min(255, int(round(dbm + 139))))


def loratap_header(frame) -> bytes:
    """LoRaTap v1 header for an RxFrame (all multi-byte fields big-endian)."""
    bw_steps = frame.bw_hz // 125_000 if frame.bw_hz % 125_000 == 0 else 0   # 62.5 kHz isn't representable
    snr = 0 if frame.snr_db is None else max(-128, min(127, int(round(frame.snr_db * 4))))
    flags = FLAG_IQ_INVERTED if frame.invert_iq else 0
    if not frame.has_crc:
        flags |= FLAG_NO_CRC
    else:
        flags |= FLAG_CRC_OK if frame.crc_ok else FLAG_CRC_BAD
    from .radio import LORAWAN_SYNC_WORD, MESHCORE_SYNC_WORD, MESHTASTIC_SYNC_WORD
    sync = {"meshtastic": MESHTASTIC_SYNC_WORD, "lorawan": LORAWAN_SYNC_WORD,
            "meshcore": MESHCORE_SYNC_WORD}.get(frame.protocol, 0)
    return struct.pack(
        ">BBH" "IBB" "BBBb" "B" "QIBBHBBH",
        1, 0, LORATAP_V1_LEN,
        int(round(frame.frequency_hz)), bw_steps, frame.sf,
        _rssi_byte(frame.rssi_dbm), 0, _rssi_byte(frame.noise_dbm), snr,   # dBm + 139, only when calibrated
        sync,
        0, int(frame.timestamp * 1e6) & 0xFFFFFFFF, flags, 0, 0, 0, 0, 0)


def comment_for(pkt) -> str:
    """The sdrmon1 key=value line carrying what Wireshark cannot derive itself."""
    f = pkt.frame
    kv = {"proto": pkt.protocol, "rx": f.receiver, "crc": "ok" if f.crc_ok else "bad",
          "bw": f.bw_hz, "snr": "" if f.snr_db is None else f"{f.snr_db:.1f}",
          "rssi_dbfs": "" if f.rssi_dbfs is None else f"{f.rssi_dbfs:.1f}",
          "noise_dbfs": "" if f.noise_dbfs is None else f"{f.noise_dbfs:.1f}",
          "rssi_dbm": "" if f.rssi_dbm is None else f"{f.rssi_dbm:.1f}", "clipped": 1 if f.clipped else ""}
    if pkt.protocol == "meshtastic":
        if pkt.decrypted:
            kv.update(method=pkt.method, channel=pkt.channel_name or "", plain=pkt.plaintext.hex())
            if pkt.key_label:
                kv["key"] = pkt.key_label
        if getattr(pkt, "duplicate", 0):
            kv["dup"] = pkt.duplicate
    elif pkt.protocol == "meshcore":
        if pkt.plaintext is not None:
            kv["plain"] = pkt.plaintext.rstrip(b"\x00").hex()
        if pkt.channel:
            kv["channel"] = pkt.channel
        if pkt.identity:
            kv["identity"] = pkt.identity
        for k in ("text", "name", "type", "signature_ok"):
            if k in pkt.fields:
                kv[k] = pkt.fields[k]
    elif pkt.protocol == "trustedwireless":
        kv.update(station=pkt.station, addr=pkt.addr, role=pkt.role, type=pkt.kind, nbits=pkt.nbits,
                  exchange=pkt.exchange, header=pkt.header.hex())
    elif pkt.protocol == "lorawan":
        if pkt.plaintext is not None:
            kv["plain"] = pkt.plaintext.hex()
        if pkt.mic_ok is not None:
            kv["mic"] = "ok" if pkt.mic_ok else "bad"
        if pkt.session and pkt.session.label:
            kv["device"] = pkt.session.label
        if pkt.decoded:
            kv["decoded"] = ",".join(f"{k}:{v}" for k, v in pkt.decoded.items())
        if pkt.join_accept:
            kv["join_accept"] = ",".join(f"{k}:{v}" for k, v in pkt.join_accept.items())
    return "sdrmon1 " + " ".join(f"{k}={quote(str(v), safe='')}" for k, v in kv.items() if v != "")


def record(pkt) -> tuple[float, bytes, str]:
    """(timestamp, LoRaTap packet bytes, comment) for one decoded frame."""
    return pkt.frame.timestamp, loratap_header(pkt.frame) + pkt.frame.data, comment_for(pkt)


# ---------------------------------------------------------------- pcapng

def _opt(code: int, value: bytes) -> bytes:
    pad = (-len(value)) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * pad


def _block(btype: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


class PcapngWriter:
    """Minimal pcapng writer: one Section, one LoRaTap interface, Enhanced Packet Blocks with comments."""

    def __init__(self, fileobj, app: str = "LoRaSpy"):
        self.f = fileobj
        shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _opt(4, app.encode()) + _opt(0, b"")
        self.f.write(_block(0x0A0D0D0A, shb))
        idb = struct.pack("<HHI", LINKTYPE_LORATAP, 0, 0) + \
            _opt(2, b"LoRaSpy") + _opt(3, b"LoRa frames decoded by LoRaSpy (RTL-SDR + gr-lora_sdr)") + \
            _opt(9, bytes([6])) + _opt(0, b"")      # if_tsresol = 10^-6
        self.f.write(_block(0x00000001, idb))
        self.f.flush()

    def write(self, ts: float, data: bytes, comment: str | None = None):
        us = int(ts * 1e6)
        body = struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(data), len(data))
        body += data + b"\x00" * ((-len(data)) % 4)
        if comment:
            body += _opt(1, comment.encode("utf-8")) + _opt(0, b"")
        self.f.write(_block(0x00000006, body))
        self.f.flush()

    def write_packet(self, pkt):
        ts, data, comment = record(pkt)
        self.write(ts, data, comment)


def now() -> float:
    return time.time()


# ---------------------------------------------------------------- live UDP feed

FEED_MAGIC = b"SDRM"
FEED_PORT = 47474


def encode_feed(ts: float, data: bytes, comment: str) -> bytes:
    """One datagram per frame: magic, version, timestamp, comment, LoRaTap packet."""
    c = comment.encode("utf-8")
    return FEED_MAGIC + struct.pack("<BdH", 1, ts, len(c)) + c + data


def decode_feed(dgram: bytes) -> tuple[float, bytes, str] | None:
    if len(dgram) < 15 or dgram[:4] != FEED_MAGIC or dgram[4] != 1:
        return None
    ts, clen = struct.unpack_from("<dH", dgram, 5)
    c = dgram[15:15 + clen].decode("utf-8", errors="replace")
    return ts, dgram[15 + clen:], c


class FeedSender:
    """Sends every decoded frame to a UDP address, where the Wireshark extcap listens with
    'Receive the UDP feed instead' set (e.g. on another machine)."""

    def __init__(self, host: str = "127.0.0.1", port: int = FEED_PORT):
        import socket

        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_packet(self, pkt):
        self.send_record(*record(pkt))

    def send_record(self, ts: float, data: bytes, comment: str):
        try:
            self.sock.sendto(encode_feed(ts, data, comment), self.addr)
        except OSError:
            pass   # nobody listening is fine
