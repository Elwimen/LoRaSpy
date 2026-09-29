"""
LoRaWAN 1.0.x PHYPayload decoding.

    PHYPayload = MHDR(1) | MACPayload | MIC(4)
    MACPayload = FHDR(DevAddr 4 LE, FCtrl 1, FCnt 2 LE, FOpts 0..15) | [FPort 1 | FRMPayload]

Without keys only headers are readable (DevAddr, counters, ports, join EUIs).
With a session's NwkSKey the MIC is verified; with AppSKey (FPort > 0) or NwkSKey
(FPort 0) the FRMPayload is decrypted.
"""

import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

from .config import Config, LoRaWANOTAADevice, LoRaWANSession
from .decoder import RxFrame

MTYPES = ["JOIN_REQUEST", "JOIN_ACCEPT", "UNCONFIRMED_UP", "UNCONFIRMED_DOWN",
          "CONFIRMED_UP", "CONFIRMED_DOWN", "REJOIN_REQUEST", "PROPRIETARY"]
UPLINK_MTYPES = {0, 2, 4, 6}

# Type-0 DevAddr NwkID (top 7 bits) → operator, for the networks common in Europe
NETWORKS = {0x00: "experimental/private NetID 0", 0x01: "experimental/private NetID 1",
            0x13: "The Things Network"}


@dataclass
class LoRaWANPacket:
    frame: RxFrame
    mtype: int = -1
    major: int = 0
    mic: bytes = b""
    error: str | None = None
    # join request
    join_eui: str | None = None
    dev_eui: str | None = None
    dev_nonce: int | None = None
    # data frames
    dev_addr: int | None = None
    fctrl: int = 0
    fcnt: int | None = None
    fopts: bytes = b""
    fport: int | None = None
    frm_payload: bytes = b""
    # join-accept (decrypted with an OTAA device's AppKey)
    join_accept: dict | None = None
    otaa_device: LoRaWANOTAADevice | None = None
    # with keys
    session: LoRaWANSession | None = None
    mic_ok: bool | None = None
    plaintext: bytes | None = None
    decoded: dict | None = None      # payload codec output
    duplicate: int = 0
    notes: list[str] = field(default_factory=list)

    protocol = "lorawan"

    @property
    def kind(self) -> str:
        return MTYPES[self.mtype] if 0 <= self.mtype < 8 else "INVALID"

    @property
    def uplink(self) -> bool:
        return self.mtype in UPLINK_MTYPES

    @property
    def decrypted(self) -> bool:
        return self.plaintext is not None

    @property
    def network(self) -> str:
        if self.dev_addr is None:
            return ""
        return NETWORKS.get(self.dev_addr >> 25, f"NwkID 0x{self.dev_addr >> 25:02x}")


def codec_t3s3_bmp180(fport: int, p: bytes) -> dict | None:
    """~/code/lorawan/t3s3-sensor payload: FPort 1 = BMP180 temp/pressure, die temp, counter; FPort 2 = text."""
    if fport == 2:
        return {"text": p.decode("utf-8", errors="replace")}
    if fport != 1 or len(p) != 10:
        return None
    t_bmp, pa, t_die, n = struct.unpack(">hIhH", p)
    out = {"die_temperature_c": t_die / 100, "reading": n}
    if t_bmp != 0x7FFF:
        out.update({"temperature_c": t_bmp / 100, "pressure_hpa": pa / 100})
    return out


# Payload codecs, selected per device with "codec" in lorawan.sessions / lorawan.otaa_devices
CODECS = {"t3s3_bmp180": codec_t3s3_bmp180}


def _eui(b: bytes) -> str:
    return b[::-1].hex().upper()  # EUIs are sent little-endian


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def compute_mic(nwk_s_key: bytes, msg: bytes, dev_addr: int, fcnt32: int, uplink: bool) -> bytes:
    b0 = struct.pack("<BIBIIBB", 0x49, 0, 0 if uplink else 1, dev_addr, fcnt32, 0, len(msg))
    c = CMAC(algorithms.AES(nwk_s_key))
    c.update(b0 + msg)
    return c.finalize()[:4]


def crypt_frm(key: bytes, payload: bytes, dev_addr: int, fcnt32: int, uplink: bool) -> bytes:
    """FRMPayload encryption/decryption (symmetric): XOR with AES(key, A_i)."""
    out = bytearray()
    for i in range((len(payload) + 15) // 16):
        a = struct.pack("<BIBIIBB", 0x01, 0, 0 if uplink else 1, dev_addr, fcnt32, 0, i + 1)
        s = _aes_ecb(key, a)
        chunk = payload[i * 16:(i + 1) * 16]
        out += bytes(x ^ y for x, y in zip(chunk, s))
    return bytes(out)


def join_request_mic(app_key: bytes, msg: bytes) -> bytes:
    c = CMAC(algorithms.AES(app_key))
    c.update(msg)
    return c.finalize()[:4]


def derive_session_keys(app_key: bytes, join_nonce: bytes, net_id: bytes, dev_nonce: int) -> tuple[bytes, bytes]:
    """LoRaWAN 1.0.x: NwkSKey / AppSKey = AES(AppKey, 0x01/0x02 | JoinNonce | NetID | DevNonce | pad)."""
    tail = join_nonce + net_id + struct.pack("<H", dev_nonce)
    nwk = _aes_ecb(app_key, (b"\x01" + tail).ljust(16, b"\x00"))
    app = _aes_ecb(app_key, (b"\x02" + tail).ljust(16, b"\x00"))
    return nwk, app


class LoRaWANDecoder:
    def __init__(self, cfg: Config):
        self.sessions: dict[int, LoRaWANSession] = {}
        self._joined: dict[int, LoRaWANSession] = {}   # sessions derived from join-accepts heard on air
        self.set_keys(cfg)
        self.pending: dict[str, list[int]] = {}  # DevEUI → recent DevNonces awaiting a join-accept
        self._seen: dict[bytes, int] = {}

    def set_keys(self, cfg: Config):
        """(Re)load session keys and OTAA devices; sessions learned from joins are kept
        (configured ones win for the same DevAddr)."""
        self.sessions = {**self._joined, **{s.dev_addr: s for s in cfg.lorawan_sessions}}
        self.otaa = {d.dev_eui: d for d in cfg.lorawan_otaa}

    def decode(self, frame: RxFrame) -> LoRaWANPacket:
        pkt = LoRaWANPacket(frame=frame)
        data = frame.data
        if not frame.crc_ok:
            return pkt
        if len(data) < 5:
            pkt.error = f"too short for LoRaWAN ({len(data)} bytes)"
            return pkt
        # The same frame on several demodulators / repeated downlinks
        count = self._seen.get(data, -1) + 1
        self._seen[data] = count
        if len(self._seen) > 2000:
            self._seen.clear()
        pkt.duplicate = count

        mhdr = data[0]
        pkt.mtype, pkt.major = mhdr >> 5, mhdr & 0x03
        pkt.mic = data[-4:]
        body = data[1:-4]
        if pkt.major != 0:
            pkt.notes.append(f"Major version {pkt.major} (only LoRaWAN R1 = 0 is defined)")

        if pkt.mtype == 0:  # Join-request: JoinEUI, DevEUI, DevNonce in the clear
            if len(body) != 18:
                pkt.error = f"join request should be 23 bytes, got {len(data)}"
                return pkt
            pkt.join_eui, pkt.dev_eui = _eui(body[0:8]), _eui(body[8:16])
            pkt.dev_nonce = struct.unpack_from("<H", body, 16)[0]
            dev = self.otaa.get(pkt.dev_eui)
            if dev:
                pkt.otaa_device = dev
                pkt.mic_ok = join_request_mic(dev.app_key, data[:-4]) == pkt.mic
                if pkt.mic_ok:
                    nonces = self.pending.setdefault(pkt.dev_eui, [])
                    if pkt.dev_nonce not in nonces:
                        nonces.append(pkt.dev_nonce)
                        del nonces[:-8]
            return pkt
        if pkt.mtype == 1:
            self._join_accept(pkt, data)
            return pkt
        if pkt.mtype in (6, 7):
            return pkt

        if len(body) < 7:
            pkt.error = "data frame too short"
            return pkt
        pkt.dev_addr, pkt.fctrl, pkt.fcnt = struct.unpack_from("<IBH", body, 0)
        fopts_len = pkt.fctrl & 0x0F
        pkt.fopts = body[7:7 + fopts_len]
        rest = body[7 + fopts_len:]
        if rest:
            pkt.fport, pkt.frm_payload = rest[0], rest[1:]
        if len(pkt.fopts) != fopts_len:
            pkt.error = "FOpts longer than frame"
            return pkt

        sess = self.sessions.get(pkt.dev_addr)
        if sess:
            pkt.session = sess
            fcnt32 = pkt.fcnt  # only the low 16 bits go over the air; assume the high bits are 0
            if sess.nwk_s_key:
                pkt.mic_ok = compute_mic(sess.nwk_s_key, data[:-4], pkt.dev_addr, fcnt32, pkt.uplink) == pkt.mic
            key = sess.nwk_s_key if pkt.fport == 0 else sess.app_s_key
            if key and pkt.frm_payload:
                pkt.plaintext = crypt_frm(key, pkt.frm_payload, pkt.dev_addr, fcnt32, pkt.uplink)
                codec = CODECS.get(sess.codec or "")
                if codec and pkt.uplink and pkt.fport:
                    pkt.decoded = codec(pkt.fport, pkt.plaintext)
        return pkt

    def _join_accept(self, pkt: LoRaWANPacket, data: bytes):
        """
        Join-accept = MHDR | AES-ECB-*decrypt*(AppKey) applied by the server, so the receiver
        *encrypts* to recover: JoinNonce(3) NetID(3) DevAddr(4) DLSettings(1) RxDelay(1)
        [CFList(16)] MIC(4). Try every OTAA device that has sent a join request recently.
        """
        enc = data[1:]
        if len(enc) not in (16, 32):
            pkt.error = f"join-accept should be 17 or 33 bytes, got {len(data)}"
            return
        for dev_eui, nonces in self.pending.items():
            dev = self.otaa[dev_eui]
            plain = _aes_ecb(dev.app_key, enc)
            body, mic = plain[:-4], plain[-4:]
            c = CMAC(algorithms.AES(dev.app_key))
            c.update(data[:1] + body)
            if c.finalize()[:4] != mic:
                continue
            join_nonce, net_id = body[0:3], body[3:6]
            dev_addr = struct.unpack_from("<I", body, 6)[0]
            dl, rx_delay = body[10], body[11]
            ja = {"dev_eui": dev_eui, "join_nonce": int.from_bytes(join_nonce, "little"),
                  "net_id": f"{int.from_bytes(net_id, 'little'):06X}", "dev_addr": f"{dev_addr:08X}",
                  "rx1_dr_offset": (dl >> 4) & 0x07, "rx2_dr": dl & 0x0F, "rx_delay_s": rx_delay or 1}
            if len(body) == 28:  # CFList: 5 extra channel frequencies ×100 Hz (+ type byte)
                ja["cflist_mhz"] = [int.from_bytes(body[12 + 3 * i:15 + 3 * i], "little") / 1e4
                                    for i in range(5) if int.from_bytes(body[12 + 3 * i:15 + 3 * i], "little")]
            # The join-accept doesn't say which DevNonce it answers; use the newest one
            dev_nonce = nonces[-1]
            nwk, app = derive_session_keys(dev.app_key, join_nonce, net_id, dev_nonce)
            ja["dev_nonce"] = dev_nonce
            self.sessions[dev_addr] = self._joined[dev_addr] = LoRaWANSession(
                dev_addr=dev_addr, nwk_s_key=nwk, app_s_key=app, label=dev.label or dev_eui, codec=dev.codec)
            pkt.join_accept, pkt.otaa_device, pkt.mic_ok = ja, dev, True
            pkt.dev_addr = dev_addr
            pkt.plaintext = body
            pkt.notes.append(f"session keys derived for DevAddr {dev_addr:08X}; its traffic now decrypts")
            return
        pkt.notes.append("Join-accept is encrypted with the device AppKey (add it under lorawan.otaa_devices)")

    # -------------------------------------------------------------- output

    @staticmethod
    def fctrl_flags(pkt: LoRaWANPacket) -> list[str]:
        f = pkt.fctrl
        flags = []
        if f & 0x80:
            flags.append("ADR")
        if pkt.uplink and f & 0x40:
            flags.append("ADRACKReq")
        if f & 0x20:
            flags.append("ACK")
        if f & 0x10:
            flags.append("ClassB" if pkt.uplink else "FPending")
        return flags
