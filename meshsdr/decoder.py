"""
Turn raw LoRa payloads into decoded Meshtastic packets.

Decryption order mirrors firmware Router::perhapsDecode(): PKI is tried first for
unicast packets whose channel hash byte is 0, then every configured channel whose
hash matches the header's channel byte.
"""

import logging
import time
from dataclasses import dataclass, field

from google.protobuf.message import DecodeError
from meshtastic.protobuf import mesh_pb2, portnums_pb2

from . import crypto
from .config import Config
from .nodedb import NodeDB
from .packet import RadioHeader, parse_frame

log = logging.getLogger(__name__)


@dataclass
class RxFrame:
    """One frame as delivered by the demodulator."""
    data: bytes
    crc_ok: bool
    receiver: str
    frequency_hz: float
    sf: int
    bw_hz: int
    snr_db: float | None = None
    protocol: str = "meshtastic"
    rssi_dbfs: float | None = None     # measured in-band power over the frame
    noise_dbfs: float | None = None    # channel quiet level
    rssi_dbm: float | None = None      # only with sdr.rssi_offset_db calibration
    noise_dbm: float | None = None
    snr_lora_db: float | None = None   # gr-lora_sdr's preamble estimate (snr_db is our measurement)
    has_crc: bool = True       # False: frame was sent without a payload CRC (LoRaWAN downlink)
    invert_iq: bool = False
    clipped: bool = False      # the SDR's ADC clipped during the frame: lower the gain
    timestamp: float = field(default_factory=time.time)


@dataclass
class DecodedPacket:
    frame: RxFrame
    header: RadioHeader | None
    encrypted: bytes = b""
    method: str | None = None        # "psk", "plain", "pki" or None when undecrypted
    channel_name: str | None = None  # matched channel, or "PKI"
    key_label: str | None = None     # which private key decrypted a PKI DM
    data: mesh_pb2.Data | None = None
    plaintext: bytes = b""
    duplicate: int = 0               # how many times (from, id) was seen before
    candidate_channels: list[str] = field(default_factory=list)

    protocol = "meshtastic"

    @property
    def decrypted(self) -> bool:
        return self.data is not None

    @property
    def kind(self) -> str:
        return self.portnum_name

    @property
    def portnum_name(self) -> str:
        if self.data is None:
            return ""
        try:
            return portnums_pb2.PortNum.Name(self.data.portnum)
        except ValueError:
            return f"PORT_{self.data.portnum}"


def _parse_data(plaintext: bytes) -> mesh_pb2.Data | None:
    """A wrong key yields random bytes; accept only a parseable Data with a real portnum."""
    d = mesh_pb2.Data()
    try:
        d.ParseFromString(plaintext)
    except (DecodeError, ValueError):
        return None
    if d.portnum == portnums_pb2.UNKNOWN_APP:
        return None
    return d


class Decoder:
    DUP_WINDOW_S = 600

    def __init__(self, cfg: Config, node_db: NodeDB):
        self.node_db = node_db
        self.set_keys(cfg)
        self._seen: dict[tuple[int, int], tuple[float, int]] = {}

    def set_keys(self, cfg: Config):
        """(Re)load channel PSKs and PKI private keys; tables are swapped whole (decoder thread)."""
        by_hash: dict[int, list] = {}
        for ch in cfg.channels:
            by_hash.setdefault(crypto.channel_hash(ch.name, ch.psk), []).append(ch)
            log.debug("channel %s -> hash 0x%02x", ch.name, crypto.channel_hash(ch.name, ch.psk))
        self.private_keys, self.by_hash = list(cfg.private_keys), by_hash

    def decode(self, frame: RxFrame) -> DecodedPacket:
        parsed = parse_frame(frame.data)
        if parsed is None:
            return DecodedPacket(frame=frame, header=None)
        hdr, enc = parsed
        pkt = DecodedPacket(frame=frame, header=hdr, encrypted=enc)
        if not frame.crc_ok:
            return pkt  # never trust header fields of a corrupted frame

        pkt.duplicate = self._count_duplicate(hdr)
        self.node_db.touch(hdr.sender)

        if hdr.channel == 0 and not hdr.is_broadcast and len(enc) > crypto.PKI_OVERHEAD:
            if self._try_pki(pkt):
                return self._post(pkt)

        channels = self.by_hash.get(hdr.channel, [])
        pkt.candidate_channels = [c.name for c in channels]
        for ch in channels:
            plain = crypto.aes_ctr(ch.psk, hdr.packet_id, hdr.sender, enc) if ch.psk else enc
            data = _parse_data(plain)
            if data is not None:
                pkt.method = "psk" if ch.psk else "plain"
                pkt.channel_name, pkt.data, pkt.plaintext = ch.name, data, plain
                return self._post(pkt)
        return pkt

    def _try_pki(self, pkt: DecodedPacket) -> bool:
        """
        ECDH is symmetric, so holding *either* party's private key is enough:
        recipient key + sender pubkey, or sender key + recipient pubkey.
        The nonce always uses the original sender's node number.
        """
        hdr = pkt.header
        for pk in self.private_keys:
            if pk.node == hdr.to:
                peer = hdr.sender
            elif pk.node == hdr.sender:
                peer = hdr.to
            else:
                continue
            peer_pub = self.node_db.public_key(peer)
            if peer_pub is None:
                log.info("PKI packet %08x: no public key known for !%08x yet", hdr.packet_id, peer)
                continue
            shared = crypto.pki_shared_key(pk.key, peer_pub)
            plain = crypto.pki_decrypt(shared, hdr.packet_id, hdr.sender, pkt.encrypted)
            if plain is None:
                continue
            data = _parse_data(plain)
            if data is None:
                continue
            pkt.method, pkt.channel_name, pkt.data, pkt.plaintext = "pki", "PKI", data, plain
            pkt.key_label = pk.label or f"!{pk.node:08x}"
            return True
        return False

    def _post(self, pkt: DecodedPacket) -> DecodedPacket:
        if pkt.data.portnum == portnums_pb2.NODEINFO_APP:
            user = mesh_pb2.User()
            try:
                user.ParseFromString(pkt.data.payload)
                self.node_db.update_user(pkt.header.sender, user)
            except DecodeError:
                pass
        return pkt

    def _count_duplicate(self, hdr: RadioHeader) -> int:
        now = time.time()
        key = (hdr.sender, hdr.packet_id)
        first, count = self._seen.get(key, (now, -1))
        self._seen[key] = (first, count + 1)
        if len(self._seen) > 5000:
            self._seen = {k: v for k, v in self._seen.items() if now - v[0] < self.DUP_WINDOW_S}
        return count + 1
