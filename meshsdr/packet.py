"""
Over-the-air Meshtastic frame layout (firmware src/mesh/RadioInterface.h PacketHeader).

    offset size field
    0      4    to          (LE)
    4      4    from        (LE)
    8      4    id          (LE)
    12     1    flags       bits 0-2 hop_limit, 3 want_ack, 4 via_mqtt, 5-7 hop_start
    13     1    channel     channel hash (0 for PKI-encrypted DMs)
    14     1    next_hop    last byte of next-hop node num
    15     1    relay_node  last byte of relaying node num
    16     ...  payload     encrypted mesh_pb2.Data
"""

import struct
from dataclasses import dataclass

HEADER_LEN = 16
BROADCAST = 0xFFFFFFFF


@dataclass
class RadioHeader:
    to: int
    sender: int
    packet_id: int
    flags: int
    channel: int
    next_hop: int
    relay_node: int

    @property
    def hop_limit(self) -> int:
        return self.flags & 0x07

    @property
    def want_ack(self) -> bool:
        return bool(self.flags & 0x08)

    @property
    def via_mqtt(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def hop_start(self) -> int:
        return (self.flags & 0xE0) >> 5

    @property
    def hops_away(self) -> int | None:
        # hop_start == 0 means firmware < 2.3: unknown
        return self.hop_start - self.hop_limit if self.hop_start else None

    @property
    def is_broadcast(self) -> bool:
        return self.to == BROADCAST


def parse_frame(frame: bytes) -> tuple[RadioHeader, bytes] | None:
    if len(frame) < HEADER_LEN:
        return None
    to, sender, pid, flags, ch, nh, relay = struct.unpack_from("<IIIBBBB", frame, 0)
    return RadioHeader(to, sender, pid, flags, ch, nh, relay), frame[HEADER_LEN:]


def build_frame(h: RadioHeader, payload: bytes) -> bytes:
    return struct.pack("<IIIBBBB", h.to, h.sender, h.packet_id, h.flags, h.channel,
                       h.next_hop, h.relay_node) + payload


def node_hex(num: int) -> str:
    return "^all" if num == BROADCAST else f"!{num:08x}"
