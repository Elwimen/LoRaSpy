"""
"Decoder" for the encrypted 2-FSK hopping networks found in 869.40–869.65 MHz (tw_rx.py).

The payload is encrypted, so nothing inside can be read. What is reported per frame:
- size class from the number of bits after the sync word,
- the station, by received level: frames within STATION_TOLERANCE_DB of a known station's
  average belong to it (S1, S2, … in order of appearance) — works for every frame type,
- its role in an exchange: frames less than EXCHANGE_GAP_S apart form one exchange; the first
  is the initiator (the polling master), the others are replies,
- the raw header (first bytes after the sync word). In the recordings analysed, header bytes
  6–7 matched the transmitting station in every LONG frame (75 + 45 frames, no exception):
  reported as `addr`. Bytes 0–4 change from frame to frame (counters), byte 5 was constant.
"""

import time
from dataclasses import dataclass, field

from .decoder import RxFrame

STATION_TOLERANCE_DB = 4.0
EXCHANGE_GAP_S = 0.6
HEADER_BYTES = 12


@dataclass
class Station:
    label: str
    level_db: float
    frames: int = 0
    first: float = 0.0
    last: float = 0.0
    initiator: int = 0          # frames that started an exchange
    replies: int = 0


@dataclass
class TwPacket:
    frame: RxFrame
    protocol: str = "trustedwireless"
    kind: str = ""
    station: str = ""
    role: str = ""
    exchange: int = 0
    nbits: int = 0
    header: bytes = b""
    addr: str = ""              # header bytes 6–7: per-station in LONG frames (provisional)
    decrypted: bool = False
    duplicate: int = 0
    error: str | None = None
    notes: list = field(default_factory=list)


class TrustedWirelessDecoder:
    def __init__(self, *_):
        self.stations: list[Station] = []
        self._exchange = 0
        self._last_t = 0.0

    def _station(self, level: float, t: float) -> Station:
        near = [s for s in self.stations if abs(s.level_db - level) <= STATION_TOLERANCE_DB]
        st = min(near, key=lambda s: abs(s.level_db - level)) if near else None
        if st is None:
            st = Station(f"S{len(self.stations) + 1}", level, first=t)
            self.stations.append(st)
        else:
            st.level_db += (level - st.level_db) * 0.1      # follow slow drifts
        st.frames += 1
        st.last = t
        return st

    def decode(self, frame: RxFrame) -> TwPacket:
        nbits = len(frame.bits)
        kind = "SHORT" if nbits < 110 else "MEDIUM" if nbits < 190 else "LONG"
        pkt = TwPacket(frame=frame, kind=kind, nbits=nbits, header=frame.data[:HEADER_BYTES],
                       addr=frame.data[6:8].hex() if len(frame.data) >= 8 else "")
        t = frame.timestamp
        new_exchange = t - self._last_t > EXCHANGE_GAP_S
        if new_exchange:
            self._exchange += 1
        self._last_t = max(self._last_t, t + (frame.duration_ms or 0) / 1e3)
        level = frame.rssi_dbfs if frame.rssi_dbfs is not None else -100.0
        st = self._station(level, t)
        pkt.station, pkt.exchange = st.label, self._exchange
        if new_exchange:
            pkt.role = "initiator"
            st.initiator += 1
        else:
            pkt.role = "reply"
            st.replies += 1
        pkt.notes.append("payload encrypted (AES-128 per the radio's specification): not decodable")
        return pkt

    def summary(self) -> list[dict]:
        now = time.time()
        return [{"station": s.label, "level_db": round(s.level_db, 1), "frames": s.frames,
                 "initiator": s.initiator, "replies": s.replies, "last_seen_s": round(now - s.last, 1)}
                for s in self.stations]
