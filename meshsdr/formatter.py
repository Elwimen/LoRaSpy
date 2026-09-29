"""
Console and JSONL output, in the style of meshprobe's MessageFormatter.

Formats:
  text     decoded packet contents
  hex      xxd-style dumps of the raw LoRa frame and of the decrypted payload
  hextext  both
"""

import base64
import json
from datetime import datetime

from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.json_format import MessageToDict
from meshtastic import protocols
from meshtastic.protobuf import mesh_pb2, portnums_pb2

from .decoder import DecodedPacket
from .hexdump import hex_dump
from .nodedb import NodeDB
from .packet import BROADCAST, node_hex

WIDTH = 68

BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Plain-text payloads (no protobuf inside)
TEXT_PORTS = {portnums_pb2.TEXT_MESSAGE_APP, portnums_pb2.RANGE_TEST_APP,
              portnums_pb2.DETECTION_SENSOR_APP, portnums_pb2.ALERT_APP, portnums_pb2.REPLY_APP}


def payload_message(data: mesh_pb2.Data):
    """Decode Data.payload into its protobuf type, or None if unknown/undecodable."""
    proto = protocols.get(data.portnum)
    if proto is None or proto.protobufFactory is None:
        return None
    msg = proto.protobufFactory()
    try:
        msg.ParseFromString(data.payload)
    except Exception:
        return None
    return msg


def signal_text(f) -> str:
    """'RSSI -87.2 dBm · noise -110.4 · SNR 12.3 dB' (dBFS when the RSSI offset isn't calibrated)."""
    parts = []
    if f.rssi_dbm is not None:
        parts.append(f"RSSI {f.rssi_dbm:.1f} dBm")
        if f.noise_dbm is not None:
            parts.append(f"noise {f.noise_dbm:.1f}")
    elif f.rssi_dbfs is not None:
        parts.append(f"RSSI {f.rssi_dbfs:.1f} dBFS")
        if f.noise_dbfs is not None:
            parts.append(f"noise {f.noise_dbfs:.1f}")
    if f.snr_db is not None:
        parts.append(f"SNR {f.snr_db:.1f} dB")
    if getattr(f, "clipped", False):
        parts.append("⚠ CLIPPED (SDR overloaded: lower the gain)")
    return " · ".join(parts)


class Formatter:
    def __init__(self, fmt: str, colored: bool, node_db: NodeDB, show_crc_errors: bool, show_undecrypted: bool):
        self.fmt = fmt
        self.colored = colored
        self.node_db = node_db
        self.show_crc_errors = show_crc_errors
        self.show_undecrypted = show_undecrypted

    def c(self, color: str, text: str) -> str:
        return f"{color}{text}{RESET}" if self.colored else text

    def wants(self, pkt) -> bool:
        if not pkt.frame.crc_ok:
            return self.show_crc_errors
        if pkt.protocol == "lorawan":
            return True  # headers are always readable; payload decryption is optional
        if not pkt.decrypted:
            return self.show_undecrypted
        return True

    # ------------------------------------------------------------------ console

    def format(self, pkt) -> str:
        f = pkt.frame
        lines = ["=" * WIDTH]
        ts = datetime.fromtimestamp(f.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        snr = signal_text(f)
        snr = f"  {snr}" if snr else ""
        proto = self.c(BOLD, {"meshtastic": "Meshtastic", "lorawan": "LoRaWAN", "meshcore": "MeshCore"}[pkt.protocol])
        iq = ", inverted IQ" if f.invert_iq else ""
        lines.append(f"{proto}  {ts}   Receiver: {f.receiver} "
                     f"({f.frequency_hz / 1e6:.4f} MHz, SF{f.sf}/{f.bw_hz / 1e3:g}k{iq}){snr}")
        if not f.crc_ok:
            lines.append(self.c(RED, f"CRC ERROR — {len(f.data)} bytes, contents unreliable"))
        elif not f.has_crc:
            lines.append(self.c(DIM, "No payload CRC (normal for LoRaWAN downlinks) — contents unverified"))

        body, hex_extra = {"meshtastic": self._meshtastic, "lorawan": self._lorawan,
                           "meshcore": self._meshcore}[pkt.protocol](pkt)
        lines += body
        if self.fmt in ("hex", "hextext"):
            lines.append("─" * WIDTH)
            lines.append(f"LoRa frame ({len(f.data)} bytes):")
            lines.append(hex_dump(f.data, use_color=self.colored))
            for title, data in hex_extra:
                lines.append("─" * WIDTH)
                lines.append(f"{title} ({len(data)} bytes):")
                lines.append(hex_dump(data, use_color=self.colored))
        lines.append("=" * WIDTH)
        return "\n".join(lines)

    def _meshtastic(self, pkt: DecodedPacket):
        f, h, lines = pkt.frame, pkt.header, []
        if h is None:
            lines.append(self.c(RED, f"Frame too short for a Meshtastic header ({len(f.data)} bytes)"))
        else:
            lines.append(f"From: {self._node(h.sender)} → To: {self._node(h.to)}")
            lines.append(f"Channel: {self._channel(pkt)}")
            hop = f"Hops: {h.hops_away} away (limit={h.hop_limit}, start={h.hop_start})" \
                if h.hops_away is not None else f"Hop limit: {h.hop_limit} (hop_start unknown, firmware < 2.3)"
            extras = []
            if h.hop_start:
                extras.append(f"relay: 0x{h.relay_node:02x}")
                if h.next_hop:
                    extras.append(f"next hop: 0x{h.next_hop:02x}")
            lines.append(hop + (f"   ({', '.join(extras)})" if extras else ""))
            flags = []
            if h.want_ack:
                flags.append("want ACK")
            if h.via_mqtt:
                flags.append("via MQTT")
            # Same (from, id) again: a relay if the relay byte isn't the sender's, else the sender repeating it
            kind = "repeat" if h.relay_node == (h.sender & 0xFF) else "relayed copy"
            dup = self.c(DIM, f"   [{kind} #{pkt.duplicate}]") if pkt.duplicate else ""
            lines.append(f"Packet ID: 0x{h.packet_id:08x}" + (f"   Flags: {', '.join(flags)}" if flags else "") + dup)
        if self.fmt in ("text", "hextext"):
            lines.append("─" * WIDTH)
            lines.append(self._content(pkt))
        extra = []
        if pkt.decrypted:
            extra.append(("Decrypted Data protobuf", pkt.plaintext))
            if pkt.data.payload:
                extra.append((f"Data.payload, {pkt.portnum_name}", pkt.data.payload))
        return lines, extra

    def _lorawan(self, pkt):
        from .lorawan import LoRaWANDecoder

        lines = []
        if not pkt.frame.crc_ok:
            return lines, []
        direction = "uplink" if pkt.uplink else "downlink"
        lines.append(f"Type: {self.c(BOLD, pkt.kind)} ({direction})" +
                     (self.c(DIM, f"   [seen #{pkt.duplicate + 1}]") if pkt.duplicate else ""))
        if pkt.error:
            lines.append(self.c(RED, pkt.error))
        if pkt.mtype == 0 and pkt.dev_eui:
            label = f" {self.c(CYAN, pkt.otaa_device.label)}" if pkt.otaa_device and pkt.otaa_device.label else ""
            lines.append(f"DevEUI: {self.c(CYAN, pkt.dev_eui)}{label}   JoinEUI: {pkt.join_eui}   DevNonce: {pkt.dev_nonce}")
        elif pkt.mtype == 1 and pkt.join_accept:
            ja = pkt.join_accept
            lines.append(f"{self.c(GREEN, 'JOIN ACCEPTED')} for DevEUI {ja['dev_eui']} (DevNonce {ja['dev_nonce']}): "
                         f"DevAddr {self.c(CYAN, ja['dev_addr'])}  NetID {ja['net_id']}  JoinNonce {ja['join_nonce']}")
            lines.append(f"RX1 DR offset {ja['rx1_dr_offset']}, RX2 DR{ja['rx2_dr']}, RX delay {ja['rx_delay_s']} s" +
                         (f", extra channels {', '.join(f'{f:.1f}' for f in ja['cflist_mhz'])} MHz"
                          if ja.get("cflist_mhz") else ""))
        elif pkt.dev_addr is not None:
            label = f" {self.c(CYAN, pkt.session.label)}" if pkt.session and pkt.session.label else ""
            lines.append(f"DevAddr: {pkt.dev_addr:08X}{label} ({pkt.network})   FCnt: {pkt.fcnt}   "
                         f"FPort: {pkt.fport if pkt.fport is not None else '-'}")
            flags = LoRaWANDecoder.fctrl_flags(pkt)
            if flags or pkt.fopts:
                lines.append(f"FCtrl: {', '.join(flags) or '-'}" +
                             (f"   FOpts (MAC commands): {pkt.fopts.hex()}" if pkt.fopts else ""))
        for n in pkt.notes:
            lines.append(self.c(DIM, n))
        lines.append(f"MIC: {pkt.mic.hex()}" + ("" if pkt.mic_ok is None else
                     "  " + (self.c(GREEN, "verified") if pkt.mic_ok else self.c(RED, "MISMATCH (wrong key or FCnt > 65535)"))))
        if self.fmt in ("text", "hextext") and pkt.frm_payload:
            lines.append("─" * WIDTH)
            if pkt.plaintext is not None:
                printable = pkt.plaintext.decode("utf-8", errors="replace")
                lines.append(f"FRMPayload (decrypted, {len(pkt.plaintext)} bytes): {pkt.plaintext.hex()}")
                if pkt.decoded:
                    for k, v in pkt.decoded.items():
                        lines.append(f"  {k}: {self.c(GREEN, str(v))}")
                elif printable.isprintable():
                    lines.append("  " + self.c(GREEN, printable))
            else:
                lines.append(f"🔒 FRMPayload {len(pkt.frm_payload)} bytes (encrypted; add a session under lorawan.sessions)")
        extra = [("FRMPayload decrypted", pkt.plaintext)] if pkt.plaintext else []
        return lines, extra

    def _meshcore(self, pkt):
        lines = []
        if not pkt.frame.crc_ok:
            return lines, []
        path = " → ".join(h.hex() for h in pkt.path) or "(none)"
        dup = self.c(DIM, f"   [seen #{pkt.duplicate + 1}]") if pkt.duplicate else ""
        lines.append(f"Type: {self.c(BOLD, pkt.kind)}   Route: {pkt.route}   Path: {path}{dup}")
        if pkt.transport_codes:
            lines.append(f"Transport codes: 0x{pkt.transport_codes[0]:04x} 0x{pkt.transport_codes[1]:04x}")
        if pkt.error:
            lines.append(self.c(RED, pkt.error))
        fl = pkt.fields
        if self.fmt in ("text", "hextext"):
            lines.append("─" * WIDTH)
            if pkt.payload_type == 4 and "public_key" in fl:
                sig = self.c(GREEN, "signature OK") if fl["signature_ok"] else self.c(RED, "BAD SIGNATURE")
                lines.append(f"  {self.c(CYAN, fl.get('name', '(no name)'))}  [{fl.get('type', '?')}]  {sig}")
                lines.append(f"  public key: {fl['public_key']}")
                ts = datetime.fromtimestamp(fl["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                lines.append(f"  advert time: {ts}")
                if "lat" in fl:
                    lines.append(f"  📍 {fl['lat']:.6f}, {fl['lon']:.6f}")
            elif "text" in fl:
                where = f"channel {self.c(GREEN, pkt.channel)}" if pkt.channel else \
                    self.c(MAGENTA, f"🔑 DM decrypted with identity {pkt.identity}")
                ts = datetime.fromtimestamp(fl["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                lines.append(f"  {where}   sent {ts}   ({fl['txt_type']}, attempt {fl['attempt']})")
                lines.append("  " + self.c(GREEN, fl["text"]))
            elif pkt.plaintext is not None:
                lines.append(f"  decrypted ({pkt.channel or pkt.identity}): {pkt.plaintext.rstrip(bytes(1)).hex()}")
            elif pkt.payload_type in (5, 6):
                lines.append(f"🔒 group message on unknown channel (hash {fl.get('channel_hash')})")
            elif pkt.payload_type in (0, 1, 2, 7, 8):
                lines.append(f"🔒 {pkt.kind} {fl.get('src_name', '')} ({fl.get('src', '?')}) → "
                             f"{fl.get('dest_name', '')} ({fl.get('dest')})")
            else:
                for k, v in fl.items():
                    lines.append(f"  {k}: {v}")
        extra = [("Decrypted payload", pkt.plaintext)] if pkt.plaintext else [("Payload", pkt.payload)]
        return lines, extra

    def _node(self, num: int) -> str:
        if num == BROADCAST:
            return "^all (broadcast)"
        name = self.node_db.display_name(num)
        return f"{node_hex(num)}" + (f" {self.c(CYAN, name)}" if name else "")

    def _channel(self, pkt: DecodedPacket) -> str:
        h = pkt.header
        if not pkt.frame.crc_ok:
            return self.c(RED, f"hash 0x{h.channel:02x} (not decrypted: CRC error)")
        if pkt.method == "pki":
            return self.c(MAGENTA, f"🔑 PKI direct message (decrypted with key {pkt.key_label})")
        if pkt.method == "psk":
            return f"{self.c(GREEN, pkt.channel_name)} (hash 0x{h.channel:02x}, PSK)"
        if pkt.method == "plain":
            return f"{self.c(YELLOW, pkt.channel_name)} (hash 0x{h.channel:02x}, unencrypted)"
        if h.channel == 0 and not h.is_broadcast:
            return self.c(RED, "hash 0x00 — likely PKI direct message, no matching private key/public key")
        if pkt.candidate_channels:
            return self.c(RED, f"hash 0x{h.channel:02x} — matches {', '.join(pkt.candidate_channels)} "
                               f"but decryption failed")
        return self.c(RED, f"hash 0x{h.channel:02x} — no configured channel matches")

    def _content(self, pkt: DecodedPacket) -> str:
        if not pkt.frame.crc_ok or pkt.header is None:
            return self.c(DIM, "(not decoded)")
        if not pkt.decrypted:
            return f"🔒 ENCRYPTED ({len(pkt.encrypted)} bytes)"
        d = pkt.data
        out = [self.c(BOLD, f"[{pkt.portnum_name}]")]
        if d.portnum in TEXT_PORTS:
            out.append("  " + self.c(GREEN, d.payload.decode("utf-8", errors="replace")))
        else:
            msg = payload_message(d)
            if msg is None:
                out.append(f"  ({len(d.payload)} bytes, no decoder for this port)")
            elif d.portnum == portnums_pb2.POSITION_APP:
                out.extend(self._position(msg))
            elif d.portnum == portnums_pb2.TRACEROUTE_APP:
                out.extend(self._traceroute(msg, pkt))
            else:
                out.extend(self._fields(msg, indent=1))
        meta = []
        if d.want_response:
            meta.append("want_response")
        if d.request_id:
            meta.append(f"request_id=0x{d.request_id:08x}")
        if d.reply_id:
            meta.append(f"reply_id=0x{d.reply_id:08x}")
        if d.emoji:
            meta.append("emoji reaction")
        if d.HasField("bitfield"):
            meta.append(f"ok_to_mqtt={'yes' if d.bitfield & 1 else 'no'}")
        if meta:
            out.append(self.c(DIM, "  " + ", ".join(meta)))
        return "\n".join(out)

    def _position(self, p: mesh_pb2.Position) -> list[str]:
        out = []
        if p.HasField("latitude_i") or p.HasField("longitude_i"):
            lat, lon = p.latitude_i * 1e-7, p.longitude_i * 1e-7
            out.append(f"  📍 {lat:.6f}, {lon:.6f}   https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}")
        rest = mesh_pb2.Position()
        rest.CopyFrom(p)
        rest.ClearField("latitude_i")
        rest.ClearField("longitude_i")
        out.extend(self._fields(rest, indent=1))
        return out

    def _traceroute(self, r: mesh_pb2.RouteDiscovery, pkt: DecodedPacket) -> list[str]:
        def snr(v):
            return "?" if v == -128 else f"{v / 4:.2f}dB"

        def path(start, nodes, snrs, end):
            hops = [node_hex(start)]
            for i, n in enumerate(nodes):
                hops.append(f"({snr(snrs[i]) if i < len(snrs) else '?'}) → {node_hex(n)}")
            if len(snrs) > len(nodes):
                hops.append(f"({snr(snrs[len(nodes)])}) → {node_hex(end)}")
            return " ".join(hops)

        h = pkt.header
        # A reply (request_id set) travels target → origin, so the forward path runs to → from
        origin, target = (h.to, h.sender) if pkt.data.request_id else (h.sender, h.to)
        out = []
        if r.route or r.snr_towards:
            out.append("  towards: " + path(origin, r.route, r.snr_towards, target))
        if r.route_back or r.snr_back:
            out.append("  back:    " + path(target, r.route_back, r.snr_back, origin))
        return out or ["  (empty route)"]

    def _fields(self, msg, indent: int) -> list[str]:
        pad = "  " * indent
        out = []
        for fd, value in msg.ListFields():
            if fd.is_repeated:
                if fd.type == FieldDescriptor.TYPE_MESSAGE:
                    out.append(f"{pad}{fd.name}:")
                    for i, item in enumerate(value):
                        out.append(f"{pad}  [{i}]")
                        out.extend(self._fields(item, indent + 2))
                else:
                    out.append(f"{pad}{fd.name}: [{', '.join(self._scalar(fd, v) for v in value)}]")
            elif fd.type == FieldDescriptor.TYPE_MESSAGE:
                out.append(f"{pad}{fd.name}:")
                out.extend(self._fields(value, indent + 1))
            else:
                out.append(f"{pad}{fd.name}: {self._scalar(fd, value)}")
        return out

    @staticmethod
    def _scalar(fd, v) -> str:
        if fd.type == FieldDescriptor.TYPE_ENUM:
            ev = fd.enum_type.values_by_number.get(v)
            return ev.name if ev else str(v)
        if fd.type == FieldDescriptor.TYPE_BYTES:
            return base64.b64encode(v).decode() if len(v) > 8 else v.hex()
        if fd.type in (FieldDescriptor.TYPE_FLOAT, FieldDescriptor.TYPE_DOUBLE):
            return f"{v:.3f}"
        if fd.type == FieldDescriptor.TYPE_FIXED32 and fd.name.endswith(("node_id", "from", "to", "source", "dest")):
            return node_hex(v)
        return str(v)

    # ------------------------------------------------------------------ JSONL

    @staticmethod
    def to_json(pkt) -> str:
        f = pkt.frame
        rec = {
            "time": datetime.fromtimestamp(f.timestamp).isoformat(timespec="milliseconds"),
            "protocol": pkt.protocol, "receiver": f.receiver, "frequency_hz": f.frequency_hz, "sf": f.sf,
            "bw_hz": f.bw_hz, "invert_iq": f.invert_iq, "snr_db": f.snr_db, "snr_lora_db": f.snr_lora_db,
            "rssi_dbfs": f.rssi_dbfs, "noise_dbfs": f.noise_dbfs, "rssi_dbm": f.rssi_dbm, "noise_dbm": f.noise_dbm,
            "clipped": f.clipped,
            "crc_ok": f.crc_ok,
            "has_crc": f.has_crc, "raw": f.data.hex(),
        }
        if pkt.protocol == "lorawan":
            rec.update({"join_accept": pkt.join_accept})
            rec.update({"type": pkt.kind, "uplink": pkt.uplink, "dev_addr": f"{pkt.dev_addr:08X}"
                        if pkt.dev_addr is not None else None, "fcnt": pkt.fcnt, "fport": pkt.fport,
                        "dev_eui": pkt.dev_eui, "join_eui": pkt.join_eui, "mic_ok": pkt.mic_ok,
                        "decrypted": pkt.decrypted, "payload": pkt.plaintext.hex() if pkt.plaintext else None,
                        "decoded": pkt.decoded,
                        "duplicate": pkt.duplicate, "error": pkt.error})
            return json.dumps(rec, ensure_ascii=False)
        if pkt.protocol == "meshcore":
            rec.update({"type": pkt.kind, "route": pkt.route, "path": [h.hex() for h in pkt.path],
                        "channel": pkt.channel, "identity": pkt.identity, "decrypted": pkt.decrypted,
                        "fields": pkt.fields, "duplicate": pkt.duplicate, "error": pkt.error})
            return json.dumps(rec, ensure_ascii=False, default=str)
        return Formatter._meshtastic_json(pkt, rec)

    @staticmethod
    def _meshtastic_json(pkt: DecodedPacket, rec: dict) -> str:
        h = pkt.header
        if h is not None:
            rec.update({
                "from": node_hex(h.sender), "to": node_hex(h.to), "id": h.packet_id,
                "hop_limit": h.hop_limit, "hop_start": h.hop_start, "want_ack": h.want_ack,
                "via_mqtt": h.via_mqtt, "channel_hash": h.channel, "next_hop": h.next_hop,
                "relay_node": h.relay_node, "duplicate": pkt.duplicate,
            })
        rec["decrypted"] = pkt.decrypted
        if pkt.decrypted:
            d = pkt.data
            rec.update({"method": pkt.method, "channel": pkt.channel_name, "portnum": pkt.portnum_name,
                        "payload": d.payload.hex()})
            if d.portnum in TEXT_PORTS:
                rec["text"] = d.payload.decode("utf-8", errors="replace")
            else:
                msg = payload_message(d)
                if msg is not None:
                    rec["decoded"] = MessageToDict(msg)
        return json.dumps(rec, ensure_ascii=False)


def summarize(pkt, node_db: NodeDB | None = None) -> dict:
    """Compact fields for one-line displays: kind, src, dst, text, ok (bool), extra (str)."""
    f = pkt.frame
    out = {"kind": getattr(pkt, "kind", "") or "", "src": "", "dst": "", "text": "", "ok": f.crc_ok}
    if not f.crc_ok:
        out["kind"], out["text"] = "CRC ERROR", f"{len(f.data)} bytes"
        return out
    if pkt.protocol == "meshtastic":
        h = pkt.header
        if h is None:
            out["text"] = "too short"
            return out
        name = (lambda n: node_db.display_name(n) if node_db else "")
        out["src"] = name(h.sender) or node_hex(h.sender)
        out["dst"] = "all" if h.to == BROADCAST else (name(h.to) or node_hex(h.to))
        if not pkt.decrypted:
            out["kind"] = "PKI?" if h.channel == 0 and h.to != BROADCAST else f"enc #{h.channel:02x}"
            out["text"] = f"🔒 {len(pkt.encrypted)} bytes"
            return out
        out["kind"] = pkt.portnum_name.replace("_APP", "")
        d = pkt.data
        if d.portnum in TEXT_PORTS:
            out["text"] = d.payload.decode("utf-8", errors="replace")
        else:
            msg = payload_message(d)
            if d.portnum == portnums_pb2.POSITION_APP and msg is not None:
                out["text"] = f"{msg.latitude_i * 1e-7:.5f}, {msg.longitude_i * 1e-7:.5f}"
            elif d.portnum == portnums_pb2.NODEINFO_APP and msg is not None:
                out["text"] = f"{msg.long_name} ({msg.short_name})"
            elif d.portnum == portnums_pb2.TELEMETRY_APP and msg is not None:
                which = msg.WhichOneof("variant") or ""
                sub = getattr(msg, which) if which else None
                vals = [f"{fd.name}={v:.3g}" if isinstance(v, float) else f"{fd.name}={v}"
                        for fd, v in (sub.ListFields() if sub is not None else [])][:4]
                out["text"] = f"{which}: " + " ".join(vals)
            elif msg is not None:
                out["text"] = MessageToDict(msg).__repr__()[:80]
        out["text"] = (f"[{pkt.channel_name}] " if pkt.channel_name and pkt.channel_name != "PKI" else
                       "[PKI] " if pkt.method == "pki" else "") + out["text"]
        return out
    if pkt.protocol == "lorawan":
        out["src"] = pkt.dev_eui or (f"{pkt.dev_addr:08X}" if pkt.dev_addr is not None else "")
        if pkt.session and pkt.session.label:
            out["src"] = pkt.session.label
        out["dst"] = "network" if pkt.uplink else "device"
        if pkt.join_accept:
            out["text"] = f"JOIN ACCEPTED → DevAddr {pkt.join_accept['dev_addr']}"
        elif pkt.mtype == 0:
            out["text"] = f"DevNonce {pkt.dev_nonce}" + (" MIC ok" if pkt.mic_ok else "")
        elif pkt.decoded:
            out["text"] = " ".join(f"{k}={v}" for k, v in pkt.decoded.items())
        elif pkt.plaintext is not None:
            out["text"] = pkt.plaintext.hex()
        elif pkt.dev_addr is not None:
            out["text"] = f"FCnt {pkt.fcnt} FPort {pkt.fport} 🔒 {len(pkt.frm_payload)} B ({pkt.network})"
        return out
    if pkt.protocol == "meshcore":
        fl = pkt.fields
        if pkt.payload_type == 4:
            out["src"] = fl.get("name", fl.get("public_key", "")[:8])
            out["text"] = f"advert [{fl.get('type', '?')}]" + ("" if fl.get("signature_ok") else " BAD SIG")
        elif "text" in fl:
            out["src"] = pkt.channel or pkt.identity or ""
            out["text"] = fl["text"]
        elif pkt.payload_type in (5, 6):
            out["text"] = f"🔒 group {fl.get('channel_hash')}"
        elif pkt.payload_type in (0, 1, 2, 7, 8):
            out["src"], out["dst"] = fl.get("src_name", fl.get("src", "")), fl.get("dest_name", fl.get("dest", ""))
            out["text"] = "🔒 direct"
        out["extra"] = f"{pkt.route} path {len(pkt.path)}"
        return out
    return out
