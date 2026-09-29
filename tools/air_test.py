#!/usr/bin/env python3
"""
Over-the-air test driver: makes a USB-connected Meshtastic node transmit known
packets under different presets, then checks which of them LoRaSpy decoded.

1. Start the monitor with every preset you want to test and a JSONL log:
     ./loraspy.py -c all.jsonc listen --jsonl air.jsonl
2. Drive the node (restores the node's original LoRa settings afterwards):
     tools/air_test.py send --presets LONG_FAST,MEDIUM_FAST --channels 0,1 \\
         --nodeinfo !a1b2c3d4 --traceroute !a1b2c3d4 --dm !a1b2c3d4 --jsonl air.jsonl --out sent.json
3. Compare:
     tools/air_test.py check sent.json air.jsonl

Preset changes go through writeConfig("lora"). On firmware with live LoRa apply this
does not reboot; if the node does reboot, the script reconnects.
"""

import argparse
import json
import math
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from meshsdr.radio import PRESETS  # noqa: E402


def airtime_s(preset: str, payload_len: int = 60) -> float:
    """Semtech LoRa time-on-air (explicit header, CRC on, 16-symbol preamble)."""
    p = PRESETS[preset]
    tsym = (2 ** p.sf) / (p.bw_khz * 1000)
    de = 1 if tsym >= 0.016 else 0
    n = 8 + max(math.ceil((8 * payload_len - 4 * p.sf + 28 + 16) / (4 * (p.sf - 2 * de))) * p.cr, 0)
    return (16 + 4.25 + n) * tsym


class Node:
    def __init__(self, port: str):
        self.port = port
        self.iface = None
        self.connect()

    def connect(self, attempts: int = 20):
        import meshtastic.serial_interface as si

        for n in range(attempts):
            try:
                self.iface = si.SerialInterface(self.port, noNodes=False)
                return
            except Exception as e:  # port vanishes while the node reboots
                print(f"  (connect attempt {n + 1} failed: {e}); retrying", file=sys.stderr)
                time.sleep(3)
        raise RuntimeError(f"cannot connect to {self.port}")

    def close(self):
        if self.iface:
            try:
                self.iface.close()
            except Exception:
                pass
            self.iface = None

    @property
    def node_num(self) -> int:
        return self.iface.myInfo.my_node_num

    def lora(self):
        return self.iface.localNode.localConfig.lora

    def set_preset(self, preset: str, hop_limit: int, attempts: int = 3):
        from meshtastic.protobuf import config_pb2

        want = config_pb2.Config.LoRaConfig.ModemPreset.Value(preset)
        for n in range(attempts):
            lora = self.lora()
            lora.hop_limit = hop_limit
            lora.use_preset = True
            lora.modem_preset = want
            self.iface.localNode.writeConfig("lora")
            # Give the admin packet time to be processed before dropping the serial link,
            # then reconnect to read back what the node really applied (survives a reboot too)
            time.sleep(8)
            self.close()
            time.sleep(2)
            self.connect()
            if self.lora().modem_preset == want and self.lora().hop_limit == hop_limit:
                return
            print(f"  (preset write not applied on attempt {n + 1}, retrying)", flush=True)
        got = config_pb2.Config.LoRaConfig.ModemPreset.Name(self.lora().modem_preset)
        raise RuntimeError(f"node reports preset {got}, wanted {preset}")

    def restore(self, saved: bytes):
        from meshtastic.protobuf import config_pb2

        orig = config_pb2.Config.LoRaConfig()
        orig.ParseFromString(saved)
        for _ in range(3):
            self.lora().CopyFrom(orig)
            self.iface.localNode.writeConfig("lora")
            time.sleep(8)
            self.close()
            time.sleep(2)
            self.connect()
            if self.lora().SerializeToString() == saved:
                print("original LoRa config confirmed")
                return
            print("  (restore not applied yet, retrying)", flush=True)
        print("WARNING: could not confirm LoRa config restore — check the node manually", file=sys.stderr)

    def send_nodeinfo_request(self, dest: str, channel: int) -> int:
        """Unicast our NodeInfo with want_response: PSK-encrypted (NODEINFO is exempt from PKI)."""
        from google.protobuf.json_format import ParseDict
        from meshtastic.protobuf import mesh_pb2, portnums_pb2

        user = ParseDict(self.iface.getMyNodeInfo()["user"], mesh_pb2.User(), ignore_unknown_fields=True)
        pkt = self.iface.sendData(user.SerializeToString(), destinationId=dest, portNum=portnums_pb2.NODEINFO_APP,
                                  wantResponse=True, channelIndex=channel)
        return pkt.id

    def send_traceroute(self, dest: str, channel: int) -> int:
        from meshtastic.protobuf import mesh_pb2, portnums_pb2

        pkt = self.iface.sendData(mesh_pb2.RouteDiscovery().SerializeToString(), destinationId=dest,
                                  portNum=portnums_pb2.TRACEROUTE_APP, wantResponse=True, channelIndex=channel)
        return pkt.id

    def send_text(self, text: str, channel: int, dest: str | None = None) -> int:
        if dest:
            pkt = self.iface.sendText(text, destinationId=dest, wantAck=True, channelIndex=channel)
        else:
            pkt = self.iface.sendText(text, channelIndex=channel)
        return pkt.id


class AirWatch:
    """Tail LoRaSpy's JSONL so the driver can wait until a packet has actually aired."""

    def __init__(self, path: str | None, node: str):
        self.path, self.node, self.pos = path, node, 0
        if path and Path(path).exists():
            self.pos = Path(path).stat().st_size

    def wait(self, pid: int, timeout: float) -> dict | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if Path(self.path).exists():
                with open(self.path, encoding="utf-8") as f:
                    f.seek(self.pos)
                    for line in f:
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue
                        if rec.get("from") == self.node and rec.get("id") == pid:
                            return rec
            time.sleep(0.5)
        return None


def cmd_send(args) -> int:
    presets = [p.strip().upper() for p in args.presets.split(",")]
    for p in presets:
        if p not in PRESETS:
            raise SystemExit(f"unknown preset {p}")
        if PRESETS[p].bw_khz > 250:
            print(f"warning: {p} is 500 kHz; EU_868 is only 250 kHz wide and firmware falls back to LongFast",
                  file=sys.stderr)
    channels = [int(c) for c in args.channels.split(",")] if args.channels else []

    node = Node(args.port)
    me = node.node_num
    saved = node.lora().SerializeToString()
    run_id = f"{random.getrandbits(16):04x}"
    sent = {"node": f"!{me:08x}", "run": run_id, "packets": []}
    print(f"node !{me:08x}, run {run_id}, original preset restored at the end")

    watch = AirWatch(args.jsonl, f"!{me:08x}") if args.jsonl else None

    def record(preset, kind, channel, dest, text, pid, gap):
        sent["packets"].append({"preset": preset, "kind": kind, "channel": channel, "dest": dest,
                                "text": text, "id": pid, "time": time.time()})
        print(f"  sent {kind:<10} ch{channel} {dest or '^all':<10} id=0x{pid:08x}  {text!r}", end="", flush=True)
        if watch is None:
            print()
            time.sleep(gap)
            return
        t0 = time.time()
        rec = watch.wait(pid, args.air_timeout)
        if rec is None:
            print(f"  -> not heard within {args.air_timeout:.0f} s")
        else:
            print(f"  -> aired after {time.time() - t0:.1f} s ({rec['receiver']}, "
                  f"{'decrypted ' + str(rec.get('channel')) if rec.get('decrypted') else 'NOT decrypted'})")
        time.sleep(gap)  # let ACKs / retransmissions finish before the next one

    try:
        for preset in presets:
            print(f"== {preset}", flush=True)
            node.set_preset(preset, args.hop_limit)
            gap = max(args.min_gap, 3 * airtime_s(preset))
            time.sleep(2)
            for ch in channels:
                text = f"sdrtest {run_id} {preset} ch{ch}"
                record(preset, "broadcast", ch, None, text, node.send_text(text, ch), gap)
            if args.nodeinfo:
                record(preset, "nodeinfo", args.unicast_channel, args.nodeinfo, "",
                       node.send_nodeinfo_request(args.nodeinfo, args.unicast_channel), gap * 2)
            if args.traceroute:
                record(preset, "traceroute", args.unicast_channel, args.traceroute, "",
                       node.send_traceroute(args.traceroute, args.unicast_channel), gap * 2)
            if args.dm:
                text = f"sdrtest {run_id} {preset} dm"
                record(preset, "dm", args.unicast_channel, args.dm, text,
                       node.send_text(text, args.unicast_channel, args.dm), gap * (4 if args.wait_retries else 1))
    finally:
        print("restoring original LoRa config")
        try:
            node.restore(saved)
        finally:
            node.close()
            Path(args.out).write_text(json.dumps(sent, indent=2))
            print(f"wrote {args.out}")
    return 0


def cmd_check(args) -> int:
    sent = json.loads(Path(args.sent).read_text())
    node = sent["node"]
    frames = [json.loads(line) for line in Path(args.jsonl).read_text().splitlines() if line.strip()]
    by_id: dict[int, list] = {}
    for f in frames:
        if f.get("from") == node and "id" in f:
            by_id.setdefault(f["id"], []).append(f)

    ok = 0
    print(f"{'preset':<14}{'kind':<11}{'ch':<4}{'heard':<7}{'decoded as':<44}{'chain':<12}{'SNR':>6}")
    for p in sent["packets"]:
        hits = by_id.get(p["id"], [])
        good = [h for h in hits if h.get("decrypted")]
        text_ok = any(h.get("text") == p["text"] for h in good) if p["text"] else bool(good)
        ok += text_ok
        if good:
            h = good[0]
            how = f"{h['method']}/{h['channel']} {h['portnum']}" + (
                (" text OK" if text_ok else " TEXT MISMATCH") if p["text"] else "")
        elif hits:
            h = hits[0]
            how = "CRC error" if not h["crc_ok"] else "not decrypted"
        else:
            h, how = None, "—"
        snr = f"{h['snr_db']:.1f}" if h and h.get("snr_db") is not None else ""
        print(f"{p['preset']:<14}{p['kind']:<11}{p['channel']:<4}{len(hits):<7}{how:<44}"
              f"{(h or {}).get('receiver', ''):<12}{snr:>6}")
    print(f"\n{ok}/{len(sent['packets'])} sent packets decoded (text compared where there is text)")
    # Anything else our node sent in the window (ACKs, NodeInfo, telemetry)
    ids = {p["id"] for p in sent["packets"]}
    extra = [f for f in frames if f.get("from") == node and f.get("id") not in ids]
    if extra:
        print(f"\nother frames from {node}:")
        for f in extra:
            print(f"  {f['time']} {f['receiver']:<11} id=0x{f['id']:08x} to={f['to']} "
                  f"{f.get('portnum') or ('CRC error' if not f['crc_ok'] else 'not decrypted')} "
                  f"{f.get('method') or ''}/{f.get('channel') or ''}")
    replies = [f for f in frames if f.get("to") == node and f.get("from") != node]
    if replies:
        print(f"\nframes addressed to {node}:")
        for f in replies:
            print(f"  {f['time']} {f['receiver']:<11} from={f['from']} id=0x{f['id']:08x} "
                  f"{f.get('portnum') or 'not decrypted'} {f.get('method') or ''}/{f.get('channel') or ''} "
                  f"{json.dumps(f.get('decoded', f.get('text', '')))[:80]}")
    return 0 if ok == len(sent["packets"]) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("send", help="drive the node")
    s.add_argument("--port", default="/dev/ttyACM0")
    s.add_argument("--presets", default="LONG_FAST")
    s.add_argument("--channels", default="0", help="channel indexes to broadcast on, e.g. 0,1")
    s.add_argument("--dm", help="node id for a text DM. Firmware 2.5+ sends it PKI-encrypted, and refuses "
                                "if it doesn't know the destination's public key (no legacy PSK fallback for text)")
    s.add_argument("--nodeinfo", help="node id to send a NodeInfo request to (PSK-encrypted unicast; the reply "
                                      "gives the node our public key and us theirs)")
    s.add_argument("--traceroute", help="node id to traceroute (PSK-encrypted unicast)")
    s.add_argument("--unicast-channel", type=int, default=1,
                   help="channel index for unicasts (default 1 = LongFast here, which other nodes share)")
    s.add_argument("--hop-limit", type=int, default=0,
                   help="hop limit while testing; 0 (default) keeps test packets from being relayed across the mesh")
    s.add_argument("--min-gap", type=float, default=6.0, help="minimum seconds between transmissions")
    s.add_argument("--wait-retries", action="store_true", help="after a DM, wait for ACK retransmissions")
    s.add_argument("--jsonl", help="LoRaSpy JSONL to watch: wait until each packet has aired (recommended)")
    s.add_argument("--air-timeout", type=float, default=60.0, help="max seconds to wait for a packet to air")
    s.add_argument("--out", default="sent.json")
    c = sub.add_parser("check", help="compare sent.json with LoRaSpy JSONL")
    c.add_argument("sent")
    c.add_argument("jsonl")
    args = ap.parse_args()
    return cmd_send(args) if args.cmd == "send" else cmd_check(args)


if __name__ == "__main__":
    sys.exit(main())
