#!/usr/bin/python3
"""
Wireshark extcap for LoRaSpy. Adds one capture interface:

  sdrmon-live    "LoRaSpy (RTL-SDR, shared)": attaches to a running LoRaSpy
                 (serve, GUI, TUI or text mode) through its sharing socket, so Wireshark sees
                 the same SDR and decoders; when none is running it opens the RTL-SDR itself
                 and shares it, so a GUI/TUI started later attaches to Wireshark's capture.
                 Option "Receive the UDP feed instead" (tab Remote) captures what
                 loraspy.py --wireshark-feed sends, e.g. from another machine.

Frames arrive as LoRaTap (link type 270) pcapng with an "sdrmon1 ..." packet comment; the
loraspy.lua plugin dissects Meshtastic (sync 0x2B) and MeshCore (0x12), Wireshark's own
dissector handles LoRaWAN (0x34).

Installed by tools/wireshark/install.sh as a symlink in Wireshark's personal extcap folder.
Must run with the system Python (GNU Radio bindings) for the live interface.
"""

import argparse
import os
import signal
import socket
import sys
import time
from pathlib import Path

ROOT = Path(os.path.realpath(__file__)).parent.parent.parent   # loraspy/
sys.path.insert(0, str(ROOT))

from meshsdr.pcap import FEED_PORT, LINKTYPE_LORATAP, PcapngWriter, decode_feed  # noqa: E402

VERSION = "1.0"


def interfaces():
    print(f"extcap {{version={VERSION}}}{{help=file://{ROOT}/README.md}}")
    print("interface {value=sdrmon-live}{display=LoRaSpy (RTL-SDR, shared)}")


def dlts():
    print(f"dlt {{number={LINKTYPE_LORATAP}}}{{name=LORATAP}}{{display=LoRaTap}}")


def config(iface: str):
    cfg = ROOT / "config.jsonc"
    print(f"arg {{number=0}}{{call=--config}}{{display=Config file}}{{type=fileselect}}"
          f"{{mustexist=true}}{{default={cfg}}}{{group=SDR}}"
          f"{{tooltip=LoRaSpy JSONC config (receivers, keys); used when this capture opens the SDR}}")
    print("arg {number=1}{call=--protocols}{display=Protocols}{type=string}{default=}{group=SDR}"
          "{tooltip=Comma separated: meshtastic,meshcore,lorawan (empty = all)}")
    print("arg {number=2}{call=--gain}{display=Gain (dB or auto)}{type=string}{default=}{group=SDR}"
          "{tooltip=Tuner gain; also changes the gain of a LoRaSpy this capture attaches to}")
    print("arg {number=3}{call=--iq-file}{display=Replay IQ file instead of the SDR}{type=fileselect}"
          "{mustexist=true}{group=SDR}{tooltip=Optional: cu8 recording, played in real time and looped}")
    print("arg {number=4}{call=--udp}{display=Receive the UDP feed instead}{type=boolflag}{default=false}"
          "{group=Remote (UDP)}{tooltip=Capture what loraspy.py --wireshark-feed HOST:PORT sends, "
          "e.g. from another machine, instead of using this machine's SDR}")
    print(f"arg {{number=5}}{{call=--port}}{{display=UDP port}}{{type=integer}}{{range=1,65535}}"
          f"{{default={FEED_PORT}}}{{group=Remote (UDP)}}")
    print("arg {number=6}{call=--bind}{display=Listen address}{type=string}{default=127.0.0.1}"
          "{group=Remote (UDP)}{tooltip=0.0.0.0 to receive from other machines}")


def capture_attach(fifo, port: int, bind: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    sock.settimeout(0.5)
    with open(fifo, "wb") as f:
        w = PcapngWriter(f)
        while not STOP:
            try:
                dgram, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            rec = decode_feed(dgram)
            if rec:
                ts, data, comment = rec
                w.write(ts, data, comment)


def capture_live(fifo, cfg_path: str, protocols: str, gain: str, iq_file: str):
    from meshsdr import share

    want = {p.strip().lower() for p in protocols.split(",") if p.strip()}
    path = share.default_socket_path()
    server = None
    if share.server_alive(path):
        # the SDR is already open: share it (gain / IQ file options belong to its owner)
        from meshsdr.remote import RemoteCore

        core = RemoteCore(path, "wireshark")
        if gain:
            try:
                core.set_gain(gain)    # a shared, live setting (like --gain of an attached listen)
            except ValueError:
                pass
    else:
        from meshsdr.config import load_config
        from meshsdr.core import MonitorCore
        from meshsdr.server import Server

        cfg = load_config(cfg_path)
        if gain:
            cfg.sdr.gain = gain
        core = MonitorCore(cfg, iq_file=iq_file or None, realtime=bool(iq_file), iq_loop=bool(iq_file))
        if want:
            core.set_receivers_enabled({rx.name for rx in cfg.receivers if rx.protocol in want})
            want = set()   # nothing else is decoded anyway
    with open(fifo, "wb") as f:
        w = PcapngWriter(f)
        broken = []

        def write(ev):
            if broken or (want and ev.frame.protocol not in want):
                return
            try:
                w.write(*core.record(ev))
            except (BrokenPipeError, OSError):
                broken.append(True)   # Wireshark stopped reading
        core.callbacks.append(write)
        core.start()
        if not getattr(core, "remote", False):
            try:
                src = f"IQ file {iq_file}" if iq_file else "RTL-SDR"
                server = Server(core, path, source=f"{src} (opened by Wireshark)")
                server.start()
            except (RuntimeError, OSError):
                server = None
        try:
            while not STOP and not broken and not core.finished.is_set():
                time.sleep(0.2)
            linger(server, core)
        finally:
            core.stop()


def linger(server, core):
    """Capture stopped, but GUI/TUI front-ends attached to our SDR: serve them until they close."""
    global STOP
    if server is None or server.client_count == 0:
        return
    STOP = False                  # a second SIGTERM/SIGINT stops for good
    while not STOP and server.client_count > 0 and not core.finished.is_set():
        time.sleep(0.5)


STOP = False


def main():
    global STOP
    ap = argparse.ArgumentParser()
    ap.add_argument("--extcap-interfaces", action="store_true")
    ap.add_argument("--extcap-interface")
    ap.add_argument("--extcap-dlts", action="store_true")
    ap.add_argument("--extcap-config", action="store_true")
    ap.add_argument("--extcap-version")
    ap.add_argument("--capture", action="store_true")
    ap.add_argument("--fifo")
    ap.add_argument("--extcap-capture-filter")
    ap.add_argument("--config", default=str(ROOT / "config.jsonc"))
    ap.add_argument("--protocols", default="")
    ap.add_argument("--gain", default="")
    ap.add_argument("--iq-file", default="")
    ap.add_argument("--port", type=int, default=FEED_PORT)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--udp", action="store_true")
    args, _ = ap.parse_known_args()

    if args.extcap_interfaces:
        interfaces()
    elif args.extcap_dlts:
        dlts()
    elif args.extcap_config:
        config(args.extcap_interface or "sdrmon-live")
    elif args.capture:
        def stop(*_):
            global STOP
            STOP = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        if args.udp or args.extcap_interface == "sdrmon-attach":   # old separate interface name
            capture_attach(args.fifo, args.port, args.bind)
        else:
            capture_live(args.fifo, args.config, args.protocols, args.gain, args.iq_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
