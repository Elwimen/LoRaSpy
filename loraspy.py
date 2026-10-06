#!/usr/bin/env python3
"""
LoRaSpy — receive and decode Meshtastic, LoRaWAN and MeshCore traffic off the
air with an RTL-SDR and GNU Radio (gr-lora_sdr).

    ./loraspy.py info                       # show resolved frequencies / keys
    ./loraspy.py listen                     # live from the RTL-SDR
    ./loraspy.py listen --format hextext    # decoded text + hex dumps
    ./loraspy.py listen --iq-file cap.cu8 --iq-center 869.775e6 --iq-rate 2e6
    ./loraspy.py serve                      # headless: share the SDR with GUI/TUI/Wireshark
    ./loraspy.py gain 15                    # change the running SDR's gain (shared)
    ./loraspy.py --help                     # every command with its full argument list

One RTL-SDR, many front-ends: the first LoRaSpy opens the SDR and shares it on a Unix
socket; every later `listen` (GUI, TUI, text) and Wireshark's LoRaSpy capture attach to it.
"""

import argparse
import base64
import logging
import signal
import sys
import threading
import time

from meshsdr import crypto
from meshsdr.config import ConfigError, load_config
from meshsdr.formatter import Formatter

log = logging.getLogger("loraspy")


EXAMPLES = """\
examples:
  loraspy.py listen                          decoded packets as text (opens or attaches to the SDR)
  loraspy.py listen --format hextext --show-crc-errors
  loraspy.py listen --filter text,position --protocol meshtastic
  loraspy.py listen --tui                    btop-style terminal UI
  loraspy.py listen --gui                    spectrum + waterfall window
  loraspy.py serve --gain 20                 headless: open the SDR and share it
  loraspy.py gain 15                         change the running SDR's gain (no value: show gain + ADC level)
  loraspy.py tune 868.95M                    retune the running SDR (decoders stay on their channels)
  loraspy.py keys add channel name=X psk=random   add a channel (keys: list; live when running)
  loraspy.py decoder add preset=LONG_SLOW      add a decoder (decoder: list; set/reset/remove)
  loraspy.py listen --pcap cap.pcapng --jsonl cap.jsonl
  loraspy.py listen --iq-file cap.cu8 --iq-center 869.775e6 --iq-rate 2e6

One RTL-SDR, many front-ends: the first LoRaSpy (listen, --tui, --gui, serve or Wireshark's
'LoRaSpy') opens the SDR and shares it; later ones attach automatically, and the
SDR is released when the last one closes. Receivers, FFT and gain are shared settings.

keys: TUI  1-4 boxes, space decoder, m/o/w protocol, [ ] gain, g AGC, k keys, p pause, f freeze, x clear, q quit
      GUI  1-4 boxes, [ ] gain, G AGC, K keys, R reset view, Ctrl+, settings; frequency dial: wheel
           over a digit = ±1 in that place, right click = zero the digits to its right
"""


class FullHelp(argparse.Action):
    """Top-level -h/--help: every command's complete argument list, not just their names."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        out = [parser.format_help()]
        for action in parser._subparsers._group_actions:
            for name, sub in action.choices.items():
                out.append("\n" + "═" * 78 + f"\n{name}\n" + "═" * 78 + "\n" + sub.format_help())
        parser.exit(message="".join(out))


def build_parser() -> argparse.ArgumentParser:
    fmt = argparse.RawDescriptionHelpFormatter
    p = argparse.ArgumentParser(
        description="Decode Meshtastic, LoRaWAN and MeshCore packets off the air with an RTL-SDR + GNU Radio "
                    "(gr-lora_sdr). Without a command, 'listen' runs.",
        epilog=EXAMPLES, formatter_class=fmt, add_help=False)
    p.add_argument("-h", "--help", action=FullHelp, help="show this help, with every command's arguments, and exit")
    p.add_argument("-c", "--config", default="config.jsonc", help="JSONC config file (default: config.jsonc)")
    p.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                   help="log verbosity on stderr (default: WARNING)")
    sub = p.add_subparsers(dest="command", title="commands", metavar="{listen,serve,gain,tune,channel,keys,record,info}")

    # ---- listen
    lp = sub.add_parser("listen", formatter_class=fmt,
                        help="receive and decode: text output, --tui or --gui (default command)",
                        description="Receive and decode. Opens the SDR and shares it, or attaches to a "
                                    "LoRaSpy that already runs (see 'sharing').")
    out = lp.add_argument_group("output (text mode, and files in any mode)")
    out.add_argument("--format", choices=["text", "hex", "hextext"],
                     help="text = decoded fields, hex = xxd-style dumps of the raw frame and decrypted "
                          "payload, hextext = both (overrides output.format)")
    color = out.add_mutually_exclusive_group()
    color.add_argument("--colored", dest="colored", action="store_true", default=None,
                       help="ANSI colours (default: on when stdout is a terminal)")
    color.add_argument("--no-color", dest="colored", action="store_false", help="no ANSI colours")
    out.add_argument("--filter", metavar="KINDS",
                     help="only these packet types, comma separated. Meshtastic: text, position, nodeinfo, "
                          "telemetry, routing, traceroute, neighbor, waypoint, encrypted or a PortNum name; "
                          "LoRaWAN: join, up, confup, down, confdown; MeshCore: advert, group, dm, ack, path")
    out.add_argument("--protocol", metavar="PROTOS",
                     help="only these protocols: meshtastic, lorawan, meshcore (comma separated). Owning the "
                          "SDR: the other receivers are switched off; attached: filters this output only")
    out.add_argument("--show-crc-errors", action="store_true", default=None, help="also print frames with bad CRC")
    out.add_argument("--hide-undecrypted", action="store_true", help="hide packets no key could decrypt")
    out.add_argument("--jsonl", metavar="FILE",
                     help="append every frame as a JSON line (overrides output.jsonl_file)")
    out.add_argument("--pcap", metavar="FILE", help="write a Wireshark capture (pcapng, LoRaTap)")
    out.add_argument("--wireshark-feed", nargs="?", const="127.0.0.1:47474", metavar="HOST:PORT",
                     help="stream frames over UDP to a Wireshark 'LoRaSpy' capture with "
                          "'Receive the UDP feed instead' set, e.g. on another machine (default 127.0.0.1:47474)")
    out.add_argument("--duration", type=float, metavar="S", help="stop after this many seconds")

    ui_grp = lp.add_argument_group("interface")
    ui = ui_grp.add_mutually_exclusive_group()
    ui.add_argument("--tui", action="store_true", help="btop-style terminal UI: spectrum, decoders, live packets")
    ui.add_argument("--gui", action="store_true", help="Qt window: spectrum + waterfall with band overlays")
    ui_grp.add_argument("--fft-size", type=int, metavar="N",
                        help="spectrum FFT size when opening the SDR (default: gui_settings.json, 1024)")
    lp.add_argument("--screenshot", help=argparse.SUPPRESS)  # GUI: save a PNG after --duration s and exit

    add_source_args(lp.add_argument_group(
        "signal source (applies when this process opens the SDR; --gain also changes a shared SDR)"))
    add_share_args(lp, attach=True)

    # ---- serve
    sp = sub.add_parser("serve", formatter_class=fmt,
                        help="headless: open the SDR, decode and share it with the other front-ends",
                        description="Headless owner of the SDR: decodes and serves GUI/TUI/text/Wireshark "
                                    "front-ends, which attach automatically. Runs until Ctrl-C.")
    add_source_args(sp.add_argument_group("signal source"))
    run = sp.add_argument_group("run")
    run.add_argument("--protocol", metavar="PROTOS",
                     help="start with only these protocols' receivers on (front-ends can change it): "
                          "meshtastic, lorawan, meshcore")
    run.add_argument("--fft-size", type=int, metavar="N",
                     help="initial spectrum FFT size (front-ends can change it)")
    run.add_argument("--duration", type=float, metavar="S", help="stop after this many seconds")
    add_share_args(sp, attach=False)

    # ---- gain
    gp = sub.add_parser("gain", formatter_class=fmt,
                        help="show or set the running SDR's gain, ADC level and clipping",
                        description="Talk to the running LoRaSpy (e.g. a headless serve or listen): show "
                                    "the tuner gain, its steps and the ADC level, or set the gain for everybody.")
    gp.add_argument("value", nargs="?",
                    help="'auto' (tuner AGC) or dB, snapped to the nearest tuner step; omit to only show")
    add_share_args(gp, attach=False)

    # ---- tune
    tp = sub.add_parser("tune", formatter_class=fmt,
                        help="show or set the running SDR's centre frequency (decoders stay on their channels)",
                        description="Retune the running LoRaSpy's SDR. Every decoder keeps its own channel "
                                    "frequency; those outside the new 2 MHz window go idle until tuned back.")
    tp.add_argument("freq", nargs="?", help="869.0M, 868500k, 868500000 or MHz (868.5); omit to show")
    add_share_args(tp, attach=False)

    # ---- channel
    cp = sub.add_parser("channel", formatter_class=fmt,
                        help="list the running LoRaSpy's channels, or move one (runtime only)",
                        description="Decoders sharing a channel filter (e.g. the Meshtastic presets on one "
                                    "frequency, a LoRaWAN channel's SFs) move together. Not saved to the config.")
    cp.add_argument("receiver", nargs="?", help="any decoder on the channel, e.g. LongFast or 'LW 868.1 SF7'")
    cp.add_argument("freq", nargs="?", help="new centre: 869.5M, 869500k, MHz …; 'reset' = configured value")
    add_share_args(cp, attach=False)

    # ---- decoder
    dp = sub.add_parser("decoder", formatter_class=fmt,
                        help="list, add, change or remove decoders (decoders.jsonc; live when running)",
                        description="Decoders added or changed here go to decoders.jsonc next to the config "
                                    "(config.jsonc itself is never rewritten). With a LoRaSpy running they "
                                    "apply at once: a frequency change of a decoder with a channel filter of "
                                    "its own is live, anything else restarts the decoders (≈1–2 s).",
                        epilog="""\
examples:
  loraspy.py decoder                                list decoders (+ added, * changed)
  loraspy.py decoder add preset=LONG_SLOW name=LS2  a Meshtastic preset (on its default slot)
  loraspy.py decoder add preset=LONG_FAST channel_num=3 name=LF-slot3
  loraspy.py decoder add preset=SHORT_TURBO region=US   another region's slot plan → "ShortTurbo US"
  loraspy.py decoder add protocol=meshcore preset=EU_UK_NARROW name=MC2
  loraspy.py decoder add protocol=meshtastic frequency_hz=869.4M bandwidth_hz=125000 \\
                          spreading_factor=10 coding_rate=5 sync_word=0x12 name=Custom
  loraspy.py decoder add protocol=lorawan frequency_hz=868.8M spreading_factors=[9,12]
  loraspy.py decoder add protocol=trustedwireless offset_khz=-15 name=B
  loraspy.py decoder set LongFast sf=12 frequency=869.5M    change parameters
  loraspy.py decoder reset LongFast                 back to its config.jsonc parameters
  loraspy.py decoder remove LF-slot3                remove a decoder (a config one is hidden; reset-all restores it)
  loraspy.py decoder reset-all                      drop every added/changed/removed decoder, switch all off
  loraspy.py decoder enable LongFast MediumSlow     switch decoders on (they start off); 'all' for every one
  loraspy.py decoder disable all                    switch every decoder off
fields for 'add': any config.jsonc receiver key (preset, protocol, frequency_hz, bandwidth_hz,
  spreading_factor, coding_rate, channel_num, primary_channel, region, plan, offset_khz, name …) plus
  sync_word and invert_iq. 'set' takes frequency (or frequency_hz), bw_hz, sf, cr, sync_word, invert_iq.
""")
    dp.add_argument("action", nargs="?", default="list",
                    choices=["list", "add", "set", "reset", "remove", "reset-all", "enable", "disable"])
    dp.add_argument("rest", nargs="*", metavar="NAME|field=value",
                    help="set/reset/remove: the decoder name first; add/set: field=value pairs; "
                         "enable/disable: decoder names (or 'all')")
    add_share_args(dp, attach=False)

    # ---- keys
    kp = sub.add_parser("keys", formatter_class=fmt,
                        help="list, add, edit or remove channels and keys (keys.jsonc; live when running)",
                        description="Channels and keys added here go to keys.jsonc next to the config "
                                    "(config.jsonc itself is never rewritten; its entries are listed "
                                    "read-only). With a LoRaSpy running, changes apply to it at once.",
                        epilog="""\
examples:
  loraspy.py keys                                   list everything (secrets masked)
  loraspy.py keys show                              the same with the keys in full
  loraspy.py keys show channel                      only Meshtastic channels (keys in full)
  loraspy.py keys show channel 0                    one entry: keys.jsonc channel #0
  loraspy.py keys kinds                             key types and their fields
  loraspy.py keys add channel name=MyChannel psk=base64key=
  loraspy.py keys add channel name=MyChannel psk=random     (new random AES-256 PSK)
  loraspy.py keys add pki-private node=!1337b4b3 private_key=base64= label="my node"
  loraspy.py keys add mc-channel name=#test
  loraspy.py keys add lw-otaa dev_eui=70B3D57ED0000000 app_key=32hex label=sensor
  loraspy.py keys edit channel 0 psk=otherkey=        change only the given fields
  loraspy.py keys remove channel 0                  (N = the #N shown by 'keys')
""")
    kp.add_argument("action", nargs="?", default="list", choices=["list", "show", "kinds", "add", "edit", "remove"],
                    help="list (secrets masked), show (keys in full), kinds, add, edit, remove; "
                         "list/show take an optional KIND and entry N to narrow it down")
    kp.add_argument("kind", nargs="?", help="channel, pki-private, pki-public, mc-channel, mc-identity, "
                                            "mc-public, lw-session, lw-otaa")
    kp.add_argument("rest", nargs="*", metavar="N|field=value", help="edit/remove: the entry number N; "
                                                                     "add/edit: field=value pairs")
    kp.add_argument("--show-secrets", action="store_true", help="print keys in full (default: masked)")
    add_share_args(kp, attach=False)

    # ---- record
    rp = sub.add_parser("record", formatter_class=fmt,
                        help="record IQ (whole band or a slice around a frequency) while decoding goes on",
                        description="Record IQ samples into recordings/ next to the config. With a LoRaSpy "
                                    "running, it records from the shared SDR without interrupting anything; "
                                    "otherwise it opens the SDR just for the recording.",
                        epilog="""\
examples:
  loraspy.py record --freq 869.525M --bw 40k --duration 60      one 40 kHz channel, 1 min
  loraspy.py record --freq 869.525M --bw 300k --format cu8      cu8: rtl_433 -r FILE -s RATE …
  loraspy.py record --duration 5                                the whole tuned band (big: ~16 MB/s cf32)
  loraspy.py record --list                                      recordings made by the running LoRaSpy
open with: inspectrum FILE.cf32 (rate from FILE.json) · URH · GNU Radio file source (complex) ·
           rtl_433 -r FILE.cu8 -s RATE -f FREQ -A
""")
    rp.add_argument("--freq", metavar="F", help="centre frequency: 869.525M, 869525k, 869525000 or MHz (869.525); "
                                               "default: tuner centre")
    rp.add_argument("--bw", metavar="B", help="bandwidth to keep around --freq: 40k, 0.3M or Hz; "
                                             "default: the whole tuned band, not decimated")
    rp.add_argument("--duration", type=float, default=10.0, metavar="S", help="seconds (default 10, max 600)")
    rp.add_argument("--format", choices=["cf32", "cu8"], default="cf32",
                    help="cf32 = complex float32 (GNU Radio, inspectrum, URH); cu8 = rtl_sdr/rtl_433 bytes")
    rp.add_argument("--name", help="file name (default: time_frequency_bandwidth)")
    rp.add_argument("--list", action="store_true", help="list the running LoRaSpy's recordings and exit")
    add_source_args(rp.add_argument_group("signal source (only when no LoRaSpy is running)"))
    add_share_args(rp, attach=False)

    # ---- info
    sub.add_parser("info", help="show receivers, tuner plan, channel hashes and keys, then exit",
                   description="Show the resolved receivers, the tuner plan, channel hashes and PKI / "
                               "MeshCore / LoRaWAN keys from the config, then exit.")
    return p


def add_share_args(p, attach: bool):
    g = p.add_argument_group("sharing")
    if attach:
        m = g.add_mutually_exclusive_group()
        m.add_argument("--connect", action="store_true",
                       help="only attach to a running LoRaSpy (fail if none), never open the SDR")
        m.add_argument("--standalone", action="store_true",
                       help="open the SDR for this process only: don't attach, don't share")
    g.add_argument("--socket", metavar="PATH", help="sharing socket (default $XDG_RUNTIME_DIR/loraspy.sock)")


def add_source_args(g):
    """Options about the signal source; they apply to whoever opens the SDR."""
    g.add_argument("--gain", metavar="DB|auto",
                   help="tuner gain in dB (snapped to a tuner step) or 'auto' = tuner AGC (overrides sdr.gain)")
    g.add_argument("--ppm", type=float, help="frequency correction in ppm (overrides sdr.ppm)")
    g.add_argument("--hard-decoding", action="store_true",
                   help="hard-decision decoding (less CPU, less sensitive)")
    g.add_argument("--iq-file", metavar="FILE", help="decode a recorded IQ file instead of the live SDR")
    g.add_argument("--iq-format", default="cu8", choices=["cu8", "cf32"],
                   help="cu8 = rtl_sdr output (default), cf32 = GNU Radio complex float")
    g.add_argument("--iq-rate", type=float, metavar="HZ", help="sample rate of the IQ file (default: sdr.sample_rate)")
    g.add_argument("--iq-center", type=float, metavar="HZ",
                   help="centre frequency of the IQ file (default: this config's tuner plan)")
    g.add_argument("--iq-loop", action="store_true", help="loop the IQ file")
    g.add_argument("--realtime", action="store_true",
                   help="play the IQ file at its real sample rate (automatic with --tui/--gui and serve)")


def cmd_info(cfg) -> int:
    from meshsdr.flowgraph import plan_center

    print(f"Config: {cfg.source_path}   Region: {cfg.region}")
    print("\nReceivers:")
    for rx in cfg.receivers:
        print(f"  {rx.describe()}")
    try:
        center = plan_center(cfg.receivers, cfg.sdr.sample_rate, cfg.sdr.dc_clearance_hz,
                             cfg.sdr.center_frequency_hz)
        print(f"\nTuner: {center / 1e6:.4f} MHz @ {cfg.sdr.sample_rate / 1e6:g} MS/s, gain {cfg.sdr.gain}, "
              f"ppm {cfg.sdr.ppm}")
        filters = {(r.frequency_hz, r.bw_hz) for r in cfg.receivers}
        print(f"       {len(cfg.receivers)} demodulators on {len(filters)} channel filters")
    except ValueError as e:
        print(f"\nTuner plan error: {e}")
    protocols = {r.protocol for r in cfg.receivers}
    print("\nMeshtastic channels (name → hash):")
    for ch in cfg.channels:
        kind = "unencrypted" if not ch.psk else f"AES-{len(ch.psk) * 8}"
        print(f"  {ch.name:<16} 0x{crypto.channel_hash(ch.name, ch.psk):02x}  {kind}")
    print("\nPKI private keys (for direct messages):")
    if not cfg.private_keys:
        print("  none — PKI direct messages will show as encrypted")
    for pk in cfg.private_keys:
        pub = crypto.derive_public_key(pk.key)
        print(f"  !{pk.node:08x} {pk.label}  public key {base64.b64encode(pub).decode()}")
    print(f"\nStatic public keys: {len(cfg.public_keys)}   Node DB: {cfg.node_db_file or 'disabled'}")
    if "meshcore" in protocols:
        import hashlib
        print("\nMeshCore channels (name → hash):")
        for ch in cfg.meshcore_channels:
            print(f"  {ch.name:<16} 0x{hashlib.sha256(ch.secret).digest()[0]:02x}")
        print(f"MeshCore identities (for DMs): {', '.join(i.name for i in cfg.meshcore_identities) or 'none'}")
    if "lorawan" in protocols:
        print(f"\nLoRaWAN sessions (for MIC check / decryption): "
              f"{', '.join(f'{s.dev_addr:08X} {s.label}'.strip() for s in cfg.lorawan_sessions) or 'none'}")
    return 0


FILTER_ALIASES = {
    "text": "TEXT_MESSAGE_APP", "ctext": "TEXT_MESSAGE_COMPRESSED_APP", "position": "POSITION_APP",
    "nodeinfo": "NODEINFO_APP", "telemetry": "TELEMETRY_APP", "routing": "ROUTING_APP",
    "traceroute": "TRACEROUTE_APP", "neighbor": "NEIGHBORINFO_APP", "neighborinfo": "NEIGHBORINFO_APP",
    "waypoint": "WAYPOINT_APP", "storeforward": "STORE_FORWARD_APP", "rangetest": "RANGE_TEST_APP",
    "admin": "ADMIN_APP", "paxcounter": "PAXCOUNTER_APP", "map": "MAP_REPORT_APP",
    "encrypted": "",  # packets nobody could decrypt have no portnum
    # LoRaWAN
    "join": "JOIN_REQUEST", "joinaccept": "JOIN_ACCEPT", "up": "UNCONFIRMED_UP", "confup": "CONFIRMED_UP",
    "down": "UNCONFIRMED_DOWN", "confdown": "CONFIRMED_DOWN",
    # MeshCore
    "advert": "ADVERT", "group": "GRP_TXT", "dm": "TXT_MSG", "ack": "ACK", "path": "PATH",
}
OTHER_KINDS = {"JOIN_REQUEST", "JOIN_ACCEPT", "UNCONFIRMED_UP", "UNCONFIRMED_DOWN", "CONFIRMED_UP",
               "CONFIRMED_DOWN", "REJOIN_REQUEST", "PROPRIETARY", "REQ", "RESPONSE", "TXT_MSG", "ACK",
               "ADVERT", "GRP_TXT", "GRP_DATA", "ANON_REQ", "PATH", "TRACE", "MULTIPART", "CONTROL", "RAW_CUSTOM"}


def normalize_filter(spec: str | None) -> set[str] | None:
    """Accept short aliases (text, position, encrypted ...) or full PortNum names."""
    if not spec:
        return None
    from meshtastic.protobuf import portnums_pb2

    out = set()
    for item in filter(None, (x.strip() for x in spec.split(","))):
        if item.lower() in FILTER_ALIASES:
            out.add(FILTER_ALIASES[item.lower()])
        elif item.upper() in portnums_pb2.PortNum.keys() or item.upper() in OTHER_KINDS:
            out.add(item.upper())
        else:
            raise SystemExit(f"Unknown filter '{item}'. Use {', '.join(FILTER_ALIASES)} or a PortNum name.")
    return out


def apply_source_args(cfg, args):
    if args.gain is not None:
        cfg.sdr.gain = args.gain
    if args.ppm is not None:
        cfg.sdr.ppm = args.ppm
    if args.iq_rate:
        cfg.sdr.sample_rate = args.iq_rate


SOURCE_OPTS = ("gain", "ppm", "hard_decoding", "iq_file", "iq_rate", "iq_center", "iq_loop", "realtime")


def _radio_stack_missing(exc: ImportError):
    """A clear message when the native SDR stack isn't installed, instead of a raw traceback."""
    missing = getattr(exc, "name", "") or str(exc)
    print(
        f"error: the GNU Radio SDR stack is not available ({missing}).\n"
        "LoRaSpy needs GNU Radio 3.10, gr-osmosdr and gr-lora_sdr — these are native packages,\n"
        "NOT pip/requirements.txt installs. 'pip install gnuradio' does not exist.\n"
        "  • Linux:   install via your distro (e.g. pacman -S gnuradio gnuradio-osmosdr rtl-sdr),\n"
        "             then ./scripts/build_gr_lora_sdr.sh for gr-lora_sdr.\n"
        "  • Windows: use WSL2 — see docs/WINDOWS.md. (Native Windows has no gr-lora_sdr build.)\n"
        "Commands that don't touch the SDR still work: loraspy.py info | decoder | keys.",
        file=sys.stderr)
    return 3


def open_local_core(cfg, args, ust, *, live_view: bool):
    """Open the SDR (or IQ file) with its own decoders."""
    from meshsdr.core import MonitorCore

    apply_source_args(cfg, args)
    try:
        return MonitorCore(cfg, iq_file=args.iq_file, iq_format=args.iq_format, iq_center_hz=args.iq_center,
                           soft_decoding=not args.hard_decoding, fft_size=ust.fft_size, spectrum_window=ust.window,
                           realtime=args.realtime or (live_view and args.iq_file is not None), iq_loop=args.iq_loop)
    except ImportError as e:               # gnuradio / pmt / osmosdr / gr-lora_sdr not installed
        raise SystemExit(_radio_stack_missing(e)) from e


def start_sharing(core, cfg, args, path: str):
    from meshsdr.server import Server

    src = f"IQ file {args.iq_file}" if args.iq_file else f"RTL-SDR {cfg.sdr.device}"
    try:
        return Server(core, path, source=src).start()
    except (RuntimeError, OSError) as e:
        print(f"note: not sharing this SDR ({e})", file=sys.stderr)
        return None


def load_ui_settings(cfg, args):
    from meshsdr import ui_settings

    settings_path = str(cfg.source_path.resolve().parent / "gui_settings.json")
    ust = ui_settings.load(settings_path)
    if getattr(args, "fft_size", None):
        ust.fft_size = args.fft_size
        ust.validate()
    return ust, settings_path


def install_stop(stop: threading.Event):
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())


def cmd_listen(cfg, args) -> int:
    from meshsdr import share

    out = cfg.output
    if args.format:
        out.format = args.format
    if args.colored is not None:
        out.colored = args.colored
    elif not sys.stdout.isatty():
        out.colored = False
    if args.show_crc_errors:
        out.show_crc_errors = True
    if args.hide_undecrypted:
        out.show_undecrypted = False
    if args.jsonl:
        out.jsonl_file = args.jsonl
    port_filter = normalize_filter(args.filter)
    proto_filter = {p.strip().lower() for p in args.protocol.split(",")} if args.protocol else None
    ui = "gui" if args.gui else "tui" if args.tui else None
    ust, settings_path = load_ui_settings(cfg, args)

    # ---- one SDR, many front-ends: attach to a running LoRaSpy, or open the SDR and share it
    sock_path = args.socket or share.default_socket_path()
    server = None
    remote = not args.standalone and share.server_alive(sock_path)
    if args.connect and not remote:
        print(f"no LoRaSpy is serving {sock_path} (start one with: loraspy.py serve)", file=sys.stderr)
        return 1
    if remote:
        from meshsdr.remote import RemoteCore

        fmt_opts = None if ui else {"format": out.format, "colored": out.colored,
                                    "show_crc_errors": out.show_crc_errors,
                                    "show_undecrypted": out.show_undecrypted}
        core = RemoteCore(sock_path, ui or "text", format_opts=fmt_opts, history=300 if ui else 0,
                          reconnect=ui is not None)
        given = [o for o in SOURCE_OPTS if o != "gain" and getattr(args, o) not in (None, False)] + \
            (["fft_size"] if args.fft_size else [])
        print(f"attached to LoRaSpy pid {core.server_pid} ({core.source}) via {sock_path}"
              + (f"; ignoring {', '.join('--' + o.replace('_', '-') for o in given)}" if given else ""),
              file=sys.stderr)
        if proto_filter is not None and ui:
            print("note: --protocol is not applied to a shared SDR from the GUI/TUI; use the decoder list",
                  file=sys.stderr)
        fmt = None
    else:
        core = open_local_core(cfg, args, ust, live_view=ui is not None)
        if proto_filter is not None:
            # receivers of other protocols are not even connected (no CPU)
            core.set_receivers_enabled({rx.name for rx in cfg.receivers if rx.protocol in proto_filter})
        fmt = Formatter(out.format, out.colored, core.node_db, out.show_crc_errors, out.show_undecrypted)
        if args.iq_file and args.iq_center is None:
            print("note: no --iq-center given; assuming the file was recorded with this config's tuner plan "
                  f"({core.center_hz / 1e6:.4f} MHz). A wrong centre shifts every channel and nothing decodes.",
                  file=sys.stderr)

    def wanted(ev) -> bool:
        return not getattr(ev, "history", False) and \
            (proto_filter is None or ev.frame.protocol in proto_filter)

    jsonl = open(out.jsonl_file, "a", encoding="utf-8") if out.jsonl_file else None
    if jsonl:
        def log_json(ev):
            if wanted(ev):
                jsonl.write(core.to_json(ev) + "\n")
                jsonl.flush()
        core.callbacks.append(log_json)
    if args.pcap:
        from meshsdr.pcap import PcapngWriter
        pcap = PcapngWriter(open(args.pcap, "wb"))
        core.callbacks.append(lambda ev: wanted(ev) and pcap.write(*core.record(ev)))
        print(f"writing Wireshark capture (LoRaTap pcapng) to {args.pcap}", file=sys.stderr)
    if args.wireshark_feed:
        from meshsdr.pcap import FeedSender
        host, _, port = args.wireshark_feed.rpartition(":")
        feed = FeedSender(host or "127.0.0.1", int(port))
        core.callbacks.append(lambda ev: wanted(ev) and feed.send_record(*core.record(ev)))
        print(f"sending frames to Wireshark feed udp://{feed.addr[0]}:{feed.addr[1]}", file=sys.stderr)

    if not ui:
        src = f"IQ file {args.iq_file}" if args.iq_file else f"RTL-SDR {cfg.sdr.device}"
        if not remote:
            print(f"Listening via {src}, tuner {core.center_hz / 1e6:.4f} MHz @ "
                  f"{cfg.sdr.sample_rate / 1e6:g} MS/s", file=sys.stderr)
        for rx in core.cfg.receivers:
            print(f"  {rx.describe()}", file=sys.stderr)

        def show(ev):
            if not wanted(ev):
                return
            if remote:
                ok, kind, text = ev.show, ev.kind, ev.text
            else:
                ok, kind, text = fmt.wants(ev.pkt), ev.pkt.kind, None
            if not ok or (port_filter is not None and kind not in port_filter):
                return
            print(text if remote else fmt.format(ev.pkt), flush=True)
        core.callbacks.append(show)

    stop = threading.Event()
    if not ui:
        install_stop(stop)              # the UIs handle SIGINT/SIGTERM themselves (they quit)
    core.start()
    if remote and args.gain is not None:
        try:
            core.set_gain(args.gain)    # the gain is a shared, live setting
            print(f"set the shared SDR's gain to {args.gain}", file=sys.stderr)
        except ValueError as e:
            print(f"note: --gain not applied: {e}", file=sys.stderr)
    if not remote and not args.standalone:
        server = start_sharing(core, cfg, args, sock_path)
        if server:
            print(f"sharing this SDR on {sock_path} — start more front-ends (--gui, --tui, text, "
                  f"Wireshark) and they attach", file=sys.stderr)
    started = time.time()
    try:
        if ui == "tui":
            from meshsdr.tui import run_tui
            run_tui(core)
        elif ui == "gui":
            from meshsdr.gui import run_gui
            run_gui(core, ust, settings_path, screenshot=args.screenshot, screenshot_after=args.duration or 8.0)
        else:
            while not stop.is_set():
                if core.finished.is_set() and (remote or core._frames.empty()):
                    time.sleep(0.5)  # let the worker finish the last frames
                    break
                if args.duration and time.time() - started >= args.duration:
                    break
                time.sleep(0.2)
        if server is not None:
            # this front-end is closed; the SDR is released when the last attached one closes too
            stop = threading.Event()
            install_stop(stop)          # fresh: the first Ctrl-C (or the UI's handlers) was used
            linger(server, core, stop)
    finally:
        core.stop()
        if jsonl:
            jsonl.close()
        if not ui:
            by = ", ".join(f"{k} {v}" for k, v in sorted(core.per_protocol.items()))
            t = core.totals
            print(f"\n{t['frames']} frames ({by or 'none'}), {t['crc_err']} CRC errors, {t['decrypted']} decrypted"
                  + (" (totals of the shared SDR)" if remote else ""), file=sys.stderr)
    return 0


def linger(server, core, stop: threading.Event):
    """This front-end closed but others still use its SDR: keep serving them headless."""
    if server.client_count == 0:
        return
    print(f"still sharing the SDR with {', '.join(server.client_names())} — "
          f"running headless until they detach (Ctrl-C stops now)", file=sys.stderr)
    while not stop.is_set() and server.client_count > 0 and not core.finished.is_set():
        stop.wait(0.5)


def cmd_gain(args) -> int:
    from meshsdr import share
    from meshsdr.remote import RemoteCore

    path = args.socket or share.default_socket_path()
    if not share.server_alive(path):
        print(f"no LoRaSpy is running ({path}); start one with: loraspy.py serve --gain DB",
              file=sys.stderr)
        return 1
    core = RemoteCore(path, "gain-cli")
    core.start()

    def show(prefix):
        g, a = core.gain_info, core.adc
        gain = "n/a (IQ file)" if not g.get("supported") else "AGC" if g["mode"] == "auto" else f"{g['gain']:g} dB"
        adc = "—" if a.get("peak_dbfs") is None else f"peak {a['peak_dbfs']:.1f} dBFS" + (
            f", CLIPPING ({a['clip_ratio'] * 100:.2g} % of samples) — lower the gain" if a.get("clipping") else "")
        print(f"{prefix}gain {gain}   ADC {adc}   ({core.source}, pid {core.server_pid})")
    try:
        time.sleep(0.7)                 # first stats message carries the ADC level
        if args.value is None:
            show("")
            steps = core.gain_info.get("steps") or []
            if steps:
                print("tuner steps (dB): " + " ".join(f"{v:g}" for v in steps))
            return 0
        show("before: ")
        try:
            core.set_gain(args.value)
        except ValueError as e:
            print(f"cannot set the gain: {e}", file=sys.stderr)
            return 1
        time.sleep(3.0)                 # buffered samples + the 1 s peak window: let the new level show
        show("now:    ")
        return 0
    finally:
        core.stop()


def cmd_tune(args) -> int:
    from meshsdr import share
    from meshsdr.remote import RemoteCore

    path = args.socket or share.default_socket_path()
    if not share.server_alive(path):
        print(f"no LoRaSpy is running ({path}); start one with: loraspy.py serve", file=sys.stderr)
        return 1
    core = RemoteCore(path, "tune-cli")
    core.start()
    try:
        def show(prefix):
            n, k = len(core.active), len(core.enabled)
            print(f"{prefix}tuner {core.center_hz / 1e6:.6f} MHz @ {core.sample_rate / 1e6:g} MS/s · "
                  f"{n} of {k} enabled decoders in range")
        if args.freq is None:
            show("")
            out = sorted(core.enabled - core.in_range)
            if out:
                print("idle (outside the window): " + ", ".join(out))
            return 0
        show("before: ")
        core.set_center(parse_hz(args.freq))
        time.sleep(0.7)
        show("now:    ")
        return 0
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        core.stop()


def cmd_channel(args) -> int:
    from meshsdr import share
    from meshsdr.remote import RemoteCore

    path = args.socket or share.default_socket_path()
    if not share.server_alive(path):
        print(f"no LoRaSpy is running ({path}); start one with: loraspy.py serve", file=sys.stderr)
        return 1
    core = RemoteCore(path, "channel-cli")
    core.start()
    try:
        chans = core.channels()
        if args.receiver is None:
            for ch in chans:
                moved = "" if abs(ch["frequency_hz"] - ch["configured_hz"]) < 1 else \
                    f"  (configured {ch['configured_hz'] / 1e6:.4f})"
                names = ", ".join(ch["receivers"])
                print(f"{ch['frequency_hz'] / 1e6:10.4f} MHz  {ch['bw_hz'] / 1e3:5g} kHz  {ch['protocol']:15} "
                      f"{names[:70] + ('…' if len(names) > 70 else '')}{moved}")
            return 0
        ch = next((c for c in chans if args.receiver in c["receivers"]), None)
        if ch is None:
            raise ValueError(f"no decoder named '{args.receiver}' (see: loraspy.py channel)")
        if args.freq is None:
            print(f"{args.receiver}: {ch['frequency_hz'] / 1e6:.4f} MHz, reachable "
                  f"{ch['min_hz'] / 1e6:.4f}–{ch['max_hz'] / 1e6:.4f} MHz, configured {ch['configured_hz'] / 1e6:.4f}")
            return 0
        hz = ch["configured_hz"] if args.freq == "reset" else parse_hz(args.freq)
        names = core.set_channel_frequency(args.receiver, hz)
        print(f"moved {len(names)} decoder(s) to {hz / 1e6:.4f} MHz: {', '.join(names)}")
        return 0
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        core.stop()


def _field_value(text: str):
    """field=value on the command line: JSON when it parses (numbers, true, [9,12]), else a string."""
    import json

    try:
        return json.loads(text)
    except ValueError:
        return text


def cmd_decoder(args) -> int:
    from meshsdr import share
    from meshsdr.decoderstore import OfflineDecoders

    path = args.socket or share.default_socket_path()
    live = share.server_alive(path)
    if live:
        from meshsdr.remote import RemoteCore
        core = RemoteCore(path, "decoder-cli")
        core.start()
    else:
        core = OfflineDecoders(args.config)
    try:
        rest = list(args.rest)
        name = None
        if args.action in ("set", "reset", "remove"):
            if not rest or "=" in rest[0]:
                raise ValueError(f"'{args.action}' needs the decoder name first (see: loraspy.py decoder)")
            name = rest.pop(0)
        fields = {}
        if args.action in ("add", "set"):
            for kv in rest:
                k, sep, v = kv.partition("=")
                if not sep:
                    raise ValueError(f"expected field=value, got '{kv}'")
                fields[k.strip()] = _field_value(v)
        if args.action == "list":
            for d in core.decoder_list():
                mark = "+" if d["origin"] == "added" else "*" if d["overridden"] else " "
                lora = "" if d["protocol"] == "trustedwireless" else \
                    f"{d['bw_hz'] / 1e3:5g} kHz SF{d['sf']:<2} 4/{d['cr']} sync 0x{d['sync_word']:02X}" + \
                    (" IQ-inv" if d["invert_iq"] else "")
                print(f"{mark} {d['name']:<22} {d['protocol']:<15} {d['frequency_hz'] / 1e6:10.4f} MHz  {lora}")
            print("\n+ added (decoders.jsonc)   * parameters changed (decoders.jsonc)"
                  + ("" if live else "   — no LoRaSpy running: changes apply at its next start"))
        elif args.action == "add":
            for k in ("frequency_hz",):
                if isinstance(fields.get(k), str):
                    fields[k] = parse_hz(fields[k])
            names = core.decoder_add(fields)
            print(f"added {', '.join(names)}")
        elif args.action == "set":
            params = {}
            for k, v in fields.items():
                k = {"frequency": "frequency_hz", "freq": "frequency_hz", "bw": "bw_hz", "bandwidth_hz": "bw_hz",
                     "spreading_factor": "sf", "coding_rate": "cr"}.get(k, k)
                params[k] = parse_hz(str(v)) if k == "frequency_hz" else v
            if not params:
                raise ValueError("nothing to set: give field=value pairs")
            print(f"{name}: {core.decoder_update(name, params)}")
        elif args.action == "reset":
            print(f"{name}: {core.decoder_reset(name)}")
        elif args.action == "remove":
            print(f"removed {', '.join(core.decoder_remove(name))}")
        elif args.action == "reset-all":
            print(core.decoder_reset_all())
        elif args.action in ("enable", "disable"):
            on = args.action == "enable"
            allnames = [d["name"] for d in core.decoder_list()]
            if not rest or rest == ["all"]:
                sel = set(allnames)
            else:
                sel = set(rest)
                unknown = sel - set(allnames)
                if unknown:
                    raise ValueError(f"unknown decoder(s): {', '.join(sorted(unknown))}")
            cur = set(core.enabled)
            new = (cur | sel) if on else (cur - sel)
            core.set_receivers_enabled(new, persist=True)
            if live:
                core.decoder_list()   # round-trip: the enable is delivered before we disconnect
            suffix = "" if live else " (applies at the next start)"
            print(f"{'enabled' if on else 'disabled'} {', '.join(sorted(sel))}; "
                  f"{len(new)} of {len(allnames)} decoders on{suffix}")
        return 0
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        if live:
            core.stop()


def cmd_keys(args) -> int:
    from meshsdr import keystore, share

    if args.action == "kinds":
        for k in keystore.KINDS.values():
            print(f"{k.kind:<12} {k.group} · {k.title} — {k.help}")
            for f in k.fields:
                print(f"    {f.name + ('' if f.required else ' (optional)'):<26} {f.hint}")
        return 0
    path = args.socket or share.default_socket_path()
    live = share.server_alive(path)
    if live:
        from meshsdr.remote import RemoteCore
        store = RemoteCore(path, "keys-cli")
        store.start()
    else:
        cfg_path = args.config
        store = keystore.KeyStore(cfg_path)
        store.keys_list, store.keys_add = store.entries, store.add
        store.keys_update, store.keys_remove = store.update, store.remove
    try:
        return _keys_action(args, store, live)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        if live:
            store.stop()


def _keys_action(args, store, live: bool) -> int:
    from meshsdr import keystore

    def parse_fields(items):
        out = {}
        for it in items:
            if "=" not in it:
                raise ValueError(f"expected field=value, got '{it}'")
            k, v = it.split("=", 1)
            out[k.strip()] = v
        return out

    def random_fill(kind, fields):
        for name, style in keystore.KINDS[kind].generate.items():
            if fields.get(name, "").lower() == "random":
                fields[name] = keystore.random_key(style)
                print(f"generated {name}: {fields[name]}")
        return fields

    where = "applied to the running LoRaSpy" if live else \
        "saved to keys.jsonc; applies when LoRaSpy starts"
    act, kind = args.action, args.kind
    if act in ("list", "show") and kind is not None and kind not in keystore.KINDS:
        raise ValueError(f"unknown kind '{kind}'; one of: {', '.join(keystore.KINDS)}")
    if act in ("add", "edit", "remove") and kind not in keystore.KINDS:
        raise ValueError(f"which kind? one of: {', '.join(keystore.KINDS)} (see 'keys kinds')")
    if act == "add":
        store.keys_add(kind, random_fill(kind, parse_fields(args.rest)))
        print(f"added ({where})")
    elif act in ("edit", "remove"):
        if not args.rest or not args.rest[0].isdigit():
            raise ValueError(f"{act}: give the entry number N shown by 'loraspy.py keys'")
        n = int(args.rest[0])
        if act == "remove":
            store.keys_remove(kind, n)
            print(f"removed ({where})")
        else:
            cur = next((e for e in store.keys_list() if e["kind"] == kind and e["source"] == "keys"
                        and e["index"] == n), None)
            if cur is None:
                raise ValueError(f"{kind} #{n}: no such entry in keys.jsonc")
            store.keys_update(kind, n, random_fill(kind, {**cur["fields"], **parse_fields(args.rest[1:])}))
            print(f"updated ({where})")
    if act not in ("list", "show"):
        return 0

    reveal = act == "show" or args.show_secrets
    only = None
    if args.rest:
        if kind is None or not args.rest[0].isdigit():
            raise ValueError(f"{act}: expected KIND [N], e.g. 'keys {act} channel 0'")
        only = int(args.rest[0])
    entries = store.keys_list()
    if kind is not None:
        entries = [e for e in entries if e["kind"] == kind]
    if only is not None:
        entries = [e for e in entries if e["source"] == "keys" and e["index"] == only]
        if not entries:
            raise ValueError(f"{kind} #{only}: no such entry in keys.jsonc")
    print(f"keys: {'live, from the running LoRaSpy' if live else 'from the config files'}   "
          f"(#N = editable in keys.jsonc, 'config' = edit config.jsonc)"
          + ("" if reveal else "   — 'keys show' prints them in full"))
    for k in keystore.KINDS.values():
        mine = [e for e in entries if e["kind"] == k.kind]
        if not mine:
            continue
        print(f"\n{k.group} · {k.title}   [{k.kind}]")
        for e in mine:
            ref = "config" if e["source"] == "config" else f"#{e['index']}"
            vals = []
            for f in k.fields:
                v = e["fields"].get(f.name, "")
                if v:
                    vals.append(f"{f.name}={v if reveal or not f.secret else keystore.mask(v)}")
            print(f"  {ref:<7} {'  '.join(vals)}" + (f"   ({e['info']})" if e["info"] else ""))
    return 0


def parse_hz(text: str | None, mhz_if_small: bool = True) -> float | None:
    """'869.525M', '40k', '869525000', '869.525' (MHz when it's that small) → Hz."""
    if text is None:
        return None
    t = str(text).strip().lower().replace("hz", "")
    mult = {"k": 1e3, "m": 1e6, "g": 1e9}.get(t[-1:], 1.0)
    if t[-1:] in "kmg":
        t = t[:-1]
    try:
        v = float(t) * mult
    except ValueError:
        raise ValueError(f"not a frequency: '{text}'") from None
    if mult == 1.0 and mhz_if_small and v < 1e4:
        v *= 1e6
    return v


def cmd_record(cfg, args) -> int:
    from meshsdr import share

    path = args.socket or share.default_socket_path()
    live = share.server_alive(path)
    try:
        freq, bw = parse_hz(args.freq), parse_hz(args.bw, mhz_if_small=False)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if live:
        from meshsdr.remote import RemoteCore
        core = RemoteCore(path, "record-cli")
        core.start()
    elif args.list:
        print("no LoRaSpy running; recordings are in recordings/ next to the config", file=sys.stderr)
        return 0
    else:
        ust, _ = load_ui_settings(cfg, args)
        core = open_local_core(cfg, args, ust, live_view=True)
        core.set_receivers_enabled(set())          # recording only: no decoders
        core.start()
        time.sleep(1.0)                            # let the SDR settle
    try:
        if args.list:
            for r in core.recordings():
                print(f"{'done ' if r['done'] else 'busy '} {r['file']}  {r['frequency_hz'] / 1e6:.4f} MHz  "
                      f"{r['sample_rate'] / 1e3:g} kS/s  {r['samples']} samples" + (f"  ERROR {r['error']}" if r['error'] else ""))
            return 0
        st = core.record_iq(freq, bw, args.duration, args.format, args.name)
        mbps = st["sample_rate"] * (8 if args.format == "cf32" else 2) / 1e6
        print(f"recording {st['frequency_hz'] / 1e6:.4f} MHz, {st['bandwidth_hz'] / 1e3:g} kHz → "
              f"{st['sample_rate'] / 1e3:g} kS/s {args.format} ({mbps:.2f} MB/s), {args.duration:g} s"
              + ("  (via the running LoRaSpy)" if live else "") + f"\n  {st['file']}", file=sys.stderr)
        stop = threading.Event()
        install_stop(stop)
        r = None
        while not stop.is_set():
            r = next((x for x in core.recordings() if x["id"] == st["id"]), None)
            if r is None or r["done"]:
                break
            stop.wait(1.0)
        if r and r["error"]:
            print(f"recording failed: {r['error']}", file=sys.stderr)
            return 1
        if r:
            print(f"done: {r['samples']} samples ({r['samples'] / r['sample_rate']:.1f} s)\n  {r['file']}\n  {r['meta']}")
        return 0
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        core.stop()


def cmd_serve(cfg, args) -> int:
    from meshsdr import share

    ust, _ = load_ui_settings(cfg, args)
    path = args.socket or share.default_socket_path()
    if share.server_alive(path):
        print(f"a LoRaSpy already serves {path}", file=sys.stderr)
        return 1
    core = open_local_core(cfg, args, ust, live_view=True)
    if args.protocol:
        want = {p.strip().lower() for p in args.protocol.split(",")}
        core.set_receivers_enabled({rx.name for rx in cfg.receivers if rx.protocol in want})
    stop = threading.Event()
    install_stop(stop)
    core.start()
    server = start_sharing(core, cfg, args, path)
    if server is None:
        core.stop()
        return 1
    src = f"IQ file {args.iq_file}" if args.iq_file else f"RTL-SDR {cfg.sdr.device}"
    print(f"serving {src}, tuner {core.center_hz / 1e6:.4f} MHz @ {core.sample_rate / 1e6:g} MS/s, "
          f"{len(core.enabled)}/{len(cfg.receivers)} receivers enabled\n"
          f"socket {path}\n"
          f"attach with: loraspy.py listen [--gui|--tui]   or Wireshark → 'LoRaSpy'",
          file=sys.stderr)
    started = time.time()
    shown = []
    try:
        while not stop.is_set() and not core.finished.is_set():
            if server.clients_changed.wait(0.5):
                server.clients_changed.clear()
                names = server.client_names()
                if names != shown:
                    shown = names
                    print(f"{time.strftime('%H:%M:%S')} clients: {', '.join(names) or 'none'}   "
                          f"frames {core.totals['frames']}", file=sys.stderr)
            if args.duration and time.time() - started >= args.duration:
                break
    finally:
        core.stop()
    t = core.totals
    print(f"{t['frames']} frames, {t['crc_err']} CRC errors, {t['decrypted']} decrypted", file=sys.stderr)
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command is None:
        args = parser.parse_args(sys.argv[1:] + ["listen"])
    logging.basicConfig(level=args.log_level, format="%(levelname)s %(name)s: %(message)s")
    import faulthandler
    if hasattr(faulthandler, "register") and hasattr(signal, "SIGUSR1"):
        faulthandler.register(signal.SIGUSR1, all_threads=True)   # kill -USR1 <pid>: dump every thread's stack (POSIX only)
    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        print(f"Config file '{args.config}' not found — copy config.example.jsonc to config.jsonc", file=sys.stderr)
        return 2
    except ConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2
    if args.command == "info":
        return cmd_info(cfg)
    if args.command == "gain":
        return cmd_gain(args)
    if args.command == "keys":
        return cmd_keys(args)
    if args.command == "decoder":
        return cmd_decoder(args)
    if args.command == "tune":
        return cmd_tune(args)
    if args.command == "channel":
        return cmd_channel(args)
    if args.command == "serve":
        return cmd_serve(cfg, args)
    if args.command == "record":
        return cmd_record(cfg, args)
    return cmd_listen(cfg, args)


if __name__ == "__main__":
    sys.exit(main())
