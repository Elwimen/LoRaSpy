#!/usr/bin/env python3
"""
Generate a synthetic IQ recording for testing the decoders without hardware.
For every protocol present in the config's receivers it builds packets
(Meshtastic: NodeInfo, text, position, telemetry, PKI DM, unknown channel;
LoRaWAN: join request, uplinks, RX2 downlink; MeshCore: advert, Public and
#test channel messages, DM), modulates them with gr-lora_sdr's TX chain using
each protocol's sync word / IQ sense / preamble, and places them one after
another at the right offset from the tuner plan, with noise and crystal error.

    tools/simulate_iq.py -c config.jsonc -o sim.cu8 --write-sim-config sim.jsonc
    ./loraspy.py -c sim.jsonc listen --iq-file sim.cu8
"""

import argparse
import base64
import hashlib
import json
import os
import random
import struct
import sys
import time
from pathlib import Path

import numpy as np
from scipy.signal import resample_poly

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import pmt  # noqa: E402
except ImportError:
    from gnuradio import pmt  # noqa: E402
from gnuradio import blocks, gr  # noqa: E402
from meshtastic.protobuf import mesh_pb2, portnums_pb2, telemetry_pb2  # noqa: E402

from meshsdr import crypto  # noqa: E402
from meshsdr.config import load_config, load_jsonc  # noqa: E402
from meshsdr.flowgraph import OS_FACTOR, plan_center  # noqa: E402
from meshsdr.grlora import import_lora_sdr  # noqa: E402
from meshsdr.packet import BROADCAST, RadioHeader, build_frame  # noqa: E402
from meshsdr.radio import MESHTASTIC_PREAMBLE_LEN, sync_word_symbols  # noqa: E402


def modulate(payload: bytes, rx, has_crc: bool = True, preamble_len: int = MESHTASTIC_PREAMBLE_LEN) -> np.ndarray:
    """Run gr-lora_sdr's TX chain over one payload; returns complex64 at 4×BW (IQ inverted if rx.invert_iq)."""
    lora = import_lora_sdr()
    tb = gr.top_block()
    tag = gr.tag_utils.python_to_tag((0, pmt.intern("packet_len"), pmt.from_long(len(payload))))
    src = blocks.vector_source_b(list(payload), False, 1, [tag])
    white = lora.whitening(False, True, ",", "packet_len")
    header = lora.header(False, has_crc, rx.cr - 4)
    add_crc = lora.add_crc(has_crc)
    ham = lora.hamming_enc(rx.cr - 4, rx.sf)
    inter = lora.interleaver(rx.cr - 4, rx.sf, 1 if rx.ldro else 0, rx.bw_hz)
    gray = lora.gray_demap(rx.sf)
    mod = lora.modulate(rx.sf, rx.bw_hz * OS_FACTOR, rx.bw_hz, sync_word_symbols(rx.sync_word, rx.sf),
                        int(rx.bw_hz * OS_FACTOR * 0.05), preamble_len)
    sink = blocks.vector_sink_c()
    tb.connect(src, white, header, add_crc, ham, inter, gray, mod, sink)
    tb.run()
    sig = np.array(sink.data(), dtype=np.complex64)
    return np.conj(sig) if rx.invert_iq else sig


def make_packets(cfg, sender_priv: bytes, recipient_priv: bytes, sender: int, recipient: int) -> list[bytes]:
    ch = cfg.channels[0]
    ch_hash = crypto.channel_hash(ch.name, ch.psk)
    flags = 3 | (3 << 5)  # hop_limit 3, hop_start 3
    out = []

    def psk_frame(portnum, payload: bytes, to=BROADCAST, pid=None, psk=ch.psk, h=ch_hash):
        pid = pid or random.getrandbits(32)
        data = mesh_pb2.Data(portnum=portnum, payload=payload, bitfield=1).SerializeToString()
        enc = crypto.aes_ctr(psk, pid, sender, data) if psk else data
        return build_frame(RadioHeader(to, sender, pid, flags, h, 0, sender & 0xFF), enc)

    user = mesh_pb2.User(id=f"!{sender:08x}", long_name="SDR Test Node", short_name="SDRT",
                         hw_model=mesh_pb2.HardwareModel.TBEAM,
                         public_key=crypto.derive_public_key(sender_priv))
    out.append(psk_frame(portnums_pb2.NODEINFO_APP, user.SerializeToString()))
    out.append(psk_frame(portnums_pb2.TEXT_MESSAGE_APP, "Hello from the air! čćžšđ 📡".encode()))
    pos = mesh_pb2.Position(latitude_i=int(12.345 * 1e7), longitude_i=int(67.89 * 1e7), altitude=120,
                            precision_bits=32, time=1790000000)
    out.append(psk_frame(portnums_pb2.POSITION_APP, pos.SerializeToString()))
    tel = telemetry_pb2.Telemetry(time=1790000000, device_metrics=telemetry_pb2.DeviceMetrics(
        battery_level=87, voltage=4.02, channel_utilization=12.5, air_util_tx=1.2, uptime_seconds=3600))
    out.append(psk_frame(portnums_pb2.TELEMETRY_APP, tel.SerializeToString()))

    # PKI direct message sender -> recipient
    pid = random.getrandbits(32)
    data = mesh_pb2.Data(portnum=portnums_pb2.TEXT_MESSAGE_APP, payload=b"secret PKI DM", bitfield=1)
    shared = crypto.pki_shared_key(sender_priv, crypto.derive_public_key(recipient_priv))
    enc = crypto.pki_encrypt(shared, pid, sender, data.SerializeToString(), random.getrandbits(32))
    out.append(build_frame(RadioHeader(recipient, sender, pid, flags | 0x08, 0, 0, sender & 0xFF), enc))

    # Channel nobody configured: must show as undecryptable
    other_key = os.urandom(16)
    out.append(psk_frame(portnums_pb2.TEXT_MESSAGE_APP, b"you cannot read this", psk=other_key,
                         h=crypto.channel_hash("Hidden", other_key)))
    return out


def make_lorawan(receivers) -> tuple[list, dict]:
    """Join request, uplinks with a known session, and an RX2 downlink (inverted IQ, no CRC)."""
    from meshsdr.lorawan import compute_mic, crypt_frm

    def pick(name):
        return next((r for r in receivers if r.name == name), None)

    dev_addr = 0x260B1234  # TTN-range DevAddr
    nwk, app = os.urandom(16), os.urandom(16)
    session = {"dev_addr": f"{dev_addr:08X}", "nwk_s_key": nwk.hex(), "app_s_key": app.hex(), "label": "sim sensor"}

    def data_frame(mtype, fcnt, fport, payload, uplink=True, fctrl=0x80):
        enc = crypt_frm(app, payload, dev_addr, fcnt, uplink)
        msg = bytes([mtype << 5]) + struct.pack("<IBH", dev_addr, fctrl, fcnt) + bytes([fport]) + enc
        return msg + compute_mic(nwk, msg, dev_addr, fcnt, uplink)

    bursts = []
    join = bytes([0x00]) + bytes.fromhex("0102030405060708")[::-1] + bytes.fromhex("70B3D57ED0001234")[::-1] \
        + struct.pack("<H", 0x1A2B) + os.urandom(4)
    for name, pkt, crc in [
        ("LW 868.1 SF12", join, True),
        ("LW 868.3 SF7", data_frame(2, 17, 1, b"temp=21.5"), True),
        ("LW 868.5 SF10", data_frame(4, 18, 2, b"\x01\x02\x03"), True),
        ("LW RX2 SF9", data_frame(5, 3, 1, b"cmd:on", uplink=False, fctrl=0x20), False),
    ]:
        rx = pick(name)
        if rx:
            bursts.append((pkt, rx, crc, 8))
    return bursts, session


def make_meshcore(receivers) -> tuple[list, dict]:
    """Signed advert, Public + #test channel messages, and a DM from A to B."""
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from meshsdr import meshcore as mc

    rx = next((r for r in receivers if r.protocol == "meshcore"), None)
    if rx is None:
        return [], {}

    def identity():
        seed = os.urandom(32)
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        pub = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        h = bytearray(hashlib.sha512(seed).digest())  # orlp ed25519 64-byte private key
        h[0] &= 248
        h[31] &= 63
        h[31] |= 64
        return sk, pub, bytes(h)

    a_sk, a_pub, a_prv = identity()
    b_sk, b_pub, b_prv = identity()
    ts = int(time.time())

    def packet(ptype, payload, route=1, path=b""):
        return bytes([(ptype << 2) | route, len(path)]) + path + payload

    app = bytes([0x01 | 0x10 | 0x80]) + struct.pack("<ii", 12345000, 67890000) + "SimNode Ž".encode()
    sig = a_sk.sign(a_pub + struct.pack("<I", ts) + app)
    advert = packet(4, a_pub + struct.pack("<I", ts) + sig + app)

    def group(secret, text):
        plain = struct.pack("<IB", ts, 0) + text.encode()
        return packet(5, hashlib.sha256(secret).digest()[:1] + mc.encrypt_then_mac(secret, plain), path=b"\x42")

    public = bytes.fromhex("8b3387e9c5cdea6ac9e5edbaa115cd72")
    hashtag = hashlib.sha256(b"#test").digest()[:16]
    dm_plain = struct.pack("<IB", ts, 0) + "secret MeshCore DM".encode()
    dm = packet(2, b_pub[:1] + a_pub[:1] + mc.encrypt_then_mac(mc.shared_secret(a_prv, b_pub), dm_plain), route=2)
    bursts = [(advert, rx, True, 32), (group(public, "SimNode: hello Public"), rx, True, 32),
              (group(hashtag, "SimNode: hello #test"), rx, True, 32), (dm, rx, True, 32)]
    extra = {"identities": [{"name": "sim B", "private_key": b_prv.hex()}],
             "channels": [{"name": "Public", "secret": public.hex()}, {"name": "#test"}]}
    return bursts, extra


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-c", "--config", default="config.example.jsonc")
    ap.add_argument("-o", "--output", default="sim.cu8")
    ap.add_argument("--format", choices=["cu8", "cf32"], default="cu8")
    ap.add_argument("--snr", type=float, default=5.0, help="In-band SNR in dB (default 5)")
    ap.add_argument("--ppm", type=float, default=3.0,
                    help="Transmitter crystal error in ppm; shifts the carrier and the chip rate together, "
                         "like a real radio (default 3)")
    ap.add_argument("--write-sim-config", help="Write a config with the simulated keys added here")
    args = ap.parse_args()

    cfg = load_config(args.config)
    fs = int(cfg.sdr.sample_rate)
    center = plan_center(cfg.receivers, fs, cfg.sdr.dc_clearance_hz, cfg.sdr.center_frequency_hz)

    bursts = []  # (payload, rx, has_crc, preamble_len)
    raw = load_jsonc(args.config)
    mt = next((r for r in cfg.receivers if r.protocol == "meshtastic"), None)
    if mt:
        sender, recipient = 0x5D12A7C3, 0x1337B4B3
        sender_priv, recipient_priv = os.urandom(32), os.urandom(32)
        bursts += [(f, mt, True, MESHTASTIC_PREAMBLE_LEN)
                   for f in make_packets(cfg, sender_priv, recipient_priv, sender, recipient)]
        raw.setdefault("pki", {}).setdefault("private_keys", []).append(
            {"node": f"!{recipient:08x}", "private_key": base64.b64encode(recipient_priv).decode(),
             "label": "simulated recipient"})
    lw_bursts, session = make_lorawan(cfg.receivers)
    bursts += lw_bursts
    if lw_bursts:
        raw.setdefault("lorawan", {}).setdefault("sessions", []).append(session)
    mc_bursts, mc_extra = make_meshcore(cfg.receivers)
    bursts += mc_bursts
    if mc_bursts:
        m = raw.setdefault("meshcore", {})
        m.setdefault("identities", []).extend(mc_extra["identities"])
        m["channels"] = mc_extra["channels"]
    if not bursts:
        raise SystemExit("config has no receivers the simulator knows how to feed")

    ppm = args.ppm * 1e-6
    rng = np.random.default_rng()
    pieces = [np.zeros(fs // 5, dtype=np.complex64)]
    for payload, rx, has_crc, pre in bursts:
        bb = modulate(payload, rx, has_crc, pre)
        fs_bb = rx.bw_hz * OS_FACTOR
        up = resample_poly(bb, fs, fs_bb).astype(np.complex64) if fs != fs_bb else bb
        # Crystal error: the transmitter's chip clock runs (1 + ppm) fast along with its carrier.
        # Linear interpolation is adequate at >= 8x oversampling.
        n_out = int(len(up) / (1 + ppm))
        t = np.arange(n_out) * (1 + ppm)
        up = (np.interp(t, np.arange(len(up)), up.real)
              + 1j * np.interp(t, np.arange(len(up)), up.imag)).astype(np.complex64)
        shift = rx.frequency_hz - center + rx.frequency_hz * ppm
        up *= np.exp(2j * np.pi * shift * np.arange(len(up)) / fs).astype(np.complex64)
        # Scale each burst so its in-band SNR is args.snr regardless of bandwidth
        # power ∝ bandwidth, so every protocol's in-band SNR equals args.snr
        pieces += [up * np.sqrt(rx.bw_hz / 125_000 / np.mean(np.abs(up) ** 2)),
                   np.zeros(int(fs * 0.3), dtype=np.complex64)]
        print(f"  {rx.name:<22} {len(payload):3d} bytes{'' if has_crc else ' (no CRC)'}")
    sig = np.concatenate(pieces)
    # Noise density chosen so a 125 kHz channel at unit power sees args.snr; power scaled per BW above
    noise_power = (1 / (10 ** (args.snr / 10))) * fs / 125_000
    noise = (rng.standard_normal(len(sig)) + 1j * rng.standard_normal(len(sig))) * np.sqrt(noise_power / 2)
    sig = (sig + noise).astype(np.complex64)

    if args.format == "cf32":
        sig.tofile(args.output)
    else:
        scale = 0.7 / np.max(np.abs(np.concatenate([sig.real, sig.imag])))
        iq = np.empty(2 * len(sig), dtype=np.float32)
        iq[0::2], iq[1::2] = sig.real * scale, sig.imag * scale
        np.clip(np.round(iq * 127.5 + 127.5), 0, 255).astype(np.uint8).tofile(args.output)

    print(f"{len(bursts)} frames, {len(sig) / fs:.2f} s @ {fs / 1e6:g} MS/s, centre {center / 1e6:.4f} MHz, "
          f"SNR {args.snr} dB, {args.ppm:+g} ppm -> {args.output}")
    if args.write_sim_config:
        if raw.get("node_db_file"):
            raw["node_db_file"] = None
        Path(args.write_sim_config).write_text(json.dumps(raw, indent=2))
        print(f"wrote {args.write_sim_config} (simulated keys added)")


if __name__ == "__main__":
    main()
