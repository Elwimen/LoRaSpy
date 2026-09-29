"""
JSONC configuration loading: comments (// and /* */) and trailing commas are allowed.
"""

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .radio import ReceiverParams, resolve_receivers

# Firmware Channels.h defaultpsk (the well-known "AQ==" key)
DEFAULT_PSK = bytes([0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                     0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01])


class ConfigError(Exception):
    pass


def strip_jsonc(text: str) -> str:
    """Remove comments and trailing commas without touching string contents."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise ConfigError("Unterminated /* comment")
            i = j + 2
        else:
            out.append(c)
            i += 1
    # Trailing commas: `,` followed only by whitespace before } or ]
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_jsonc(path: str | Path) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(strip_jsonc(text))
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: {e}") from e


def expand_psk(psk_b64: str) -> bytes:
    """
    Decode a channel PSK the way firmware Channels::getKey() does.

    Returns b"" for "no encryption". 1-byte values are PSK indexes: 0 = none,
    1 = default key, N = default key with the last byte increased by N-1.
    Short keys are zero-padded to 16 bytes, 17..31 bytes to 32.
    """
    try:
        raw = base64.b64decode(psk_b64, validate=True)
    except Exception as e:
        raise ConfigError(f"PSK '{psk_b64}' is not valid base64: {e}") from e
    if len(raw) == 0:
        return b""
    if len(raw) == 1:
        idx = raw[0]
        if idx == 0:
            return b""
        key = bytearray(DEFAULT_PSK)
        key[-1] = (key[-1] + idx - 1) & 0xFF
        return bytes(key)
    if len(raw) < 16:
        return raw.ljust(16, b"\x00")
    if 16 < len(raw) < 32:
        return raw.ljust(32, b"\x00")
    return raw[:32]


def parse_node_id(value) -> int:
    """Accept '!da548c90', 'da548c90', '0xda548c90' or an int."""
    if isinstance(value, int):
        return value & 0xFFFFFFFF
    s = str(value).strip().lstrip("!@")
    if s.lower().startswith("0x"):
        s = s[2:]
    try:
        return int(s, 16) & 0xFFFFFFFF
    except ValueError as e:
        raise ConfigError(f"Invalid node id '{value}'") from e


# MeshCore's default "Public" channel (examples/companion_radio/MyMesh.cpp: PUBLIC_GROUP_PSK)
MESHCORE_PUBLIC_SECRET = "izOH6cXN6mrJ5e26oRXNcg=="


def decode_bytes(value: str, what: str) -> bytes:
    """Hex (with or without spaces) or base64."""
    v = str(value).strip().replace(" ", "")
    try:
        return bytes.fromhex(v)
    except ValueError:
        pass
    try:
        return base64.b64decode(v, validate=True)
    except Exception as e:
        raise ConfigError(f"{what}: not hex or base64") from e


def decode_key32(value: str, what: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        try:
            raw = bytes.fromhex(value)
        except ValueError as e:
            raise ConfigError(f"{what}: not base64 or hex") from e
    if len(raw) != 32:
        raise ConfigError(f"{what}: expected 32 bytes, got {len(raw)}")
    return raw


@dataclass
class ChannelKey:
    name: str
    psk: bytes  # expanded; b"" = unencrypted


@dataclass
class PrivateKey:
    node: int
    key: bytes
    label: str = ""


@dataclass
class SdrConfig:
    device: str = "rtl=0"
    sample_rate: float = 2_000_000
    gain: float | str = 40.0      # dB or "auto"
    ppm: float = 0.0
    center_frequency_hz: float | None = None  # None = pick automatically (see flowgraph.plan_center)
    dc_clearance_hz: float = 25_000  # keep the RTL-SDR DC spike at least this far outside every channel
    rssi_offset_db: float | None = None  # dBm = dBFS + offset at the configured gain (calibrate!)
    bias_tee: bool = False


@dataclass
class OutputConfig:
    format: str = "text"           # text | hex | hextext
    colored: bool = True
    show_crc_errors: bool = False
    show_undecrypted: bool = True
    jsonl_file: str | None = None


@dataclass
class MeshCoreChannel:
    name: str
    secret: bytes  # 16 or 32 bytes


@dataclass
class MeshCoreIdentity:
    name: str
    private_key: bytes  # 64-byte MeshCore (orlp ed25519) private key
    public_key: bytes


@dataclass
class LoRaWANSession:
    dev_addr: int
    nwk_s_key: bytes | None
    app_s_key: bytes | None
    label: str = ""
    codec: str | None = None


@dataclass
class LoRaWANOTAADevice:
    dev_eui: str        # 16 hex digits, big-endian as shown in consoles
    app_key: bytes
    join_eui: str | None = None
    label: str = ""
    codec: str | None = None


@dataclass
class Config:
    region: str
    sdr: SdrConfig
    receivers: list[ReceiverParams]
    channels: list[ChannelKey]
    private_keys: list[PrivateKey]
    public_keys: dict[int, bytes]
    node_db_file: str | None
    output: OutputConfig
    meshcore_channels: list[MeshCoreChannel] = field(default_factory=list)
    meshcore_identities: list[MeshCoreIdentity] = field(default_factory=list)
    meshcore_public_keys: dict[str, bytes] = field(default_factory=dict)
    lorawan_sessions: list[LoRaWANSession] = field(default_factory=list)
    lorawan_otaa: list[LoRaWANOTAADevice] = field(default_factory=list)
    source_path: Path | None = None
    keys_path: Path | None = None
    extra: dict = field(default_factory=dict)


KEYS_FILE = "keys.jsonc"


def keys_path_for(config_path: str | Path) -> Path:
    return Path(config_path).resolve().parent / KEYS_FILE


def merge_keys(raw: dict, keys: dict) -> dict:
    """config.jsonc + keys.jsonc: lists are appended, maps merged (keys.jsonc wins)."""
    import copy

    out = copy.deepcopy(raw)
    out["channels"] = list(raw.get("channels", [])) + list(keys.get("channels", []))
    for sec, lists, maps in (("pki", ("private_keys",), ("public_keys",)),
                             ("meshcore", ("channels", "identities"), ("public_keys",)),
                             ("lorawan", ("sessions", "otaa_devices"), ())):
        src, add = raw.get(sec, {}), keys.get(sec, {})
        if not add:
            continue
        dst = out.setdefault(sec, {})
        for name in lists:
            if add.get(name):
                base = src.get(name)
                if base is None and (sec, name) == ("meshcore", "channels"):
                    base = [{"name": "Public", "secret": MESHCORE_PUBLIC_SECRET}]   # the implicit default
                dst[name] = list(base or []) + list(add[name])
        for name in maps:
            if add.get(name):
                dst[name] = {**src.get(name, {}), **add[name]}
    return out


def parse_keys(raw: dict) -> dict:
    """The key/channel sections of a (merged) config; raises ConfigError on bad entries."""
    channels = []
    for i, ch in enumerate(raw.get("channels", [])):
        if "name" not in ch or "psk" not in ch:
            raise ConfigError(f"channels[{i}] needs 'name' and 'psk'")
        channels.append(ChannelKey(name=ch["name"], psk=expand_psk(ch["psk"])))
    if not channels:
        channels.append(ChannelKey(name="LongFast", psk=DEFAULT_PSK))

    pki = raw.get("pki", {})
    private_keys = []
    for i, entry in enumerate(pki.get("private_keys", [])):
        if "node" not in entry or "private_key" not in entry:
            raise ConfigError(f"pki.private_keys[{i}] needs 'node' and 'private_key'")
        private_keys.append(PrivateKey(
            node=parse_node_id(entry["node"]),
            key=decode_key32(entry["private_key"], f"pki.private_keys[{i}]"),
            label=entry.get("label", ""),
        ))
    public_keys = {
        parse_node_id(node): decode_key32(key, f"pki.public_keys[{node}]")
        for node, key in pki.get("public_keys", {}).items()
    }

    mc = raw.get("meshcore", {})
    mc_channels = []
    for i, ch in enumerate(mc.get("channels", [{"name": "Public", "secret": MESHCORE_PUBLIC_SECRET}])):
        name = ch.get("name", "")
        if "secret" in ch:
            secret = decode_bytes(ch["secret"], f"meshcore.channels[{i}].secret")
        elif name.startswith("#"):
            secret = hashlib.sha256(name.encode("utf-8")).digest()[:16]  # hashtag channel
        else:
            raise ConfigError(f"meshcore.channels[{i}] needs a 'secret' (or a '#hashtag' name)")
        if len(secret) not in (16, 32):
            raise ConfigError(f"meshcore.channels[{i}]: secret must be 16 or 32 bytes")
        mc_channels.append(MeshCoreChannel(name=name, secret=secret))
    mc_ids = []
    for i, ident in enumerate(mc.get("identities", [])):
        prv = decode_bytes(ident.get("private_key", ""), f"meshcore.identities[{i}].private_key")
        if len(prv) != 64:
            raise ConfigError(f"meshcore.identities[{i}]: private_key must be the 64-byte MeshCore export")
        pub = decode_bytes(ident["public_key"], f"meshcore.identities[{i}].public_key") \
            if "public_key" in ident else None
        mc_ids.append(MeshCoreIdentity(name=ident.get("name", f"identity {i}"), private_key=prv, public_key=pub))
    mc_pubs = {name: decode_bytes(v, f"meshcore.public_keys[{name}]") for name, v in mc.get("public_keys", {}).items()}

    sessions = []
    for i, sess in enumerate(raw.get("lorawan", {}).get("sessions", [])):
        try:
            dev_addr = int(str(sess["dev_addr"]), 16)
        except (KeyError, ValueError) as e:
            raise ConfigError(f"lorawan.sessions[{i}]: dev_addr must be 8 hex digits") from e
        keys = {}
        for k in ("nwk_s_key", "app_s_key"):
            keys[k] = decode_bytes(sess[k], f"lorawan.sessions[{i}].{k}") if sess.get(k) else None
            if keys[k] is not None and len(keys[k]) != 16:
                raise ConfigError(f"lorawan.sessions[{i}].{k} must be 16 bytes")
        sessions.append(LoRaWANSession(dev_addr=dev_addr, label=sess.get("label", ""), codec=sess.get("codec"), **keys))

    otaa = []
    for i, dev in enumerate(raw.get("lorawan", {}).get("otaa_devices", [])):
        try:
            eui = f"{int(str(dev['dev_eui']).replace(' ', '').replace(':', ''), 16):016X}"
        except (KeyError, ValueError) as e:
            raise ConfigError(f"lorawan.otaa_devices[{i}]: dev_eui must be 16 hex digits") from e
        key = decode_bytes(dev.get("app_key", ""), f"lorawan.otaa_devices[{i}].app_key")
        if len(key) != 16:
            raise ConfigError(f"lorawan.otaa_devices[{i}].app_key must be 16 bytes")
        otaa.append(LoRaWANOTAADevice(dev_eui=eui, app_key=key, join_eui=dev.get("join_eui"),
                                      label=dev.get("label", ""), codec=dev.get("codec")))

    return {"channels": channels, "private_keys": private_keys, "public_keys": public_keys,
            "meshcore_channels": mc_channels, "meshcore_identities": mc_ids, "meshcore_public_keys": mc_pubs,
            "lorawan_sessions": sessions, "lorawan_otaa": otaa}


def load_config(path: str | Path) -> Config:
    """config.jsonc, plus keys.jsonc next to it (keys and channels added from the key editors)."""
    raw = load_jsonc(path)
    base = Path(path).resolve().parent
    kpath = keys_path_for(path)
    if kpath.exists():
        try:
            raw = merge_keys(raw, load_jsonc(kpath))
        except ConfigError as e:
            raise ConfigError(f"{kpath.name}: {e}") from e

    region = str(raw.get("region", "EU_868")).upper()

    sdr_raw = raw.get("sdr", {})
    sdr = SdrConfig(**{k: v for k, v in sdr_raw.items() if k in SdrConfig.__dataclass_fields__})

    receiver_specs = raw.get("receivers") or [{"preset": "LONG_FAST"}]
    try:
        receivers = [rx for spec in receiver_specs for rx in resolve_receivers(region, spec)]
    except ValueError as e:
        raise ConfigError(str(e)) from e
    names = [r.name for r in receivers]
    for dup in {n for n in names if names.count(n) > 1}:
        raise ConfigError(f"Two receivers are both named '{dup}'; give one an explicit \"name\"")

    keys = parse_keys(raw)

    node_db_file = raw.get("node_db_file", "nodes.json")
    if node_db_file:
        node_db_file = str((base / node_db_file).resolve())

    out_raw = raw.get("output", {})
    output = OutputConfig(**{k: v for k, v in out_raw.items() if k in OutputConfig.__dataclass_fields__})
    if output.format not in ("text", "hex", "hextext"):
        raise ConfigError("output.format must be one of: text, hex, hextext")
    if output.jsonl_file:
        output.jsonl_file = str((base / output.jsonl_file).resolve())

    return Config(region=region, sdr=sdr, receivers=receivers, channels=keys["channels"],
                  private_keys=keys["private_keys"], public_keys=keys["public_keys"],
                  node_db_file=node_db_file, output=output,
                  meshcore_channels=keys["meshcore_channels"], meshcore_identities=keys["meshcore_identities"],
                  meshcore_public_keys=keys["meshcore_public_keys"],
                  lorawan_sessions=keys["lorawan_sessions"], lorawan_otaa=keys["lorawan_otaa"],
                  source_path=Path(path), keys_path=kpath)
