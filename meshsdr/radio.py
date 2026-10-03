"""
LoRa radio parameters for the supported protocols.

Meshtastic: regions, modem presets and frequency-slot selection.
Mirrors firmware src/mesh/RadioInterface.cpp (regions[], applyModemConfig(), hash())
and src/mesh/MeshRadio.h (modemPresetToParams()). LORA_24 is omitted: it is outside
the RTL-SDR tuning range.
"""

from dataclasses import dataclass
from math import floor

import numpy as np

# Meshtastic uses a fixed LoRa sync word (RadioLibInterface.h: syncWord = 0x2b)
MESHTASTIC_SYNC_WORD = 0x2B
# LoRaWAN public networks (TTN, Helium, ...) use 0x34
LORAWAN_SYNC_WORD = 0x34
# MeshCore: RadioLib's RADIOLIB_SX126X_SYNC_WORD_PRIVATE (src/helpers/radiolib/Custom*.h)
MESHCORE_SYNC_WORD = 0x12


def sync_word_symbols(sync_word: int, sf: int) -> list[int]:
    """
    The two network-id symbol values a real SX126x sends for `sync_word` at this SF.

    Each nibble is a *signed* 4-bit value times 8, taken modulo 2^SF. Measured on a
    live Meshtastic LongFast (SF11) capture: 0x2B gives symbols +16 and -40 (2008).
    gr-lora_sdr's own single-byte conversion uses unsigned nibbles (16, 88); that only
    matches hardware at SF7, where -40 mod 128 == 88.
    """
    n = 2 ** sf

    def nib(v: int) -> int:
        return v - 16 if v >= 8 else v

    return [(nib((sync_word >> 4) & 0xF) * 8) % n, (nib(sync_word & 0xF) * 8) % n]


# Firmware transmits a 16-symbol preamble (RadioInterface.h: preambleLength = 16)
MESHTASTIC_PREAMBLE_LEN = 16


@dataclass(frozen=True)
class Region:
    name: str
    freq_start_mhz: float
    freq_end_mhz: float
    spacing_mhz: float = 0.0


REGIONS: dict[str, Region] = {r.name: r for r in (
    Region("US", 902.0, 928.0),
    Region("EU_433", 433.0, 434.0),
    Region("EU_868", 869.4, 869.65),
    Region("CN", 470.0, 510.0),
    Region("JP", 920.5, 923.5),
    Region("ANZ", 915.0, 928.0),
    Region("ANZ_433", 433.05, 434.79),
    Region("RU", 868.7, 869.2),
    Region("KR", 920.0, 923.0),
    Region("TW", 920.0, 925.0),
    Region("IN", 865.0, 867.0),
    Region("NZ_865", 864.0, 868.0),
    Region("TH", 920.0, 925.0),
    Region("UA_433", 433.0, 434.7),
    Region("UA_868", 868.0, 868.6),
    Region("MY_433", 433.0, 435.0),
    Region("MY_919", 919.0, 924.0),
    Region("SG_923", 917.0, 925.0),
    Region("PH_433", 433.0, 434.7),
    Region("PH_868", 868.0, 869.4),
    Region("PH_915", 915.0, 918.0),
    Region("KZ_433", 433.075, 434.775),
    Region("KZ_863", 863.0, 868.0),
    Region("NP_865", 865.0, 868.0),
    Region("BR_902", 902.0, 907.5),
)}


@dataclass(frozen=True)
class Preset:
    key: str            # config enum name, e.g. LONG_FAST
    display_name: str   # DisplayFormatters::getModemPresetDisplayName(), used for slot hashing
    bw_khz: float
    sf: int
    cr: int             # 5..8 meaning 4/5..4/8


PRESETS: dict[str, Preset] = {p.key: p for p in (
    Preset("SHORT_TURBO", "ShortTurbo", 500.0, 7, 5),
    Preset("SHORT_FAST", "ShortFast", 250.0, 7, 5),
    Preset("SHORT_SLOW", "ShortSlow", 250.0, 8, 5),
    Preset("MEDIUM_FAST", "MediumFast", 250.0, 9, 5),
    Preset("MEDIUM_SLOW", "MediumSlow", 250.0, 10, 5),
    Preset("LONG_TURBO", "LongTurbo", 500.0, 11, 8),
    Preset("LONG_FAST", "LongFast", 250.0, 11, 5),
    Preset("LONG_MODERATE", "LongMod", 125.0, 11, 8),
    Preset("LONG_SLOW", "LongSlow", 125.0, 12, 8),
)}


def djb2(text: str) -> int:
    """Firmware hash() — djb2, truncated to uint32."""
    h = 5381
    for c in text.encode("utf-8"):
        h = ((h << 5) + h + c) & 0xFFFFFFFF
    return h


@dataclass
class ReceiverParams:
    """Everything the demodulator chain needs for one LoRa channel."""
    name: str
    frequency_hz: float
    bw_hz: int
    sf: int
    cr: int                  # 5..8 (only used for display; explicit headers carry the real CR)
    slot: int | None = None  # 1-based Meshtastic frequency slot, None if given explicitly
    protocol: str = "meshtastic"
    sync_word: int = MESHTASTIC_SYNC_WORD
    invert_iq: bool = False  # LoRaWAN downlinks

    @property
    def symbol_time_ms(self) -> float:
        return (2 ** self.sf) / (self.bw_hz / 1000.0)

    @property
    def ldro(self) -> bool:
        """RadioLib and the LoRaWAN spec enable low-data-rate optimisation when a symbol lasts >= 16 ms."""
        return self.symbol_time_ms >= 16.0

    def describe(self) -> str:
        if self.protocol == "trustedwireless":
            return (f"{self.name} [trustedwireless]: {self.frequency_hz / 1e6:.4f} MHz, 30 kHz channel, "
                    f"2-FSK ~10 kBd (encrypted: frames shown, not decrypted)")
        slot = f", slot {self.slot}" if self.slot is not None else ""
        iq = ", inverted IQ" if self.invert_iq else ""
        return (f"{self.name} [{self.protocol}]: {self.frequency_hz / 1e6:.4f} MHz, BW {self.bw_hz / 1e3:g} kHz, "
                f"SF{self.sf}, sync 0x{self.sync_word:02X}{', LDRO' if self.ldro else ''}{iq}{slot}")


def resolve_receiver(region_name: str, spec: dict) -> ReceiverParams:
    """
    Turn one `receivers[]` entry from the config into concrete radio parameters.

    Accepted keys: preset, primary_channel, channel_num (1-based slot), frequency_hz,
    frequency_offset_hz, bandwidth_hz, spreading_factor, coding_rate, name.
    Explicit values override anything derived from the preset.
    """
    preset = None
    if "preset" in spec:
        key = str(spec["preset"]).upper()
        if key not in PRESETS:
            raise ValueError(f"Unknown modem preset '{spec['preset']}'. Valid: {', '.join(PRESETS)}")
        preset = PRESETS[key]

    bw_hz = spec.get("bandwidth_hz", preset.bw_khz * 1000 if preset else None)
    sf = spec.get("spreading_factor", preset.sf if preset else None)
    cr = spec.get("coding_rate", preset.cr if preset else None)
    if bw_hz is None or sf is None or cr is None:
        raise ValueError(f"Receiver {spec!r}: give a 'preset' or all of bandwidth_hz, spreading_factor, coding_rate")
    bw_hz = int(bw_hz)
    bw_khz = bw_hz / 1000.0
    if not 7 <= int(sf) <= 12:
        raise ValueError(f"Receiver {spec!r}: spreading_factor must be 7..12")
    if not 5 <= int(cr) <= 8:
        raise ValueError(f"Receiver {spec!r}: coding_rate must be 5..8 (meaning 4/5..4/8)")

    slot = None
    if "frequency_hz" in spec:
        freq_hz = float(spec["frequency_hz"])
    else:
        if region_name not in REGIONS:
            raise ValueError(f"Unknown region '{region_name}'. Valid: {', '.join(REGIONS)}")
        region = REGIONS[region_name]
        # Firmware does this in float32; emulate it so edge cases (e.g. EU_868) round identically
        f32 = np.float32
        span = f32(region.freq_end_mhz) - f32(region.freq_start_mhz)
        num_channels = int(floor(span / (f32(region.spacing_mhz) + f32(bw_khz) / f32(1000))))
        if num_channels < 1:
            raise ValueError(f"Region {region_name} is too narrow for {bw_khz:g} kHz bandwidth")
        # The slot is picked by hashing the *primary* channel name; an empty/default
        # name means the preset display name (e.g. "LongFast").
        primary = spec.get("primary_channel") or (preset.display_name if preset else "Custom")
        if spec.get("channel_num"):
            channel_num = (int(spec["channel_num"]) - 1) % num_channels
        else:
            channel_num = djb2(primary) % num_channels
        freq_mhz = region.freq_start_mhz + bw_khz / 2000 + channel_num * (bw_khz / 1000)
        freq_hz = round(freq_mhz * 1e6)
        slot = channel_num + 1

    freq_hz += float(spec.get("frequency_offset_hz", 0))
    name = spec.get("name") or (preset.display_name if preset else f"SF{sf}BW{bw_khz:g}")
    return ReceiverParams(name=name, frequency_hz=freq_hz, bw_hz=bw_hz, sf=int(sf), cr=int(cr), slot=slot)


# --------------------------------------------------------------------------- LoRaWAN

# EU863-870 (LoRaWAN Regional Parameters RP002 + The Things Network frequency plan):
# three mandatory join channels, TTN's five extra channels, SF7BW250 on 868.3 MHz,
# RX2 downlink on 869.525 MHz (spec default SF12, TTN uses SF9).
LORAWAN_PLANS = {
    "EU868": {"uplink": [868.1e6, 868.3e6, 868.5e6], "sf7bw250": 868.3e6, "rx2": (869.525e6, [9, 12])},
    "EU868_TTN": {"uplink": [867.1e6, 867.3e6, 867.5e6, 867.7e6, 867.9e6, 868.1e6, 868.3e6, 868.5e6],
                  "sf7bw250": 868.3e6, "rx2": (869.525e6, [9, 12])},
}


def resolve_lorawan(spec: dict) -> list[ReceiverParams]:
    """
    {"protocol": "lorawan", "plan": "EU868"} expands to every uplink channel × SF7..12,
    SF7BW250 and RX2 downlinks; "rx1": true adds RX1 downlinks (inverted IQ on the
    uplink channels, which doubles the uplink demodulators but not the filters). Or explicit: frequency_hz, bandwidth_hz (125000),
    spreading_factors ([7..12]), downlink (false).
    """
    out = []
    sfs = [int(x) for x in spec.get("spreading_factors", range(7, 13))]
    if "plan" in spec:
        plan_name = str(spec["plan"]).upper()
        if plan_name not in LORAWAN_PLANS:
            raise ValueError(f"Unknown LoRaWAN plan '{spec['plan']}'. Valid: {', '.join(LORAWAN_PLANS)}")
        plan = LORAWAN_PLANS[plan_name]
        for f in plan["uplink"]:
            out += [ReceiverParams(f"LW {f / 1e6:.1f} SF{sf}", f, 125_000, sf, 5, protocol="lorawan",
                                   sync_word=LORAWAN_SYNC_WORD) for sf in sfs]
        if spec.get("sf7bw250", True) and plan.get("sf7bw250"):
            f = plan["sf7bw250"]
            out.append(ReceiverParams(f"LW {f / 1e6:.1f} SF7/250", f, 250_000, 7, 5, protocol="lorawan",
                                      sync_word=LORAWAN_SYNC_WORD))
        if spec.get("rx1", False):
            # RX1 downlinks: same channel as the uplink, inverted IQ (EU868 RX1DROffset 0 → same SF)
            for f in plan["uplink"]:
                out += [ReceiverParams(f"LW {f / 1e6:.1f} RX1 SF{sf}", f, 125_000, sf, 5, protocol="lorawan",
                                       sync_word=LORAWAN_SYNC_WORD, invert_iq=True) for sf in sfs]
        if spec.get("rx2", True):
            f, rx2_sfs = plan["rx2"]
            out += [ReceiverParams(f"LW RX2 SF{sf}", f, 125_000, sf, 5, protocol="lorawan",
                                   sync_word=LORAWAN_SYNC_WORD, invert_iq=True) for sf in rx2_sfs]
        return out
    if "frequency_hz" not in spec:
        raise ValueError(f"LoRaWAN receiver {spec!r}: give 'plan' or 'frequency_hz'")
    f = float(spec["frequency_hz"])
    bw = int(spec.get("bandwidth_hz", 125_000))
    down = bool(spec.get("downlink", False))
    tag = "down" if down else "up"
    return [ReceiverParams(spec.get("name", f"LW {f / 1e6:.3f} {tag}") + f" SF{sf}", f, bw, sf, 5,
                           protocol="lorawan", sync_word=LORAWAN_SYNC_WORD, invert_iq=down) for sf in sfs]


# --------------------------------------------------------------------------- MeshCore

# MeshCore firmware defaults (platformio.ini: LORA_FREQ=869.618, LORA_BW=62.5, LORA_SF=8),
# which is the EU/UK narrow setting. Coding rate is carried in the LoRa header.
MESHCORE_PRESETS = {
    "EU_UK_NARROW": (869.618e6, 62_500, 8, 5),
}


def resolve_meshcore(spec: dict) -> list[ReceiverParams]:
    if "preset" in spec:
        key = str(spec["preset"]).upper()
        if key not in MESHCORE_PRESETS:
            raise ValueError(f"Unknown MeshCore preset '{spec['preset']}'. Valid: {', '.join(MESHCORE_PRESETS)}")
        f, bw, sf, cr = MESHCORE_PRESETS[key]
    else:
        try:
            f, bw, sf = float(spec["frequency_hz"]), int(spec["bandwidth_hz"]), int(spec["spreading_factor"])
        except KeyError as e:
            raise ValueError(f"MeshCore receiver {spec!r}: give 'preset' or frequency_hz/bandwidth_hz/"
                             f"spreading_factor") from e
        cr = int(spec.get("coding_rate", 5))
    f += float(spec.get("frequency_offset_hz", 0))
    return [ReceiverParams(spec.get("name", f"MeshCore SF{sf}/{bw / 1e3:g}k"), f, bw, sf, cr,
                           protocol="meshcore", sync_word=MESHCORE_SYNC_WORD)]


def resolve_receivers(region_name: str, spec: dict) -> list[ReceiverParams]:
    """One config `receivers[]` entry → one or more demodulator chains."""
    proto = str(spec.get("protocol", "meshtastic")).lower()
    if proto == "meshtastic":
        return [resolve_receiver(region_name, spec)]
    if proto == "lorawan":
        return resolve_lorawan(spec)
    if proto == "meshcore":
        return resolve_meshcore(spec)
    if proto in ("trustedwireless", "trusted-wireless", "tw"):
        return resolve_trustedwireless(spec)
    raise ValueError(f"Unknown protocol '{proto}' (meshtastic, lorawan, meshcore, trustedwireless)")


# 2-FSK hopping telemetry networks in the 869.40–869.65 MHz sub-band (e.g. Phoenix Contact
# Trusted Wireless): the 7 channels seen in use, 30 kHz apart
TW_CHANNELS_HZ = [869.435e6 + 30e3 * i for i in range(7)]


def resolve_trustedwireless(spec: dict) -> list[ReceiverParams]:
    """{"protocol": "trustedwireless", "channels": [869.435, …] (MHz, optional)} → one
    listener per hop channel. The payload is encrypted: frames are shown, not decrypted."""
    chans = [float(f) * (1e6 if float(f) < 1e4 else 1) for f in spec.get("channels", [])] or TW_CHANNELS_HZ
    return [ReceiverParams(name=f"TW {f / 1e6:.3f}", frequency_hz=f, bw_hz=30_000, sf=0, cr=0,
                           protocol="trustedwireless", sync_word=0) for f in chans]
