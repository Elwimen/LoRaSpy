"""
Frequency overlays for the spectrum views: one band per configured channel (LoRaWAN is
split into its individual channels), plus the regulatory sub-bands of the region as a
background layer.
"""

from dataclasses import dataclass, field

from .radio import ReceiverParams

PROTOCOL_COLORS = {  # (r, g, b); also used by the TUI
    "meshtastic": (103, 234, 148),   # green
    "lorawan": (94, 166, 255),       # blue
    "meshcore": (255, 170, 64),      # orange
    "trustedwireless": (190, 130, 255),  # purple
    "regulatory": (120, 120, 140),   # grey
}

# ERC Recommendation 70-03 Annex 1 SRD sub-bands used by LoRa in Europe (EU863-870).
# (start MHz, end MHz, label)
EU868_SUBBANDS = [
    (863.0, 865.0, "h1.3 0.1%"),
    (865.0, 868.0, "h1.4 1%"),
    (868.0, 868.6, "h1.4 1%"),
    (868.7, 869.2, "h1.5 0.1%"),
    (869.4, 869.65, "h1.6 10%"),
    (869.7, 870.0, "h1.7 1%"),
]


@dataclass
class Band:
    protocol: str
    start_hz: float
    end_hz: float
    label: str
    detail: str = ""
    receivers: list[str] = field(default_factory=list)  # receiver names that decode in this band

    @property
    def center_hz(self) -> float:
        return (self.start_hz + self.end_hz) / 2

    @property
    def color(self) -> tuple[int, int, int]:
        return PROTOCOL_COLORS.get(self.protocol, (200, 200, 200))


def receiver_bands(receivers: list[ReceiverParams]) -> list[Band]:
    """Group receivers by (protocol, frequency, bandwidth) into overlay bands; LoRaWAN per channel."""
    groups: dict[tuple, Band] = {}
    dirs: dict[tuple, set] = {}
    for rx in receivers:
        key = (rx.protocol, rx.frequency_hz, rx.bw_hz)
        if key not in groups:
            groups[key] = Band(rx.protocol, rx.frequency_hz - rx.bw_hz / 2, rx.frequency_hz + rx.bw_hz / 2, "")
            dirs[key] = set()
        groups[key].receivers.append(rx.name)
        dirs[key].add("down" if rx.invert_iq else "up")
    for (proto, f, bw), b in groups.items():
        fm, kbw = f / 1e6, f"{bw / 1e3:g}k"
        if proto == "lorawan":
            arrows = {frozenset({"up"}): "↑", frozenset({"down"}): "↓", frozenset({"up", "down"}): "↑↓"}[frozenset(dirs[(proto, f, bw)])]
            b.label = f"LW {fm:.3f}".rstrip("0").rstrip(".") + f" {arrows}" + ("" if bw == 125_000 else f" {kbw}")
            sfs = sorted({int(n.split("SF")[-1].split("/")[0]) for n in b.receivers if "SF" in n})
            b.detail = (f"SF{sfs[0]}-{sfs[-1]}" if len(sfs) > 1 else f"SF{sfs[0]}") if sfs else ""
            if "RX2" in " ".join(b.receivers):
                b.label += " RX2"
        elif proto == "meshcore":
            b.label, b.detail = f"MeshCore {kbw}", ", ".join(b.receivers)
        elif proto == "trustedwireless":
            b.label, b.detail = "TW", f"{fm:.3f} MHz, 2-FSK hop channel (encrypted)"
        else:
            b.label, b.detail = f"Meshtastic {kbw}", ", ".join(b.receivers)
    return sorted(groups.values(), key=lambda b: (b.start_hz, b.protocol))


def regulatory_bands(region: str) -> list[Band]:
    if region.upper() not in ("EU_868", "EU868"):
        return []
    return [Band("regulatory", a * 1e6, b * 1e6, lbl) for a, b, lbl in EU868_SUBBANDS]


def band_for(bands: list[Band], frame) -> Band | None:
    """The band a decoded frame was received in (same protocol, frequency and bandwidth)."""
    for b in bands:
        if b.protocol == frame.protocol and b.start_hz <= frame.frequency_hz <= b.end_hz and \
                abs((b.end_hz - b.start_hz) - frame.bw_hz) < 1:
            return b
    return None
