"""
Display settings for the spectrum/waterfall views, persisted as JSON (gui_settings.json next
to the config). Edited from the GUI's Settings dialog; every field applies live.

Spectrum model (as in SDRangel / SDR#): every sample goes through the FFT; each displayed
spectrum frame / waterfall line shows the detector (peak or mean) over all FFTs since the
previous one. No averaging across frames. Levels are dBFS (0 dBFS = full-scale sine).
"""

import json
import logging
from dataclasses import asdict, dataclass, fields
from pathlib import Path

log = logging.getLogger(__name__)

DETECTORS = ["Peak", "Mean"]
WINDOWS = ["Blackman-Harris", "Hann", "Hamming", "Blackman", "Nuttall", "Flat-top", "Rectangular"]
FFT_SIZES = [256, 512, 1024, 2048, 4096, 8192]
COLORMAPS = ["btop", "viridis", "inferno", "plasma", "magma", "turbo", "grey"]


@dataclass
class UISettings:
    fft_size: int = 1024
    window: str = "Blackman-Harris"
    detector: str = "Peak"             # per display frame over all FFTs in it: Peak (max) or Mean
    spectrum_fps: float = 25.0         # spectrum trace refresh rate
    lines_per_second: float = 10.0     # waterfall rows per second
    history_s: float = 30.0            # waterfall length
    auto_levels: bool = True           # track the noise floor slowly; range = level_range_db above it
    level_range_db: float = 30.0       # dynamic range shown in auto mode (RTL-SDR: ~40 dB usable)
    level_min_db: float = -100.0       # manual range (used when auto_levels is off)
    level_max_db: float = -50.0
    spectrum_top_db: float = -10.0     # spectrum plot vertical scale (dBFS)
    spectrum_bottom_db: float = -110.0
    colormap: str = "btop"
    peak_hold: bool = False
    peak_decay_db_s: float = 3.0

    def validate(self) -> "UISettings":
        if self.fft_size not in FFT_SIZES:
            self.fft_size = 1024
        if self.window not in WINDOWS:
            self.window = "Blackman-Harris"
        if self.colormap not in COLORMAPS:
            self.colormap = "btop"
        self.lines_per_second = min(max(float(self.lines_per_second), 1.0), 50.0)
        self.history_s = min(max(float(self.history_s), 5.0), 600.0)
        if self.detector not in DETECTORS:
            self.detector = "Peak"
        self.spectrum_fps = min(max(float(self.spectrum_fps), 1.0), 60.0)
        self.level_range_db = min(max(float(self.level_range_db), 10.0), 120.0)
        if self.spectrum_top_db <= self.spectrum_bottom_db + 5:
            self.spectrum_top_db = self.spectrum_bottom_db + 5
        if self.level_max_db <= self.level_min_db:
            self.level_max_db = self.level_min_db + 10
        return self


def gr_window(name: str):
    from gnuradio.fft import window

    return {"Blackman-Harris": window.blackman_harris, "Hann": window.hann, "Hamming": window.hamming,
            "Blackman": window.blackman, "Nuttall": window.nuttall, "Flat-top": window.flattop,
            "Rectangular": window.rectangular}[name]


def load(path: str | Path) -> UISettings:
    p = Path(path)
    if p.exists():
        try:
            raw = json.loads(p.read_text())
            known = {f.name for f in fields(UISettings)}
            return UISettings(**{k: v for k, v in raw.items() if k in known}).validate()
        except (OSError, ValueError, TypeError) as e:
            log.warning("ignoring %s: %s", p, e)
    return UISettings()


def save(path: str | Path, s: UISettings):
    Path(path).write_text(json.dumps(asdict(s), indent=2) + "\n")
