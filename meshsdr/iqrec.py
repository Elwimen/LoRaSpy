"""
IQ recordings from the running flowgraph, while it keeps decoding (shared with every front-end).

IqTap is connected to the source for the whole run and idles until a recording is armed (no
rewiring at runtime; see flowgraph.SpectrumTap). A recording either keeps the full tuned band
or a narrow slice around one frequency: shifted to 0 Hz, low-pass filtered and decimated, so a
30 kHz signal doesn't cost 2 MS/s of disk. Output is cf32 (GNU Radio, inspectrum, URH) or cu8
(rtl_sdr / rtl_433 format), plus a JSON sidecar with frequency, sample rate, time and gain.
"""

import json
import logging
import threading
import time
from pathlib import Path

import numpy as np
from gnuradio import gr
from scipy import signal

log = logging.getLogger(__name__)

MAX_DURATION_S = 600


class IqRecording:
    """One recording job; fed by IqTap.work() on the GNU Radio thread."""

    def __init__(self, rid: int, path: Path, source_center_hz: float, source_rate: float,
                 freq_hz: float | None, bw_hz: float | None, duration_s: float, fmt: str, meta: dict):
        if fmt not in ("cf32", "cu8"):
            raise ValueError("format must be cf32 or cu8")
        if not 0 < duration_s <= MAX_DURATION_S:
            raise ValueError(f"duration must be 0 < s <= {MAX_DURATION_S}")
        half = source_rate / 2
        self.freq = source_center_hz if freq_hz is None else float(freq_hz)
        if bw_hz is None:                                   # the whole tuned band, as received
            self.decim, self.offset = 1, 0.0
            self.freq = source_center_hz
            bw_hz = source_rate
        else:
            bw_hz = float(bw_hz)
            self.offset = self.freq - source_center_hz
            if abs(self.offset) + bw_hz / 2 > half * 0.98:
                raise ValueError(f"{self.freq / 1e6:.4f} MHz ± {bw_hz / 2e3:g} kHz is outside the tuned range "
                                 f"{(source_center_hz - half) / 1e6:.3f}–{(source_center_hz + half) / 1e6:.3f} MHz")
            # keep at least 1.25 × the bandwidth so the filter edge stays clear of the signal
            self.decim = max(1, int(source_rate // (bw_hz * 1.25)))
        self.rid, self.path, self.fmt = rid, path, fmt
        self.rate_in = source_rate
        self.rate = source_rate / self.decim
        self.bw = bw_hz
        self.need = int(duration_s * source_rate)           # input samples still to take
        self.duration_s = duration_s
        self.done = threading.Event()
        self.error: str | None = None
        self.written = 0
        self.started = time.time()
        self._n = 0                                         # global index of the next input sample
        if self.decim > 1:
            # Band-pass taps (low-pass shifted to the offset): filtering and decimating compute only
            # the kept outputs (polyphase), and the shift back to 0 Hz runs at the output rate.
            ntaps = 16 * self.decim + 1
            lp = signal.firwin(ntaps, cutoff=bw_hz / 2 * 1.1, fs=source_rate)
            self._cyc = self.offset / source_rate               # offset in cycles per input sample
            bp = lp * np.exp(2j * np.pi * self._cyc * np.arange(ntaps))
            self._hrev = bp[::-1].astype(np.complex64)
            self._tail = np.zeros(ntaps - 1, np.complex64)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._f = open(path, "wb")
        self.meta = {"format": fmt, "sample_rate": self.rate, "center_frequency_hz": self.freq,
                     "bandwidth_hz": bw_hz, "decimation": self.decim, "duration_s": duration_s,
                     "start_time": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self.started)),
                     "data_file": path.name, **meta}

    def feed(self, x: np.ndarray):
        if self.done.is_set():
            return
        x = x[:self.need]
        n = len(x)
        try:
            if self.decim > 1:
                out = self._decimate(x)
            else:
                out = x
            out = np.asarray(out, np.complex64)
            if self.fmt == "cu8":
                iq = np.empty(2 * len(out), np.float32)
                iq[0::2], iq[1::2] = out.real, out.imag
                self._f.write(np.clip(iq * 127.5 + 127.5, 0, 255).astype(np.uint8).tobytes())
            else:
                self._f.write(out.tobytes())
            self.written += len(out)
        except Exception as e:              # disk full, …: stop this recording, never the flowgraph
            self.error = str(e)
            self.need = 0
        self._n += n
        self.need -= n
        if self.need <= 0:
            self.finish()

    def _decimate(self, x: np.ndarray) -> np.ndarray:
        """Outputs at global input indices g ≡ 0 (mod decim): band-pass FIR, then × e^(−j2π·off·g)."""
        ntaps = len(self._hrev)
        buf = np.concatenate((self._tail, x))
        g0 = self._n - (ntaps - 1)                          # global index of buf[0]
        first = (ntaps - 1) + (-(g0 + ntaps - 1)) % self.decim
        js = np.arange(first, len(buf), self.decim)
        self._tail = buf[len(buf) - (ntaps - 1):]
        if not len(js):
            return np.zeros(0, np.complex64)
        windows = np.lib.stride_tricks.sliding_window_view(buf, ntaps)[js - (ntaps - 1)]
        y = windows @ self._hrev
        g = g0 + js
        return (y * np.exp(-2j * np.pi * np.mod(self._cyc * g, 1.0))).astype(np.complex64)

    def finish(self):
        if self.done.is_set():
            return
        try:
            self._f.close()
            self.meta.update(samples=self.written, error=self.error)
            self.path.with_suffix(".json").write_text(json.dumps(self.meta, indent=2) + "\n")
        except OSError as e:
            self.error = self.error or str(e)
        self.done.set()
        log.info("IQ recording %s finished: %d samples%s", self.path.name, self.written,
                 f" ({self.error})" if self.error else "")

    def status(self) -> dict:
        return {"id": self.rid, "file": str(self.path), "meta": str(self.path.with_suffix(".json")),
                "done": self.done.is_set(), "error": self.error, "samples": self.written,
                "sample_rate": self.rate, "frequency_hz": self.freq, "bandwidth_hz": self.bw,
                "format": self.fmt, "duration_s": self.duration_s,
                "progress": min(1.0, (time.time() - self.started) / self.duration_s)}


class IqTap(gr.sync_block):
    """Permanently connected to the source; feeds whatever recordings are armed (normally none)."""

    def __init__(self):
        gr.sync_block.__init__(self, name="iq_tap", in_sig=[np.complex64], out_sig=None)
        self._jobs: list[IqRecording] = []
        self._lock = threading.Lock()

    def add(self, job: IqRecording):
        with self._lock:
            self._jobs = self._jobs + [job]

    def stop_all(self, reason: str | None = None):
        with self._lock:
            jobs, self._jobs = self._jobs, []
        for j in jobs:
            if reason and not j.done.is_set():
                j.error = reason
            j.finish()

    def work(self, input_items, output_items):
        x = input_items[0]
        jobs = self._jobs
        if jobs:
            for j in jobs:
                j.feed(x)
            if any(j.done.is_set() for j in jobs):
                with self._lock:
                    self._jobs = [j for j in self._jobs if not j.done.is_set()]
        return len(x)
