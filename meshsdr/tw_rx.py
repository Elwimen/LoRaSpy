"""
Receiver for the narrowband 2-FSK frequency-hopping networks in the 869.40–869.65 MHz
sub-band (characteristics match Phoenix Contact "Trusted Wireless 2.0" radios: 30 kHz channel
grid, ~10 kBd 2-FSK with ±4 kHz deviation, long 0101 preamble, encrypted payload).

One TwChannelSink per hop channel, fed at ~50 kS/s by the flowgraph's channel filter: it finds
bursts by power, demodulates them non-coherently (energy at +dev vs −dev per symbol, symbol
clock fitted per burst), locks onto the sync word and hands the bits after it to the decoder.
The payload can't be decrypted; what is shown is timing, level, size and the raw header.
"""

import logging
import time
from typing import Callable

import numpy as np
from gnuradio import gr

from .decoder import RxFrame
from .radio import ReceiverParams

log = logging.getLogger(__name__)

BAUD = 10_000.0
DEVIATION = 4.1e3
# end of the 0101… preamble and the sync word, as seen in every frame recorded so far
SYNC = "01011011001110011"
SYNC_MAX_ERRORS = 1
THRESHOLD_DB = 8.0          # burst = power this far above the channel noise
MIN_BURST_S, MAX_BURST_S = 0.005, 0.045   # frames seen: 10–32 ms; LoRa through the filter: longer
PREAMBLE_CHECK = 24        # alternating bits required right before the sync word (frames have ~50)
PREAMBLE_MAX_ERRORS = 2


def demodulate(seg: np.ndarray, fs: float) -> tuple[str, float]:
    """Bits of one burst and the carrier offset found in its preamble.

    Frequency discriminator → carrier offset from the (balanced) 0101 preamble → symbol clock
    fitted to all zero crossings (rate and phase) → integrate-and-dump over each symbol."""
    f = np.angle(seg[1:] * np.conj(seg[:-1])) * fs / (2 * np.pi)
    pwr = np.convolve(np.abs(seg[1:]) ** 2, np.ones(10) / 10, "same")
    loud = np.flatnonzero(pwr > pwr.max() * 0.2)
    if len(loud) < 10:
        return "", 0.0
    a, b = loud[0] + int(0.0003 * fs), loud[-1] - int(0.0003 * fs)
    if b - a < 10:                       # a click (e.g. while retuning), not a burst
        return "", 0.0
    f = f[a:b]
    pre = f[int(0.0005 * fs):int(0.0045 * fs)]
    cfo = float(np.median(pre)) if len(pre) else float(np.median(f))
    f = f - cfo
    fl = np.convolve(f, np.ones(3) / 3, "same")
    zc = np.flatnonzero(np.sign(fl[1:]) != np.sign(fl[:-1]))
    if len(zc) < 8:
        return "", cfo
    c = zc + fl[zc] / (fl[zc] - fl[zc + 1])                    # fractional crossing positions
    sps = fs / BAUD
    Ts = np.linspace(sps * 0.97, sps * 1.03, 241)
    ph = np.exp(2j * np.pi * c[None, :] / Ts[:, None])        # crossings fall on symbol edges
    R = np.abs(ph.mean(axis=1))
    k = int(np.argmax(R))
    T = Ts[k]
    t0 = (np.angle(ph[k].mean()) / (2 * np.pi)) * T
    cs = np.concatenate(([0.0], np.cumsum(f)))
    edges = np.arange(t0 % T, len(f), T)
    xs = np.arange(len(cs))
    integ = np.diff(np.interp(edges, xs, cs))
    return "".join("1" if v > 0 else "0" for v in integ), cfo


PREAMBLE_GAP = 8           # bits just before the sync vary between frame types (e.g. …1111 1101)


def has_preamble(bits: str, sync_end: int) -> bool:
    """PREAMBLE_CHECK bits ending PREAMBLE_GAP bits before the sync word must be a 0101…
    preamble (the last few bits before the sync differ between frame variants). Counts
    neighbouring equal bits: 0 for a clean preamble, +1 for a phase step, ≤ +2 per bit error;
    random bits give ~11 of 23. Rejects chance sync matches in other signals (LoRa chirps)."""
    s0 = sync_end - len(SYNC) - PREAMBLE_GAP
    seg = bits[max(0, s0 - PREAMBLE_CHECK):s0]
    if len(seg) < PREAMBLE_CHECK:
        return False
    return sum(a == b for a, b in zip(seg, seg[1:])) <= 1 + PREAMBLE_MAX_ERRORS


def find_sync(bits: str, search: int = 160) -> int | None:
    """Index just after the sync word, or None."""
    n = len(SYNC)
    best = None
    for i in range(0, min(len(bits) - n, search) + 1):
        d = sum(a != b for a, b in zip(bits[i:i + n], SYNC))
        if d <= SYNC_MAX_ERRORS and (best is None or d < best[1]):
            best = (i + n, d)
            if d == 0:
                break
    return best[0] if best else None


class TwChannelSink(gr.sync_block):
    def __init__(self, rx: ReceiverParams, fs: float, on_frame: Callable[[RxFrame], None],
                 rssi_offset: Callable[[], float | None] = lambda: None, adc=None):
        gr.sync_block.__init__(self, name=f"tw_{rx.name}", in_sig=[np.complex64], out_sig=None)
        self.rx, self.fs, self.on_frame = rx, fs, on_frame
        self.rssi_offset, self.adc = rssi_offset, adc
        self.noise = None                   # channel noise power (EWMA of quiet periods)
        self._pre = np.zeros(0, np.complex64)   # a little history to start bursts early
        self._burst: list[np.ndarray] | None = None
        self._burst_len = 0
        self._quiet = 0
        self._t0 = None                     # wall time of sample 0: timestamps follow the samples
        self.frames = self.bursts = self.unsynced = 0

    def work(self, input_items, output_items):
        x = np.asarray(input_items[0])
        n = len(x)
        if not n:
            return 0
        if self._t0 is None:
            self._t0 = time.time() - self.nitems_read(0) / self.fs
        self._base = self.nitems_read(0)
        p = np.convolve(np.abs(x) ** 2, np.ones(25, np.float32) / 25, "same")      # 0.5 ms power
        if self.noise is None:
            self.noise = float(np.median(p)) + 1e-12
        thr = self.noise * 10 ** (THRESHOLD_DB / 10)
        on = p > thr
        if self._burst is None and not on.any():
            self.noise = 0.97 * self.noise + 0.03 * float(np.median(p))
            self._pre = x[-200:].copy()
            return n
        i = 0
        while i < n:
            if self._burst is None:
                idx = np.flatnonzero(on[i:])
                if not len(idx):
                    q = p[i:]
                    if len(q):
                        self.noise = 0.97 * self.noise + 0.03 * float(np.median(q))
                    break
                s = i + idx[0]
                head = np.concatenate((self._pre, x[max(0, s - 100):s]))[-100:]
                self._burst, self._burst_len, self._quiet = [head], len(head), 0
                self._burst_start = self._base + s - len(head)
                i = s
            # inside a burst: take samples until the power has been low for 2 ms
            q = int(0.002 * self.fs)
            on_pos = np.flatnonzero(on[i:])
            prev = -1 - self._quiet                       # last loud sample, relative to i
            nxt = np.r_[on_pos, n - i]
            gaps = nxt - np.r_[prev, on_pos] - 1          # quiet samples before each loud one (and the end)
            big = np.flatnonzero(gaps > q)
            if len(big):
                last_on = prev if big[0] == 0 else on_pos[big[0] - 1]
                seg_end, done = max(i, i + last_on + q + 1), True
                self._quiet = 0
            else:
                seg_end, done = n, False
                self._quiet = int(gaps[-1])
            chunk = x[i:seg_end]
            self._burst.append(chunk)
            self._burst_len += len(chunk)
            if self._burst_len > MAX_BURST_S * self.fs:        # a carrier, not a frame: drop it
                self._burst, done = None, False
                i = seg_end
                continue
            i = seg_end
            if done:
                samples = np.concatenate(self._burst)
                self._burst = None
                try:
                    self._decode(samples)
                except Exception:
                    log.exception("%s: demodulation failed", self.rx.name)
        self._pre = x[-200:].copy()
        return n

    def _decode(self, samples: np.ndarray):
        dur = len(samples) / self.fs
        if not MIN_BURST_S <= dur <= MAX_BURST_S:
            return
        self.bursts += 1
        bits, cfo = demodulate(samples, self.fs)
        start = find_sync(bits)
        if start is None or not has_preamble(bits, start):
            self.unsynced += 1
            return                              # not one of these frames (or too corrupted)
        payload = bits[start:]
        nbytes = len(payload) // 8
        data = bytes(int(payload[i * 8:i * 8 + 8], 2) for i in range(nbytes))
        mid = samples[int(0.15 * len(samples)):int(0.85 * len(samples))]
        power = float(np.mean(np.abs(mid) ** 2)) + 1e-20
        now = time.time()
        t_start = self._t0 + self._burst_start / self.fs
        f = RxFrame(data=data, crc_ok=True, receiver=self.rx.name, frequency_hz=self.rx.frequency_hz, sf=0,
                    bw_hz=self.rx.bw_hz, protocol=self.rx.protocol, has_crc=False, bits=payload,
                    timestamp=t_start)
        f.rssi_dbfs = 10 * np.log10(power)
        f.noise_dbfs = 10 * np.log10(self.noise)
        sig = power - self.noise
        f.snr_db = 10 * np.log10(sig / self.noise) if sig > 0 else -30.0
        f.freq_offset_hz = cfo
        f.duration_ms = dur * 1e3
        off = self.rssi_offset()
        if off is not None:
            f.rssi_dbm, f.noise_dbm = f.rssi_dbfs + off, f.noise_dbfs + off
        if self.adc is not None:
            f.clipped = bool(self.adc.clipped_since(now - dur - 0.5) or f.rssi_dbfs > -3)
        self.frames += 1
        self.on_frame(f)
