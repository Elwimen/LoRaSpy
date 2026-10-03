"""
GNU Radio flowgraph: one RTL-SDR (or IQ file) source feeding one gr-lora_sdr
demodulator chain per configured receiver (any protocol).

    source ─┬─ freq_xlating_fir (shift + low-pass + decimate to 4×BW) ─ frame_sync ─ fft_demod ─
            │   gray_mapping ─ deinterleaver ─ hamming_dec ─ header_decoder ─ dewhitening ─
            │   crc_verif ─ FrameSink ──► on_frame(RxFrame)
            │                     frame_sync[1] ─ SnrProbe (per-frame SNR estimate)
            └─ (next receiver ...)

Receivers on the same frequency and bandwidth (e.g. Meshtastic LongFast and
MediumSlow on EU_868, or LoRaWAN SF7..SF12 on one channel) share one channel
filter and get one demodulator each. Inverted-IQ receivers (LoRaWAN downlinks)
get a conjugate block after the shared filter.
"""

import logging
import threading
from collections import deque
import time
from fractions import Fraction
from typing import Callable

import numpy as np
import scipy.fft as sp_fft
import pmt
from gnuradio import blocks, filter, gr
from gnuradio.filter import firdes

from .config import SdrConfig
from .decoder import RxFrame
from .grlora import import_lora_sdr
from .radio import ReceiverParams, sync_word_symbols

log = logging.getLogger(__name__)

OS_FACTOR = 4  # samples per chip handed to gr-lora_sdr
# Meshtastic transmits 16 preamble symbols, but telling frame_sync to expect 8 makes it lock
# after fewer clean up-chirps; in simulation at -5..-12 dB SNR this decoded 36/36 frames vs 33/36.
RX_PREAMBLE_LEN = 8


class SnrProbe(gr.sync_block):
    """frame_sync's optional log port emits 5 floats per detected frame: snr, cfo, sto, sfo, off_by_one."""

    def __init__(self):
        gr.sync_block.__init__(self, name="snr_probe", in_sig=[np.float32], out_sig=None)
        self._pos = 0
        self.last_snr: float | None = None

    def work(self, input_items, output_items):
        for v in input_items[0]:
            if self._pos == 0:
                self.last_snr = float(v)
            self._pos = (self._pos + 1) % 5
        return len(input_items[0])


class SpectrumTap(gr.sync_block):
    """
    The spectrum, permanently connected to the source. Every sample goes through the FFT
    (windowed, DC-centred |X|²), like SDRangel and SDR#, but only while `active` — otherwise
    work() just returns. FFT size and window are plain attributes, so turning the spectrum on
    or off or changing it never rewires the flowgraph: changing GNU Radio blocks next to the
    source at runtime intermittently stopped the whole flowgraph.
    """

    CLIP_LEVEL = 0.97   # |I| or |Q| of a full-scale sample (8-bit ADC: raw 0..3 or 252..255)

    def __init__(self, fft_size: int, window: str, on_spectrum: Callable[[np.ndarray], None] | None):
        gr.sync_block.__init__(self, name="spectrum_tap", in_sig=[np.complex64], out_sig=None)
        self.on_spectrum = on_spectrum
        self.active = False
        # ADC level, always measured (cheap): (time, peak |I|/|Q|, clipped components, samples) per call
        self._adc: deque = deque(maxlen=4000)
        self._adc_lock = threading.Lock()
        self._lock = threading.Lock()
        self._rest = np.zeros(0, np.complex64)
        self.configure(fft_size, window)

    def configure(self, fft_size: int, window: str):
        from .ui_settings import gr_window

        taps = np.asarray(gr_window(window)(fft_size), dtype=np.float32)
        with self._lock:
            self.fft_size, self.window, self._taps = fft_size, window, taps
            self.window_gain = float(np.sum(taps)) ** 2   # |X|² of a full-scale tone → 0 dBFS
            self._rest = np.zeros(0, np.complex64)

    def adc_stats(self, window_s: float = 1.0) -> dict:
        """Peak level (dBFS) and clipped share of the samples over the last window_s."""
        t0 = time.time() - window_s
        with self._adc_lock:
            recent = [r for r in self._adc if r[0] >= t0]
        if not recent:
            return {"peak_dbfs": None, "clipped": 0, "clip_ratio": 0.0, "clipping": False}
        peak = max(r[1] for r in recent)
        clipped, total = sum(r[2] for r in recent), sum(r[3] for r in recent)
        return {"peak_dbfs": 20 * np.log10(peak) if peak > 0 else -120.0, "clipped": clipped,
                "clip_ratio": clipped / (2 * total) if total else 0.0, "clipping": clipped > 0}

    def clipped_since(self, t0: float) -> bool:
        with self._adc_lock:
            return any(r[2] for r in self._adc if r[0] >= t0)

    def work(self, input_items, output_items):
        x = input_items[0]
        if len(x):
            comp = np.abs(x.view(np.float32))
            rec = (time.time(), float(comp.max()), int(np.count_nonzero(comp > self.CLIP_LEVEL)), len(x))
            with self._adc_lock:
                self._adc.append(rec)
        if self.active and self.on_spectrum is not None:
            with self._lock:
                n, taps = self.fft_size, self._taps
                buf = np.concatenate((self._rest, x)) if len(self._rest) else x
                k = len(buf) // n
                self._rest = buf[k * n:].copy()
            if k:
                spec = sp_fft.fft(buf[:k * n].reshape(k, n) * taps, axis=1)
                power = np.fft.fftshift(spec.real ** 2 + spec.imag ** 2, axes=1)
                try:
                    self.on_spectrum(power)
                except Exception:
                    log.exception("spectrum handler failed")
        elif len(self._rest):
            self._rest = np.zeros(0, np.complex64)
        return len(x)


class PowerProbe(gr.sync_block):
    """
    Channel power history: receives 1 ms mean |x|² values (from complex_to_mag_squared →
    integrate_ff in C++) and keeps the last `keep_s` seconds for per-frame RSSI/SNR.
    """

    def __init__(self, name: str, block_rate: float, keep_s: float = 20.0):
        gr.sync_block.__init__(self, name=f"power_{name}", in_sig=[np.float32], out_sig=None)
        self.rate = block_rate
        self.buf = np.full(int(keep_s * block_rate), np.nan, dtype=np.float64)
        self.n = 0                       # blocks received so far
        self._lock = threading.Lock()

    def work(self, input_items, output_items):
        x = input_items[0]
        with self._lock:
            k = len(x)
            idx = (self.n + np.arange(k)) % len(self.buf)
            self.buf[idx] = x
            self.n += k
        return len(x)

    def measure(self, airtime_s: float, search_s: float = 1.5):
        """
        (burst power, noise power) in linear full-scale units: the airtime-long window with the
        highest mean power among the last `airtime + search_s` seconds, and the channel's quiet
        level (10th percentile of the history before that window).
        """
        with self._lock:
            n = min(self.n, len(self.buf))
            if n < 10:
                return None, None
            hist = np.roll(self.buf, -(self.n % len(self.buf)))[-n:]
        w = max(1, int(round(airtime_s * self.rate)))
        span = min(n, w + int(search_s * self.rate))
        recent = hist[-span:]
        # quiet level from the history *before* this frame's search window (10th percentile),
        # so the burst itself and neighbouring traffic don't lift the noise estimate
        older = hist[:-span]
        noise = float(np.nanpercentile(older if len(older) >= 200 else hist, 10))
        if len(recent) < w:
            return float(np.nanmean(recent)), noise
        c = np.concatenate([[0.0], np.cumsum(np.nan_to_num(recent))])
        means = (c[w:] - c[:-w]) / w
        return float(means.max()), noise


def lora_airtime_s(rx: ReceiverParams, payload_len: int, cr: int, has_crc: bool) -> float:
    """Semtech time-on-air (explicit header) with the protocol's preamble length."""
    preamble = {"meshtastic": 16, "lorawan": 8, "meshcore": 32 if rx.sf <= 8 else 16}.get(rx.protocol, 8)
    tsym = (2 ** rx.sf) / rx.bw_hz
    de = 1 if rx.ldro else 0
    cr = min(max(cr, 1), 4)   # 1..4 = 4/5..4/8
    num = 8 * payload_len - 4 * rx.sf + 28 + (16 if has_crc else 0)
    n_payload = 8 + max(int(np.ceil(num / (4 * (rx.sf - 2 * de)))) * (cr + 4), 0)
    return (preamble + 4.25 + n_payload) * tsym


class FrameSink(gr.sync_block):
    """Reassemble crc_verif's byte stream into frames using its 'frame_info' tags."""

    CLIP_RSSI_DBFS = -3.0    # in-band power this close to full scale means the ADC clipped too
    CLIP_SLACK_S = 1.5       # demodulator latency: look back this much further than the airtime

    def __init__(self, rx: ReceiverParams, snr: SnrProbe, on_frame: Callable[[RxFrame], None],
                 power: PowerProbe | None = None, rssi_offset: Callable[[], float | None] = lambda: None,
                 adc: SpectrumTap | None = None):
        gr.sync_block.__init__(self, name=f"frame_sink_{rx.name}", in_sig=[np.uint8], out_sig=None)
        self.rx, self.snr, self.on_frame = rx, snr, on_frame
        self.power, self.rssi_offset, self.adc = power, rssi_offset, adc
        self._cr = rx.cr - 4
        self._buf = bytearray()
        self._need = 0
        self._crc_ok = False
        self._has_crc = True

    def work(self, input_items, output_items):
        data = input_items[0]
        start = self.nitems_read(0)
        tags = {t.offset: t for t in self.get_tags_in_window(0, 0, len(data), pmt.intern("frame_info"))}
        for i, b in enumerate(data):
            tag = tags.get(start + i)
            if tag is not None:
                if self._buf:
                    log.debug("%s: dropping %d-byte partial frame", self.rx.name, len(self._buf))
                d = tag.value
                self._need = pmt.to_long(pmt.dict_ref(d, pmt.intern("pay_len"), pmt.from_long(0)))
                # LoRaWAN downlinks carry no payload CRC; nothing to verify then
                self._has_crc = bool(pmt.to_long(pmt.dict_ref(d, pmt.intern("crc"), pmt.from_long(1))))
                self._crc_ok = pmt.to_bool(pmt.dict_ref(d, pmt.intern("crc_valid"), pmt.PMT_F))
                self._cr = pmt.to_long(pmt.dict_ref(d, pmt.intern("cr"), pmt.from_long(self.rx.cr - 4)))
                self._buf = bytearray()
            if self._need:
                self._buf.append(int(b))
                if len(self._buf) == self._need:
                    self._emit()
        return len(data)

    def _emit(self):
        rx = self.rx
        frame = RxFrame(data=bytes(self._buf), crc_ok=self._crc_ok or not self._has_crc, receiver=rx.name,
                        frequency_hz=rx.frequency_hz, sf=rx.sf, bw_hz=rx.bw_hz, snr_db=self.snr.last_snr,
                        protocol=rx.protocol, has_crc=self._has_crc, invert_iq=rx.invert_iq)
        frame.snr_lora_db = self.snr.last_snr
        airtime = lora_airtime_s(rx, len(self._buf), self._cr, self._has_crc)
        if self.adc is not None:
            frame.clipped = self.adc.clipped_since(time.time() - airtime - self.CLIP_SLACK_S)
        if self.power is not None:
            # RSSI = in-band power over the frame (as SX126x reports it); SNR measured against
            # the channel's quiet level — steadier than gr-lora's preamble estimate
            burst, noise = self.power.measure(airtime)
            if burst and noise and burst > 0 and noise > 0:
                frame.rssi_dbfs = 10 * np.log10(burst)
                frame.noise_dbfs = 10 * np.log10(noise)
                sig = burst - noise
                frame.snr_db = 10 * np.log10(sig / noise) if sig > 0 else -30.0
                frame.clipped = bool(frame.clipped or frame.rssi_dbfs > self.CLIP_RSSI_DBFS)
                offset = self.rssi_offset()
                if offset is not None:
                    frame.rssi_dbm = frame.rssi_dbfs + offset
                    frame.noise_dbm = frame.noise_dbfs + offset
        self._buf, self._need = bytearray(), 0
        try:
            self.on_frame(frame)
        except Exception:
            log.exception("frame handler failed")


def plan_center(receivers: list[ReceiverParams], sample_rate: float, dc_clearance_hz: float = 25_000,
                fixed: float | None = None) -> float:
    """
    Pick the tuner frequency. Every channel must sit inside the flat part of the
    passband (90 % of Nyquist), and the RTL-SDR's DC spike should land outside every
    channel with some clearance. Among the valid choices prefer the one with the most
    DC clearance (capped at 100 kHz), then the most margin from the band edges.
    """
    usable = sample_rate / 2 * 0.9
    lo_min = max(r.frequency_hz + r.bw_hz / 2 for r in receivers) - usable
    lo_max = min(r.frequency_hz - r.bw_hz / 2 for r in receivers) + usable

    def dc_distance(lo):
        return min(max(abs(lo - r.frequency_hz) - r.bw_hz / 2, 0) for r in receivers)

    def edge_margin(lo):
        return min(usable - abs(r.frequency_hz - lo) - r.bw_hz / 2 for r in receivers)

    span = (max(r.frequency_hz + r.bw_hz / 2 for r in receivers) - min(r.frequency_hz - r.bw_hz / 2 for r in receivers))
    if fixed is not None:
        if edge_margin(fixed) < 0:
            raise ValueError(f"sdr.center_frequency_hz {fixed / 1e6:.4f} MHz leaves some receivers outside the "
                             f"usable ±{usable / 1e3:.0f} kHz")
        if dc_distance(fixed) < dc_clearance_hz:
            log.warning("DC spike at %.4f MHz is within %.0f kHz of a channel", fixed / 1e6, dc_clearance_hz / 1e3)
        return fixed
    if lo_min > lo_max:
        raise ValueError(f"Receivers span {span / 1e6:.3f} MHz but {sample_rate / 1e6:g} MS/s only covers "
                         f"{2 * usable / 1e6:.3f} MHz usable. Raise sdr.sample_rate or drop receivers.")
    step = 1_000.0
    candidates = [lo_min + i * step for i in range(int((lo_max - lo_min) / step) + 1)] or [lo_min]
    best = max(candidates, key=lambda lo: (min(dc_distance(lo), 100_000), edge_margin(lo)))
    if dc_distance(best) < dc_clearance_hz:
        log.warning("No tuner frequency keeps the DC spike %.0f kHz clear of all channels; best is %.0f kHz",
                    dc_clearance_hz / 1e3, dc_distance(best) / 1e3)
    return round(best)


class MonitorFlowgraph(gr.top_block):
    def __init__(self, receivers: list[ReceiverParams], sdr: SdrConfig,
                 on_frame: Callable[[RxFrame], None], iq_file: str | None = None,
                 iq_format: str = "cu8", iq_center_hz: float | None = None, soft_decoding: bool = True,
                 on_spectrum: Callable[[np.ndarray], None] | None = None, fft_size: int = 1024,
                 realtime: bool = False, iq_loop: bool = False, spectrum_window=None):
        gr.top_block.__init__(self, "lora_sdr_monitor", catch_exceptions=True)
        self._keep: list = []   # see connect()
        # [freq_xlating filter, frequency it extracts, reference (None = tuner centre)]: retuning
        # and channel moves just change their offsets
        self._xlates: list[list] = []
        self._groups: dict = {}         # channel key → {entry, names, bw, protocol, configured, window}
        self._rx_group: dict[str, object] = {}
        self._rx_obj = {rx.name: rx for rx in receivers}
        self._rx_freq = {rx.name: (rx.frequency_hz, rx.bw_hz) for rx in receivers}
        self.in_range: set[str] = set(self._rx_freq)
        self._rtl = None        # osmosdr source when live (gain control)
        self.gain_steps: list[float] = []
        self.gain_mode = "auto" if str(sdr.gain).lower() == "auto" else "manual"
        self.gain = None if self.gain_mode == "auto" else float(sdr.gain)
        # sdr.rssi_offset_db is calibrated at the configured gain; it moves with manual gain changes
        self._rssi_base = sdr.rssi_offset_db
        self._gain_ref = self.gain
        lora_sdr = import_lora_sdr()
        samp_rate = float(sdr.sample_rate)

        if iq_file:
            center = iq_center_hz if iq_center_hz is not None else \
                plan_center(receivers, samp_rate, sdr.dc_clearance_hz, sdr.center_frequency_hz)
            source = self._file_source(iq_file, iq_format, iq_loop)
            if realtime:  # pace file playback like a live SDR (needed by the UIs)
                throttle = blocks.throttle(gr.sizeof_gr_complex, samp_rate, True)
                self.connect(source, throttle)
                source = throttle
        else:
            center = plan_center(receivers, samp_rate, sdr.dc_clearance_hz, sdr.center_frequency_hz)
            source = self._rtl_source(sdr, center)
            self._rtl = source
        self.center_hz = center
        self.sample_rate = samp_rate

        # Python blocks must stay referenced from Python, or they are freed while the
        # scheduler still runs them (segfault in block_executor)
        self.py_blocks = []
        # The source always feeds the spectrum tap (idle unless someone looks), which also keeps
        # the graph valid with every receiver off
        self.spectrum = SpectrumTap(fft_size, spectrum_window or "Blackman-Harris", on_spectrum)
        self.connect(source, self.spectrum)
        from .iqrec import IqTap
        self.iq_tap = IqTap()          # IQ recordings (idle unless one is armed)
        self.connect(source, self.iq_tap)
        self._source = source

        # Everything stays connected for the whole run. Receivers are switched on and off with
        # gates (blocks.copy: when disabled it drops its input): one in front of each channel
        # filter (closed when none of its receivers is on, so the filter costs nothing) and one
        # in front of each demodulator. Rewiring a running flowgraph instead (lock/disconnect/
        # unlock) intermittently wedged it for good in this GNU Radio build.
        self._rx_gate: dict[str, object] = {}
        self._rx_key: dict[str, tuple] = {}
        self._filter_gate: dict[tuple, object] = {}
        self.enabled: set[str] = {rx.name for rx in receivers}
        filters: dict[tuple, tuple[object, list]] = {}   # (freq, bw) → (head block, edges source→head)
        conjs: dict[tuple, tuple[object, list]] = {}
        max_sf: dict[tuple, int] = {}
        wired: set[tuple] = set()
        lora_rxs = [rx for rx in receivers if rx.protocol != "trustedwireless"]
        for rx in lora_rxs:
            key = (rx.frequency_hz, rx.bw_hz)
            max_sf[key] = max(max_sf.get(key, 0), rx.sf)
        for rx in lora_rxs:
            key = (rx.frequency_hz, rx.bw_hz)
            if key not in filters:
                fgate = blocks.copy(gr.sizeof_gr_complex)
                self.connect(source, fgate)
                self._filter_gate[key] = fgate
                head, edges = self._channel_filter(fgate, rx, center, samp_rate)
                self._groups[key] = {"entry": self._last_xlate, "names": [], "bw": rx.bw_hz, "protocol": rx.protocol,
                                     "configured": rx.frequency_hz, "window": None}
                # frame_sync wants slightly more than one symbol (2^SF × OS) per call
                head.set_min_output_buffer(4 * (2 ** max_sf[key]) * OS_FACTOR)
                # channel power in 1 ms blocks for RSSI/SNR (C++ does the per-sample work)
                ch_rate = rx.bw_hz * OS_FACTOR
                n_int = max(1, int(ch_rate / 1000))
                mag = blocks.complex_to_mag_squared()
                integ = blocks.integrate_ff(n_int)
                scale = blocks.multiply_const_ff(1.0 / n_int)
                probe = PowerProbe(f"{key[0] / 1e6:.4f}_{key[1] // 1000}k", ch_rate / n_int)
                self.py_blocks.append(probe)
                edges = edges + [("s", head, 0, mag, 0), ("s", mag, 0, integ, 0), ("s", integ, 0, scale, 0),
                                 ("s", scale, 0, probe, 0)]
                filters[key] = (head, edges, probe)
            head, edges, probe = filters[key]
            edges = list(edges)
            if rx.invert_iq:
                if key not in conjs:
                    # Inverted IQ (LoRaWAN downlinks) is the complex conjugate of the signal
                    conj = blocks.conjugate_cc()
                    conj.set_min_output_buffer(4 * (2 ** max_sf[key]) * OS_FACTOR)
                    conjs[key] = (conj, [("s", head, 0, conj, 0)])
                conj, cedges = conjs[key]
                edges += cedges
                head = conj

            sync = lora_sdr.frame_sync(int(rx.frequency_hz), rx.bw_hz, rx.sf, False,
                                       sync_word_symbols(rx.sync_word, rx.sf), OS_FACTOR, RX_PREAMBLE_LEN)
            demod = lora_sdr.fft_demod(soft_decoding, True)
            gray = lora_sdr.gray_mapping(soft_decoding)
            deint = lora_sdr.deinterleaver(soft_decoding)
            hamming = lora_sdr.hamming_dec(soft_decoding)
            header = lora_sdr.header_decoder(False, rx.cr - 4, 255, True, 1 if rx.ldro else 0, False)
            dewhite = lora_sdr.dewhitening()
            crc = lora_sdr.crc_verif(0, False)
            snr = SnrProbe()
            sink = FrameSink(rx, snr, on_frame, probe, self.rssi_offset, self.spectrum)
            gate = blocks.copy(gr.sizeof_gr_complex)
            # frame_sync wants slightly more than one symbol per call; copy only honours the per-port form
            gate.set_min_output_buffer(0, 4 * (2 ** rx.sf) * OS_FACTOR)
            chain = [gate, sync, demod, gray, deint, hamming, header, dewhite, crc, sink]
            edges.append(("s", head, 0, gate, 0))
            edges += [("s", a, 0, b, 0) for a, b in zip(chain, chain[1:])]
            edges.append(("s", sync, 1, snr, 0))
            edges.append(("m", header, "frame_info", sync, "frame_info"))
            for kind, a, pa, b, pb in edges:
                if kind == "m":
                    self.msg_connect((a, pa), (b, pb))
                elif (a, pa, b, pb) not in wired:   # filter / conjugate edges are shared
                    wired.add((a, pa, b, pb))
                    self.connect((a, pa), (b, pb))
            self._rx_gate[rx.name] = gate
            self._rx_key[rx.name] = key
            self._groups[key]["names"].append(rx.name)
            self._rx_group[rx.name] = key
            self.py_blocks += [snr, sink]
        self._build_fsk([rx for rx in receivers if rx.protocol == "trustedwireless"], source, center, samp_rate,
                        on_frame)
        self._apply_gates()
        self._topo_lock = threading.RLock()   # start/stop (watchdog vs. shutdown)
        self.running = False
        log.info("%d demodulators on %d channel filters", len(receivers), len(filters))

    def connect(self, *points):
        # Keep a Python reference to every block ever connected, so Python blocks (SpectrumTap,
        # sinks) can't be freed while the scheduler runs them, whoever forgets them later.
        for p in points:
            b = p[0] if isinstance(p, tuple) else p
            if not any(b is k for k in self._keep):
                self._keep.append(b)
        return super().connect(*points)

    def _build_fsk(self, rxs, source, center, samp_rate, on_frame):
        """2-FSK hop channels (tw_rx): one C++ filter cuts out their block at 250 kS/s, then one
        narrow C++ channel filter per hop channel to 50 kS/s feeds a Python burst demodulator.
        Gated like the LoRa receivers (wide gate open while any of the channels is on)."""
        if not rxs:
            return
        from .tw_rx import TwChannelSink

        lo = min(r.frequency_hz for r in rxs) - 20e3
        hi = max(r.frequency_hz for r in rxs) + 20e3
        mid = (lo + hi) / 2
        decim_w = max(1, int(samp_rate // 250e3))
        rate_w = samp_rate / decim_w
        if (hi - lo) / 2 > rate_w * 0.45:
            raise ValueError("trustedwireless channels span more than the 250 kHz block they are cut out with")
        fgate = blocks.copy(gr.sizeof_gr_complex)
        wide = filter.freq_xlating_fir_filter_ccc(decim_w, firdes.low_pass(1.0, samp_rate, (hi - lo) / 2 + 5e3, 20e3),
                                                  mid - center, samp_rate)
        self.connect(source, fgate, wide)
        self._xlates.append([wide, mid, None])
        key = ("fsk", mid)
        self._filter_gate[key] = fgate
        decim_c = max(1, int(round(rate_w / 50e3)))
        taps = firdes.low_pass(1.0, rate_w, 9e3, 4e3)        # ±9 kHz: the neighbours sit 30 kHz away
        for rx in rxs:
            gate = blocks.copy(gr.sizeof_gr_complex)
            chan = filter.freq_xlating_fir_filter_ccc(decim_c, taps, rx.frequency_hz - mid, rate_w)
            self._xlates.append([chan, rx.frequency_hz, mid])          # relative to the block, not the tuner
            gkey = ("tw", rx.name)
            half = rate_w * 0.45 - rx.bw_hz / 2
            self._groups[gkey] = {"entry": self._xlates[-1], "names": [rx.name], "bw": rx.bw_hz,
                                  "protocol": rx.protocol, "configured": rx.frequency_hz, "window": (mid - half, mid + half)}
            self._rx_group[rx.name] = gkey
            sink = TwChannelSink(rx, rate_w / decim_c, on_frame, self.rssi_offset, self.spectrum)
            self.connect(wide, gate, chan, sink)
            self._rx_gate[rx.name] = gate
            self._rx_key[rx.name] = key
            self.py_blocks.append(sink)
        log.info("FSK listener: %d channels around %.4f MHz (%g kS/s → %g kS/s per channel)",
                 len(rxs), mid / 1e6, rate_w / 1e3, rate_w / decim_c / 1e3)

    def _apply_gates(self):
        active = self.enabled & self.in_range           # out-of-range receivers idle
        on_keys = {self._rx_key[n] for n in active}
        for key, g in self._filter_gate.items():
            g.set_enabled(key in on_keys)
        for name, g in self._rx_gate.items():
            g.set_enabled(name in active)

    TUNE_MIN_HZ, TUNE_MAX_HZ = 24e6, 1766e6        # R828D tuner range

    def channels(self) -> list[dict]:
        """Channel groups: decoders sharing one filter move together."""
        half = self.sample_rate / 2 * 0.98
        out = []
        for g in self._groups.values():
            lo, hi = g["window"] or (self.center_hz - half + g["bw"] / 2, self.center_hz + half - g["bw"] / 2)
            out.append({"receivers": list(g["names"]), "frequency_hz": g["entry"][1], "bw_hz": g["bw"],
                        "protocol": g["protocol"], "configured_hz": g["configured"], "min_hz": lo, "max_hz": hi})
        return out

    def set_channel_frequency(self, receiver: str, hz: float) -> list[str]:
        """Move the channel `receiver` belongs to (and every decoder sharing its filter)."""
        key = self._rx_group.get(receiver)
        if key is None:
            raise ValueError(f"unknown receiver '{receiver}'")
        g = self._groups[key]
        hz = float(hz)
        info = next(c for c in self.channels() if receiver in c["receivers"])
        if not info["min_hz"] <= hz <= info["max_hz"]:
            raise ValueError(f"{hz / 1e6:.4f} MHz is outside what this channel can reach now "
                             f"({info['min_hz'] / 1e6:.4f}–{info['max_hz'] / 1e6:.4f} MHz)")
        entry = g["entry"]
        entry[1] = hz
        entry[0].set_center_freq(hz - (self.center_hz if entry[2] is None else entry[2]))
        for n in g["names"]:
            self._rx_freq[n] = (hz, g["bw"])
            self._rx_obj[n].frequency_hz = hz        # what decoded frames report
        self._update_range()
        self._apply_gates()
        log.info("channel %s moved to %.4f MHz", ", ".join(g["names"]), hz / 1e6)
        return list(g["names"])

    def _update_range(self):
        half = self.sample_rate / 2 * 0.98
        self.in_range = {n for n, (f, bw) in self._rx_freq.items() if abs(f - self.center_hz) + bw / 2 <= half}

    def set_center(self, hz: float):
        """Retune the SDR. Every channel filter keeps extracting its own frequency (its offset
        follows the new centre); receivers outside the new window go idle until tuned back."""
        if self._rtl is None:
            raise ValueError("only a live SDR can be retuned (not an IQ file)")
        hz = float(hz)
        if not self.TUNE_MIN_HZ <= hz <= self.TUNE_MAX_HZ:
            raise ValueError(f"{hz / 1e6:.3f} MHz is outside the tuner range "
                             f"{self.TUNE_MIN_HZ / 1e6:g}–{self.TUNE_MAX_HZ / 1e6:g} MHz")
        self._rtl.set_center_freq(hz, 0)
        for blk, f, ref in self._xlates:
            blk.set_center_freq(f - (hz if ref is None else ref))
        self.center_hz = hz
        self._update_range()
        self._apply_gates()
        self.iq_tap.stop_all("stopped: the tuner was retuned")   # their offsets refer to the old centre
        log.info("tuned to %.6f MHz; %d of %d receivers in range", hz / 1e6, len(self.in_range), len(self._rx_freq))

    def set_enabled(self, names: set[str]):
        """Run exactly the receivers in `names`; the others (and filters nobody uses) idle."""
        self.enabled = set(names) & set(self._rx_gate)
        self._apply_gates()

    @property
    def fft_size(self) -> int:
        return self.spectrum.fft_size

    @property
    def spectrum_window_gain(self) -> float:
        return self.spectrum.window_gain

    def set_spectrum_active(self, on: bool):
        """The FFT only runs while somebody looks at the spectrum (no CPU otherwise)."""
        if on != self.spectrum.active:
            self.spectrum.active = on
            log.info("spectrum %s", "on" if on else "off")

    def rebuild_spectrum(self, fft_size: int, window: str):
        self.spectrum.configure(fft_size, window)

    def _channel_filter(self, source, rx: ReceiverParams, center: float, samp_rate: float):
        """Shift rx to baseband, low-pass and resample to OS_FACTOR × bandwidth.
        Returns (output block, edges from the source to it)."""
        target = rx.bw_hz * OS_FACTOR
        ratio = Fraction(int(samp_rate), int(target))
        taps = firdes.low_pass(1.0, samp_rate, rx.bw_hz * 0.55, rx.bw_hz * 0.2)
        if ratio.denominator == 1:
            xlate = filter.freq_xlating_fir_filter_ccc(ratio.numerator, taps, rx.frequency_hz - center, samp_rate)
            self._xlates.append([xlate, rx.frequency_hz, None])
            self._last_xlate = self._xlates[-1]
            head, edges = xlate, [("s", source, 0, xlate, 0)]
        else:
            # e.g. 2.4 MS/s → 1 MS/s: shift/filter at full rate, then resample exactly
            xlate = filter.freq_xlating_fir_filter_ccc(1, taps, rx.frequency_hz - center, samp_rate)
            self._xlates.append([xlate, rx.frequency_hz, None])
            self._last_xlate = self._xlates[-1]
            resamp = filter.rational_resampler_ccc(interpolation=ratio.denominator, decimation=ratio.numerator)
            head, edges = resamp, [("s", source, 0, xlate, 0), ("s", xlate, 0, resamp, 0)]
        log.info("filter %.4f MHz/%g kHz: offset %+.1f kHz, %s → %.0f S/s", rx.frequency_hz / 1e6, rx.bw_hz / 1e3,
                 (rx.frequency_hz - center) / 1e3,
                 f"decim {ratio.numerator}" if ratio.denominator == 1 else f"resample {ratio}", target)
        return head, edges

    def _rtl_source(self, sdr: SdrConfig, center: float):
        import osmosdr

        args = f"numchan=1 {sdr.device}"
        if sdr.bias_tee:
            args += ",bias=1"
        src = osmosdr.source(args=args)
        src.set_sample_rate(sdr.sample_rate)
        actual = src.get_sample_rate()
        if abs(actual - sdr.sample_rate) > 1:
            raise RuntimeError(f"SDR refused sample rate {sdr.sample_rate:g} (got {actual:g})")
        src.set_center_freq(center, 0)
        if sdr.ppm:
            src.set_freq_corr(sdr.ppm, 0)
        self.gain_steps = self._read_gain_steps(src)
        if str(sdr.gain).lower() == "auto":
            src.set_gain_mode(True, 0)
        else:
            src.set_gain_mode(False, 0)
            src.set_gain(self._snap_gain(float(sdr.gain)), 0)
            self.gain = float(src.get_gain(0))
        src.set_dc_offset_mode(0, 0)
        src.set_iq_balance_mode(0, 0)
        src.set_bandwidth(0, 0)
        return src

    @staticmethod
    def _read_gain_steps(src) -> list[float]:
        """The tuner's discrete gains (R828D: 0 … 49.6 dB in ~29 steps)."""
        import re

        r = src.get_gain_range(0)
        vals: list[float] = []
        try:
            vals = [float(v) for v in r.values()]
        except Exception:
            # gr-osmosdr's pybind11 build can't convert values(); parse the printable form
            # instead: one "(value)" or "(start, stop, step)" line per range
            for m in re.finditer(r"\(([^)]*)\)", r.to_pp_string()):
                nums = [float(x) for x in m.group(1).split(",") if x.strip()]
                if len(nums) == 1:
                    vals.append(nums[0])
                elif len(nums) >= 2:
                    step = nums[2] if len(nums) > 2 and nums[2] > 0 else 1.0
                    vals += list(np.arange(nums[0], nums[1] + step / 2, step))
        if not vals:
            # last resort: let the range snap a fine grid to its valid values
            vals = [r.clip(float(v), True) for v in np.arange(r.start(), r.stop() + 0.05, 0.1)]
        return sorted(set(round(float(v), 1) for v in vals))

    def _snap_gain(self, db: float) -> float:
        return min(self.gain_steps, key=lambda g: abs(g - db)) if self.gain_steps else db

    def gain_info(self) -> dict:
        return {"supported": self._rtl is not None, "mode": self.gain_mode, "gain": self.gain,
                "steps": self.gain_steps}

    def set_gain(self, value):
        """'auto' = the tuner's AGC; a number = fixed gain, snapped to the nearest tuner step."""
        if self._rtl is None:
            raise ValueError("gain can only be changed on a live SDR")
        if str(value).lower() == "auto":
            self._rtl.set_gain_mode(True, 0)
            self.gain_mode, self.gain = "auto", None
        else:
            self._rtl.set_gain_mode(False, 0)
            self._rtl.set_gain(self._snap_gain(float(value)), 0)
            self.gain_mode, self.gain = "manual", float(self._rtl.get_gain(0))
        log.info("gain %s", "AGC" if self.gain is None else f"{self.gain:g} dB")

    def rssi_offset(self) -> float | None:
        """dBm = dBFS + this. The calibration holds for the configured gain; a manual change
        shifts it by the gain difference, the AGC (unless calibrated with it) makes it unknown."""
        b = self._rssi_base
        if b is None or self._rtl is None:
            return b
        if self.gain_mode == "auto":
            return b if self._gain_ref is None else None
        return None if self._gain_ref is None else b + (self._gain_ref - self.gain)

    def _file_source(self, path: str, fmt: str, loop: bool = False):
        if fmt == "cf32":
            src = blocks.file_source(gr.sizeof_gr_complex, path, loop)
            return src
        if fmt == "cu8":  # rtl_sdr native output: interleaved unsigned 8-bit I/Q
            src = blocks.file_source(gr.sizeof_char, path, loop)
            to_f = blocks.uchar_to_float()
            center = blocks.add_const_ff(-127.5)
            scale = blocks.multiply_const_ff(1 / 127.5)
            deint = blocks.deinterleave(gr.sizeof_float)
            to_c = blocks.float_to_complex()
            self.connect(src, to_f, center, scale, deint)
            self.connect((deint, 0), (to_c, 0))
            self.connect((deint, 1), (to_c, 1))
            return to_c
        raise ValueError(f"Unknown IQ format '{fmt}' (use cu8 or cf32)")
