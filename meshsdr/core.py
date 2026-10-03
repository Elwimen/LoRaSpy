"""
MonitorCore: the flowgraph, the protocol decoders and the node databases, shared by the
text, TUI and GUI front-ends.

Frames arrive from GNU Radio threads and are decoded on one worker thread; front-ends
either register callbacks (text mode) or poll `drain_events` / `take_spectrum` (UIs).
meshsdr.server shares one MonitorCore with other processes; meshsdr.remote.RemoteCore is
the client-side stand-in with the same interface, so GUI, TUI and Wireshark can all run
on one RTL-SDR at once.
"""

import logging
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from . import crypto
from .bands import Band, band_for, receiver_bands, regulatory_bands
from .config import Config
from .decoder import Decoder, RxFrame
from .formatter import Formatter, summarize
from .lorawan import LoRaWANDecoder
from .meshcore import MeshCoreDB, MeshCoreDecoder
from .nodedb import NodeDB

log = logging.getLogger(__name__)


KEY_ATTRS = ("channels", "private_keys", "public_keys", "meshcore_channels", "meshcore_identities",
             "meshcore_public_keys", "lorawan_sessions", "lorawan_otaa")


def _static_public_keys(cfg: Config) -> dict[int, bytes]:
    """Pinned Meshtastic public keys, plus those of our own nodes (from their private keys)."""
    static_pub = dict(cfg.public_keys)
    for pk in cfg.private_keys:
        static_pub.setdefault(pk.node, crypto.derive_public_key(pk.key))
    return static_pub


@dataclass
class ReceiverStats:
    frames: int = 0
    crc_errors: int = 0
    decrypted: int = 0
    last_snr: float | None = None
    last_rssi: float | None = None       # dBm when calibrated, else dBFS
    last_time: float | None = None
    enabled: bool = True


@dataclass
class Event:
    """One decoded frame as seen by the front-ends."""
    pkt: object
    frame: RxFrame
    seq: int
    received: float = field(default_factory=time.time)


class MonitorCore:
    def __init__(self, cfg: Config, *, iq_file: str | None = None, iq_format: str = "cu8",
                 iq_center_hz: float | None = None, soft_decoding: bool = True,
                 fft_size: int = 1024, realtime: bool = False, iq_loop: bool = False, history: int = 2000,
                 spectrum_window: str = "Blackman-Harris"):
        self.cfg = cfg
        self.node_db = NodeDB(cfg.node_db_file, _static_public_keys(cfg))
        self.mc_db = MeshCoreDB(cfg.node_db_file.replace(".json", "") + "_meshcore.json"
                                if cfg.node_db_file else None, cfg.meshcore_public_keys)
        from .trustedwireless import TrustedWirelessDecoder
        self.decoders = {"meshtastic": Decoder(cfg, self.node_db), "lorawan": LoRaWANDecoder(cfg),
                         "meshcore": MeshCoreDecoder(cfg, self.mc_db), "trustedwireless": TrustedWirelessDecoder()}
        self.formatter = Formatter("hextext", False, self.node_db, True, True)
        self.bands: list[Band] = receiver_bands(cfg.receivers)
        self.regulatory: list[Band] = regulatory_bands(cfg.region)
        self.stats = {rx.name: ReceiverStats() for rx in cfg.receivers}
        self.protocol_enabled = {p: True for p in {rx.protocol for rx in cfg.receivers}}
        self.totals = {"frames": 0, "crc_err": 0, "decrypted": 0}
        self.per_protocol: dict[str, int] = {}

        self.packets: deque[Event] = deque(maxlen=history)
        self._events: queue.Queue[Event] = queue.Queue()
        self._frames: queue.Queue[RxFrame] = queue.Queue()
        self._seq = 0
        self._lock = threading.Lock()
        self.latest_spectrum: np.ndarray | None = None
        self.spectrum_seq = 0
        # per-consumer detector state: name → [max |X|², sum |X|², count] since that consumer's last take
        self._spec_acc: dict[str, list] = {}
        self._spec_lock = threading.Lock()
        self.callbacks = []   # fn(Event), called on the worker thread
        self.on_change = []   # fn(), after receivers were enabled/disabled or the FFT changed
        self.on_keys = []     # fn(), after keys/channels were edited (keys.jsonc) and reloaded
        self.bands_version = 0
        self._recordings: dict = {}
        self._rec_id = 0
        self.keys_version = 0
        self._reconf_lock = threading.Lock()
        self.server = None    # meshsdr.server.Server when this core is shared

        from .flowgraph import MonitorFlowgraph

        self.tb = MonitorFlowgraph(cfg.receivers, cfg.sdr, self._frames.put, iq_file=iq_file, iq_format=iq_format,
                                   iq_center_hz=iq_center_hz, soft_decoding=soft_decoding,
                                   on_spectrum=self._on_spectrum, fft_size=fft_size,
                                   realtime=realtime, iq_loop=iq_loop, spectrum_window=spectrum_window)
        self.center_hz = self.tb.center_hz
        self.sample_rate = self.tb.sample_rate
        self.fft_size = fft_size
        self.window = spectrum_window
        self.started = time.time()
        self._running = False
        self.finished = threading.Event()   # file source ran out
        self._finite = bool(iq_file) and not iq_loop   # only a non-looping IQ file can end
        self.restarts = 0                               # flowgraph restarts by the watchdog
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._run, name="decoder", daemon=True)

    # ------------------------------------------------------------------ lifecycle

    def start(self):
        self._running = True
        with self.tb._topo_lock:
            self.tb.running = True
            self.tb.start()
        self._worker.start()
        threading.Thread(target=self._wait_tb, name="tb-wait", daemon=True).start()
        threading.Thread(target=self._watchdog, name="watchdog", daemon=True).start()

    STALL_S = 2.0

    def _watchdog(self):
        """
        Restart the flowgraph when the source stops delivering samples for STALL_S (e.g. a USB
        hiccup of a live SDR). A finite IQ file legitimately stops, so it isn't watched.
        """
        if self._finite:
            return
        last, since = None, time.time()
        while not self._stop.wait(0.5):
            try:
                n = self.tb.spectrum.nitems_read(0)   # the tap sees every source sample
            except Exception:
                continue
            if n != last:
                last, since = n, time.time()
                continue
            if time.time() - since < self.STALL_S:
                continue
            log.warning("no samples from the source for %.0f s — restarting the flowgraph", self.STALL_S)
            self.restarts += 1
            with self.tb._topo_lock:
                if self._stop.is_set():
                    break
                self.tb.stop()
                self.tb.wait()
                self.tb.start()
            last, since = None, time.time()

    def _wait_tb(self):
        """Sets `finished` when a non-looping IQ file has been played to the end."""
        if not self._finite:
            return
        self.tb.wait()
        if not self._stop.is_set():
            log.info("source finished")
            self.finished.set()

    def stop(self):
        self._stop.set()
        if self.server is not None:
            self.server.stop()
        self.tb.iq_tap.stop_all()      # close running recordings (sidecar written)
        with self.tb._topo_lock:
            self.tb.stop()
            self.tb.wait()
            self.tb.running = False
        self._worker.join(timeout=2)
        while not self._frames.empty():
            self._process(self._frames.get_nowait())
        self.save()

    def set_receivers_enabled(self, names: set[str]):
        """Enable exactly these receivers; the rest (and filters nobody uses) are gated off (~no CPU)."""
        with self._reconf_lock:
            for name, st in self.stats.items():
                st.enabled = name in names
            self.tb.set_enabled(names)
        self._changed()

    def _changed(self):
        for cb in self.on_change:
            try:
                cb()
            except Exception:
                log.exception("change listener failed")

    # ------------------------------------------------------------------ keys and channels (keys.jsonc)

    def _store(self):
        from .keystore import KeyStore

        if self.cfg.source_path is None:
            raise ValueError("no config file: keys can't be edited")
        return KeyStore(self.cfg.source_path)

    def keys_list(self) -> list[dict]:
        return self._store().entries()

    def keys_add(self, kind: str, fields: dict):
        self._store().add(kind, fields)
        self.reload_keys()

    def keys_update(self, kind: str, index: int, fields: dict):
        self._store().update(kind, index, fields)
        self.reload_keys()

    def keys_remove(self, kind: str, index: int):
        self._store().remove(kind, index)
        self.reload_keys()

    def reload_keys(self):
        """Re-read config.jsonc + keys.jsonc and hand the keys to the running decoders. Only the
        key sections are taken over; receivers and SDR settings need a restart."""
        from .config import ConfigError, load_config

        try:
            fresh = load_config(self.cfg.source_path)
        except ConfigError as e:
            raise ValueError(str(e)) from e
        for attr in KEY_ATTRS:
            setattr(self.cfg, attr, getattr(fresh, attr))
        self.node_db.set_static_keys(_static_public_keys(self.cfg))
        self.decoders["meshtastic"].set_keys(self.cfg)
        self.decoders["lorawan"].set_keys(self.cfg)
        self.decoders["meshcore"].set_keys(self.cfg)
        self.keys_version += 1
        log.info("keys reloaded")
        for cb in self.on_keys:
            try:
                cb()
            except Exception:
                log.exception("keys listener failed")

    # ------------------------------------------------------------------ IQ recordings

    def record_iq(self, freq_hz: float | None = None, bw_hz: float | None = None, duration_s: float = 10,
                  fmt: str = "cf32", name: str | None = None) -> dict:
        """Start recording IQ (whole band, or bw_hz around freq_hz) into recordings/ next to the
        config; returns its status. Decoding continues meanwhile."""
        import re

        from .iqrec import IqRecording

        base = (self.cfg.source_path.resolve().parent if self.cfg.source_path else Path.cwd()) / "recordings"
        if name:
            name = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).name).strip("._") or "recording"
        else:
            f = (freq_hz or self.center_hz) / 1e6
            name = time.strftime("%Y%m%d-%H%M%S") + f"_{f:.4f}MHz" + (f"_{bw_hz / 1e3:g}k" if bw_hz else "_full")
        path = base / (name if name.endswith("." + fmt) else f"{name}.{fmt}")
        g = self.gain_info
        meta = {"source": "LoRaSpy", "tuner_center_hz": self.center_hz, "tuner_sample_rate": self.sample_rate,
                "gain": "AGC" if g.get("mode") == "auto" else g.get("gain"), "supported_gain": g.get("supported")}
        with self._lock:
            self._rec_id += 1
            job = IqRecording(self._rec_id, path, self.center_hz, self.sample_rate, freq_hz, bw_hz,
                              float(duration_s), fmt, meta)
            self._recordings[job.rid] = job
        self.tb.iq_tap.add(job)
        log.info("IQ recording %s: %.4f MHz, %s, %g s → %s", job.rid, job.freq / 1e6,
                 "full band" if bw_hz is None else f"{bw_hz / 1e3:g} kHz", duration_s, path)
        return job.status()

    def recordings(self) -> list[dict]:
        return [j.status() for j in self._recordings.values()]

    # ------------------------------------------------------------------ tuning

    def set_center(self, hz: float):
        """Retune the SDR (shared). Decoders stay on their channels; those outside the new
        window go idle."""
        with self._reconf_lock:
            self.tb.set_center(hz)
            self.center_hz = self.tb.center_hz
        self._changed()

    def channels(self) -> list[dict]:
        """Channel groups (decoders sharing a filter), with frequency, reachable range, configured."""
        return self.tb.channels()

    def set_channel_frequency(self, receiver: str, hz: float) -> list[str]:
        """Move a decoder's channel (all decoders on the same filter move with it). Runtime only:
        config.jsonc is not changed."""
        with self._reconf_lock:
            names = self.tb.set_channel_frequency(receiver, hz)
            self.bands = receiver_bands(self.cfg.receivers)
            self.bands_version += 1
        self._changed()
        return names

    @property
    def tunable(self) -> bool:
        return self.tb._rtl is not None

    @property
    def in_range(self) -> set[str]:
        return set(self.tb.in_range)

    @property
    def active(self) -> set[str]:
        """Receivers really running: enabled and inside the tuned window."""
        return self.enabled & self.tb.in_range

    @property
    def gain_info(self) -> dict:
        """{'supported', 'mode': 'auto'|'manual', 'gain': dB or None, 'steps': [dB, …]}"""
        return self.tb.gain_info()

    def set_gain(self, value):
        """'auto' (tuner AGC) or dB (snapped to a tuner step). Shared by every front-end."""
        with self._reconf_lock:
            self.tb.set_gain(value)
        self._changed()

    @property
    def adc(self) -> dict:
        """ADC level over the last second: peak_dbfs, clipped, clip_ratio, clipping."""
        return self.tb.spectrum.adc_stats()

    @property
    def enabled(self) -> set[str]:
        return {n for n, st in self.stats.items() if st.enabled}

    @property
    def role(self) -> str:
        n = self.server.client_count if self.server else 0
        role = f"sharing SDR with {n} client{'s' * (n != 1)}" if self.server else "own SDR"
        return role + (f" · {self.restarts} stall restart{'s' * (self.restarts != 1)}" if self.restarts else "")

    def save(self):
        self.node_db.save()
        self.mc_db.save()

    def apply_spectrum(self, fft_size: int, window: str):
        """Change the FFT size or window (name, ui_settings.WINDOWS).
        Shared by everybody looking at this core."""
        with self._reconf_lock:
            if fft_size == self.fft_size and window == self.window:
                return
            self.tb.rebuild_spectrum(fft_size, window)
            self.fft_size = fft_size
            self.window = window
            with self._spec_lock:
                for acc in self._spec_acc.values():
                    acc[:] = [None, None, 0]
            self.latest_spectrum = None
        self._changed()

    @property
    def freq_axis_hz(self) -> np.ndarray:
        n = self.fft_size
        return self.center_hz + (np.arange(n) - n / 2) * self.sample_rate / n

    # ------------------------------------------------------------------ data flow

    def _on_spectrum(self, power: np.ndarray):
        """power: (k, fft_size) |X|² frames covering every sample since the previous call."""
        mx, sm, n = power.max(axis=0), power.sum(axis=0), len(power)
        with self._spec_lock:
            for acc in self._spec_acc.values():
                if acc[0] is None or len(acc[0]) != len(mx):
                    acc[:] = [mx.copy(), sm.copy(), n]
                else:
                    np.maximum(acc[0], mx, out=acc[0])
                    acc[1] += sm
                    acc[2] += n
        self.latest_spectrum = self.to_dbfs(mx)
        self.spectrum_seq += 1

    def to_dbfs(self, power: np.ndarray) -> np.ndarray:
        return 10 * np.log10(power / self.tb.spectrum_window_gain + 1e-20)

    def take_spectrum(self, consumer: str, detector: str = "peak") -> np.ndarray | None:
        """
        dBFS spectrum over everything received since this consumer's previous call, using a
        peak (max) or mean detector — as SDRangel/SDR# do per display frame. None if no data.
        """
        with self._spec_lock:
            acc = self._spec_acc.get(consumer)
            if acc is None:
                acc = self._spec_acc[consumer] = [None, None, 0]
                first = len(self._spec_acc) == 1
            else:
                first = False
        if first:
            self.tb.set_spectrum_active(True)   # the FFT runs only while someone looks
        with self._spec_lock:
            if acc[0] is None or acc[2] == 0:
                return None
            mx, sm, n = acc
            acc[:] = [None, None, 0]
        return self.to_dbfs(mx if detector == "peak" else sm / n)

    def release_spectrum(self, *consumers: str):
        """Forget these spectrum consumers; the FFT stops when none are left."""
        with self._spec_lock:
            for c in consumers:
                self._spec_acc.pop(c, None)
            idle = not self._spec_acc
        if idle:
            self.tb.set_spectrum_active(False)

    # ------------------------------------------------------------------ rendering (same API as RemoteCore)

    def summarize(self, ev: Event) -> dict:
        return summarize(ev.pkt, self.node_db)

    def details(self, ev: Event) -> str:
        return self.formatter.format(ev.pkt)

    @staticmethod
    def to_json(ev: Event) -> str:
        return Formatter.to_json(ev.pkt)

    @staticmethod
    def record(ev: Event) -> tuple[float, bytes, str]:
        from .pcap import record

        return record(ev.pkt)

    def _run(self):
        last_save = time.time()
        while not self._stop.is_set():
            try:
                frame = self._frames.get(timeout=0.25)
            except queue.Empty:
                frame = None
            if frame is not None:
                self._process(frame)
            if time.time() - last_save > 30:
                self.save()
                last_save = time.time()

    def _process(self, frame: RxFrame):
        st = self.stats.get(frame.receiver)
        if st is not None and not st.enabled:
            return
        if not self.protocol_enabled.get(frame.protocol, True):
            return
        pkt = self.decoders[frame.protocol].decode(frame)
        with self._lock:
            self._seq += 1
            ev = Event(pkt, frame, self._seq)
            self.totals["frames"] += 1
            self.per_protocol[frame.protocol] = self.per_protocol.get(frame.protocol, 0) + 1
            if not frame.crc_ok:
                self.totals["crc_err"] += 1
            if pkt.decrypted:
                self.totals["decrypted"] += 1
            if st is not None:
                st.frames += 1
                st.crc_errors += not frame.crc_ok
                st.decrypted += bool(pkt.decrypted)
                st.last_snr, st.last_time = frame.snr_db, frame.timestamp
                st.last_rssi = frame.rssi_dbm if frame.rssi_dbm is not None else frame.rssi_dbfs
            self.packets.append(ev)
        self._events.put(ev)
        for cb in self.callbacks:
            try:
                cb(ev)
            except Exception:
                log.exception("packet callback failed")

    def drain_events(self, limit: int = 500) -> list[Event]:
        out = []
        while len(out) < limit:
            try:
                out.append(self._events.get_nowait())
            except queue.Empty:
                break
        return out

    def band_for(self, frame: RxFrame) -> Band | None:
        return band_for(self.bands, frame)
