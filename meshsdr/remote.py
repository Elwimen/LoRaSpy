"""
RemoteCore: a front-end's view of a MonitorCore running in another process (meshsdr.server).

It offers the part of MonitorCore's interface the GUI, TUI, text mode and Wireshark extcap
use — drain_events, take_spectrum, stats, set_receivers_enabled, apply_spectrum, summarize,
details, … — so they run unchanged against a shared RTL-SDR. Needs no GNU Radio.

Frames arrive already decoded and rendered by the server (it holds the keys and node DBs);
spectrum frames arrive at SUBSCRIBE_FPS and are combined per consumer with the requested
detector (peak = max, mean = linear average), like MonitorCore.take_spectrum.
"""

import json
import logging
import queue
import socket
import threading
import time
from dataclasses import dataclass, field
from types import SimpleNamespace

import numpy as np

from . import share
from .bands import Band, band_for
from .radio import ReceiverParams

log = logging.getLogger(__name__)

SUBSCRIBE_FPS = 30.0


@dataclass
class RemoteEvent:
    seq: int
    received: float
    frame: SimpleNamespace          # RxFrame fields; data as bytes
    kind: str
    summary: dict
    details: str
    json: str
    record: tuple                   # (timestamp, LoRaTap bytes, comment) for pcap / Wireshark
    show: bool = True               # passes the client's --format filters (show CRC errors, …)
    text: str | None = None         # rendered in the client's --format, when it asked for one
    history: bool = False           # replayed from before this client attached
    pkt: None = field(default=None, repr=False)


class RemoteCore:
    remote = True
    node_db = None

    def __init__(self, path: str | None = None, name: str = "client", *, format_opts: dict | None = None,
                 history: int = 0, reconnect: bool = False):
        self.path = path or share.default_socket_path()
        self.name = name
        self.format_opts = format_opts
        self.history = history
        self.reconnect = reconnect
        self.callbacks = []
        self.finished = threading.Event()   # server gone (and not reconnecting)
        self.connected = False
        self.server_pid = None
        self.source = ""
        self.clients = 0
        self._events: queue.Queue[RemoteEvent] = queue.Queue()
        self._sock: socket.socket | None = None
        self._send_lock = threading.Lock()
        self._spec_lock = threading.Lock()
        self._spec: dict[str, list] = {}        # consumer → [detector, accumulator, count]
        self._stopping = False
        self._thread: threading.Thread | None = None
        self._req = 0
        self._waiting: dict[int, list] = {}    # request id → [Event, reply]
        self.keys_version = 0
        self.receivers_version = 0
        self.on_rebuild = []                    # fn(), after the server's decoder set changed
        self._connect()                         # raises OSError / ConnectionError when nobody serves

    # ------------------------------------------------------------------ connection

    def _connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        try:
            sock.connect(self.path)
            kind, body = share.recv_message(sock)
            hello = json.loads(body) if kind == share.KIND_JSON else {}
            if hello.get("type") != "hello":
                raise ConnectionError("not a LoRaSpy server")
            if hello.get("version") != share.PROTOCOL_VERSION:
                raise ConnectionError(f"server speaks protocol {hello.get('version')}, "
                                      f"this client {share.PROTOCOL_VERSION}")
        except BaseException:
            sock.close()
            raise
        sock.settimeout(None)
        self._sock = sock
        self._apply_hello(hello)
        self._send({"cmd": "hello", "name": self.name, "format": self.format_opts, "history": self.history})
        self._subscribe()
        self.connected = True

    def _apply_hello(self, h: dict):
        self.server_pid = h.get("pid")
        self.source = h.get("source", "")
        self.center_hz = h["center_hz"]
        self.sample_rate = h["sample_rate"]
        self.started = h["started"]
        self.cfg = SimpleNamespace(receivers=[ReceiverParams(**d) for d in h["receivers"]],
                                   region=h.get("region", "EU_868"))
        self.receivers_version = h.get("receivers_version", 0)
        self.bands = [Band(**d) for d in h["bands"]]
        self.regulatory = [Band(**d) for d in h["regulatory"]]
        if not hasattr(self, "stats"):
            self.stats = {}                     # kept across reconnects: the UIs hold its keys
        self._apply_stats(h)
        self._apply_config(h)

    def _apply_config(self, m: dict):
        self.fft_size = m["fft_size"]
        self.window = m["window"]
        self.center_hz = m.get("center_hz", getattr(self, "center_hz", 0.0))
        self._in_range = set(m["in_range"]) if "in_range" in m else None
        self.tunable = m.get("tunable", False)
        self._channels = m.get("channels", [])
        if "rx_freq" in m and hasattr(self, "cfg"):
            for rx in self.cfg.receivers:
                rx.frequency_hz = m["rx_freq"].get(rx.name, rx.frequency_hz)
        if "bands" in m and m.get("bands_version", 0) != getattr(self, "bands_version", 0):
            self.bands = [Band(**d) for d in m["bands"]]
        self.bands_version = m.get("bands_version", 0)
        self.gain_info = m.get("gain", {"supported": False, "mode": "auto", "gain": None, "steps": []})
        on = set(m["enabled"])
        for name, st in self.stats.items():
            st.enabled = name in on
        self._enabled = on

    def _apply_stats(self, m: dict):
        for name, d in m["stats"].items():
            if name in self.stats:
                vars(self.stats[name]).update(d)
            else:
                self.stats[name] = SimpleNamespace(**d)
        self.totals = m["totals"]
        self.per_protocol = m["per_protocol"]
        self.clients = m.get("clients", self.clients)
        self.restarts = m.get("restarts", 0)
        self.adc = m.get("adc", {"peak_dbfs": None, "clipped": 0, "clip_ratio": 0.0, "clipping": False})

    def _send(self, obj: dict):
        sock = self._sock
        if sock is None:
            return
        try:
            with self._send_lock:
                sock.sendall(share.pack_json(obj))
        except OSError:
            pass   # the reader notices the disconnect

    def _subscribe(self):
        with self._spec_lock:
            dets = sorted({v[0] for v in self._spec.values()})
        self._send({"cmd": "spectrum", "fps": SUBSCRIBE_FPS if dets else 0, "detectors": dets})

    # ------------------------------------------------------------------ lifecycle (MonitorCore API)

    def start(self):
        self._thread = threading.Thread(target=self._run, name="remote-core", daemon=True)
        self._thread.start()

    def stop(self):
        self._stopping = True
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def save(self):
        pass   # the server owns the node databases

    def _run(self):
        while not self._stopping:
            try:
                while True:
                    kind, body = share.recv_message(self._sock)
                    if kind == share.KIND_JSON:
                        self._handle(json.loads(body))
                    elif kind == share.KIND_SPECTRUM:
                        self._on_spectrum(*share.unpack_spectrum(body))
            except (OSError, ConnectionError, ValueError, AttributeError) as e:
                if self._stopping:
                    break
                log.info("lost the LoRaSpy server: %s", e)
            self.connected = False
            if not self.reconnect:
                break
            while not self._stopping:          # wait for a server to come (back)
                time.sleep(1.0)
                try:
                    self._connect()
                    log.info("re-attached to %s", self.path)
                    break
                except (OSError, ConnectionError, ValueError):
                    continue
        self.connected = False
        self.finished.set()

    def _handle(self, m: dict):
        t = m.get("type")
        if t == "event":
            f = m["frame"]
            f["data"] = bytes.fromhex(f["data"])
            ts, data, comment = m["record"]
            ev = RemoteEvent(seq=m["seq"], received=m["received"], frame=SimpleNamespace(**f), kind=m["kind"],
                             summary=m["summary"], details=m["details"], json=m["json"],
                             record=(ts, bytes.fromhex(data), comment), show=m.get("show", True),
                             text=m.get("text"), history=m.get("history", False))
            self._events.put(ev)
            for cb in self.callbacks:
                try:
                    cb(ev)
                except Exception:
                    log.exception("packet callback failed")
        elif t == "stats":
            self._apply_stats(m)
        elif t == "config":
            self._apply_config(m)
        elif t == "reply":
            slot = self._waiting.get(m.get("req"))
            if slot is not None:
                slot[1] = m
                slot[0].set()
        elif t == "reconfigured":
            names = [d["name"] for d in m["receivers"]]
            self.stats = {n: self.stats[n] for n in names if n in self.stats}   # new dict: the UIs rebuild
            self._apply_hello(m)
            for cb in self.on_rebuild:
                try:
                    cb()
                except Exception:
                    log.exception("rebuild listener failed")
        elif t == "keys_changed":
            self.keys_version += 1
        elif t == "bye":
            log.info("server says bye: %s", m.get("reason"))

    # ------------------------------------------------------------------ control (shared by all clients)

    def set_receivers_enabled(self, names: set[str]):
        for name, st in self.stats.items():
            st.enabled = name in names           # optimistic; the server's config message confirms
        self._send({"cmd": "enable", "receivers": sorted(names)})

    def _request(self, msg: dict, timeout: float = 10.0) -> dict:
        """A command the server answers ('reply' with ok / error)."""
        if not self.connected:
            raise ValueError("not connected to the LoRaSpy server")
        with self._send_lock:
            self._req += 1
            rid = self._req
        slot = self._waiting[rid] = [threading.Event(), None]
        try:
            self._send({**msg, "req": rid})
            if not slot[0].wait(timeout):
                raise ValueError("the LoRaSpy server did not answer")
        finally:
            self._waiting.pop(rid, None)
        if not slot[1].get("ok"):
            raise ValueError(slot[1].get("error") or "refused")
        return slot[1]

    # keys and channels: edited in the server's keys.jsonc, applied live (same API as MonitorCore)
    def keys_list(self) -> list[dict]:
        return self._request({"cmd": "keys", "op": "list"})["entries"]

    def keys_add(self, kind: str, fields: dict):
        self._request({"cmd": "keys", "op": "add", "kind": kind, "fields": fields})

    def keys_update(self, kind: str, index: int, fields: dict):
        self._request({"cmd": "keys", "op": "update", "kind": kind, "index": index, "fields": fields})

    def keys_remove(self, kind: str, index: int):
        self._request({"cmd": "keys", "op": "remove", "kind": kind, "index": index})

    def record_iq(self, freq_hz=None, bw_hz=None, duration_s: float = 10, fmt: str = "cf32",
                  name: str | None = None) -> dict:
        """Recorded by the process that owns the SDR, into its recordings/ folder."""
        return self._request({"cmd": "record", "freq_hz": freq_hz, "bw_hz": bw_hz, "duration_s": duration_s,
                              "format": fmt, "name": name})["recording"]

    def recordings(self) -> list[dict]:
        return self._request({"cmd": "record", "op": "status"})["recordings"]

    # decoder set: edited in the server's decoders.jsonc (same API as MonitorCore)
    def decoder_list(self) -> list[dict]:
        return self._request({"cmd": "decoder", "op": "list"})["decoders"]

    def decoder_add(self, spec: dict) -> list[str]:
        return self._request({"cmd": "decoder", "op": "add", "spec": spec}, timeout=30)["result"]

    def decoder_update(self, name: str, params: dict) -> str:
        return self._request({"cmd": "decoder", "op": "update", "name": name, "params": params}, timeout=30)["result"]

    def decoder_reset(self, name: str) -> str:
        return self._request({"cmd": "decoder", "op": "reset", "name": name}, timeout=30)["result"]

    def decoder_remove(self, name: str) -> list[str]:
        return self._request({"cmd": "decoder", "op": "remove", "name": name}, timeout=30)["result"]

    def channels(self) -> list[dict]:
        return list(self._channels)

    def set_channel_frequency(self, receiver: str, hz: float) -> list[str]:
        return self._request({"cmd": "channel", "receiver": receiver, "hz": float(hz)})["receivers"]

    def set_center(self, hz: float):
        """Retune the shared SDR (decoders stay on their channels)."""
        self._request({"cmd": "tune", "hz": float(hz)})

    @property
    def in_range(self) -> set[str]:
        return set(self.stats) if self._in_range is None else set(self._in_range)

    @property
    def active(self) -> set[str]:
        return self.enabled & self.in_range

    def set_gain(self, value):
        """'auto' or dB; the server applies it to the shared SDR and tells everybody."""
        if not self.gain_info.get("supported"):
            raise ValueError("gain can only be changed on a live SDR")
        self._send({"cmd": "gain", "value": value})

    def apply_spectrum(self, fft_size: int, window: str):
        if (fft_size, window) != (self.fft_size, self.window):
            self.fft_size, self.window = fft_size, window
            self._send({"cmd": "fft", "fft_size": fft_size, "window": window})

    @property
    def enabled(self) -> set[str]:
        return {n for n, st in self.stats.items() if st.enabled}

    @property
    def role(self) -> str:
        if not self.connected:
            return "server gone — waiting for it" if self.reconnect else "server gone"
        r = self.restarts
        return f"attached to pid {self.server_pid} ({self.clients} client{'s' * (self.clients != 1)})" + \
            (f" · {r} stall restart{'s' * (r != 1)}" if r else "")

    # ------------------------------------------------------------------ data

    def _on_spectrum(self, header: dict, db: np.ndarray):
        det = header.get("det", "peak")
        if len(db) != self.fft_size:
            return                               # FFT size is changing
        lin = None
        with self._spec_lock:
            for acc in self._spec.values():
                if acc[0] != det:
                    continue
                if det == "mean":
                    if lin is None:
                        lin = 10 ** (db / 10)
                    val = lin
                else:
                    val = db
                if acc[1] is None or len(acc[1]) != len(val):
                    acc[1], acc[2] = val.copy(), 1
                else:
                    if det == "mean":
                        acc[1] += val
                    else:
                        np.maximum(acc[1], val, out=acc[1])
                    acc[2] += 1

    def take_spectrum(self, consumer: str, detector: str = "peak") -> np.ndarray | None:
        with self._spec_lock:
            acc = self._spec.get(consumer)
            changed = acc is None or acc[0] != detector
            if changed:
                acc = self._spec[consumer] = [detector, None, 0]
            val, n = acc[1], acc[2]
            acc[1], acc[2] = None, 0
        if changed:
            self._subscribe()
        if val is None or n == 0:
            return None
        return val if detector == "peak" else 10 * np.log10(val / n + 1e-20)

    def release_spectrum(self, *consumers: str):
        with self._spec_lock:
            for c in consumers:
                self._spec.pop(c, None)
        self._subscribe()

    def drain_events(self, limit: int = 500) -> list[RemoteEvent]:
        out = []
        while len(out) < limit:
            try:
                out.append(self._events.get_nowait())
            except queue.Empty:
                break
        return out

    @property
    def freq_axis_hz(self) -> np.ndarray:
        n = self.fft_size
        return self.center_hz + (np.arange(n) - n / 2) * self.sample_rate / n

    def band_for(self, frame) -> Band | None:
        return band_for(self.bands, frame)

    @staticmethod
    def summarize(ev: RemoteEvent) -> dict:
        return ev.summary

    @staticmethod
    def details(ev: RemoteEvent) -> str:
        return ev.details

    @staticmethod
    def to_json(ev: RemoteEvent) -> str:
        return ev.json

    @staticmethod
    def record(ev: RemoteEvent) -> tuple:
        return ev.record
