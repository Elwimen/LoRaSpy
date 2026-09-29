"""
Share one MonitorCore (one RTL-SDR, one set of decoders) with any number of front-ends in
other processes: GUI, TUI, text mode and the Wireshark extcap attach to the Unix socket and
get the same frames, spectrum and statistics; receiver and FFT changes made by any of them
apply to the shared flowgraph and are broadcast to all. See meshsdr/share.py for the wire format.
"""

import json
import logging
import os
import queue
import socket
import threading
import time
from dataclasses import asdict

from . import share
from .formatter import Formatter
from .ui_settings import FFT_SIZES, WINDOWS

log = logging.getLogger(__name__)

SPECTRUM_BACKLOG = 16        # skip spectrum frames for a client that has this many messages queued
EVENT_BACKLOG = 20000        # a client this far behind on events is disconnected


def frame_dict(frame) -> dict:
    d = asdict(frame)
    d["data"] = frame.data.hex()
    return d


class _Client:
    def __init__(self, server: "Server", sock: socket.socket, cid: int):
        self.server, self.sock, self.cid = server, sock, cid
        self.name = f"client{cid}"
        self.q: queue.Queue[bytes | None] = queue.Queue(maxsize=EVENT_BACKLOG)
        self.fmt: Formatter | None = None
        self.fps = 0.0
        self.detectors: set[str] = set()
        self.alive = True
        self.attached = False       # sent its hello (liveness probes never do)
        self.connected_at = time.time()

    # ---- threads
    def start(self):
        for target, what in ((self._reader, "rd"), (self._writer, "wr"), (self._spectrum, "sp")):
            threading.Thread(target=target, name=f"share-{what}{self.cid}", daemon=True).start()

    def _reader(self):
        try:
            while self.alive:
                kind, body = share.recv_message(self.sock)
                if kind == share.KIND_JSON:
                    self.server._command(self, json.loads(body))
        except (OSError, ConnectionError, ValueError) as e:
            if self.alive:
                log.debug("%s: %s", self.name, e)
        finally:
            self.close()

    def _writer(self):
        try:
            while True:
                msg = self.q.get()
                if msg is None:
                    break
                self.sock.sendall(msg)
        except OSError:
            pass
        finally:
            self.close()

    def _spectrum(self):
        core = self.server.core
        while self.alive:
            if self.fps <= 0 or not self.detectors:
                time.sleep(0.1)
                continue
            time.sleep(1.0 / self.fps)
            for det in list(self.detectors):
                db = core.take_spectrum(f"{self.name}:{det}", det)
                if db is not None and self.q.qsize() < SPECTRUM_BACKLOG:
                    self.send(share.pack_spectrum({"det": det, "fft": len(db)}, db))

    # ---- helpers
    def send(self, msg: bytes):
        if not self.alive:
            return
        try:
            self.q.put_nowait(msg)
        except queue.Full:
            log.warning("%s is not keeping up, disconnecting it", self.name)
            self.close()

    def set_detectors(self, dets: set[str]):
        gone = self.detectors - dets
        self.detectors = dets
        if gone:
            self.server.core.release_spectrum(*(f"{self.name}:{d}" for d in gone))

    def close(self):
        if not self.alive:
            return
        self.alive = False
        self.server._drop(self)
        self.server.core.release_spectrum(*(f"{self.name}:{d}" for d in self.detectors))
        try:
            self.q.put_nowait(None)
        except queue.Full:
            pass
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class Server:
    def __init__(self, core, path: str | None = None, source: str = ""):
        self.core = core
        self.path = path or share.default_socket_path()
        self.source = source
        self._clients: dict[int, _Client] = {}
        self._lock = threading.Lock()
        self._next = 1
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self.clients_changed = threading.Event()

    @property
    def client_count(self) -> int:
        return sum(c.attached for c in list(self._clients.values()))

    def client_names(self) -> list[str]:
        return [c.name for c in list(self._clients.values()) if c.attached]

    # ------------------------------------------------------------------ lifecycle

    def start(self):
        if share.server_alive(self.path):
            raise RuntimeError(f"another LoRaSpy already serves {self.path}")
        if os.path.exists(self.path):
            os.unlink(self.path)                  # stale socket from a crashed run
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)                     # user-only socket (0600)
        try:
            sock.bind(self.path)
        finally:
            os.umask(old)
        sock.listen(8)
        sock.settimeout(0.5)
        self._sock = sock
        self.core.server = self
        self.core.callbacks.append(self._on_event)
        self.core.on_change.append(self._on_change)
        self.core.on_keys.append(self._on_keys)
        threading.Thread(target=self._accept, name="share-accept", daemon=True).start()
        threading.Thread(target=self._stats_loop, name="share-stats", daemon=True).start()
        log.info("sharing on %s", self.path)
        return self

    def stop(self):
        if self._stop.is_set():
            return
        self._stop.set()
        self._broadcast(share.pack_json({"type": "bye", "reason": "server stopped"}))
        deadline = time.time() + 1.0
        while time.time() < deadline and any(c.q.qsize() for c in list(self._clients.values())):
            time.sleep(0.02)
        for c in list(self._clients.values()):
            c.close()
        if self._sock is not None:
            self._sock.close()
            try:
                os.unlink(self.path)
            except OSError:
                pass

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(None)
            with self._lock:
                c = _Client(self, conn, self._next)
                self._next += 1
                self._clients[c.cid] = c
            c.send(share.pack_json(self._hello()))
            c.start()

    def _drop(self, c: _Client):
        with self._lock:
            self._clients.pop(c.cid, None)
        if c.attached:
            log.info("%s disconnected", c.name)
            self.clients_changed.set()

    # ------------------------------------------------------------------ messages

    def _hello(self) -> dict:
        core = self.core
        return {"type": "hello", "version": share.PROTOCOL_VERSION, "pid": os.getpid(), "source": self.source,
                "center_hz": core.center_hz, "sample_rate": core.sample_rate, "started": core.started,
                "receivers": [asdict(rx) for rx in core.cfg.receivers],
                "bands": [asdict(b) for b in core.bands], "regulatory": [asdict(b) for b in core.regulatory],
                **self._config(), **self._stats()}

    def _config(self) -> dict:
        c = self.core
        return {"enabled": sorted(c.enabled), "fft_size": c.fft_size, "window": c.window, "gain": c.gain_info}

    def _stats(self) -> dict:
        c = self.core
        return {"stats": {n: asdict(st) for n, st in c.stats.items()}, "totals": dict(c.totals),
                "per_protocol": dict(c.per_protocol), "clients": self.client_count, "restarts": c.restarts,
                "adc": c.adc}

    def _broadcast(self, msg: bytes):
        for c in list(self._clients.values()):
            c.send(msg)

    def _stats_loop(self):
        while not self._stop.wait(0.5):
            if self._clients:
                self._broadcast(share.pack_json({"type": "stats", **self._stats()}))

    def _on_keys(self):
        self._broadcast(share.pack_json({"type": "keys_changed", "version": self.core.keys_version}))

    @staticmethod
    def _reply(c: _Client, msg: dict, **kw):
        c.send(share.pack_json({"type": "reply", "req": msg.get("req"), **kw}))

    def _keys_command(self, c: _Client, msg: dict):
        """Key editors (GUI/TUI/CLI) on other processes; entries include secrets, which is fine
        for this user-only socket."""
        core, op = self.core, msg.get("op", "list")
        try:
            if op == "add":
                core.keys_add(msg["kind"], msg.get("fields") or {})
            elif op == "update":
                core.keys_update(msg["kind"], int(msg["index"]), msg.get("fields") or {})
            elif op == "remove":
                core.keys_remove(msg["kind"], int(msg["index"]))
            elif op != "list":
                raise ValueError(f"unknown keys operation '{op}'")
            if op != "list":
                log.info("%s: keys %s %s", c.name, op, msg.get("kind"))
            self._reply(c, msg, ok=True, entries=core.keys_list())
        except (ValueError, KeyError, TypeError, OSError) as e:
            self._reply(c, msg, ok=False, error=str(e))

    def _on_change(self):
        self._broadcast(share.pack_json({"type": "config", **self._config()}))

    def _render(self, ev) -> dict:
        core = self.core
        ts, data, comment = core.record(ev)
        return {"type": "event", "seq": ev.seq, "received": ev.received, "frame": frame_dict(ev.frame),
                "kind": getattr(ev.pkt, "kind", "") or "", "summary": core.summarize(ev),
                "details": core.details(ev), "json": core.to_json(ev), "record": [ts, data.hex(), comment]}

    def _event_for(self, c: _Client, base: dict, ev) -> bytes | None:
        if c.fmt is None:
            return None
        return share.pack_json({**base, "show": c.fmt.wants(ev.pkt), "text": c.fmt.format(ev.pkt)})

    def _on_event(self, ev):
        """Decoder worker thread: render each frame once, send it to every client."""
        clients = list(self._clients.values())
        if not clients:
            return
        try:
            base = self._render(ev)
        except Exception:
            log.exception("rendering frame %d failed", ev.seq)
            return
        shared = share.pack_json(base)
        for c in clients:
            c.send(self._event_for(c, base, ev) or shared)

    def _command(self, c: _Client, msg: dict):
        cmd = msg.get("cmd")
        if cmd == "hello":
            c.name = f"{str(msg.get('name', 'client'))[:24]}#{c.cid}"
            f = msg.get("format")
            if f:
                c.fmt = Formatter(f.get("format", "text"), bool(f.get("colored")), self.core.node_db,
                                  bool(f.get("show_crc_errors")), bool(f.get("show_undecrypted", True)))
            n = int(msg.get("history", 0))
            if n > 0:
                with self.core._lock:
                    recent = list(self.core.packets)[-n:]
                for ev in recent:
                    base = self._render(ev)
                    c.send(self._event_for(c, {**base, "history": True}, ev) or
                           share.pack_json({**base, "history": True}))
            c.attached = True
            log.info("%s attached", c.name)
            self.clients_changed.set()
        elif cmd == "spectrum":
            c.fps = min(max(float(msg.get("fps", 0)), 0.0), 60.0)
            c.set_detectors({d for d in msg.get("detectors", []) if d in ("peak", "mean")})
        elif cmd == "enable":
            self.core.set_receivers_enabled(set(msg.get("receivers", [])))
        elif cmd == "keys":
            self._keys_command(c, msg)
        elif cmd == "gain":
            try:
                self.core.set_gain(msg.get("value"))
            except (ValueError, TypeError) as e:
                log.info("%s: gain %r refused: %s", c.name, msg.get("value"), e)
        elif cmd == "fft":
            size, window = int(msg.get("fft_size", self.core.fft_size)), msg.get("window", self.core.window)
            if size in FFT_SIZES and window in WINDOWS:
                self.core.apply_spectrum(size, window)
        else:
            log.debug("%s: unknown command %r", c.name, cmd)
