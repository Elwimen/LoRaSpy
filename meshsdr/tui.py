"""
Terminal UI (Textual), styled after btop: rounded boxes with titles in the border, the
btop default palette and its green→yellow→red graph gradient.

  ╭─ spectrum ─────────────────────────────────────────────────────────────╮
  │ ▁▂▅█▇▃ level bars (peak per column)                                     │
  │ ▀▀▀▀▀  waterfall (2 time rows per character row)                        │
  │ ━━━━━ band ruler: protocol-coloured channels, flashing on decodes       │
  ╰─────────────────────────────────────────────────────────────────────────╯
  ╭─ decoders ───────╮╭─ packets ─────────────────────────────────────────────╮
  │ [x] LongFast ... ││ time proto receiver kind from → to text                │
  ╰──────────────────╯╰────────────────────────────────────────────────────────╯
                      ╭─ details ─────────────────────────────────────────────╮
"""

import os
import time
from collections import deque

import numpy as np
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widget import Widget
from textual.widgets import DataTable, Footer, Static

from .bands import PROTOCOL_COLORS
from .core import MonitorCore

# btop "Default" theme
BTOP = {
    "bg": "#000000", "fg": "#cccccc", "title": "#eeeeee", "hi": "#b54040", "inactive": "#404040",
    "graph_text": "#606060", "div": "#303030", "selected_bg": "#6a2f2f",
    "cpu_box": "#3d7b46", "mem_box": "#8a882e", "net_box": "#423ba5", "proc_box": "#923535",
}
GRADIENT = [(0x77, 0xca, 0x9b), (0xcb, 0xc0, 0x6c), (0xdc, 0x4c, 0x4c)]           # btop cpu gradient
WATERFALL = [(0x05, 0x07, 0x10), (0x12, 0x2a, 0x55), (0x3d, 0x7b, 0x46), (0xcb, 0xc0, 0x6c), (0xdc, 0x4c, 0x4c)]
BARS = " ▁▂▃▄▅▆▇█"
PROTO_SHORT = {"meshtastic": "MT", "lorawan": "LW", "meshcore": "MC"}


def _grad(stops, x: float) -> str:
    x = min(max(x, 0.0), 1.0) * (len(stops) - 1)
    i = min(int(x), len(stops) - 2)
    t = x - i
    a, b = stops[i], stops[i + 1]
    return "#%02x%02x%02x" % tuple(int(a[k] + (b[k] - a[k]) * t) for k in range(3))


def _fit_label(label: str, room: int) -> str:
    """Drop trailing words until the label fits over its band, then truncate."""
    words = label.split(" ")
    while len(words) > 1 and len(" ".join(words)) > room:
        words.pop()
    return " ".join(words)[:max(room, 1)]


def _hex(rgb, dim: float = 1.0) -> str:
    return "#%02x%02x%02x" % tuple(int(c * dim) for c in rgb)


class SpectrumView(Widget):
    """Level bars + waterfall + band ruler, drawn with block characters."""

    DEFAULT_CSS = "SpectrumView { height: 1fr; }"

    def __init__(self, core: MonitorCore, **kw):
        super().__init__(**kw)
        self.core = core
        self.freqs = core.freq_axis_hz
        self.history: deque[np.ndarray] = deque(maxlen=200)   # per-column dB, newest last
        self.markers: deque[tuple[int, int, str]] = deque(maxlen=200)  # (history index, column, color)
        self.flash: dict[str, float] = {}                       # band label → flash until
        self.floor, self.ceil = -100.0, -40.0
        self._last_seq = -1
        self._rows_added = 0
        self.frozen = False
        self.current: np.ndarray | None = None   # latest frame, for the level bars
        self._acc: np.ndarray | None = None      # max-hold of frames for the next waterfall row
        self._row_started = time.time()
        self.wf_rows = 14                          # time rows visible (set by render)
        self.wf_span_s = 20.0

    # map the DC-centred FFT onto `width` columns, keeping the peak per column
    def _columns(self, db: np.ndarray, width: int) -> np.ndarray:
        edges = np.linspace(0, len(db), width + 1).astype(int)
        return np.array([db[a:max(b, a + 1)].max() for a, b in zip(edges[:-1], edges[1:])])

    def col_of(self, f_hz: float, width: int) -> int:
        lo, hi = self.freqs[0], self.freqs[-1]
        return int(round((f_hz - lo) / (hi - lo) * (width - 1)))

    def tick(self):
        if self.frozen:
            return
        db = self.core.take_spectrum("tui", "peak")   # peak over all FFTs since the last tick
        if db is None:
            return
        if len(self.freqs) != len(db):
            self.freqs = self.core.freq_axis_hz
        width = max(self.size.width, 10)
        cols = self._columns(db, width)
        if self.current is not None and len(self.current) != width:
            self.history.clear()
            self._acc = None
        self.current = cols
        # slow auto-ranging: floor just below the 20th percentile, at least a 30 dB span
        fl = float(np.percentile(cols, 20)) - 3
        self.floor = 0.95 * self.floor + 0.05 * fl
        self.ceil = max(0.95 * self.ceil + 0.05 * float(cols.max() + 3), self.floor + 30)
        # waterfall rows are max-holds over a time slice so the visible rows span ~wf_span_s
        self._acc = cols if self._acc is None else np.maximum(self._acc, cols)
        row_period = self.wf_span_s / max(self.wf_rows, 1)
        if time.time() - self._row_started >= row_period:
            self.history.append(self._acc)
            self._acc = None
            self._row_started = time.time()
            self._rows_added += 1
        self.refresh()

    def mark(self, freq_hz: float, color: str, band_label: str | None):
        width = max(self.size.width, 10)
        self.markers.append((self._rows_added, self.col_of(freq_hz, width), color))
        if band_label:
            self.flash[band_label] = time.time() + 1.5

    def render(self) -> Text:
        width, height = max(self.size.width, 10), max(self.size.height, 6)
        out = Text()
        if self.current is None or len(self.current) != width:
            out.append("waiting for spectrum…", style=BTOP["graph_text"])
            return out
        bands = self.core.bands
        # ruler rows: greedy stacking of overlapping bands
        rows: list[list] = []
        for b in bands:
            a, z = self.col_of(b.start_hz, width), self.col_of(b.end_hz, width)
            for r in rows:
                if all(z < ra or a > rz for ra, rz, _ in r):
                    r.append((a, z, b))
                    break
            else:
                rows.append([(a, z, b)])
        ruler_h = len(rows) * 2
        axis_h = 1
        remaining = height - ruler_h - axis_h
        bars_h = max(3, remaining * 2 // 5)
        wf_h = max(1, remaining - bars_h)
        self.wf_rows = 2 * wf_h

        span = max(self.ceil - self.floor, 1.0)
        cur = self.current
        level = np.clip((cur - self.floor) / span, 0, 1) * bars_h * 8
        # level bars, top row first
        for r in range(bars_h - 1, -1, -1):
            color = _grad(GRADIENT, (r + 0.5) / bars_h)
            line = []
            for c in range(width):
                v = level[c] - r * 8
                line.append(BARS[int(min(max(v, 0), 8))])
            out.append("".join(line), style=color)
            if r == bars_h - 1:
                pass
            out.append("\n")
        # waterfall: newest at top, 2 history rows per character row via ▀ (fg = newer, bg = older)
        hist = list(self.history)
        if self._acc is not None:
            hist.append(self._acc)          # the row still being accumulated
        marker_at = {}
        for idx, col, color in self.markers:
            age = self._rows_added - idx    # 0 = the row being accumulated
            marker_at[(age, col)] = color
        for r in range(wf_h):
            for c in range(width):
                ages = (2 * r, 2 * r + 1)
                vals = []
                for a in ages:
                    vals.append(hist[-1 - a][c] if a < len(hist) else self.floor)
                top = _grad(WATERFALL, (vals[0] - self.floor) / span)
                bot = _grad(WATERFALL, (vals[1] - self.floor) / span)
                mk = marker_at.get((ages[0], c)) or marker_at.get((ages[1], c))
                if mk:
                    out.append("◆", style=f"bold {mk} on {top}")
                else:
                    out.append("▀", style=f"{top} on {bot}")
            out.append("\n")
        # band ruler
        now = time.time()
        for r in rows:
            bar = [" "] * width
            styles = [None] * width
            labels = [" "] * width
            lstyles = [None] * width
            for a, z, b in r:
                hot = self.flash.get(b.label, 0) > now
                col = _hex(b.color, 1.0 if hot else 0.55)
                for c in range(max(a, 0), min(z, width - 1) + 1):
                    bar[c] = "█" if hot else "━"
                    styles[c] = col
                lbl = _fit_label(b.label, z - a + 1)
                start = max(0, min((a + z) // 2 - len(lbl) // 2, width - len(lbl)))
                for i, ch in enumerate(lbl):
                    if 0 <= start + i < width:
                        labels[start + i] = ch
                        lstyles[start + i] = f"bold {_hex(b.color)}" if hot else _hex(b.color, 0.9)
            for ch, st in zip(bar, styles):
                out.append(ch, style=st or BTOP["div"])
            out.append("\n")
            for ch, st in zip(labels, lstyles):
                out.append(ch, style=st or "")
            out.append("\n")
        # frequency axis
        axis = [" "] * width
        step = max(12, width // 8)
        for c in range(0, width - 8, step):
            s = f"{self.freqs[int(c / (width - 1) * (len(self.freqs) - 1))] / 1e6:.3f}"
            for i, ch in enumerate("┬" + s):
                if c + i < width:
                    axis[c + i] = ch
        out.append("".join(axis), style=BTOP["graph_text"])
        return out


class Stats(Static):
    def __init__(self, core: MonitorCore, **kw):
        super().__init__(**kw)
        self.core = core
        self._cpu = (time.process_time(), time.time())
        self._pct = 0.0

    def tick(self):
        c = self.core
        pt, wt = time.process_time(), time.time()
        dp, dw = pt - self._cpu[0], wt - self._cpu[1]
        if dw > 0.5:
            self._pct = 100 * dp / dw
            self._cpu = (pt, wt)
        up = int(time.time() - c.started)
        t = Text()
        t.append(" LoRaSpy ", style=f"bold {BTOP['title']} on {BTOP['cpu_box']}")
        t.append(f"  tuner {c.center_hz / 1e6:.4f} MHz  {c.sample_rate / 1e6:g} MS/s  ", style=BTOP["fg"])
        t.append(f"up {up // 3600:d}:{up // 60 % 60:02d}:{up % 60:02d}  ", style=BTOP["graph_text"])
        g = c.gain_info
        if g.get("supported"):
            t.append("gain " + ("AGC" if g.get("mode") == "auto" else f"{g.get('gain', 0):g} dB") + "  ",
                     style=BTOP["fg"])
        a = c.adc
        if a.get("clipping"):
            t.append(f" ⚠ CLIPPING {a['clip_ratio'] * 100:.2g}% — lower gain ([) ", style=f"bold white on {BTOP['hi']}")
            t.append("  ")
        elif a.get("peak_dbfs") is not None:
            t.append(f"ADC {a['peak_dbfs']:.0f} dBFS  ",
                     style=_grad(GRADIENT, min(max((a["peak_dbfs"] + 30) / 30, 0.0), 1.0)))
        t.append(f"cpu {self._pct:5.1f}%  ", style=_grad(GRADIENT, self._pct / (100 * (os.cpu_count() or 1)) * 4))
        t.append(f"frames {c.totals['frames']}  ", style=BTOP["fg"])
        for proto, rgb in PROTOCOL_COLORS.items():
            rxs = [r.name for r in c.cfg.receivers if r.protocol == proto]
            if rxs:
                on = any(c.stats[n].enabled for n in rxs)
                t.append(f"{PROTO_SHORT[proto]} {c.per_protocol.get(proto, 0)}  ",
                         style=_hex(rgb) if on else BTOP["inactive"])
        t.append(f"CRC✗ {c.totals['crc_err']}  ", style=BTOP["hi"] if c.totals["crc_err"] else BTOP["graph_text"])
        t.append(f"🔓 {c.totals['decrypted']}  ", style=BTOP["fg"])
        t.append(c.role, style=BTOP["graph_text"] if getattr(c, "connected", True) else BTOP["hi"])
        self.update(t)


class MonitorTUI(App):
    CSS = f"""
    Screen {{ background: {BTOP['bg']}; color: {BTOP['fg']}; }}
    Stats {{ height: 1; background: {BTOP['bg']}; }}
    #spectrum-box {{ height: 45%; border: round {BTOP['cpu_box']}; border-title-color: {BTOP['title']};
                    border-title-style: bold; padding: 0 1; }}
    #bottom {{ height: 1fr; }}
    #decoders {{ width: 50; border: round {BTOP['mem_box']}; border-title-color: {BTOP['title']};
                border-title-style: bold; }}
    #right {{ width: 1fr; }}
    #packets {{ height: 1fr; border: round {BTOP['net_box']}; border-title-color: {BTOP['title']};
               border-title-style: bold; }}
    #details-box {{ height: 40%; border: round {BTOP['proc_box']}; border-title-color: {BTOP['title']};
                   border-title-style: bold; }}
    DataTable {{ background: {BTOP['bg']}; scrollbar-size: 1 1; }}
    DataTable > .datatable--header {{ background: {BTOP['bg']}; color: {BTOP['graph_text']}; text-style: bold; }}
    DataTable > .datatable--cursor {{ background: {BTOP['selected_bg']}; color: {BTOP['title']}; }}
    DataTable:focus > .datatable--cursor {{ background: {BTOP['selected_bg']}; }}
    #details {{ padding: 0 1; }}
    Footer {{ background: {BTOP['bg']}; }}
    """

    BINDINGS = [
        Binding("q", "quit", "quit"),
        # btop-style: number keys show/hide the numbered boxes
        Binding("1", "toggle_box('spectrum-box')", "spectrum"),
        Binding("2", "toggle_box('decoders')", "decoders"),
        Binding("3", "toggle_box('packets')", "packets"),
        Binding("4", "toggle_box('details-box')", "details"),
        Binding("space", "toggle_decoder", "toggle decoder"),
        Binding("m", "toggle_proto('meshtastic')", "Meshtastic"),
        Binding("o", "toggle_proto('meshcore')", "MeshCore"),
        Binding("w", "toggle_proto('lorawan')", "LoRaWAN"),
        Binding("p", "pause", "pause list"),
        Binding("f", "freeze", "freeze spectrum"),
        Binding("x", "clear", "clear"),
        Binding("left_square_bracket", "gain(-1)", "gain−"),
        Binding("right_square_bracket", "gain(1)", "gain+"),
        Binding("g", "gain_agc", "AGC"),
        Binding("k", "keys", "keys"),
    ]

    def __init__(self, core: MonitorCore):
        super().__init__()
        self.core = core
        self.paused = False
        self.events: dict[str, object] = {}

    def compose(self) -> ComposeResult:
        yield Stats(self.core, id="stats")
        with Vertical(id="spectrum-box"):
            yield SpectrumView(self.core, id="spectrum")
        with Horizontal(id="bottom"):
            yield DataTable(id="decoders", cursor_type="row", zebra_stripes=False)
            with Vertical(id="right"):
                yield DataTable(id="packets", cursor_type="row")
                with VerticalScroll(id="details-box"):
                    yield Static("select a packet", id="details")
        yield Footer()

    def on_mount(self):
        self.query_one("#spectrum-box").border_title = "¹spectrum"
        self.query_one("#spectrum-box").border_subtitle = "waterfall ≈20 s · bands flash on decode · ◆ decoded packet"
        dec = self.query_one("#decoders", DataTable)
        dec.border_title = "²decoders"
        dec.add_columns(" ", "receiver", "frm", "crc✗", "rssi", "snr", "ago")
        order = {"meshtastic": 0, "meshcore": 1, "lorawan": 2}
        for rx in sorted(self.core.cfg.receivers, key=lambda r: order.get(r.protocol, 9)):
            dec.add_row(*self._decoder_row(rx.name), key=rx.name)
        pk = self.query_one("#packets", DataTable)
        pk.border_title = "³packets"
        pk.add_columns("time", "  ", "receiver", "kind", "from", "to", "text")
        self.query_one("#details-box").border_title = "⁴details"
        self.set_interval(1 / 15, self._fast)
        self.set_interval(0.5, self._slow)

    def _decoder_row(self, name):
        rx = next(r for r in self.core.cfg.receivers if r.name == name)
        st = self.core.stats[name]
        on = st.enabled
        color = _hex(PROTOCOL_COLORS[rx.protocol]) if on else BTOP["inactive"]
        ago = "" if st.last_time is None else f"{int(time.time() - st.last_time)}s"
        return (Text("■" if on else "□", style=color), Text(name, style=color if on else BTOP["inactive"]),
                str(st.frames), Text(str(st.crc_errors), style=BTOP["hi"] if st.crc_errors else BTOP["graph_text"]),
                "" if st.last_rssi is None else f"{st.last_rssi:.0f}",
                "" if st.last_snr is None else f"{st.last_snr:.0f}", ago)

    def _fast(self):
        spec = self.query_one("#spectrum", SpectrumView)
        spec.tick()
        for ev in self.core.drain_events():
            band = self.core.band_for(ev.frame)
            color = _hex(PROTOCOL_COLORS[ev.frame.protocol])
            spec.mark(ev.frame.frequency_hz, color, band.label if band else None)
            if not self.paused:
                self._add_packet(ev)

    def _slow(self):
        self.query_one("#stats", Stats).tick()
        dec = self.query_one("#decoders", DataTable)
        for rx in self.core.cfg.receivers:
            row = self._decoder_row(rx.name)
            for col, val in zip(dec.columns.keys(), row):
                dec.update_cell(rx.name, col, val)

    def _add_packet(self, ev):
        s = self.core.summarize(ev)
        color = _hex(PROTOCOL_COLORS[ev.frame.protocol])
        dim = BTOP["hi"] if not s["ok"] else color
        pk = self.query_one("#packets", DataTable)
        key = str(ev.seq)
        self.events[key] = ev
        pk.add_row(Text(time.strftime("%H:%M:%S", time.localtime(ev.frame.timestamp)), style=BTOP["graph_text"]),
                   Text(PROTO_SHORT[ev.frame.protocol], style=f"bold {color}"),
                   Text(ev.frame.receiver, style=color),
                   Text(("⚠ " if getattr(ev.frame, "clipped", False) else "") + s["kind"][:16],
                        style=BTOP["hi"] if getattr(ev.frame, "clipped", False) else dim),
                   s["src"][:22], s["dst"][:14],
                   Text(s["text"][:120], style=BTOP["title"] if s["ok"] else BTOP["hi"]), key=key)
        if pk.row_count > 1000:
            first = next(iter(pk.rows))
            pk.remove_row(first)
            self.events.pop(first.value, None)
        if pk.cursor_row >= pk.row_count - 2 or not pk.has_focus:
            pk.move_cursor(row=pk.row_count - 1)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted):
        if event.data_table.id != "packets" or event.row_key is None:
            return
        ev = self.events.get(event.row_key.value)
        if ev is not None:
            self.query_one("#details", Static).update(Text(self.core.details(ev)))

    def action_toggle_box(self, box_id: str):
        box = self.query_one(f"#{box_id}")
        box.display = not box.display
        self._relayout()

    def _relayout(self):
        """Let the visible boxes take the space of the hidden ones."""
        spec, dec = self.query_one("#spectrum-box"), self.query_one("#decoders")
        pk, det = self.query_one("#packets"), self.query_one("#details-box")
        right, bottom = self.query_one("#right"), self.query_one("#bottom")
        right.display = pk.display or det.display
        bottom.display = dec.display or right.display
        spec.styles.height = "45%" if bottom.display else "1fr"
        det.styles.height = "40%" if pk.display else "1fr"
        dec.styles.width = 50 if right.display else "1fr"

    def action_toggle_decoder(self):
        dec = self.query_one("#decoders", DataTable)
        if dec.row_count == 0:
            return
        name = dec.coordinate_to_cell_key(dec.cursor_coordinate).row_key.value
        on = {n for n, st in self.core.stats.items() if st.enabled} ^ {name}
        self.core.set_receivers_enabled(on)   # gates the demodulator (and its filter) on/off
        self._slow()

    def action_toggle_proto(self, proto: str):
        """All receivers of a protocol off if any is on, otherwise all on."""
        mine = {rx.name for rx in self.core.cfg.receivers if rx.protocol == proto}
        on = {n for n, st in self.core.stats.items() if st.enabled}
        on = on - mine if on & mine else on | mine
        self.core.set_receivers_enabled(on)
        self._slow()

    def action_keys(self):
        from .tui_keys import KeysScreen

        self.push_screen(KeysScreen(self.core))

    def action_gain(self, step: int):
        """Next/previous tuner gain step (leaves AGC). Shared with every front-end on this SDR."""
        g = self.core.gain_info
        steps = g.get("steps") or []
        if not g.get("supported") or not steps:
            self.notify("gain is only adjustable on a live SDR", severity="warning")
            return
        cur = g.get("gain")
        i = len(steps) // 2 if cur is None else min(range(len(steps)), key=lambda k: abs(steps[k] - cur))
        if cur is not None:
            i = min(max(i + step, 0), len(steps) - 1)
        self._set_gain(steps[i])

    def action_gain_agc(self):
        g = self.core.gain_info
        if not g.get("supported"):
            self.notify("gain is only adjustable on a live SDR", severity="warning")
            return
        steps = g.get("steps") or [40.0]
        self._set_gain(steps[len(steps) // 2] if g.get("mode") == "auto" else "auto")

    def _set_gain(self, value):
        try:
            self.core.set_gain(value)
        except ValueError as e:
            self.notify(str(e), severity="warning")
            return
        self.notify("gain: AGC" if value == "auto" else f"gain: {value:g} dB", timeout=2)

    def action_pause(self):
        self.paused = not self.paused
        self.query_one("#packets").border_subtitle = "PAUSED" if self.paused else ""

    def action_freeze(self):
        spec = self.query_one("#spectrum", SpectrumView)
        spec.frozen = not spec.frozen
        self.query_one("#spectrum-box").border_subtitle = "FROZEN" if spec.frozen else \
            "waterfall ≈20 s · bands flash on decode · ◆ decoded packet"

    def action_clear(self):
        self.query_one("#packets", DataTable).clear()
        self.events.clear()
        self.query_one("#details", Static).update("select a packet")


def run_tui(core: MonitorCore):
    """Runs until the user quits; the caller starts and stops the (local or remote) core."""
    import signal

    app = MonitorTUI(core)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: app.exit())
    try:
        app.run()
    finally:
        core.release_spectrum("tui")
