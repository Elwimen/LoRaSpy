"""
Qt/pyqtgraph GUI: spectrum + waterfall with protocol band overlays (LoRaWAN split into its
channels, Meshtastic, MeshCore, EU868 duty-cycle sub-bands), decoded-packet markers on the
waterfall, a decoder tree with checkboxes and a packet log with a detail view.
Palette follows btop's default theme, like the TUI.
"""

import time

import numpy as np
import pyqtgraph as pg
from pyqtgraph.Qt import QtCore, QtGui, QtWidgets

from . import ui_settings
from .bands import PROTOCOL_COLORS
from .core import MonitorCore
from .ui_settings import COLORMAPS, DETECTORS, FFT_SIZES, WINDOWS, UISettings

BG, FG, DIV, TITLE, HI = "#0b0d10", "#cccccc", "#303030", "#eeeeee", "#b54040"
BOX = {"spectrum": "#3d7b46", "decoders": "#8a882e", "packets": "#423ba5", "details": "#923535"}
WATERFALL_STOPS = [(0.0, (5, 7, 16)), (0.25, (18, 42, 85)), (0.5, (61, 123, 70)),
                   (0.75, (203, 192, 108)), (1.0, (220, 76, 76))]
PROTO_NAME = {"meshtastic": "Meshtastic", "lorawan": "LoRaWAN", "meshcore": "MeshCore"}
PROTO_ORDER = ["meshtastic", "meshcore", "lorawan"]
MAX_COLS = 1024        # waterfall columns at most (max-pooled from the FFT bins; ≈ screen width)
FLOOR_TAU_S = 8.0      # auto levels: the noise-floor estimate glides with this time constant


def _lut(name: str) -> np.ndarray:
    if name == "btop":
        cmap = pg.ColorMap([p for p, _ in WATERFALL_STOPS], [c for _, c in WATERFALL_STOPS])
    elif name == "grey":
        cmap = pg.ColorMap([0.0, 1.0], [(0, 0, 0), (255, 255, 255)])
    else:
        try:
            cmap = pg.colormap.get(name)
        except Exception:
            cmap = pg.colormap.get(name, source="matplotlib")
    return cmap.getLookupTable(nPts=256)


class SettingsDialog(QtWidgets.QDialog):
    """All spectrum/waterfall parameters; Apply/OK take effect immediately and are saved."""

    def __init__(self, parent, settings: UISettings, on_apply):
        super().__init__(parent)
        self.setWindowTitle("Spectrum & waterfall settings")
        self.on_apply = on_apply
        form = QtWidgets.QFormLayout(self)
        self.fft = QtWidgets.QComboBox()
        self.fft.addItems([str(n) for n in FFT_SIZES])
        self.fft.setCurrentText(str(settings.fft_size))
        self.win = QtWidgets.QComboBox()
        self.win.addItems(WINDOWS)
        self.win.setCurrentText(settings.window)
        self.lps = QtWidgets.QDoubleSpinBox(decimals=1, minimum=1, maximum=50, singleStep=1,
                                            value=settings.lines_per_second, suffix=" lines/s")
        self.hist = QtWidgets.QDoubleSpinBox(decimals=0, minimum=5, maximum=600, singleStep=5,
                                             value=settings.history_s, suffix=" s")
        self.det = QtWidgets.QComboBox()
        self.det.addItems(DETECTORS)
        self.det.setCurrentText(settings.detector)
        self.det.setToolTip("Per display frame / waterfall line, over all FFTs in it:\n"
                            "Peak = strongest value (bursts never missed), Mean = average power")
        self.fps = QtWidgets.QDoubleSpinBox(decimals=0, minimum=1, maximum=60, value=settings.spectrum_fps,
                                            suffix=" fps")
        self.auto = QtWidgets.QCheckBox("automatic (follow the noise floor)")
        self.auto.setChecked(settings.auto_levels)
        self.lmin = QtWidgets.QDoubleSpinBox(decimals=0, minimum=-160, maximum=20, value=settings.level_min_db,
                                             suffix=" dB")
        self.lmax = QtWidgets.QDoubleSpinBox(decimals=0, minimum=-160, maximum=40, value=settings.level_max_db,
                                             suffix=" dB")
        self.lrange = QtWidgets.QDoubleSpinBox(decimals=0, minimum=10, maximum=120, value=settings.level_range_db,
                                               suffix=" dB")
        self.lrange.setToolTip("Auto mode: colour range shown above the noise floor")

        def mode(on):
            self.lmin.setEnabled(not on)
            self.lmax.setEnabled(not on)
            self.lrange.setEnabled(on)
        self.auto.toggled.connect(mode)
        mode(settings.auto_levels)
        self.stop = QtWidgets.QDoubleSpinBox(decimals=0, minimum=-160, maximum=40, singleStep=5,
                                             value=settings.spectrum_top_db, suffix=" dB")
        self.sbot = QtWidgets.QDoubleSpinBox(decimals=0, minimum=-200, maximum=0, singleStep=5,
                                             value=settings.spectrum_bottom_db, suffix=" dB")
        self.cmap = QtWidgets.QComboBox()
        self.cmap.addItems(COLORMAPS)
        self.cmap.setCurrentText(settings.colormap)
        self.peak = QtWidgets.QCheckBox("show peak hold")
        self.peak.setChecked(settings.peak_hold)
        self.decay = QtWidgets.QDoubleSpinBox(decimals=1, minimum=0, maximum=60, value=settings.peak_decay_db_s,
                                              suffix=" dB/s")
        form.addRow("FFT size", self.fft)
        form.addRow("Window", self.win)
        form.addRow("Waterfall speed", self.lps)
        form.addRow("Waterfall length", self.hist)
        form.addRow("Detector", self.det)
        form.addRow("Spectrum refresh", self.fps)
        form.addRow("Colour levels", self.auto)
        form.addRow("  range", self.lrange)
        form.addRow("  min", self.lmin)
        form.addRow("  max", self.lmax)
        form.addRow("Spectrum top", self.stop)
        form.addRow("Spectrum bottom", self.sbot)
        form.addRow("Colour map", self.cmap)
        form.addRow("Peak hold", self.peak)
        form.addRow("  decay", self.decay)
        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok |
                                             QtWidgets.QDialogButtonBox.StandardButton.Apply |
                                             QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(lambda: (self._apply(), self.accept()))
        buttons.rejected.connect(self.reject)
        buttons.button(QtWidgets.QDialogButtonBox.StandardButton.Apply).clicked.connect(self._apply)
        form.addRow(buttons)

    def _apply(self):
        self.on_apply(UISettings(
            fft_size=int(self.fft.currentText()), window=self.win.currentText(),
            lines_per_second=self.lps.value(), history_s=self.hist.value(), detector=self.det.currentText(),
            spectrum_fps=self.fps.value(),
            auto_levels=self.auto.isChecked(), level_range_db=self.lrange.value(),
            level_min_db=self.lmin.value(), level_max_db=self.lmax.value(),
            spectrum_top_db=self.stop.value(), spectrum_bottom_db=self.sbot.value(),
            colormap=self.cmap.currentText(), peak_hold=self.peak.isChecked(),
            peak_decay_db_s=self.decay.value()).validate())


def _box(title: str, color: str, widget: QtWidgets.QWidget) -> QtWidgets.QGroupBox:
    g = QtWidgets.QGroupBox(title)
    g.setStyleSheet(f"QGroupBox {{ border: 1px solid {color}; border-radius: 8px; margin-top: 10px; color: {TITLE};"
                    f" font-weight: bold; }} QGroupBox::title {{ subcontrol-origin: margin; left: 12px;"
                    f" padding: 0 4px; }}")
    lay = QtWidgets.QVBoxLayout(g)
    lay.setContentsMargins(6, 10, 6, 6)
    lay.addWidget(widget)
    return g


class MonitorWindow(QtWidgets.QMainWindow):
    def __init__(self, core: MonitorCore, settings: UISettings, settings_path: str | None):
        super().__init__()
        self.core = core
        self.settings = settings
        self.settings_path = settings_path
        self.setWindowTitle(f"LoRaSpy — {core.center_hz / 1e6:.4f} MHz @ {core.sample_rate / 1e6:g} MS/s")
        self.resize(1500, 950)
        self.freqs_mhz = core.freq_axis_hz / 1e6
        self.floor, self.ceil = -100.0, -50.0
        self._floor_init = False
        self._last_tick = time.time()
        self.markers: list[dict] = []
        self.band_items: dict[str, pg.LinearRegionItem] = {}
        self.flash_until: dict[str, float] = {}
        self._band_hot: dict[str, bool] = {}
        self.events: dict[int, object] = {}

        pg.setConfigOptions(antialias=False, background=BG, foreground=FG)
        central = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
        self.setCentralWidget(central)
        self.setStyleSheet(f"QMainWindow, QWidget {{ background: {BG}; color: {FG}; }}"
                           f"QHeaderView::section {{ background: {BG}; color: #808080; border: none; }}"
                           f"QTableWidget {{ gridline-color: {DIV}; selection-background-color: #6a2f2f; }}"
                           f"QTreeWidget {{ selection-background-color: #6a2f2f; }}")

        # ---- spectrum + waterfall
        glw = pg.GraphicsLayoutWidget()
        self.band_plot = glw.addPlot(row=0, col=0)
        self.band_plot.hideAxis("bottom")
        self.band_plot.getAxis("left").setStyle(showValues=False)
        self.band_plot.getAxis("left").setPen(pg.mkPen(BG))
        self.band_plot.setMouseEnabled(x=True, y=False)
        self.band_plot.invertY(True)
        glw.nextRow()
        self.spec_plot = glw.addPlot(row=1, col=0)
        self.spec_plot.setLabel("left", "dBFS")
        self.spec_plot.showGrid(x=True, y=True, alpha=0.15)
        # SDR#-style trace: line with a gradient fill down to the bottom of the scale
        grad = QtGui.QLinearGradient(0, 0, 0, 1)
        grad.setCoordinateMode(QtGui.QGradient.CoordinateMode.ObjectMode)
        grad.setColorAt(0.0, QtGui.QColor(119, 202, 155, 150))
        grad.setColorAt(1.0, QtGui.QColor(119, 202, 155, 10))
        self.spec_curve = self.spec_plot.plot(pen=pg.mkPen("#77ca9b", width=1.2), brush=QtGui.QBrush(grad),
                                              fillLevel=settings.spectrum_bottom_db)
        self.peak_curve = self.spec_plot.plot(pen=pg.mkPen((120, 120, 120, 120), width=1))
        self.spec_plot.setMouseEnabled(x=True, y=False)
        # draw at screen resolution: peak-preserving downsampling, only the visible part
        self.spec_plot.setDownsampling(auto=True, mode="peak")
        self.spec_plot.setClipToView(True)
        glw.nextRow()
        self.wf_plot = glw.addPlot(row=2, col=0)
        self.wf_plot.setLabel("left", "seconds ago")
        self.wf_plot.setLabel("bottom", "MHz")
        self.wf_plot.invertY(True)
        self.wf_plot.setXLink(self.spec_plot)
        self.wf_plot.setMouseEnabled(x=True, y=False)
        self.band_plot.setXLink(self.spec_plot)
        glw.ci.layout.setRowStretchFactor(1, 2)
        glw.ci.layout.setRowStretchFactor(2, 3)
        self.wf_img = pg.ImageItem(axisOrder="row-major")
        self.wf_plot.addItem(self.wf_img)
        f0, f1 = self.freqs_mhz[0], self.freqs_mhz[-1]
        for plot in (self.band_plot, self.spec_plot, self.wf_plot):
            plot.hideButtons()   # pyqtgraph's "A" auto-range would include the overlays; use Reset view
            plot.setLimits(xMin=f0, xMax=f1, minXRange=(f1 - f0) / 200)
        self.spec_plot.setXRange(f0, f1, padding=0)
        self._reset_waterfall()
        self.marker_scatter = pg.ScatterPlotItem(size=9, symbol="d", pen=pg.mkPen("#000000"))
        self.wf_plot.addItem(self.marker_scatter, ignoreBounds=True)
        self.marker_texts: list[pg.TextItem] = []
        self._add_overlays()
        self.boxes: dict[int, QtWidgets.QWidget] = {}
        self.boxes[1] = _box("¹spectrum · waterfall", BOX["spectrum"], glw)
        central.addWidget(self.boxes[1])

        # ---- bottom: decoders | packets + details
        bottom = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(["decoder", "frames", "crc✗", "rssi", "snr"])
        self.tree.setColumnWidth(0, 200)
        self.tree_items: dict[str, QtWidgets.QTreeWidgetItem] = {}
        self.proto_items: dict[str, QtWidgets.QTreeWidgetItem] = {}
        for proto in PROTO_ORDER:
            rxs = [rx for rx in core.cfg.receivers if rx.protocol == proto]
            if not rxs:
                continue
            parent = QtWidgets.QTreeWidgetItem([PROTO_NAME[proto]])
            # auto-tristate: the group box ticks/unticks all children and shows "partial"
            parent.setFlags(parent.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable |
                            QtCore.Qt.ItemFlag.ItemIsAutoTristate)
            parent.setForeground(0, QtGui.QColor(*PROTOCOL_COLORS[proto]))
            self.tree.addTopLevelItem(parent)
            self.proto_items[proto] = parent
            for rx in rxs:
                it = QtWidgets.QTreeWidgetItem([rx.name, "0", "0", "", ""])
                it.setFlags(it.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
                it.setCheckState(0, QtCore.Qt.CheckState.Checked if core.stats[rx.name].enabled
                                 else QtCore.Qt.CheckState.Unchecked)
                it.setData(0, QtCore.Qt.ItemDataRole.UserRole, rx.name)
                parent.addChild(it)
                self.tree_items[rx.name] = it
        self.tree.expandAll()
        self._syncing = False
        self._syncing_gain = False
        self._apply_tree = QtCore.QTimer(self, singleShot=True)
        self._apply_tree.timeout.connect(self._apply_tree_now)
        self.tree.itemChanged.connect(self._tree_changed)
        self.boxes[2] = _box("²decoders", BOX["decoders"], self.tree)
        bottom.addWidget(self.boxes[2])

        right = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["time", "proto", "receiver", "kind", "from", "to", "text"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(3, 150)     # kind, room for a "⚠ " clipping mark
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.itemSelectionChanged.connect(self._show_details)
        self.boxes[3] = _box("³packets", BOX["packets"], self.table)
        right.addWidget(self.boxes[3])
        self.details = QtWidgets.QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont))
        self.boxes[4] = _box("⁴details", BOX["details"], self.details)
        right.addWidget(self.boxes[4])
        right.setSizes([300, 200])
        bottom.addWidget(right)
        bottom.setSizes([330, 1170])
        central.addWidget(bottom)
        central.setSizes([560, 390])
        self.right_split, self.bottom_split = right, bottom

        self.status = QtWidgets.QLabel()
        self.statusBar().addWidget(self.status)
        self.statusBar().setStyleSheet(f"color: {FG};")
        tb = self.addToolBar("main")
        tb.setMovable(False)
        act = QtGui.QAction("⚙ Settings", self)
        act.setShortcut(QtGui.QKeySequence("Ctrl+,"))
        act.triggered.connect(self._open_settings)
        tb.addAction(act)
        keys = QtGui.QAction("🔑 Keys", self)
        keys.setShortcut(QtGui.QKeySequence("K"))
        keys.setToolTip("Channels, PSKs and keys (K) — applied live")
        keys.triggered.connect(self._open_keys)
        tb.addAction(keys)
        tb.addSeparator()
        # btop-style: 1-4 show/hide the numbered boxes
        self.box_actions = {}
        for n, name in ((1, "spectrum"), (2, "decoders"), (3, "packets"), (4, "details")):
            a = QtGui.QAction(f"{'¹²³⁴'[n - 1]}{name}", self, checkable=True, checked=True)
            a.setShortcut(QtGui.QKeySequence(str(n)))
            a.setToolTip(f"show/hide the {name} box (key {n})")
            a.toggled.connect(lambda on, n=n: self._show_box(n, on))
            tb.addAction(a)
            self.box_actions[n] = a
        tb.addSeparator()
        reset = QtGui.QAction("⤢ Reset view", self)
        reset.setShortcut(QtGui.QKeySequence("R"))
        reset.setToolTip("Full tuned span and the configured dB scale (R, or double-click a plot)")
        reset.triggered.connect(self.reset_view)
        tb.addAction(reset)
        tb.addSeparator()
        self._build_gain(tb)
        # the three plots share one scene: one handler covers them all
        self.spec_plot.scene().sigMouseClicked.connect(lambda ev: ev.double() and self.reset_view())

        self.timer = QtCore.QTimer(self)            # waterfall lines
        self.timer.setTimerType(QtCore.Qt.TimerType.PreciseTimer)
        self.timer.timeout.connect(self._tick)
        self.timer.start(int(1000 / settings.lines_per_second))
        self.trace_timer = QtCore.QTimer(self)      # spectrum trace
        self.trace_timer.setTimerType(QtCore.Qt.TimerType.PreciseTimer)
        self.trace_timer.timeout.connect(self._tick_trace)
        self.trace_timer.start(int(1000 / settings.spectrum_fps))
        self.slow = QtCore.QTimer(self)
        self.slow.timeout.connect(self._tick_slow)
        self.slow.start(500)

    # ------------------------------------------------------------------ overlays

    def _add_overlays(self):
        self.reg_labels: list[tuple[pg.TextItem, float]] = []
        # regulatory sub-bands: faint strips at the bottom of the spectrum plot
        for b in self.core.regulatory:
            if b.end_hz / 1e6 < self.freqs_mhz[0] or b.start_hz / 1e6 > self.freqs_mhz[-1]:
                continue
            reg = pg.LinearRegionItem((b.start_hz / 1e6, b.end_hz / 1e6), movable=False,
                                      brush=pg.mkBrush(120, 120, 140, 18), pen=pg.mkPen((120, 120, 140, 60)))
            reg.setZValue(-20)
            self.spec_plot.addItem(reg, ignoreBounds=True)
            t = pg.TextItem(b.label, color=(140, 140, 160), anchor=(0.5, 1))
            self.spec_plot.addItem(t, ignoreBounds=True)
            self.reg_labels.append((t, b.center_hz / 1e6))
        # protocol bands: shaded on the spectrum, edges dashed on the waterfall, and drawn as
        # labelled bars in the band strip (stacked so neither bars nor labels overlap; label
        # width is estimated for the full-span view, ~190 characters across)
        mhz_per_char = (self.freqs_mhz[-1] - self.freqs_mhz[0]) / 190
        used: list[tuple[float, float, int]] = []
        self.band_bars: dict[str, pg.BarGraphItem] = {}
        for b in self.core.bands:
            r, g, bl = b.color
            reg = pg.LinearRegionItem((b.start_hz / 1e6, b.end_hz / 1e6), movable=False,
                                      brush=pg.mkBrush(r, g, bl, 30), pen=pg.mkPen((r, g, bl, 150)))
            reg.setZValue(-10)
            self.spec_plot.addItem(reg, ignoreBounds=True)
            self.band_items[b.label] = reg
            for edge in (b.start_hz, b.end_hz):
                line = pg.InfiniteLine(edge / 1e6, angle=90,
                                       pen=pg.mkPen((r, g, bl, 90), style=QtCore.Qt.PenStyle.DashLine))
                self.wf_plot.addItem(line, ignoreBounds=True)
            half = max(len(b.label) * mhz_per_char / 2 + mhz_per_char, (b.end_hz - b.start_hz) / 2e6)
            lo, hi = b.center_hz / 1e6 - half, b.center_hz / 1e6 + half
            level = 0
            while any(not (hi < a0 or lo > a1) and lv == level for a0, a1, lv in used):
                level += 1
            used.append((lo, hi, level))
            bar = pg.BarGraphItem(x0=[b.start_hz / 1e6], x1=[b.end_hz / 1e6], y0=[level + 0.08], height=[0.84],
                                  brush=pg.mkBrush(r, g, bl, 70), pen=pg.mkPen((r, g, bl, 200)))
            bar.setToolTip(f"{b.label}\n{b.start_hz / 1e6:.4f}–{b.end_hz / 1e6:.4f} MHz\n{b.detail}")
            self.band_plot.addItem(bar)
            self.band_bars[b.label] = bar
            t = pg.TextItem(b.label, color=(235, 235, 235), anchor=(0.5, 0.5))
            t.setPos(b.center_hz / 1e6, level + 0.5)
            self.band_plot.addItem(t, ignoreBounds=True)
        levels = max((lv for _, _, lv in used), default=0) + 1
        self.band_plot.setYRange(0, levels, padding=0)
        self.band_plot.setFixedHeight(22 * levels + 6)
        self._apply_spectrum_scale()

    # ------------------------------------------------------------------ gain / ADC level

    def _build_gain(self, tb: QtWidgets.QToolBar):
        """Tuner gain as in SDRangel: AGC, or a fixed gain from the tuner's own steps. Shared with
        every front-end on this SDR. Next to it the ADC peak level and a CLIPPING warning."""
        steps = self.core.gain_info.get("steps") or []
        self.gain_agc = QtWidgets.QCheckBox("AGC")
        self.gain_agc.setToolTip("Tuner automatic gain control (G)")
        self.gain_slider = QtWidgets.QSlider(QtCore.Qt.Orientation.Horizontal)
        self.gain_slider.setRange(0, max(len(steps) - 1, 0))
        self.gain_slider.setFixedWidth(180)
        self.gain_slider.setToolTip("Fixed tuner gain ([ and ] step it). Lower it when CLIPPING shows.")
        self.gain_label = QtWidgets.QLabel()
        self.gain_label.setMinimumWidth(80)
        self.adc_label = QtWidgets.QLabel()
        self.adc_label.setMinimumWidth(200)
        self.adc_label.setToolTip("Peak level at the SDR's ADC over the last second. At 0 dBFS the ADC "
                                  "clips: strong nearby transmitters get distorted and CRC errors appear.")
        tb.addWidget(QtWidgets.QLabel(" Gain "))
        for w in (self.gain_agc, self.gain_slider, self.gain_label):
            tb.addWidget(w)
        tb.addSeparator()
        tb.addWidget(self.adc_label)
        if not self.core.gain_info.get("supported"):
            for w in (self.gain_agc, self.gain_slider):
                w.setEnabled(False)
            self.gain_agc.setToolTip("gain is only adjustable on a live SDR (not an IQ file)")
        self._gain_send = QtCore.QTimer(self, singleShot=True)     # slider drags: send the final value
        self._gain_send.timeout.connect(self._send_gain)
        self.gain_slider.valueChanged.connect(self._gain_moved)
        self.gain_agc.toggled.connect(lambda _: None if self._syncing_gain else self._gain_send.start(50))
        for key, step in (("[", -1), ("]", +1)):
            a = QtGui.QAction(self)
            a.setShortcut(QtGui.QKeySequence(key))
            a.triggered.connect(lambda _=False, step=step: self._gain_step(step))
            self.addAction(a)
        agc = QtGui.QAction(self)
        agc.setShortcut(QtGui.QKeySequence("G"))
        agc.triggered.connect(lambda: self.gain_agc.setChecked(not self.gain_agc.isChecked()))
        self.addAction(agc)
        self._sync_gain()

    def _gain_moved(self, _):
        steps = self.core.gain_info.get("steps") or []
        if steps:
            self.gain_label.setText(f"{steps[self.gain_slider.value()]:g} dB")
        if not self._syncing_gain:
            self.gain_agc.setChecked(False)     # touching the slider means a fixed gain
            self._gain_send.start(250)

    def _gain_step(self, step: int):
        self.gain_slider.setValue(self.gain_slider.value() + step)

    def _send_gain(self):
        steps = self.core.gain_info.get("steps") or []
        value = "auto" if self.gain_agc.isChecked() else (steps[self.gain_slider.value()] if steps else None)
        if value is None:
            return
        try:
            self.core.set_gain(value)
        except ValueError as e:
            self.statusBar().showMessage(str(e), 4000)
            return
        self.statusBar().showMessage("gain: AGC" if value == "auto" else f"gain: {value:g} dB", 3000)

    def _sync_gain(self):
        """Follow the shared SDR (another front-end may have changed the gain)."""
        if self._gain_send.isActive():
            return
        g = self.core.gain_info
        steps = g.get("steps") or []
        if not g.get("supported"):
            self.gain_label.setText("n/a (IQ file)")
            return
        self._syncing_gain = True
        try:
            self.gain_agc.setChecked(g.get("mode") == "auto")
            if steps and g.get("gain") is not None:
                self.gain_slider.setValue(min(range(len(steps)), key=lambda i: abs(steps[i] - g["gain"])))
            self.gain_slider.setEnabled(bool(steps) and g.get("mode") != "auto")
            self.gain_label.setText("AGC" if g.get("mode") == "auto" else
                                    f"{g['gain']:g} dB" if g.get("gain") is not None else "")
        finally:
            self._syncing_gain = False

    def _show_adc(self):
        a = self.core.adc
        if a.get("peak_dbfs") is None:
            self.adc_label.setText("ADC —")
        elif a.get("clipping"):
            self.adc_label.setText(f"⚠ CLIPPING  ({a['clip_ratio'] * 100:.2g} % of samples)")
            self.adc_label.setStyleSheet(f"color: white; background: {HI}; font-weight: bold; padding: 0 6px;")
            return
        else:
            self.adc_label.setText(f"ADC peak {a['peak_dbfs']:.1f} dBFS")
        self.adc_label.setStyleSheet(f"color: {FG}; padding: 0 6px;")

    def _show_box(self, n: int, on: bool):
        self.boxes[n].setVisible(on)
        # hide a splitter whose children are all hidden, so the rest gets the space
        self.right_split.setVisible(self.boxes[3].isVisibleTo(self) or self.boxes[4].isVisibleTo(self))
        self.bottom_split.setVisible(self.boxes[2].isVisibleTo(self) or self.right_split.isVisibleTo(self))

    def reset_view(self):
        f0, f1 = self.freqs_mhz[0], self.freqs_mhz[-1]
        self.spec_plot.setXRange(f0, f1, padding=0)
        self.wf_plot.setYRange(0, self.settings.history_s, padding=0)
        self._apply_spectrum_scale()

    def _apply_spectrum_scale(self):
        st = self.settings
        self.spec_plot.setYRange(st.spectrum_bottom_db, st.spectrum_top_db, padding=0)
        self.spec_curve.setFillLevel(st.spectrum_bottom_db)
        # sub-band labels sit just above the bottom edge
        y = st.spectrum_bottom_db + 0.06 * (st.spectrum_top_db - st.spectrum_bottom_db)
        for t, x in self.reg_labels:
            t.setPos(x, y)

    # ------------------------------------------------------------------ updates

    # ------------------------------------------------------------------ waterfall

    def _reset_waterfall(self):
        """(Re)allocate the waterfall for the current FFT size, speed and length."""
        st = self.settings
        self.freqs_mhz = self.core.freq_axis_hz / 1e6
        self.row_dt = 1.0 / st.lines_per_second
        self.rows = max(2, int(round(st.history_s * st.lines_per_second)))
        self.pool = max(1, self.core.fft_size // MAX_COLS)
        self.cols = self.core.fft_size // self.pool
        # ring buffers stored twice so the newest-first window is always one contiguous slice.
        # wf_buf keeps dB (for levels / re-mapping); wf_idx8 holds colour-map indices, which is
        # what gets drawn: mapping happens once per line, not per frame (as SDR# does)
        self.wf_buf = np.full((2 * self.rows, self.cols), self.floor, dtype=np.float32)
        self.wf_idx8 = np.zeros((2 * self.rows, self.cols), dtype=np.uint8)
        self._mapped_levels = (self.floor, self.ceil)
        self.wf_idx = 0
        self.row_count = 0
        self.filled = 0
        self._line_debt = 0.0
        self.peak = None
        self.wf_img.setLookupTable(_lut(st.colormap))
        # ImageItem.setRect() scales by the size of the image it holds at that moment, so it
        # must run after the new-size image is set (in _tick), not here
        self._rect_dirty = True
        self.wf_plot.setYRange(0, st.history_s, padding=0)
        self.wf_plot.setLimits(yMin=0, yMax=st.history_s)
        for m in self.markers:
            self.wf_plot.removeItem(m["text"])
        self.markers = []
        if not st.auto_levels:
            self.floor, self.ceil = st.level_min_db, st.level_max_db

    def _to_idx(self, db: np.ndarray) -> np.ndarray:
        lo, hi = self._mapped_levels
        return np.clip((db - lo) * (255.0 / max(hi - lo, 1e-3)), 0, 255).astype(np.uint8)

    def _update_levels(self, row: np.ndarray, dt: float):
        """
        Auto levels follow only the noise floor (25th percentile of the row, which bursts
        barely move) with a slow first-order glide, and show a fixed dynamic range above it.
        Signal peaks never change the colour scale, so the waterfall doesn't recolour.
        """
        st = self.settings
        if not st.auto_levels:
            self.floor, self.ceil = st.level_min_db, st.level_max_db
            return
        target = float(np.percentile(row, 25)) - 3
        if not self._floor_init:
            self.floor, self._floor_init = target, True
        else:
            self.floor += (target - self.floor) * min(dt / FLOOR_TAU_S, 1.0)
        self.ceil = self.floor + st.level_range_db

    def _tick(self):
        """Runs every 1/lines_per_second: adds exactly one row, so the time axis never stretches."""
        c = self.core
        now = time.time()
        dt, self._last_tick = now - self._last_tick, now
        peak = c.take_spectrum("waterfall", self.settings.detector.lower())
        if peak is not None and len(peak) == c.fft_size and len(self.freqs_mhz) == c.fft_size:
            row = peak[: self.cols * self.pool].reshape(self.cols, self.pool).max(axis=1)
        else:
            # no fresh spectrum this period: repeat the previous row to keep the clock steady
            row = self.wf_buf[self.wf_idx]
        # Lines owed by the wall clock: normally 1; more if this tick ran late, so the vertical
        # axis stays true to time even when rendering can't keep up with the requested speed
        self._line_debt += dt / self.row_dt
        n = min(max(int(self._line_debt), 1 if self._line_debt >= 0.5 else 0), self.rows)
        self._line_debt -= n
        row = np.array(row, copy=True)
        row8 = self._to_idx(row)
        for _ in range(n):
            self.wf_idx = (self.wf_idx - 1) % self.rows
            self.wf_buf[self.wf_idx] = row
            self.wf_buf[self.wf_idx + self.rows] = row
            self.wf_idx8[self.wf_idx] = row8
            self.wf_idx8[self.wf_idx + self.rows] = row8
        self.row_count += n
        self.filled = min(self.filled + n, self.rows)
        if peak is not None:
            self._update_levels(row, dt)
        # re-map stored lines only when the levels have really moved (auto floor glide > 1 dB,
        # or a manual change); otherwise the drawn image is plain uint8 through the LUT
        lo, hi = self._mapped_levels
        if abs(self.floor - lo) > 1.0 or abs(self.ceil - hi) > 1.0:
            self._mapped_levels = (self.floor, self.ceil)
            self.wf_idx8[:] = self._to_idx(self.wf_buf)
        self.wf_img.setImage(self.wf_idx8[self.wf_idx:self.wf_idx + self.rows], autoLevels=False, levels=(0, 255))
        if self._rect_dirty:
            f0, f1 = self.freqs_mhz[0], self.freqs_mhz[-1]
            self.wf_img.setRect(QtCore.QRectF(f0, 0, f1 - f0, self.settings.history_s))
            self._rect_dirty = False

        for ev in c.drain_events():
            self._on_event(ev)
        # markers move exactly with the rows: y = rows since the event × row period
        keep = []
        for m in self.markers:
            age = (self.row_count - m["row"]) * self.row_dt
            if age < self.settings.history_s:
                m["text"].setPos(m["f"], age)
                keep.append(m)
            else:
                self.wf_plot.removeItem(m["text"])
        self.markers = keep
        self.marker_scatter.setData([{"pos": (m["f"], (self.row_count - m["row"]) * self.row_dt),
                                      "brush": pg.mkBrush(m["color"])} for m in self.markers])
        for b in self.core.bands:
            hot = self.flash_until.get(b.label, 0) > now
            if self._band_hot.get(b.label) != hot:       # redraw only on change
                self._band_hot[b.label] = hot
                self.band_items[b.label].setBrush(pg.mkBrush(*b.color, 100 if hot else 30))
                self.band_bars[b.label].setOpts(brush=pg.mkBrush(*b.color, 230 if hot else 70))

    def _tick_trace(self):
        """Spectrum trace: detector over all FFTs since the previous refresh (no averaging)."""
        c = self.core
        db = c.take_spectrum("trace", self.settings.detector.lower())
        if db is None or len(db) != len(self.freqs_mhz):
            return
        self.spec_curve.setData(self.freqs_mhz, db)
        if self.settings.peak_hold:
            now = time.time()
            decay = self.settings.peak_decay_db_s * (now - getattr(self, "_last_trace", now))
            self._last_trace = now
            self.peak = db.copy() if self.peak is None or len(self.peak) != len(db) \
                else np.maximum(self.peak - decay, db)
            self.peak_curve.setData(self.freqs_mhz, self.peak)
        else:
            self.peak_curve.setData([], [])

    def _open_keys(self):
        from .gui_keys import KeysDialog

        KeysDialog(self, self.core).exec()

    def _open_settings(self):
        SettingsDialog(self, self.settings, self.apply_settings).exec()

    def apply_settings(self, new: UISettings):
        old, self.settings = self.settings, new
        self.core.apply_spectrum(new.fft_size, new.window)
        if (new.fft_size, new.lines_per_second, new.history_s, new.colormap) != \
                (old.fft_size, old.lines_per_second, old.history_s, old.colormap):
            self._reset_waterfall()
        if not new.auto_levels:
            self.floor, self.ceil = new.level_min_db, new.level_max_db
        else:
            self.ceil = self.floor + new.level_range_db
        self._apply_spectrum_scale()
        self.timer.setInterval(int(1000 / new.lines_per_second))
        self.trace_timer.setInterval(int(1000 / new.spectrum_fps))
        if self.settings_path:
            ui_settings.save(self.settings_path, new)
        self.statusBar().showMessage(f"settings applied: FFT {new.fft_size} {new.window}, "
                                     f"{new.lines_per_second:g} lines/s, {new.history_s:g} s", 4000)

    def _on_event(self, ev):
        s = self.core.summarize(ev)
        color = QtGui.QColor(*PROTOCOL_COLORS[ev.frame.protocol])
        band = self.core.band_for(ev.frame)
        if band:
            self.flash_until[band.label] = time.time() + 1.5
        text = pg.TextItem(f"{s['kind'][:14]} {s['src'][:12]}".strip(), color=color if s["ok"] else QtGui.QColor(HI),
                           anchor=(0, 0.5))
        self.wf_plot.addItem(text, ignoreBounds=True)
        self.markers.append({"f": ev.frame.frequency_hz / 1e6, "row": self.row_count, "color": color,
                             "text": text})
        while len(self.markers) > 150:
            old = self.markers.pop(0)
            self.wf_plot.removeItem(old["text"])
        # table row
        row = self.table.rowCount()
        self.table.insertRow(row)
        clipped = getattr(ev.frame, "clipped", False)
        vals = [time.strftime("%H:%M:%S", time.localtime(ev.frame.timestamp)), PROTO_NAME[ev.frame.protocol],
                ev.frame.receiver, ("⚠ " if clipped else "") + s["kind"], s["src"], s["dst"], s["text"]]
        for col, v in enumerate(vals):
            item = QtWidgets.QTableWidgetItem(v)
            if col in (1, 2):
                item.setForeground(color)
            elif not s["ok"] or (col == 3 and clipped):
                item.setForeground(QtGui.QColor(HI))
            if col == 3 and clipped:
                item.setToolTip("the SDR clipped during this frame: lower the gain")
            if col == 0:
                item.setData(QtCore.Qt.ItemDataRole.UserRole, ev.seq)
            self.table.setItem(row, col, item)
        self.events[ev.seq] = ev
        if self.table.rowCount() > 2000:
            first = self.table.item(0, 0)
            self.events.pop(first.data(QtCore.Qt.ItemDataRole.UserRole), None)
            self.table.removeRow(0)
        if not self.table.selectedItems():
            self.table.scrollToBottom()

    def _sync_shared(self):
        """Other front-ends on the same SDR may have changed the FFT or the receiver set."""
        c = self.core
        if (c.fft_size, c.window) != (self.settings.fft_size, self.settings.window):
            self.settings.fft_size, self.settings.window = c.fft_size, c.window
            self._reset_waterfall()
        if self._apply_tree.isActive():
            return   # the user is mid-edit; their change goes out first
        self._syncing = True
        try:
            for name, it in self.tree_items.items():
                want = QtCore.Qt.CheckState.Checked if c.stats[name].enabled else QtCore.Qt.CheckState.Unchecked
                if it.checkState(0) != want:
                    it.setCheckState(0, want)
        finally:
            self._syncing = False

    def _tick_slow(self):
        c = self.core
        self._sync_shared()
        self._sync_gain()
        self._show_adc()
        for name, it in self.tree_items.items():
            st = c.stats[name]
            it.setText(1, str(st.frames))
            it.setText(2, str(st.crc_errors))
            it.setText(3, "" if st.last_rssi is None else f"{st.last_rssi:.0f}")
            it.setText(4, "" if st.last_snr is None else f"{st.last_snr:.1f}")
        up = int(time.time() - c.started)
        per = "  ".join(f"{PROTO_NAME[p]} {n}" for p, n in sorted(c.per_protocol.items()))
        self.status.setText(f"{c.role}   up {up // 3600}:{up // 60 % 60:02d}:{up % 60:02d}   "
                            f"frames {c.totals['frames']}   "
                            f"{per}   CRC✗ {c.totals['crc_err']}   decrypted {c.totals['decrypted']}   "
                            f"FFT {c.fft_size} {self.settings.window} · {self.settings.detector} · "
                            f"{c.sample_rate / c.fft_size / 1e3:.2f} kHz/bin   "
                            f"waterfall {self.settings.lines_per_second:g} lines/s, {self.settings.history_s:g} s   "
                            f"levels {self.floor:.0f}…{self.ceil:.0f} dB")

    def _tree_changed(self, item: QtWidgets.QTreeWidgetItem, col: int):
        """Receivers are enabled individually; group boxes just drive/reflect their children.
        Changes are batched (a group tick changes many children) into one flowgraph reconfiguration."""
        if item.data(0, QtCore.Qt.ItemDataRole.UserRole) and not self._syncing:
            self._apply_tree.start(300)

    def _apply_tree_now(self):
        on = {name for name, it in self.tree_items.items()
              if it.checkState(0) == QtCore.Qt.CheckState.Checked}
        self.core.set_receivers_enabled(on)
        self.statusBar().showMessage(f"{len(on)} of {len(self.tree_items)} demodulators running "
                                     f"({len(self.tree_items) - len(on)} idle)", 4000)

    def _show_details(self):
        items = self.table.selectedItems()
        if not items:
            return
        seq = self.table.item(items[0].row(), 0).data(QtCore.Qt.ItemDataRole.UserRole)
        ev = self.events.get(seq)
        if ev is not None:
            self.details.setPlainText(self.core.details(ev))

    def closeEvent(self, e):
        self.trace_timer.stop()
        self.timer.stop()
        self.slow.stop()
        super().closeEvent(e)


def run_gui(core: MonitorCore, settings: UISettings, settings_path: str | None = None,
            screenshot: str | None = None, screenshot_after: float = 8.0):
    """Runs until the window closes; the caller starts and stops the (local or remote) core."""
    import signal

    app = pg.mkQApp("LoRaSpy")
    # Qt's event loop never returns to Python on its own, so Ctrl-C/SIGTERM would be ignored;
    # a no-op timer lets Python run its signal handlers, which quit cleanly
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: app.quit())
    wake = QtCore.QTimer()
    wake.timeout.connect(lambda: None)
    wake.start(200)
    try:
        win = MonitorWindow(core, settings, settings_path)
        win.show()
        if screenshot:
            def grab():
                win.grab().save(screenshot)
                app.quit()
            QtCore.QTimer.singleShot(int(screenshot_after * 1000), grab)
        app.exec()
    finally:
        core.release_spectrum("waterfall", "trace")
