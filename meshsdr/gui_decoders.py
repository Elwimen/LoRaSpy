"""
Decoder settings (⚙ in the decoder tree) and "＋ Add decoder…".

Both edit decoders.jsonc next to config.jsonc through the core's decoder API (MonitorCore, or
RemoteCore on an attached front-end): a frequency change of a decoder that has its channel filter
to itself is applied live, everything else restarts the decoders (≈1–2 s; tuning, gain,
statistics and the packet history are kept).
"""

from pyqtgraph.Qt import QtCore, QtGui, QtWidgets

from . import config as C
from .gui_dial import FrequencyDial
from .radio import (LORAWAN_PLANS, LORAWAN_SYNC_WORD, MESHCORE_PRESETS, MESHCORE_SYNC_WORD,
                    MESHTASTIC_SYNC_WORD, PRESETS, REGIONS)

PROTO_NAME = {"meshtastic": "Meshtastic", "lorawan": "LoRaWAN", "meshcore": "MeshCore",
              "trustedwireless": "Trusted Wireless"}
BANDWIDTHS = [62_500, 125_000, 250_000, 500_000]
DEFAULT_SYNC = {"meshtastic": MESHTASTIC_SYNC_WORD, "lorawan": LORAWAN_SYNC_WORD, "meshcore": MESHCORE_SYNC_WORD}
NOTE_STYLE = "color: #8a8a8a;"


def _busy(parent, fn, *args):
    """Run a (possibly flowgraph-restarting) core call with a wait cursor; errors → message box."""
    QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.CursorShape.WaitCursor))
    try:
        return True, fn(*args)
    except ValueError as e:
        QtWidgets.QApplication.restoreOverrideCursor()
        QtWidgets.QMessageBox.warning(parent, "Decoder", str(e))
        return False, None
    finally:
        if QtWidgets.QApplication.overrideCursor() is not None:
            QtWidgets.QApplication.restoreOverrideCursor()


def _status(parent, text: str):
    w = parent
    while w is not None and not isinstance(w, QtWidgets.QMainWindow):
        w = w.parent()
    if w is not None:
        w.statusBar().showMessage(text, 5000)


class _LoRaFields:
    """Bandwidth / SF / CR / sync word / inverted IQ rows, shared by both dialogs."""

    def __init__(self, form: QtWidgets.QFormLayout):
        self.bw = QtWidgets.QComboBox()
        for bw in BANDWIDTHS:
            self.bw.addItem(f"{bw / 1e3:g} kHz", bw)
        self.sf = QtWidgets.QSpinBox()
        self.sf.setRange(7, 12)
        self.cr = QtWidgets.QComboBox()
        for cr in range(5, 9):
            self.cr.addItem(f"4/{cr}", cr)
        self.sync = QtWidgets.QLineEdit()
        self.sync.setMaxLength(4)
        self.sync.setValidator(QtGui.QRegularExpressionValidator(QtCore.QRegularExpression(r"(0[xX])?[0-9a-fA-F]{1,2}")))
        self.sync.setToolTip("LoRa sync word, hex: Meshtastic 0x2B, LoRaWAN public 0x34, MeshCore 0x12")
        self.iq = QtWidgets.QCheckBox("inverted IQ (LoRaWAN downlinks)")
        form.addRow("Bandwidth", self.bw)
        form.addRow("Spreading factor", self.sf)
        form.addRow("Coding rate", self.cr)
        form.addRow("Sync word", self.sync)
        form.addRow("", self.iq)
        self.rows = [self.bw, self.sf, self.cr, self.sync, self.iq]
        self.form = form

    def load(self, bw: int, sf: int, cr: int, sync: int, iq: bool):
        if self.bw.findData(bw) < 0:
            self.bw.addItem(f"{bw / 1e3:g} kHz", bw)
        self.bw.setCurrentIndex(self.bw.findData(bw))
        self.sf.setValue(sf)
        self.cr.setCurrentIndex(max(0, self.cr.findData(cr)))
        self.sync.setText(f"0x{sync:02X}")
        self.iq.setChecked(iq)

    def values(self) -> dict:
        return {"bw_hz": int(self.bw.currentData()), "sf": self.sf.value(), "cr": int(self.cr.currentData()),
                "sync_word": int(self.sync.text() or "0", 16), "invert_iq": self.iq.isChecked()}

    def set_editable(self, on: bool, sync_iq: bool | None = None):
        for w in (self.bw, self.sf, self.cr):
            w.setEnabled(on)
        for w in (self.sync, self.iq):
            w.setEnabled(on if sync_iq is None else sync_iq)

    def set_visible(self, on: bool):
        for w in self.rows:
            w.setVisible(on)
            lbl = self.form.labelForField(w)
            if lbl is not None:
                lbl.setVisible(on)


class DecoderDialog(QtWidgets.QDialog):
    """⚙ Parameters of one decoder."""

    def __init__(self, parent, core, name: str):
        super().__init__(parent)
        self.core, self.name = core, name
        self.setWindowTitle(f"Decoder — {name}")
        self.setMinimumWidth(460)
        lay = QtWidgets.QVBoxLayout(self)
        self.form = QtWidgets.QFormLayout()
        lay.addLayout(self.form)
        self.origin = QtWidgets.QLabel()
        self.origin.setWordWrap(True)
        self.form.addRow("Protocol", proto := QtWidgets.QLabel())
        self.proto_label = proto
        self.form.addRow("Defined in", self.origin)
        self.dial = FrequencyDial(868e6, what="Decoder centre frequency")
        row = QtWidgets.QHBoxLayout()
        row.addWidget(self.dial)
        row.addStretch(1)
        self.form.addRow("Frequency", row)
        self.lora = _LoRaFields(self.form)
        self.mates = QtWidgets.QLabel()
        self.mates.setWordWrap(True)
        self.mates.setStyleSheet(NOTE_STYLE)
        lay.addWidget(self.mates)
        bb = QtWidgets.QDialogButtonBox()
        self.apply_btn = bb.addButton("Apply", QtWidgets.QDialogButtonBox.ButtonRole.ApplyRole)
        self.apply_btn.clicked.connect(self._apply)
        self.reset_btn = bb.addButton("Undo changes", QtWidgets.QDialogButtonBox.ButtonRole.ResetRole)
        self.reset_btn.clicked.connect(self._reset)
        self.remove_btn = bb.addButton("Remove decoder", QtWidgets.QDialogButtonBox.ButtonRole.DestructiveRole)
        self.remove_btn.clicked.connect(self._remove)
        bb.addButton(QtWidgets.QDialogButtonBox.StandardButton.Close).clicked.connect(self.reject)
        lay.addWidget(bb)
        self._load()

    def _info(self) -> dict | None:
        return next((d for d in self.core.decoder_list() if d["name"] == self.name), None)

    def _load(self) -> bool:
        try:
            d = self._info()
        except ValueError as e:
            QtWidgets.QMessageBox.warning(self, "Decoder", str(e))
            d = None
        if d is None:
            return False
        self.info = d
        tw = d["protocol"] == "trustedwireless"
        self.proto_label.setText(PROTO_NAME.get(d["protocol"], d["protocol"]))
        where = "config.jsonc" if d["origin"] == "config" else "added from the UI (decoders.jsonc)"
        if d["overridden"]:
            where += " — parameters changed in decoders.jsonc"
        self.origin.setText(where)
        self.dial.setValue(d["frequency_hz"])
        self.lora.load(d["bw_hz"], d["sf"], d["cr"], d["sync_word"], d["invert_iq"])
        self.lora.set_visible(not tw)
        notes = []
        if d["channel_mates"]:
            notes.append(f"Shares its channel filter with {', '.join(d['channel_mates'])}. Changing its frequency "
                         f"or bandwidth gives it a filter of its own (decoders restart); to move them all together "
                         f"use Channel settings… in the right-click menu.")
        else:
            notes.append("A frequency change is applied live; other changes restart the decoders (≈1–2 s).")
        if tw:
            notes.append("FSK listener channel: only the frequency can be changed (must stay in 869.40–869.65 MHz).")
        if d["origin"] == "added" and d["spec_mates"]:
            notes.append(f"Remove also removes {', '.join(d['spec_mates'])} (added together).")
        self.mates.setText("\n".join(notes))
        self.reset_btn.setEnabled(d["overridden"])
        self.remove_btn.setEnabled(d["origin"] == "added")
        self.remove_btn.setToolTip("" if d["origin"] == "added" else
                                   "defined in config.jsonc: untick it to stop it, or remove it there")
        return True

    def _apply(self):
        params = {"frequency_hz": self.dial.value()}
        if self.info["protocol"] != "trustedwireless":
            params.update(self.lora.values())
        ok, how = _busy(self, self.core.decoder_update, self.name, params)
        if ok:
            _status(self.parent(), f"{self.name}: {how}")
            self._load()

    def _reset(self):
        ok, how = _busy(self, self.core.decoder_reset, self.name)
        if ok:
            _status(self.parent(), f"{self.name}: back to its config.jsonc parameters ({how})")
            self._load()

    def _remove(self):
        names = [self.name] + self.info["spec_mates"]
        if QtWidgets.QMessageBox.question(self, "Remove decoder", f"Remove {', '.join(names)}?") != \
                QtWidgets.QMessageBox.StandardButton.Yes:
            return
        ok, gone = _busy(self, self.core.decoder_remove, self.name)
        if ok:
            _status(self.parent(), f"removed {', '.join(gone)}")
            self.accept()


class AddDecoderDialog(QtWidgets.QDialog):
    """＋ A new receiver spec (as in config.jsonc "receivers"), saved in decoders.jsonc."""

    def __init__(self, parent, core):
        super().__init__(parent)
        self.core = core
        self.region = getattr(core.cfg, "region", "EU_868")
        self.setWindowTitle("Add decoder")
        self.setMinimumWidth(480)
        lay = QtWidgets.QVBoxLayout(self)
        self.form = form = QtWidgets.QFormLayout()
        lay.addLayout(form)
        self.proto = QtWidgets.QComboBox()
        for p in ("meshtastic", "meshcore", "lorawan", "trustedwireless"):
            self.proto.addItem(PROTO_NAME[p], p)
        form.addRow("Protocol", self.proto)
        self.preset = QtWidgets.QComboBox()
        self.mregion = QtWidgets.QComboBox()
        for name, r in REGIONS.items():
            self.mregion.addItem(f"{name}  ({r.freq_start_mhz:g}–{r.freq_end_mhz:g} MHz)"
                                 + ("  — config" if name == self.region else ""), name)
        self.mregion.setCurrentIndex(max(0, self.mregion.findData(self.region)))
        self.mregion.setToolTip("Meshtastic region whose slot plan places the preset (default: the config's)")
        form.addRow("Region", self.mregion)
        form.addRow("Preset", self.preset)
        self.slot = QtWidgets.QSpinBox()
        self.slot.setRange(0, 200)
        self.slot.setSpecialValueText("by channel name")
        self.slot.setToolTip("Meshtastic frequency slot (1-based); default: the slot the preset's name hashes to")
        form.addRow("Slot", self.slot)
        self.offset = QtWidgets.QDoubleSpinBox()
        self.offset.setRange(-30, 30)
        self.offset.setSingleStep(15)
        self.offset.setSuffix(" kHz")
        self.offset.setToolTip("Shift of the 30 kHz channel grid 869.435 + n·30 kHz (−15 = the interleaved grid)")
        form.addRow("Grid offset", self.offset)
        self.set_freq = QtWidgets.QCheckBox("set explicitly")
        self.dial = FrequencyDial(869.525e6, what="Decoder centre frequency")
        row = QtWidgets.QHBoxLayout()
        row.addWidget(self.set_freq)
        row.addWidget(self.dial)
        row.addStretch(1)
        form.addRow("Frequency", row)
        self.freq_row = row
        self.lora = _LoRaFields(form)
        self.name = QtWidgets.QLineEdit()
        self.name.setPlaceholderText("default from the preset (a prefix when it adds several)")
        form.addRow("Name", self.name)
        self.preview = QtWidgets.QLabel()
        self.preview.setWordWrap(True)
        self.preview.setStyleSheet(NOTE_STYLE)
        self.preview.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(self.preview)
        bb = QtWidgets.QDialogButtonBox()
        self.add_btn = bb.addButton("Add", QtWidgets.QDialogButtonBox.ButtonRole.AcceptRole)
        self.add_btn.clicked.connect(self._add)
        bb.addButton(QtWidgets.QDialogButtonBox.StandardButton.Cancel).clicked.connect(self.reject)
        lay.addWidget(bb)

        self.proto.currentIndexChanged.connect(self._proto_changed)
        self.mregion.currentIndexChanged.connect(self._region_changed)
        self.preset.currentIndexChanged.connect(self._preset_changed)
        for sig in (self.slot.valueChanged, self.offset.valueChanged, self.set_freq.toggled, self.dial.changed,
                    self.lora.bw.currentIndexChanged, self.lora.sf.valueChanged, self.lora.cr.currentIndexChanged,
                    self.lora.sync.textChanged, self.lora.iq.toggled, self.name.textChanged):
            sig.connect(self._update_preview)
        self.set_freq.toggled.connect(self.dial.setEnabled)
        self._proto_changed()

    def _proto_changed(self):
        p = self.proto.currentData()
        self.preset.blockSignals(True)
        self.preset.clear()
        if p == "meshtastic":
            for key, pr in PRESETS.items():
                self.preset.addItem(f"{pr.display_name} ({pr.bw_khz:g} kHz SF{pr.sf})", key)
            self.preset.addItem("Custom", None)
            self.preset.setCurrentIndex(max(0, self.preset.findData("LONG_FAST")))
        elif p == "meshcore":
            for key, (f, bw, sf, _cr) in MESHCORE_PRESETS.items():
                self.preset.addItem(f"{key} ({f / 1e6:.3f} MHz {bw / 1e3:g} kHz SF{sf})", key)
            self.preset.addItem("Custom", None)
        elif p == "lorawan":
            for key, plan in LORAWAN_PLANS.items():
                self.preset.addItem(f"{key} plan ({len(plan['uplink'])} uplink channels × SF7–12 + RX2)", key)
            self.preset.addItem("Single channel", None)
        self.preset.blockSignals(False)
        lora = p != "trustedwireless"
        for w, on in ((self.preset, lora), (self.slot, p == "meshtastic"), (self.offset, p == "trustedwireless"),
                      (self.mregion, p == "meshtastic")):
            w.setVisible(on)
            self.form.labelForField(w).setVisible(on)
        self.lora.set_visible(lora)
        self._region_changed()

    def _region_changed(self):
        """Mark the Meshtastic presets that don't fit the chosen region (500 kHz on EU_868)."""
        if self.proto.currentData() == "meshtastic":
            region = self.mregion.currentData()
            for i in range(self.preset.count()):
                key = self.preset.itemData(i)
                if key is None:
                    continue
                pr = PRESETS[key]
                try:
                    C.resolve_added(region, {"preset": key})
                    tail = ""
                except ValueError:
                    tail = f" — too wide for {region}"
                self.preset.setItemText(i, f"{pr.display_name} ({pr.bw_khz:g} kHz SF{pr.sf}){tail}")
        self._preset_changed()

    def _preset_changed(self):
        p, key = self.proto.currentData(), self.preset.currentData()
        custom = key is None
        if p == "meshtastic" and not custom:
            pr = PRESETS[key]
            self.lora.load(int(pr.bw_khz * 1000), pr.sf, pr.cr, MESHTASTIC_SYNC_WORD, False)
        elif p == "meshcore" and not custom:
            f, bw, sf, cr = MESHCORE_PRESETS[key]
            self.lora.load(bw, sf, cr, MESHCORE_SYNC_WORD, False)
            self.dial.setValue(f)
        elif p == "lorawan":
            self.lora.load(125_000, 7, 5, LORAWAN_SYNC_WORD, False)
        elif custom:
            self.lora.sync.setText(f"0x{DEFAULT_SYNC.get(p, 0x12):02X}")
        plan = p == "lorawan" and not custom
        self.lora.set_editable(custom and p != "trustedwireless" and not plan, sync_iq=p != "trustedwireless" and not plan)
        if p == "lorawan" and custom:
            self.lora.sf.setEnabled(True)
        # frequency: optional for Meshtastic (slot from the region), required for custom/single channels
        need = custom and p in ("meshcore", "lorawan")
        self.set_freq.setVisible(p == "meshtastic")
        self.set_freq.setChecked(need or (self.set_freq.isChecked() and p == "meshtastic"))
        self.dial.setEnabled(need or (p == "meshtastic" and self.set_freq.isChecked()))
        show_freq = p == "meshtastic" or need
        self.dial.setVisible(show_freq)
        self.form.labelForField(self.freq_row).setVisible(show_freq)
        self._update_preview()

    def spec(self) -> dict:
        p, key = self.proto.currentData(), self.preset.currentData()
        lv = self.lora.values()
        s: dict = {"protocol": p}
        if p == "meshtastic":
            if key:
                s["preset"] = key
            else:
                s.update(bandwidth_hz=lv["bw_hz"], spreading_factor=lv["sf"], coding_rate=lv["cr"])
            if self.mregion.currentData() != self.region:
                s["region"] = self.mregion.currentData()
            if self.slot.value():
                s["channel_num"] = self.slot.value()
            if self.set_freq.isChecked():
                s["frequency_hz"] = self.dial.value()
        elif p == "meshcore":
            if key:
                s["preset"] = key
            else:
                s.update(frequency_hz=self.dial.value(), bandwidth_hz=lv["bw_hz"], spreading_factor=lv["sf"],
                         coding_rate=lv["cr"])
        elif p == "lorawan":
            if key:
                s["plan"] = key
            else:
                s.update(frequency_hz=self.dial.value(), bandwidth_hz=lv["bw_hz"], spreading_factors=[lv["sf"]],
                         downlink=lv["invert_iq"])
        else:
            if self.offset.value():
                s["offset_khz"] = self.offset.value()
        if p in DEFAULT_SYNC and lv["sync_word"] != DEFAULT_SYNC[p] and self.lora.sync.isEnabled():
            s["sync_word"] = f"0x{lv['sync_word']:02X}"
        if p in ("meshtastic", "meshcore") and lv["invert_iq"]:
            s["invert_iq"] = True
        if self.name.text().strip():
            s["name"] = self.name.text().strip()
        return s

    def _update_preview(self, *_):
        try:
            rxs = C.resolve_added(self.region, self.spec())
        except (ValueError, TypeError, KeyError) as e:
            self.preview.setText(f"✗ {e}")
            self.add_btn.setEnabled(False)
            return
        taken = {r.name for r in self.core.cfg.receivers}
        clash = [r.name for r in rxs if r.name in taken]
        lines = [f"{r.name}: {r.frequency_hz / 1e6:.4f} MHz" +
                 ("" if r.protocol == "trustedwireless" else
                  f", {r.bw_hz / 1e3:g} kHz SF{r.sf} 4/{r.cr} sync 0x{r.sync_word:02X}" +
                  (" IQ inverted" if r.invert_iq else "")) for r in rxs[:8]]
        if len(rxs) > 8:
            lines.append(f"… {len(rxs) - 8} more")
        head = f"Adds {len(rxs)} decoder{'s' if len(rxs) != 1 else ''}:"
        half = self.core.sample_rate / 2 * 0.98
        out = [r for r in rxs if abs(r.frequency_hz - self.core.center_hz) + r.bw_hz / 2 > half]
        if out:
            lines.append(f"⚠ {'all' if len(out) == len(rxs) else len(out)} outside the tuned window "
                         f"({(self.core.center_hz - half) / 1e6:.3f}–{(self.core.center_hz + half) / 1e6:.3f} MHz): "
                         f"idle until the SDR is tuned to e.g. {out[0].frequency_hz / 1e6:.3f} MHz")
        if clash:
            head = f"✗ name already in use: {', '.join(clash[:4])} — give it a name. " + head
        self.preview.setText("\n".join([head, *lines]))
        self.add_btn.setEnabled(not clash)

    def _add(self):
        ok, names = _busy(self, self.core.decoder_add, self.spec())
        if ok:
            _status(self.parent(), f"added {', '.join(names)}")
            self.accept()
