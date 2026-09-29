"""
GUI editor for channels and keys (toolbar "🔑 Keys", key K). Works on a local MonitorCore or a
RemoteCore alike: edits are stored in keys.jsonc by the process that owns the SDR and applied
to the running decoders at once. Entries from config.jsonc are shown read-only.
"""

from pyqtgraph.Qt import QtCore, QtGui, QtWidgets

from . import keystore
from .keystore import KINDS, GROUPS, mask

SOURCE_ROLE = QtCore.Qt.ItemDataRole.UserRole


class KeyForm(QtWidgets.QDialog):
    """Add / edit one entry of a kind."""

    def __init__(self, parent, kind: str, fields: dict | None = None):
        super().__init__(parent)
        k = KINDS[kind]
        self.kind = kind
        self.setWindowTitle(f"{'Edit' if fields else 'Add'} — {k.group} · {k.title}")
        self.setMinimumWidth(560)
        lay = QtWidgets.QVBoxLayout(self)
        helpl = QtWidgets.QLabel(k.help)
        helpl.setWordWrap(True)
        lay.addWidget(helpl)
        form = QtWidgets.QFormLayout()
        self.edits: dict[str, QtWidgets.QLineEdit] = {}
        for f in k.fields:
            e = QtWidgets.QLineEdit((fields or {}).get(f.name, ""))
            e.setPlaceholderText(f.hint + ("" if f.required else "  (optional)"))
            row = QtWidgets.QHBoxLayout()
            row.addWidget(e)
            if f.secret:
                e.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
                show = QtWidgets.QToolButton(text="👁", checkable=True, toolTip="show / hide")
                show.toggled.connect(lambda on, e=e: e.setEchoMode(
                    QtWidgets.QLineEdit.EchoMode.Normal if on else QtWidgets.QLineEdit.EchoMode.Password))
                row.addWidget(show)
            if f.name in k.generate:
                gen = QtWidgets.QPushButton("Random")
                gen.setToolTip("generate a new random key (share it with the other nodes)")
                gen.clicked.connect(lambda _=False, e=e, style=k.generate[f.name]:
                                    e.setText(keystore.random_key(style)))
                row.addWidget(gen)
            self.edits[f.name] = e
            form.addRow(f.label + ("" if f.required else ""), row)
        lay.addLayout(form)
        self.info = QtWidgets.QLabel()
        self.info.setStyleSheet("color: #8a8a8a;")
        lay.addWidget(self.info)
        for e in self.edits.values():
            e.textChanged.connect(self._preview)
        self._preview()
        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Save |
                                        QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def values(self) -> dict:
        return {n: e.text().strip() for n, e in self.edits.items() if e.text().strip()}

    def _preview(self):
        """Live check with the config's own parser: hash / derived key, or what's wrong."""
        try:
            self.info.setText(keystore.describe(self.kind, keystore.normalize(self.kind, self.values())) or "ok")
        except ValueError as e:
            self.info.setText(f"⚠ {e}")

    def _accept(self):
        try:
            keystore.normalize(self.kind, self.values())
        except ValueError as e:
            QtWidgets.QMessageBox.warning(self, "Invalid entry", str(e))
            return
        self.accept()


class KeysDialog(QtWidgets.QDialog):
    def __init__(self, parent, core):
        super().__init__(parent)
        self.core = core
        self.setWindowTitle("Keys & channels")
        self.resize(980, 640)
        lay = QtWidgets.QVBoxLayout(self)
        top = QtWidgets.QHBoxLayout()
        where = "the shared SDR's owner" if getattr(core, "remote", False) else "this LoRaSpy"
        note = QtWidgets.QLabel(f"Changes are saved by {where} to <b>keys.jsonc</b> and applied to the running "
                                "decoders at once. Grey rows come from config.jsonc: edit that file for them.")
        note.setWordWrap(True)
        top.addWidget(note, 1)
        self.show_secrets = QtWidgets.QCheckBox("Show keys")
        self.show_secrets.toggled.connect(self.refresh)
        top.addWidget(self.show_secrets)
        lay.addLayout(top)
        self.tabs = QtWidgets.QTabWidget()
        lay.addWidget(self.tabs, 1)
        self.tables: dict[str, QtWidgets.QTableWidget] = {}
        for group in GROUPS:
            page = QtWidgets.QWidget()
            pl = QtWidgets.QVBoxLayout(page)
            for k in (k for k in KINDS.values() if k.group == group):
                box = QtWidgets.QGroupBox(k.title)
                bl = QtWidgets.QVBoxLayout(box)
                hl = QtWidgets.QLabel(k.help)
                hl.setStyleSheet("color: #8a8a8a;")
                bl.addWidget(hl)
                row = QtWidgets.QHBoxLayout()
                t = QtWidgets.QTableWidget(0, len(k.fields) + 2)
                t.setHorizontalHeaderLabels([f.label for f in k.fields] + ["resolves to", "from"])
                t.horizontalHeader().setStretchLastSection(False)
                t.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Stretch)
                t.verticalHeader().setVisible(False)
                t.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
                t.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
                t.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
                t.doubleClicked.connect(lambda _=None, kind=k.kind: self._edit(kind))
                row.addWidget(t, 1)
                btns = QtWidgets.QVBoxLayout()
                for label, fn in (("Add…", self._add), ("Edit…", self._edit), ("Remove", self._remove)):
                    b = QtWidgets.QPushButton(label)
                    b.clicked.connect(lambda _=False, fn=fn, kind=k.kind: fn(kind))
                    btns.addWidget(b)
                btns.addStretch(1)
                row.addLayout(btns)
                bl.addLayout(row)
                pl.addWidget(box, 1)
                self.tables[k.kind] = t
            self.tabs.addTab(page, group)
        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self._version = getattr(core, "keys_version", 0)
        self._entries: list[dict] = []
        self.refresh()
        # somebody else (TUI, CLI, another GUI) edited the keys: follow
        self._watch = QtCore.QTimer(self)
        self._watch.timeout.connect(self._check_version)
        self._watch.start(1000)

    def _check_version(self):
        v = getattr(self.core, "keys_version", 0)
        if v != self._version:
            self._version = v
            self.refresh()

    def refresh(self):
        try:
            self._entries = self.core.keys_list()
        except ValueError as e:
            QtWidgets.QMessageBox.warning(self, "Keys", str(e))
            return
        reveal = self.show_secrets.isChecked()
        grey = QtGui.QColor("#6a6a6a")
        for kind, t in self.tables.items():
            k = KINDS[kind]
            rows = [e for e in self._entries if e["kind"] == kind]
            t.setRowCount(len(rows))
            for r, e in enumerate(rows):
                vals = [e["fields"].get(f.name, "") for f in k.fields]
                vals = [v if reveal or not f.secret else mask(v) for v, f in zip(vals, k.fields)]
                src = "config.jsonc" if e["source"] == "config" else f"keys.jsonc #{e['index']}"
                for c, v in enumerate(vals + [e["info"], src]):
                    it = QtWidgets.QTableWidgetItem(v)
                    it.setData(SOURCE_ROLE, (e["source"], e["index"]))
                    if e["source"] == "config":
                        it.setForeground(grey)
                        it.setToolTip("defined in config.jsonc — edit that file (restart to apply)")
                    t.setItem(r, c, it)

    def _selected(self, kind: str) -> dict | None:
        t = self.tables[kind]
        items = t.selectedItems()
        if not items:
            return None
        source, index = items[0].data(SOURCE_ROLE)
        return next((e for e in self._entries if e["kind"] == kind and e["source"] == source
                     and e["index"] == index), None)

    def _run(self, fn, *a):
        try:
            fn(*a)
        except ValueError as e:
            QtWidgets.QMessageBox.warning(self, "Keys", str(e))
            return False
        self.refresh()
        self._version = getattr(self.core, "keys_version", self._version)
        return True

    def _add(self, kind: str):
        form = KeyForm(self, kind)
        while form.exec():
            if self._run(self.core.keys_add, kind, form.values()):
                return

    def _edit(self, kind: str):
        e = self._selected(kind)
        if e is None:
            return
        if e["source"] == "config":
            QtWidgets.QMessageBox.information(self, "Keys", "This entry is defined in config.jsonc; edit it there "
                                                            "(and restart), or add your version here instead.")
            return
        form = KeyForm(self, kind, e["fields"])
        while form.exec():
            if self._run(self.core.keys_update, kind, e["index"], form.values()):
                return

    def _remove(self, kind: str):
        e = self._selected(kind)
        if e is None:
            return
        if e["source"] == "config":
            QtWidgets.QMessageBox.information(self, "Keys", "This entry is defined in config.jsonc; remove it there.")
            return
        name = next(iter(e["fields"].values()), "")
        if QtWidgets.QMessageBox.question(self, "Remove", f"Remove {KINDS[kind].title.lower()} '{name}'?") == \
                QtWidgets.QMessageBox.StandardButton.Yes:
            self._run(self.core.keys_remove, kind, e["index"])
