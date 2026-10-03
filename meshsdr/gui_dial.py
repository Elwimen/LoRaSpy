"""
Frequency dial in the style of an LCARS panel (Antonio font, bundled under the SIL OFL).

Every digit is its own control, as on SDR# / SDRangel dials:
- mouse wheel over a digit: ±1 in that decade (carries into the higher digits),
- right click on a digit: every digit to its right becomes 0,
- leading zeros are dimmed; the hovered digit is highlighted.
`changed(hz)` fires once the wheel has been still for DEBOUNCE_MS, so spinning through many
steps retunes once.
"""

from pathlib import Path

from pyqtgraph.Qt import QtCore, QtGui, QtWidgets

FONT_FILE = Path(__file__).resolve().parent / "fonts" / "Antonio.ttf"
LCARS_ORANGE, LCARS_DIM, LCARS_HOVER, LCARS_PANEL = "#ff9900", "#5c3a0a", "#9999ff", "#000000"
DEBOUNCE_MS = 300
_family: str | None = None


def lcars_family() -> str:
    """Load the bundled Antonio font once; fall back to a condensed system font."""
    global _family
    if _family is None:
        fid = QtGui.QFontDatabase.addApplicationFont(str(FONT_FILE)) if FONT_FILE.exists() else -1
        fams = QtGui.QFontDatabase.applicationFontFamilies(fid) if fid >= 0 else []
        _family = fams[0] if fams else "DejaVu Sans Condensed"
    return _family


class FrequencyDial(QtWidgets.QWidget):
    changed = QtCore.Signal(float)

    def __init__(self, hz: float, min_hz: float = 24e6, max_hz: float = 1766e6, digits: int = 10,
                 parent=None, point_size: int = 22, what: str = "Tuner centre frequency"):
        super().__init__(parent)
        self.min_hz, self.max_hz, self.digits = min_hz, max_hz, digits
        self._value = int(round(hz))
        self._hover: int | None = None             # power of ten under the mouse
        self.font_ = QtGui.QFont(lcars_family(), point_size)
        self.font_.setWeight(QtGui.QFont.Weight.DemiBold)
        self.unit_font = QtGui.QFont(lcars_family(), max(8, point_size // 2))
        self.setMouseTracking(True)
        self.setToolTip(f"{what} — wheel over a digit: ±1 in that place · "
                        "right click: zero the digits to its right")
        self._timer = QtCore.QTimer(self, singleShot=True)
        self._timer.timeout.connect(lambda: self.changed.emit(float(self._value)))
        self._cells: list[tuple[QtCore.QRectF, int]] = []
        self._layout()

    # ---- value
    def value(self) -> float:
        return float(self._value)

    @property
    def pending(self) -> bool:
        """The user is mid-change (not yet sent): don't overwrite it from outside."""
        return self._timer.isActive()

    def setValue(self, hz: float):
        if not self.pending:
            self._value = int(round(hz))
            self.update()

    def _set(self, v: int, now: bool = False):
        v = int(min(max(v, self.min_hz), self.max_hz))
        if v != self._value:
            self._value = v
            self.update()
        self._timer.start(0 if now else DEBOUNCE_MS)

    # ---- geometry: digit cells, with a gap every three digits (GHz.MHz.kHz.Hz)
    def _layout(self):
        fm = QtGui.QFontMetricsF(self.font_)
        dw = fm.horizontalAdvance("0") * 1.12
        gap = dw * 0.45
        h = fm.height() * 1.05
        x = 6.0
        self._cells = []
        for i in range(self.digits):
            p = self.digits - 1 - i
            self._cells.append((QtCore.QRectF(x, 2, dw, h), p))
            x += dw + (gap if p % 3 == 0 and p else 0)
        self._unit_x = x + 4
        um = QtGui.QFontMetricsF(self.unit_font)
        self.setFixedSize(int(self._unit_x + um.horizontalAdvance("Hz") + 10), int(h + 4))

    def _cell_at(self, pos) -> int | None:
        for r, p in self._cells:
            if r.adjusted(-2, 0, 2, 0).contains(QtCore.QPointF(pos)):
                return p
        return None

    # ---- painting
    def paintEvent(self, _ev):
        qp = QtGui.QPainter(self)
        qp.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        qp.fillRect(self.rect(), QtGui.QColor(LCARS_PANEL))
        s = f"{self._value:0{self.digits}d}"
        lead = len(s) - len(s.lstrip("0"))
        qp.setFont(self.font_)
        for (r, p), ch in zip(self._cells, s):
            i = self.digits - 1 - p
            if p == self._hover and self.isEnabled():
                qp.setBrush(QtGui.QColor(LCARS_HOVER))
                qp.setPen(QtCore.Qt.PenStyle.NoPen)
                qp.drawRoundedRect(r.adjusted(0, r.height() * 0.88, 0, 0), 2, 2)
            dim = i < lead or not self.isEnabled()
            qp.setPen(QtGui.QColor(LCARS_DIM if dim else LCARS_ORANGE))
            qp.drawText(r, QtCore.Qt.AlignmentFlag.AlignCenter, ch)
            if p % 3 == 0 and p:                     # group separator dot
                qp.setPen(QtGui.QColor(LCARS_DIM if i < lead else LCARS_ORANGE))
                qp.drawText(QtCore.QRectF(r.right(), r.top(), r.width() * 0.45, r.height()),
                            QtCore.Qt.AlignmentFlag.AlignCenter, ".")
        qp.setFont(self.unit_font)
        qp.setPen(QtGui.QColor(LCARS_ORANGE))
        qp.drawText(QtCore.QRectF(self._unit_x, 0, 40, self.height()),
                    QtCore.Qt.AlignmentFlag.AlignVCenter | QtCore.Qt.AlignmentFlag.AlignLeft, "Hz")

    # ---- interaction
    def mouseMoveEvent(self, ev):
        p = self._cell_at(ev.position())
        if p != self._hover:
            self._hover = p
            self.update()

    def leaveEvent(self, _ev):
        self._hover = None
        self.update()

    def wheelEvent(self, ev):
        p = self._cell_at(ev.position())
        if p is None or not self.isEnabled():
            return
        steps = ev.angleDelta().y() // 120 or (1 if ev.angleDelta().y() > 0 else -1)
        self._set(self._value + steps * 10 ** p)
        ev.accept()

    def mousePressEvent(self, ev):
        p = self._cell_at(ev.position())
        if p is None or not self.isEnabled():
            return
        if ev.button() == QtCore.Qt.MouseButton.RightButton and p > 0:
            self._set((self._value // 10 ** p) * 10 ** p, now=True)
            ev.accept()
