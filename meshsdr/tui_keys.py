"""
TUI editor for channels and keys (key k in the TUI). Same backend as the GUI dialog and
`loraspy.py keys`: edits go to keys.jsonc of the process that owns the SDR and apply live.
"""

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from . import keystore
from .keystore import KINDS, mask

BG, FG, DIM, HI, BOX = "#000000", "#cccccc", "#6a6a6a", "#b54040", "#3d7b46"


class KindPicker(ModalScreen):
    """Which kind of key to add."""
    DEFAULT_CSS = f"""
    KindPicker {{ align: center middle; }}
    #pick {{ width: 70; height: auto; max-height: 80%; border: round {BOX}; background: {BG}; }}
    """
    BINDINGS = [Binding("escape", "dismiss(None)", "cancel")]

    def compose(self) -> ComposeResult:
        ol = OptionList(*[Option(f"{k.group} · {k.title}", id=k.kind) for k in KINDS.values()], id="pick")
        ol.border_title = "add which key?"
        yield ol

    def on_option_list_option_selected(self, event: OptionList.OptionSelected):
        self.dismiss(event.option.id)


class KeyFormScreen(ModalScreen):
    """Add / edit one entry; dismisses with the field dict, or None."""
    DEFAULT_CSS = f"""
    KeyFormScreen {{ align: center middle; }}
    #form {{ width: 96; height: auto; border: round {BOX}; background: {BG}; padding: 0 1; }}
    #form Label {{ color: {DIM}; margin-top: 1; }}
    #form Input {{ width: 1fr; }}
    #check {{ margin-top: 1; height: auto; }}
    #buttons {{ height: 3; margin-top: 1; align-horizontal: right; }}
    """
    BINDINGS = [Binding("escape", "dismiss(None)", "cancel"), Binding("ctrl+s", "save", "save"),
                Binding("ctrl+r", "random", "random key"), Binding("ctrl+t", "reveal", "show/hide keys")]

    def __init__(self, kind: str, fields: dict | None = None):
        super().__init__()
        self.kind, self.fields = kind, fields or {}

    def compose(self) -> ComposeResult:
        k = KINDS[self.kind]
        with Vertical(id="form"):
            yield Static(Text(k.help, style=FG))
            for f in k.fields:
                yield Label(f"{f.label}{'' if f.required else ' (optional)'} — {f.hint}")
                yield Input(self.fields.get(f.name, ""), placeholder=f.hint, password=f.secret, id=f"f_{f.name}")
            yield Static(id="check")
            with Horizontal(id="buttons"):
                if k.generate:
                    yield Button("Random key (^R)", id="random")
                yield Button("Save (^S)", variant="success", id="save")
                yield Button("Cancel (Esc)", id="cancel")

    def on_mount(self):
        k = KINDS[self.kind]
        self.query_one("#form").border_title = f"{'edit' if self.fields else 'add'} · {k.group} · {k.title}"
        self._check()

    def _values(self) -> dict:
        return {f.name: self.query_one(f"#f_{f.name}", Input).value.strip() for f in KINDS[self.kind].fields
                if self.query_one(f"#f_{f.name}", Input).value.strip()}

    def _check(self) -> bool:
        box = self.query_one("#check", Static)
        try:
            info = keystore.describe(self.kind, keystore.normalize(self.kind, self._values()))
            box.update(Text("✓ " + (info or "ok"), style="#77ca9b"))
            return True
        except ValueError as e:
            box.update(Text(f"⚠ {e}", style=HI))
            return False

    def on_input_changed(self, _event):
        self._check()

    def on_button_pressed(self, event: Button.Pressed):
        {"save": self.action_save, "cancel": lambda: self.dismiss(None),
         "random": self.action_random}[event.button.id]()

    def action_save(self):
        if self._check():
            self.dismiss(self._values())

    def action_random(self):
        for name, style in KINDS[self.kind].generate.items():
            self.query_one(f"#f_{name}", Input).value = keystore.random_key(style)

    def action_reveal(self):
        for f in KINDS[self.kind].fields:
            if f.secret:
                inp = self.query_one(f"#f_{f.name}", Input)
                inp.password = not inp.password


class KeysScreen(Screen):
    """All channels and keys: a add, e/enter edit, d delete, s show keys, esc back."""
    DEFAULT_CSS = f"""
    KeysScreen {{ background: {BG}; }}
    #keys {{ height: 1fr; border: round {BOX}; }}
    #note {{ height: auto; color: {DIM}; padding: 0 1; }}
    """
    BINDINGS = [Binding("escape", "app.pop_screen", "back"), Binding("a", "add", "add"),
                Binding("e", "edit", "edit"), Binding("enter", "edit", "edit", show=False),
                Binding("d", "delete", "delete"), Binding("s", "reveal", "show keys"),
                Binding("r", "refresh", "refresh")]

    def __init__(self, core):
        super().__init__()
        self.core = core
        self.reveal = False
        self.rows: dict[str, dict] = {}
        self._version = getattr(core, "keys_version", 0)

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield DataTable(id="keys", cursor_type="row", zebra_stripes=False)
        yield Static(Text("Saved to keys.jsonc by the process that owns the SDR and applied at once. "
                          "Grey = from config.jsonc (edit that file). "
                          "Kinds: " + ", ".join(KINDS)), id="note")
        yield Footer()

    def on_mount(self):
        t = self.query_one("#keys", DataTable)
        t.border_title = "🔑 keys & channels"
        t.add_columns("kind", "entry", "resolves to", "from")
        self.action_refresh()
        self.set_interval(1.0, self._check_version)

    def _check_version(self):
        v = getattr(self.core, "keys_version", 0)
        if v != self._version:
            self._version = v
            self.action_refresh()

    def action_refresh(self):
        try:
            entries = self.core.keys_list()
        except ValueError as e:
            self.notify(str(e), severity="error")
            return
        t = self.query_one("#keys", DataTable)
        t.clear()
        self.rows = {}
        for n, e in enumerate(entries):
            k = KINDS[e["kind"]]
            vals = []
            for f in k.fields:
                v = e["fields"].get(f.name, "")
                if v:
                    vals.append(f"{f.name}={v if self.reveal or not f.secret else mask(v)}")
            style = DIM if e["source"] == "config" else FG
            src = "config.jsonc" if e["source"] == "config" else f"keys.jsonc #{e['index']}"
            key = str(n)
            self.rows[key] = e
            t.add_row(Text(f"{k.group} · {k.title}", style=style), Text("  ".join(vals), style=style),
                      Text(e["info"], style=style), Text(src, style=style), key=key)

    def _current(self) -> dict | None:
        t = self.query_one("#keys", DataTable)
        if t.row_count == 0:
            return None
        return self.rows.get(t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value)

    def _apply(self, fn, *a, done: str):
        try:
            fn(*a)
        except ValueError as e:
            self.notify(str(e), severity="error", timeout=8)
            return
        self.notify(done, timeout=3)
        self._version = getattr(self.core, "keys_version", self._version)
        self.action_refresh()

    def action_add(self):
        def picked(kind):
            if kind:
                self.app.push_screen(KeyFormScreen(kind),
                                     lambda f: f and self._apply(self.core.keys_add, kind, f, done="added"))
        self.app.push_screen(KindPicker(), picked)

    def action_edit(self):
        e = self._current()
        if e is None:
            return
        if e["source"] == "config":
            self.notify("defined in config.jsonc: edit that file (or add your own version with a)", timeout=5)
            return
        self.app.push_screen(KeyFormScreen(e["kind"], e["fields"]),
                             lambda f: f and self._apply(self.core.keys_update, e["kind"], e["index"], f,
                                                         done="updated"))

    def action_delete(self):
        e = self._current()
        if e is None:
            return
        if e["source"] == "config":
            self.notify("defined in config.jsonc: remove it there", timeout=5)
            return
        self._apply(self.core.keys_remove, e["kind"], e["index"], done="removed")

    def action_reveal(self):
        self.reveal = not self.reveal
        self.action_refresh()
