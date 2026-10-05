"""
Decoders added or changed from the UIs (GUI ⚙ / "＋ Add decoder…", `loraspy.py decoder`).

Stored in decoders.jsonc next to config.jsonc and merged at load (config.load_config), so the
hand-written config.jsonc is never rewritten:

    {
      "add":      [ {receiver spec, as in config.jsonc "receivers"}, … ],
      "override": { "LongFast": {"frequency_hz": 869.4e6, "sf": 11, …}, … },
      "remove":   [ "RX2-SF12", … ],     // config.jsonc decoders hidden from the UI
      "enabled":  [ "LongFast", … ]      // decoders switched on (absent = none active)
    }

Every change is checked by loading the whole merged configuration before it is saved.
"""

import copy
import json
import os
import tempfile
from pathlib import Path

from . import config as C

HEADER = ("// LoRaSpy decoders added or changed from the UIs (GUI ⚙ / ＋ Add decoder…, `loraspy.py decoder`).\n"
          "// Merged with config.jsonc at load: \"add\" = extra receiver specs, \"override\" = per-decoder\n"
          "// parameters (frequency_hz, bw_hz, sf, cr, sync_word, invert_iq), \"remove\" = config.jsonc\n"
          "// decoders hidden from the UI, \"enabled\" = decoders switched on (absent = none active).\n")


class DecoderStore:
    def __init__(self, config_path: str | Path):
        self.config_path = Path(config_path).resolve()
        self.path = C.decoders_path_for(self.config_path)

    def load(self) -> dict:
        d = C.load_jsonc(self.path) if self.path.exists() else {}
        d.setdefault("add", [])
        d.setdefault("override", {})
        d.setdefault("remove", [])
        return d

    def _save(self, d: dict):
        d = {k: v for k, v in d.items() if v}
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".decoders.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(HEADER + json.dumps(d, indent=2, ensure_ascii=False) + "\n")
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _check_and_save(self, d: dict):
        """Write, try loading the merged config, restore the old file if it doesn't load."""
        old = self.path.read_text(encoding="utf-8") if self.path.exists() else None
        self._save(d)
        try:
            return C.load_config(self.config_path)
        except C.ConfigError as e:
            if old is None:
                self.path.unlink(missing_ok=True)
            else:
                self.path.write_text(old, encoding="utf-8")
            raise ValueError(str(e)) from e

    def add(self, spec: dict) -> list[str]:
        """Add a receiver spec; returns the names of the decoders it produces."""
        d = self.load()
        before = {r.name for r in C.load_config(self.config_path).receivers}
        d["add"].append(copy.deepcopy(spec))
        cfg = self._check_and_save(d)
        return [r.name for r in cfg.receivers if r.name not in before]

    def remove(self, spec_index: int) -> list[str]:
        """Remove an added spec (and the overrides of the decoders it produced)."""
        d = self.load()
        if not 0 <= spec_index < len(d["add"]):
            raise ValueError("no such added decoder")
        names = [r.name for r in C.load_config(self.config_path).receivers
                 if r.origin == "added" and r.spec_index == spec_index]
        del d["add"][spec_index]
        for n in names:
            d["override"].pop(n, None)
        self._check_and_save(d)
        return names

    def set_override(self, name: str, params: dict):
        d = self.load()
        unknown = set(params) - set(C.OVERRIDABLE)
        if unknown:
            raise ValueError(f"unknown parameter(s) {', '.join(sorted(unknown))}; allowed: {', '.join(C.OVERRIDABLE)}")
        d["override"][name] = {**d["override"].get(name, {}), **params}
        self._check_and_save(d)

    def reset(self, name: str):
        d = self.load()
        d["override"].pop(name, None)
        self._check_and_save(d)

    def remove_config(self, name: str) -> list[str]:
        """Hide a config.jsonc decoder (it reappears after reset_all)."""
        d = self.load()
        if name not in d["remove"]:
            d["remove"].append(name)
        d["override"].pop(name, None)
        self._check_and_save(d)
        return [name]

    def reset_all(self):
        """Back to the config.jsonc decoder set: drop every addition, override, removal and the
        enabled list (so no decoder is active)."""
        old = self.path.read_text(encoding="utf-8") if self.path.exists() else None
        self.path.unlink(missing_ok=True)
        try:
            C.load_config(self.config_path)
        except C.ConfigError as e:
            if old is not None:
                self.path.write_text(old, encoding="utf-8")
            raise ValueError(str(e)) from e

    def enabled(self) -> set[str] | None:
        d = self.load()
        return set(d["enabled"]) if "enabled" in d else None

    def set_enabled(self, names) -> None:
        """Persist exactly these decoders as switched on (empty = none, stored as absent)."""
        d = self.load()
        d["enabled"] = sorted(set(names))
        self._check_and_save(d)


class OfflineDecoders:
    """The core's decoder API without a running LoRaSpy (CLI): edits decoders.jsonc only; the
    next start picks it up."""

    def __init__(self, config_path: str | Path):
        self.store = DecoderStore(config_path)

    def _receivers(self):
        return C.load_config(self.store.config_path).receivers

    def decoder_list(self) -> list[dict]:
        rxs = self._receivers()
        return [{"name": r.name, "protocol": r.protocol, "frequency_hz": r.frequency_hz, "bw_hz": r.bw_hz,
                 "sf": r.sf, "cr": r.cr, "sync_word": r.sync_word, "invert_iq": r.invert_iq, "origin": r.origin,
                 "spec_index": r.spec_index, "overridden": r.overridden, "channel_mates": [],
                 "spec_mates": [o.name for o in rxs if r.origin == "added" and o.spec_index == r.spec_index
                                and o.name != r.name]} for r in rxs]

    def _find(self, name: str):
        rx = next((r for r in self._receivers() if r.name == name), None)
        if rx is None:
            raise ValueError(f"unknown decoder '{name}' (see: loraspy.py decoder)")
        return rx

    def decoder_add(self, spec: dict) -> list[str]:
        return self.store.add(spec)

    def decoder_update(self, name: str, params: dict) -> str:
        self._find(name)
        self.store.set_override(name, params)
        return "saved (applies at the next start)"

    def decoder_reset(self, name: str) -> str:
        self._find(name)
        self.store.reset(name)
        return "saved (applies at the next start)"

    def decoder_remove(self, name: str) -> list[str]:
        rx = self._find(name)
        if rx.origin == "added":
            return self.store.remove(rx.spec_index)
        return self.store.remove_config(name)

    def decoder_reset_all(self) -> str:
        self.store.reset_all()
        return "reset to the config.jsonc decoders (applies at the next start)"

    @property
    def enabled(self) -> set[str]:
        return self.store.enabled() or set()

    def set_receivers_enabled(self, names, persist: bool = True) -> None:
        known = {r.name for r in self._receivers()}
        self.store.set_enabled(set(names) & known)
