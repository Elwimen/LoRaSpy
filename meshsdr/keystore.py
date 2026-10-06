"""
Keys and channels editable at runtime (GUI dialog, TUI screen, `loraspy.py keys`).

Edits go to keys.jsonc next to config.jsonc (user-only file, merged at load by
config.load_config), so the hand-written config.jsonc and its comments are never rewritten.
Entries defined in config.jsonc are listed too, read-only. Every entry is validated with the
same parser the config uses (config.parse_keys) before it is saved.
"""

import base64
import copy
import hashlib
import json
import os
import secrets
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import config as C


@dataclass
class Field:
    name: str
    label: str
    required: bool = True
    secret: bool = False
    hint: str = ""


@dataclass
class Kind:
    kind: str
    group: str                 # Meshtastic / MeshCore / LoRaWAN
    title: str
    section: tuple[str, ...]   # path in the config: ("channels",), ("pki", "private_keys"), …
    fields: list[Field]
    map_key: str | None = None  # for {key: value} sections: the field that is the key
    help: str = ""
    generate: dict = field(default_factory=dict)   # field → "psk"|"aes128": offer a random key


KINDS: dict[str, Kind] = {k.kind: k for k in [
    Kind("channel", "Meshtastic", "Channels", ("channels",),
         [Field("name", "Name", hint="exact channel name (it is part of the channel hash)"),
          Field("psk", "PSK", secret=True, hint="base64: AQ== default key, AA== none, or 16/32 bytes")],
         help="Channel name + PSK, as in the app's channel settings / share URL.",
         generate={"psk": "psk"}),
    Kind("pki-private", "Meshtastic", "PKI private keys (DMs)", ("pki", "private_keys"),
         [Field("node", "Node", hint="!1337b4b3"),
          Field("private_key", "Private key", secret=True, hint="base64, 32 bytes (Security settings)"),
          Field("label", "Label", required=False)],
         help="A node you own: reads PKI direct messages sent to or from it."),
    Kind("pki-public", "Meshtastic", "Pinned public keys", ("pki", "public_keys"),
         [Field("node", "Node", hint="!da548c90"), Field("public_key", "Public key", hint="base64, 32 bytes")],
         map_key="node", help="Only needed for nodes whose NODEINFO hasn't been heard yet."),
    Kind("mc-channel", "MeshCore", "Channels", ("meshcore", "channels"),
         [Field("name", "Name", hint="'#name' without a secret = hashtag channel"),
          Field("secret", "Secret", required=False, secret=True, hint="hex or base64, 16 or 32 bytes")],
         help="Group channel secret (MeshCore app → channel → share).", generate={"secret": "aes128"}),
    Kind("mc-identity", "MeshCore", "Identities (DMs)", ("meshcore", "identities"),
         [Field("name", "Name"),
          Field("private_key", "Private key", secret=True, hint="128 hex characters (app: export private key)")],
         help="Your own companion identity: reads DMs to and from it."),
    Kind("mc-public", "MeshCore", "Pinned public keys", ("meshcore", "public_keys"),
         [Field("name", "Name"), Field("public_key", "Public key", hint="64 hex characters")],
         map_key="name", help="Only needed for peers whose advert hasn't been heard yet."),
    Kind("lw-session", "LoRaWAN", "ABP / session keys", ("lorawan", "sessions"),
         [Field("dev_addr", "DevAddr", hint="8 hex digits"),
          Field("nwk_s_key", "NwkSKey", required=False, secret=True, hint="32 hex (MIC check)"),
          Field("app_s_key", "AppSKey", required=False, secret=True, hint="32 hex (payload)"),
          Field("label", "Label", required=False), Field("codec", "Codec", required=False)],
         help="Session keys of a device you own (ABP, or copied from the network server)."),
    Kind("lw-otaa", "LoRaWAN", "OTAA devices", ("lorawan", "otaa_devices"),
         [Field("dev_eui", "DevEUI", hint="16 hex digits"),
          Field("app_key", "AppKey", secret=True, hint="32 hex"),
          Field("join_eui", "JoinEUI", required=False), Field("label", "Label", required=False),
          Field("codec", "Codec", required=False)],
         help="Root key of a device you own: session keys are derived from the join heard on air.",
         generate={}),
]}

GROUPS = ["Meshtastic", "MeshCore", "LoRaWAN"]
HEADER = ("// LoRaSpy keys and channels added from the key editors (GUI, TUI, `loraspy.py keys`).\n"
          "// Merged with config.jsonc at load. Contains secrets: keep it private (mode 0600).\n")


def random_key(style: str) -> str:
    if style == "psk":
        return base64.b64encode(secrets.token_bytes(32)).decode()       # AES-256, as the app makes
    return secrets.token_bytes(16).hex()


def _get(raw: dict, section: tuple[str, ...]):
    node = raw
    for s in section:
        node = node.get(s) if isinstance(node, dict) else None
        if node is None:
            return None
    return node


def _items(k: Kind, raw: dict) -> list[dict]:
    """Entries of one kind in a raw config dict, as field dicts."""
    node = _get(raw, k.section)
    if not node:
        return []
    if k.map_key:
        value_field = next(f.name for f in k.fields if f.name != k.map_key)
        return [{k.map_key: key, value_field: val} for key, val in node.items()]
    return [dict(e) for e in node]


def _put(k: Kind, raw: dict, items: list[dict]):
    parent = raw
    for s in k.section[:-1]:
        parent = parent.setdefault(s, {})
    last = k.section[-1]
    if not items:
        parent.pop(last, None)
    elif k.map_key:
        value_field = next(f.name for f in k.fields if f.name != k.map_key)
        parent[last] = {e[k.map_key]: e[value_field] for e in items}
    else:
        parent[last] = items


def normalize(kind: str, fields: dict) -> dict:
    """Trimmed fields, empty optional ones dropped; raises ValueError when invalid."""
    k = KINDS.get(kind)
    if k is None:
        raise ValueError(f"unknown kind '{kind}' (one of: {', '.join(KINDS)})")
    unknown = set(fields) - {f.name for f in k.fields}
    if unknown:
        raise ValueError(f"{kind}: unknown field(s) {', '.join(sorted(unknown))}; "
                         f"fields: {', '.join(f.name for f in k.fields)}")
    out = {}
    for f in k.fields:
        v = str(fields.get(f.name) or "").strip()
        if v:
            out[f.name] = v
        elif f.required:
            raise ValueError(f"{k.group} {k.title}: '{f.label}' is required")
    raw: dict = {}
    _put(k, raw, [out])
    try:
        C.parse_keys(raw)       # the config's own checks (base64/hex, lengths, node ids …)
    except C.ConfigError as e:
        raise ValueError(f"{k.group} {k.title}: {e}") from e
    return out


def describe(kind: str, fields: dict) -> str:
    """What the key resolves to: channel hash, derived public key, …"""
    try:
        raw: dict = {}
        _put(KINDS[kind], raw, [fields])
        p = C.parse_keys(raw)
        if kind == "channel":
            from .crypto import channel_hash
            ch = p["channels"][0]
            return f"hash 0x{channel_hash(ch.name, ch.psk):02x} · " + \
                ("no encryption" if not ch.psk else f"AES-{len(ch.psk) * 8}")
        if kind == "pki-private":
            from .crypto import derive_public_key
            return "public key " + base64.b64encode(derive_public_key(p["private_keys"][0].key)).decode()[:16] + "…"
        if kind == "mc-channel":
            ch = p["meshcore_channels"][0]
            return f"hash 0x{hashlib.sha256(ch.secret).digest()[0]:02x}" + \
                (" · hashtag" if "secret" not in fields else "")
        if kind == "mc-identity":
            from .meshcore import public_key_from_private
            return "public key " + public_key_from_private(p["meshcore_identities"][0].private_key).hex()[:16] + "…"
        if kind == "lw-session":
            s = p["lorawan_sessions"][0]
            return ("MIC " if s.nwk_s_key else "") + ("+ payload" if s.app_s_key else "")
        if kind == "lw-otaa":
            return f"DevEUI {p['lorawan_otaa'][0].dev_eui}"
    except Exception as e:
        return f"invalid: {e}"
    return ""


def mask(value: str) -> str:
    return "" if not value else ("•" * 8 + value[-4:] if len(value) > 8 else "•" * len(value))


class KeyStore:
    """config.jsonc (read-only here) + keys.jsonc (editable)."""

    def __init__(self, config_path: str | Path):
        self.config_path = Path(config_path).resolve()
        self.path = C.keys_path_for(self.config_path)

    def _config_raw(self) -> dict:
        return C.load_jsonc(self.config_path)

    def _keys_raw(self) -> dict:
        return C.load_jsonc(self.path) if self.path.exists() else {}

    def entries(self) -> list[dict]:
        """[{kind, group, title, source: 'config'|'keys', index, fields, info}] — index counts
        within (kind, source); edit/remove address keys.jsonc entries by it."""
        cfg, keys = self._config_raw(), self._keys_raw()
        out = []
        for k in KINDS.values():
            cfg_items = _items(k, cfg)
            if k.kind == "mc-channel" and _get(cfg, k.section) is None:
                cfg_items = [{"name": "Public", "secret": C.MESHCORE_PUBLIC_SECRET}]   # built-in default
            for source, items in (("config", cfg_items), ("keys", _items(k, keys))):
                for i, f in enumerate(items):
                    out.append({"kind": k.kind, "group": k.group, "title": k.title, "source": source,
                                "index": i, "fields": {n: str(v) for n, v in f.items()},
                                "info": describe(k.kind, f)})
        return out

    def _save(self, raw: dict):
        raw = {k: v for k, v in raw.items() if v not in ({}, [], None)}   # drop emptied sections
        text = HEADER + json.dumps(raw, indent=2, ensure_ascii=False) + "\n"
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".keys.", suffix=".tmp")
        try:
            if hasattr(os, "fchmod"):          # POSIX: keys file user-only (no-op on Windows)
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _check_whole(self, keys: dict):
        """The merged result must still load (e.g. no clash with the config)."""
        try:
            C.parse_keys(C.merge_keys(self._config_raw(), keys))
        except C.ConfigError as e:
            raise ValueError(str(e)) from e

    def add(self, kind: str, fields: dict):
        f = normalize(kind, fields)            # also rejects unknown kinds
        k = KINDS[kind]
        keys = self._keys_raw()
        items = _items(k, keys)
        if k.map_key:
            items = [e for e in items if e[k.map_key] != f[k.map_key]]   # same key: replace
        items.append(f)
        new = copy.deepcopy(keys)
        _put(k, new, items)
        self._check_whole(new)
        self._save(new)

    def update(self, kind: str, index: int, fields: dict):
        f = normalize(kind, fields)
        k = KINDS[kind]
        keys = self._keys_raw()
        items = _items(k, keys)
        if not 0 <= index < len(items):
            raise ValueError(f"{kind} #{index}: no such entry in {self.path.name}")
        items[index] = f
        new = copy.deepcopy(keys)
        _put(k, new, items)
        self._check_whole(new)
        self._save(new)

    def remove(self, kind: str, index: int):
        if kind not in KINDS:
            raise ValueError(f"unknown kind '{kind}'")
        k = KINDS[kind]
        keys = self._keys_raw()
        items = _items(k, keys)
        if not 0 <= index < len(items):
            raise ValueError(f"{kind} #{index}: no such entry in {self.path.name}")
        del items[index]
        new = copy.deepcopy(keys)
        _put(k, new, items)
        self._save(new)
