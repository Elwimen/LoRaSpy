"""
Tiny node database: names and X25519 public keys learned from NODEINFO packets
(needed to decrypt PKI direct messages), persisted as JSON.
"""

import base64
import json
import logging
import os
import threading
import time

log = logging.getLogger(__name__)


class NodeDB:
    def __init__(self, path: str | None, static_public_keys: dict[int, bytes] | None = None):
        self.path = path
        self._lock = threading.Lock()
        self._nodes: dict[int, dict] = {}
        self._dirty = False
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    for k, v in json.load(f).items():
                        self._nodes[int(k.lstrip("!"), 16)] = v
            except (OSError, ValueError) as e:
                log.warning("Could not load node DB %s: %s", path, e)
        # Keys from the config win over anything learned over the air
        self._static_keys = dict(static_public_keys or {})

    def set_static_keys(self, keys: dict[int, bytes]):
        self._static_keys = dict(keys)

    def public_key(self, node: int) -> bytes | None:
        if node in self._static_keys:
            return self._static_keys[node]
        with self._lock:
            pk = self._nodes.get(node, {}).get("public_key")
        return base64.b64decode(pk) if pk else None

    def display_name(self, node: int) -> str:
        with self._lock:
            n = self._nodes.get(node)
        if not n:
            return ""
        short, long_ = n.get("short_name"), n.get("long_name")
        if short and long_:
            return f"{long_} ({short})"
        return long_ or short or ""

    def update_user(self, node: int, user) -> None:
        """Record a mesh_pb2.User seen in a NODEINFO_APP packet from `node`."""
        with self._lock:
            n = self._nodes.setdefault(node, {})
            if user.long_name:
                n["long_name"] = user.long_name
            if user.short_name:
                n["short_name"] = user.short_name
            if len(user.public_key) == 32:
                n["public_key"] = base64.b64encode(user.public_key).decode()
            n["last_heard"] = int(time.time())
            self._dirty = True

    def touch(self, node: int) -> None:
        with self._lock:
            self._nodes.setdefault(node, {})["last_heard"] = int(time.time())
            self._dirty = True

    def save(self) -> None:
        if not self.path:
            return
        with self._lock:
            if not self._dirty:
                return
            data = {f"!{k:08x}": v for k, v in sorted(self._nodes.items())}
            self._dirty = False
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)
