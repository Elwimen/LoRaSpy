"""
Meshtastic payload crypto (ported from meshprobe/meshtastic_mqtt/crypto.py).

PSK: AES-CTR, key = channel PSK (16 or 32 bytes),
     nonce = packet_id (8B LE) + from_node (4B LE) + 4 zero bytes.
PKI: X25519 ECDH -> SHA256(shared) -> AES-256-CCM, 8-byte tag.
     Wire layout [ciphertext][8B tag][4B extraNonce];
     nonce = packet_id (4B LE) + extraNonce (4B LE) + from_node (4B LE) + 0x00.
"""

import hashlib
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

PKI_OVERHEAD = 12  # 8-byte tag + 4-byte extraNonce


def xor_hash(data: bytes) -> int:
    h = 0
    for b in data:
        h ^= b
    return h


def channel_hash(name: str, psk: bytes) -> int:
    """Firmware Channels::generateHash(): xor(name) ^ xor(expanded key)."""
    return (xor_hash(name.encode("utf-8")) ^ xor_hash(psk)) & 0xFF


def aes_ctr(key: bytes, packet_id: int, from_node: int, data: bytes) -> bytes:
    """AES-CTR is symmetric: same call encrypts and decrypts."""
    nonce = packet_id.to_bytes(8, "little") + from_node.to_bytes(4, "little") + b"\x00" * 4
    c = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return c.update(data) + c.finalize()


def derive_public_key(private_key: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def pki_shared_key(private_key: bytes, peer_public_key: bytes) -> bytes:
    shared = X25519PrivateKey.from_private_bytes(private_key).exchange(
        X25519PublicKey.from_public_bytes(peer_public_key))
    return hashlib.sha256(shared).digest()


def _pki_nonce(packet_id: int, from_node: int, extra_nonce: int) -> bytes:
    return (packet_id.to_bytes(4, "little") + extra_nonce.to_bytes(4, "little")
            + from_node.to_bytes(4, "little") + b"\x00")


def pki_decrypt(shared_key: bytes, packet_id: int, from_node: int, payload: bytes) -> bytes | None:
    """Return plaintext, or None when the CCM tag does not verify."""
    if len(payload) <= PKI_OVERHEAD:
        return None
    extra_nonce = struct.unpack_from("<I", payload, len(payload) - 4)[0]
    body = payload[:-4]  # ciphertext + tag
    try:
        return AESCCM(shared_key, tag_length=8).decrypt(_pki_nonce(packet_id, from_node, extra_nonce), body, None)
    except Exception:
        return None


def pki_encrypt(shared_key: bytes, packet_id: int, from_node: int, plaintext: bytes, extra_nonce: int) -> bytes:
    """Used by the IQ simulator to build test frames."""
    ct = AESCCM(shared_key, tag_length=8).encrypt(_pki_nonce(packet_id, from_node, extra_nonce), plaintext, None)
    return ct + struct.pack("<I", extra_nonce)
