"""
core/file_crypto.py — hybrid AES + RSA encryption for files/images.

Real-world pattern, not textbook RSA: a fresh random AES-256 key
encrypts the file with AES-GCM (fast, no size limit), and that
one-time AES key is itself wrapped with RSA-OAEP. Everything is
packed into a single bundle so there's exactly one file to keep
track of on both ends — matches the "bundled output" decision.

Bundle layout (all integers big-endian):

    4 bytes   magic "RWT1"
    2 bytes   wrapped_key_len
    N bytes   wrapped_key            (RSA-OAEP wrapped AES-256 key)
    12 bytes  nonce                  (AES-GCM nonce)
    2 bytes   filename_len
    M bytes   filename               (utf-8, original filename)
    rest      ciphertext             (AES-GCM ciphertext, tag included)

Nothing here touches disk — callers pass bytes in, get bytes back.
"""

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .string_crypto import load_public_key, load_private_key, CryptoError

MAGIC = b"RWT1"
_OAEP = lambda: padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                              algorithm=hashes.SHA256(), label=None)


def encrypt_file(data: bytes, filename: str, pem: str = None, n: int = None, e: int = None) -> bytes:
    if not data:
        raise CryptoError("uploaded file is empty")

    pub = load_public_key(pem=pem, n=n, e=e)

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, None)

    try:
        wrapped_key = pub.encrypt(aes_key, _OAEP())
    except Exception as exc:
        raise CryptoError(f"could not wrap the AES key with this RSA key: {exc}")

    fname_bytes = (filename or "file.bin").encode("utf-8")[:255]

    header = (
        MAGIC
        + struct.pack(">H", len(wrapped_key)) + wrapped_key
        + nonce
        + struct.pack(">H", len(fname_bytes)) + fname_bytes
    )
    return header + ciphertext


def decrypt_file(bundle: bytes, pem: str = None, n: int = None, d: int = None,
                  p: int = None, q: int = None, e: int = None):
    if len(bundle) < 4 or bundle[:4] != MAGIC:
        raise CryptoError("not a valid RSA Web Toolkit bundle (bad or missing header)")

    offset = 4
    try:
        wrapped_len = struct.unpack(">H", bundle[offset:offset + 2])[0]; offset += 2
        wrapped_key = bundle[offset:offset + wrapped_len]; offset += wrapped_len
        nonce = bundle[offset:offset + 12]; offset += 12
        fname_len = struct.unpack(">H", bundle[offset:offset + 2])[0]; offset += 2
        filename = bundle[offset:offset + fname_len].decode("utf-8", errors="replace"); offset += fname_len
        ciphertext = bundle[offset:]
    except Exception:
        raise CryptoError("bundle is truncated or corrupted")

    priv = load_private_key(pem=pem, n=n, d=d, p=p, q=q, e=e)
    if priv is None:
        raise CryptoError("file decryption needs a full private key (PEM, or n+e+d+p+q)")

    try:
        aes_key = priv.decrypt(wrapped_key, _OAEP())
    except Exception as exc:
        raise CryptoError(f"could not unwrap the AES key — wrong private key? ({exc})")

    try:
        data = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise CryptoError(f"AES decryption failed — corrupted bundle or wrong key ({exc})")

    return data, filename
