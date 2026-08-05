"""
core/string_crypto.py — direct RSA encryption/decryption of a short
string. Two modes:

  oaep  — real, safe RSA-OAEP(SHA-256) via `cryptography`. Default.
  raw   — textbook RSA (m^e mod n), no padding. Deliberately available
          so learners can see *why* OAEP exists — this mode is what
          CTF challenges usually use, and it's what the crack tool
          in Stage 4 targets.

Keys can arrive either as PEM text or as raw {n, e} / {n, d} integers
(e.g. straight from the keygen page's in-memory state).
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

from .keygen import _build_private_key  # reuse the CRT-param builder


class CryptoError(ValueError):
    pass


def _int_to_bytes(i: int) -> bytes:
    if i == 0:
        return b"\x00"
    return i.to_bytes((i.bit_length() + 7) // 8, "big")


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def load_public_key(pem: str = None, n: int = None, e: int = None):
    if pem:
        try:
            key = serialization.load_pem_public_key(pem.encode(), backend=default_backend())
        except Exception as exc:
            raise CryptoError(f"could not parse public key PEM: {exc}")
        if not isinstance(key, rsa.RSAPublicKey):
            raise CryptoError("PEM does not contain an RSA public key")
        return key
    if n is not None and e is not None:
        return rsa.RSAPublicNumbers(e, n).public_key(default_backend())
    raise CryptoError("provide either a public key PEM, or both n and e")


def load_private_key(pem: str = None, n: int = None, d: int = None,
                      p: int = None, q: int = None, e: int = None):
    if pem:
        try:
            key = serialization.load_pem_private_key(pem.encode(), password=None, backend=default_backend())
        except Exception as exc:
            raise CryptoError(f"could not parse private key PEM: {exc}")
        if not isinstance(key, rsa.RSAPrivateKey):
            raise CryptoError("PEM does not contain an RSA private key")
        return key
    if p and q and d and e and n:
        return _build_private_key(p, q, d, e, n)
    if n is not None and d is not None:
        # raw-mode-only: we don't have p/q, so build a "virtual" key
        # good enough for textbook m = c^d mod n, but not for OAEP
        # (OAEP needs a real key object with CRT params for padding
        # sanity checks) — caller decides which path to use.
        return None
    raise CryptoError("provide a private key PEM, or n+d (+p+q for OAEP)")


def encrypt_string(plaintext: str, mode: str, pem: str = None, n: int = None, e: int = None):
    if not plaintext:
        raise CryptoError("plaintext is empty")

    if mode == "oaep":
        pub = load_public_key(pem=pem, n=n, e=e)
        try:
            ct = pub.encrypt(
                plaintext.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                              algorithm=hashes.SHA256(), label=None),
            )
        except Exception as exc:
            raise CryptoError(f"OAEP encryption failed: {exc}")
        return {"mode": "oaep", "ciphertext_int": str(_bytes_to_int(ct)),
                "ciphertext_b64": __import__("base64").b64encode(ct).decode()}

    if mode == "raw":
        pub = load_public_key(pem=pem, n=n, e=e)
        nums = pub.public_numbers()
        m = _bytes_to_int(plaintext.encode())
        if m >= nums.n:
            raise CryptoError("message is too long for this key size in raw mode — "
                               "use a bigger key or OAEP")
        c = pow(m, nums.e, nums.n)
        return {"mode": "raw", "ciphertext_int": str(c)}

    raise CryptoError("mode must be 'oaep' or 'raw'")


def decrypt_string(mode: str, pem: str = None, n: int = None, d: int = None,
                    p: int = None, q: int = None, e: int = None,
                    ciphertext_int: str = None, ciphertext_b64: str = None):
    if mode == "oaep":
        key = load_private_key(pem=pem, n=n, d=d, p=p, q=q, e=e)
        if key is None:
            raise CryptoError("OAEP decryption needs a full key (PEM, or n+e+d+p+q)")
        if ciphertext_b64:
            import base64
            ct = base64.b64decode(ciphertext_b64)
        elif ciphertext_int:
            ct = _int_to_bytes(int(ciphertext_int))
        else:
            raise CryptoError("no ciphertext provided")
        try:
            pt = key.decrypt(
                ct,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                              algorithm=hashes.SHA256(), label=None),
            )
        except Exception as exc:
            raise CryptoError(f"OAEP decryption failed (wrong key or ciphertext?): {exc}")
        return {"mode": "oaep", "plaintext": pt.decode(errors="replace")}

    if mode == "raw":
        if n is None or d is None:
            raise CryptoError("raw decryption needs n and d")
        if not ciphertext_int:
            raise CryptoError("no ciphertext provided")
        c = int(ciphertext_int)
        m = pow(c, d, n)
        pt_bytes = _int_to_bytes(m)
        try:
            text = pt_bytes.decode()
        except UnicodeDecodeError:
            text = pt_bytes.decode(errors="replace")
        return {"mode": "raw", "plaintext": text}

    raise CryptoError("mode must be 'oaep' or 'raw'")
