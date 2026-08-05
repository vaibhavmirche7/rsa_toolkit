"""
core/keygen.py — RSA key generation for the web toolkit.

Handles three generation modes:
  - standard      : real, secure keygen via `cryptography` (OpenSSL-backed)
  - weak_fermat   : p and q deliberately chosen close together
  - weak_wiener   : d deliberately chosen small (classic Wiener setup)

All modes return a unified `KeyResult` with n/e/d/p/q, a strength
assessment, a copy-friendly step-by-step math trace, a SHA-256
fingerprint of the public key, and every export format pre-built as
strings (PEM PKCS1/PKCS8, DER base64, raw JSON) — the caller never
touches disk. Nothing here is persisted; the API layer just ships
this dict back to the browser, which builds its own download blobs.
"""

import base64
import hashlib
import time
from dataclasses import dataclass, field
from math import gcd, isqrt

from sympy import isprime, nextprime, randprime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers,
    RSAPublicNumbers,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
    rsa_crt_iqmp,
)
from cryptography.hazmat.backends import default_backend

ALLOWED_BITS = (1024, 2048, 4096)


class KeygenError(ValueError):
    """Raised for bad user input — caller turns this into a 400."""


@dataclass
class KeyResult:
    bits: int
    mode: str
    n: int
    e: int
    d: int
    p: int
    q: int
    phi: int
    generation_ms: float
    fingerprint_sha256: str
    strength: dict = field(default_factory=dict)
    math_steps: list = field(default_factory=list)
    export: dict = field(default_factory=dict)

    def to_dict(self):
        d = self.__dict__.copy()
        # ints beyond JS's safe integer range must travel as strings
        for k in ("n", "e", "d", "p", "q", "phi"):
            d[k] = str(d[k])
        return d


# ---------------------------------------------------------------------
# Prime helpers
# ---------------------------------------------------------------------

def _random_prime_of_bitlength(bits: int):
    """A prime uniformly-ish sampled from the given bit length."""
    low = 1 << (bits - 1)
    high = (1 << bits) - 1
    return randprime(low, high)


def _validate_bits(bits: int):
    if bits not in ALLOWED_BITS:
        raise KeygenError(f"key size must be one of {ALLOWED_BITS}")


def _validate_e(e: int, phi: int):
    if e < 3 or e % 2 == 0:
        raise KeygenError("e must be an odd integer >= 3")
    if e >= phi:
        raise KeygenError("e must be smaller than phi(n)")
    if gcd(e, phi) != 1:
        raise KeygenError("e is not coprime with phi(n) — pick a different e")


# ---------------------------------------------------------------------
# Mode 1: standard, secure generation (delegates to OpenSSL via `cryptography`)
# ---------------------------------------------------------------------

def _generate_standard(bits: int, e: int):
    t0 = time.perf_counter()
    priv = rsa.generate_private_key(public_exponent=e, key_size=bits, backend=default_backend())
    elapsed = (time.perf_counter() - t0) * 1000
    nums = priv.private_numbers()
    pub = nums.public_numbers
    p, q, d, n = nums.p, nums.q, nums.d, pub.n
    phi = (p - 1) * (q - 1)
    return priv, p, q, d, n, pub.e, phi, elapsed


# ---------------------------------------------------------------------
# Mode 2: weak — p, q close together (Fermat factorization vulnerable)
# ---------------------------------------------------------------------

def _generate_weak_fermat(bits: int, e: int):
    t0 = time.perf_counter()
    half = bits // 2
    # p near the middle of the target bit range, q within a small
    # offset of p so |p - q| is tiny relative to sqrt(n) — exactly
    # what fermat_factor() in the cracker is built to exploit.
    p = _random_prime_of_bitlength(half)
    offset_cap = max(1 << (half - 16), 4)  # tiny relative to p
    q = nextprime(p + 2)
    tries = 0
    while (q - p) > offset_cap and tries < 200:
        q = nextprime(q + 2) if tries % 2 == 0 else nextprime(p + 2)
        tries += 1
    if q == p:
        q = nextprime(p + 2)

    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        e = 65537 if gcd(65537, phi) == 1 else 3
        if gcd(e, phi) != 1:
            raise KeygenError("could not find a valid e for this weak key, try again")
    d = pow(e, -1, phi)
    elapsed = (time.perf_counter() - t0) * 1000
    return _build_private_key(p, q, d, e, n), p, q, d, n, e, phi, elapsed


# ---------------------------------------------------------------------
# Mode 3: weak — small private exponent d (Wiener's attack vulnerable)
# ---------------------------------------------------------------------

def _generate_weak_wiener(bits: int):
    t0 = time.perf_counter()
    half = bits // 2
    p = _random_prime_of_bitlength(half)
    q = _random_prime_of_bitlength(half)
    while q == p:
        q = _random_prime_of_bitlength(half)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Classic Wiener bound: attack succeeds when d < (1/3) * n^(1/4).
    # We aim comfortably under that so the demo reliably breaks.
    bound = isqrt(isqrt(n)) // 4
    bound = max(bound, 5)
    d = randprime(3, bound) if bound > 3 else 3
    tries = 0
    while gcd(d, phi) != 1 and tries < 50:
        d = nextprime(d + 2)
        tries += 1
    if gcd(d, phi) != 1:
        raise KeygenError("could not find a valid small d for this weak key, try again")

    e = pow(d, -1, phi)
    elapsed = (time.perf_counter() - t0) * 1000
    return _build_private_key(p, q, d, e, n), p, q, d, n, e, phi, elapsed


def _build_private_key(p, q, d, e, n):
    """Wrap manually-derived p,q,d,e,n into a real `cryptography` key
    object so weak keys export to PEM/DER the same way standard ones do."""
    dmp1 = rsa_crt_dmp1(d, p)
    dmq1 = rsa_crt_dmq1(d, q)
    iqmp = rsa_crt_iqmp(p, q)
    pub_numbers = RSAPublicNumbers(e, n)
    priv_numbers = RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub_numbers)
    return priv_numbers.private_key(default_backend())


# ---------------------------------------------------------------------
# Strength meter
# ---------------------------------------------------------------------

def _assess_strength(bits, p, q, n, d, phi):
    notes = []
    fermat_risk = False
    wiener_risk = False

    diff = abs(p - q)
    # Fermat factorization is fast whenever |p-q| is small relative to
    # n^(1/4). We flag it with a wide net (real Fermat is fast even a
    # good bit beyond this threshold too).
    n_quarter = isqrt(isqrt(n))
    if diff < n_quarter * 1000:
        fermat_risk = True
        notes.append("p and q are close together — vulnerable to Fermat factorization.")

    wiener_bound = isqrt(isqrt(n)) // 3
    if d < wiener_bound:
        wiener_risk = True
        notes.append("Private exponent d is small relative to n — vulnerable to Wiener's attack.")

    if bits < 2048:
        notes.append(f"{bits}-bit keys are considered weak by modern standards (2048+ recommended).")

    if not notes:
        notes.append("No classical weaknesses detected (Fermat/Wiener checks passed).")

    return {
        "fermat_risk": fermat_risk,
        "wiener_risk": wiener_risk,
        "bit_length_ok": bits >= 2048,
        "notes": notes,
    }


# ---------------------------------------------------------------------
# Exports (PEM PKCS1/PKCS8, DER, raw JSON) — all pre-built as strings
# ---------------------------------------------------------------------

def _build_exports(priv_key, n, e, d, p, q):
    pub_key = priv_key.public_key()

    private_pkcs1_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    private_pkcs8_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    private_der_b64 = base64.b64encode(
        priv_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ).decode()

    public_der_b64 = base64.b64encode(
        pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode()

    raw_json = {
        "n": str(n), "e": str(e), "d": str(d), "p": str(p), "q": str(q),
    }

    return {
        "private_pkcs1_pem": private_pkcs1_pem,
        "private_pkcs8_pem": private_pkcs8_pem,
        "public_pem": public_pem,
        "private_der_b64": private_der_b64,
        "public_der_b64": public_der_b64,
        "raw_json": raw_json,
    }, pub_key


def _fingerprint(pub_key):
    der = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _math_steps(p, q, n, phi, e, d):
    return [
        {"label": "p (prime)", "value": str(p)},
        {"label": "q (prime)", "value": str(q)},
        {"label": "n = p × q", "value": str(n)},
        {"label": "φ(n) = (p−1)(q−1)", "value": str(phi)},
        {"label": "e (public exponent)", "value": str(e)},
        {"label": "d = e⁻¹ mod φ(n)", "value": str(d)},
    ]


# ---------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------

def generate_key(bits: int, e: int = 65537, mode: str = "standard") -> KeyResult:
    _validate_bits(bits)
    if mode not in ("standard", "weak_fermat", "weak_wiener"):
        raise KeygenError("unknown generation mode")

    if mode == "standard":
        if e < 3 or e % 2 == 0:
            raise KeygenError("e must be an odd integer >= 3")
        priv, p, q, d, n, e, phi, elapsed = _generate_standard(bits, e)
    elif mode == "weak_fermat":
        if e < 3 or e % 2 == 0:
            raise KeygenError("e must be an odd integer >= 3")
        priv, p, q, d, n, e, phi, elapsed = _generate_weak_fermat(bits, e)
    else:  # weak_wiener — e is derived from the deliberately-small d, not user-chosen
        priv, p, q, d, n, e, phi, elapsed = _generate_weak_wiener(bits)

    export, pub_key = _build_exports(priv, n, e, d, p, q)
    fingerprint = _fingerprint(pub_key)
    strength = _assess_strength(bits, p, q, n, d, phi)
    steps = _math_steps(p, q, n, phi, e, d)

    return KeyResult(
        bits=bits, mode=mode, n=n, e=e, d=d, p=p, q=q, phi=phi,
        generation_ms=round(elapsed, 2),
        fingerprint_sha256=fingerprint,
        strength=strength,
        math_steps=steps,
        export=export,
    )
