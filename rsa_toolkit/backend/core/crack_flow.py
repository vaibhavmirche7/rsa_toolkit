"""
core/crack_flow.py — ties the Crack a Weak Key page together.

Implements the field-dependency behavior decided for this page:

    p + q             -> n
    p + q + e         -> n, phi(n), d
    n + d (+ c)        -> direct decrypt, attacks are skipped entirely
    n + e + c (no d)  -> run the attack chain, decrypt if it succeeds
    a PEM (public or private) is auto-detected and unpacked into the
    same n/e/(d/p/q) fields before any of the above runs

Every value in the response carries a `source` so the frontend's
"show the math" panel can honestly label each one as given / derived
/ recovered-via-<attack>, instead of pretending everything was typed
in by the user.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .cracker import run_attacks


class CrackError(ValueError):
    pass


def _int_to_bytes(i: int) -> bytes:
    if i == 0:
        return b"\x00"
    return i.to_bytes((i.bit_length() + 7) // 8, "big")


def parse_ciphertext(raw: str) -> int:
    s = raw.strip()
    if not s:
        raise CrackError("ciphertext is empty")
    if s.lower().startswith("0x"):
        return int(s, 16)
    if s.isdigit():
        return int(s)
    # fall back to base64 (e.g. an OAEP-style ciphertext pasted here)
    import base64
    try:
        raw_bytes = base64.b64decode(s, validate=True)
        return int.from_bytes(raw_bytes, "big")
    except Exception:
        raise CrackError("could not parse ciphertext — expected an integer, 0x-hex, or base64")


def extract_from_pem(pem_str: str) -> dict:
    try:
        key = serialization.load_pem_public_key(pem_str.encode())
        if isinstance(key, rsa.RSAPublicKey):
            nums = key.public_numbers()
            return {"n": nums.n, "e": nums.e}
    except Exception:
        pass
    try:
        key = serialization.load_pem_private_key(pem_str.encode(), password=None)
        if isinstance(key, rsa.RSAPrivateKey):
            priv = key.private_numbers()
            pub = priv.public_numbers
            return {"n": pub.n, "e": pub.e, "d": priv.d, "p": priv.p, "q": priv.q}
    except Exception:
        pass
    raise CrackError("could not parse that PEM as either a public or private RSA key")


def analyze(pem: str = None, n: int = None, e: int = None, d: int = None,
            p: int = None, q: int = None, ciphertext: str = None):

    source = {}  # field name -> where it came from, for the math panel

    if pem:
        info = extract_from_pem(pem)
        for k, v in info.items():
            source[k] = "from PEM"
        n = info.get("n", n)
        e = info.get("e", e)
        d = info.get("d", d)
        p = info.get("p", p)
        q = info.get("q", q)
    else:
        for k, v in (("n", n), ("e", e), ("d", d), ("p", p), ("q", q)):
            if v is not None:
                source[k] = "given"

    c_int = parse_ciphertext(ciphertext) if ciphertext else None

    # --- derive n from p, q ---
    if p is not None and q is not None and n is None:
        n = p * q
        source["n"] = "derived (p × q)"

    # --- derive phi / d from p, q, e ---
    phi = None
    if p is not None and q is not None:
        phi = (p - 1) * (q - 1)
        source["phi"] = "derived ((p−1)(q−1))"
        if e is not None and d is None:
            try:
                d = pow(e, -1, phi)
                source["d"] = "derived (e⁻¹ mod φ(n))"
            except ValueError:
                pass  # e not invertible mod phi — leave d unknown

    if n is None and e is None and p is None and q is None:
        raise CrackError("need at least a PEM, or (n and e), or (p and q) to do anything")

    ran_attacks = False
    attack_log = []
    used_attack = None
    plaintext_int = None

    if d is not None and n is not None:
        # fast path — we already have everything, skip attacks entirely
        if c_int is not None:
            plaintext_int = pow(c_int, d, n)
    elif n is not None and e is not None:
        ran_attacks = True
        result, attack_log = run_attacks(n, e, c_int)
        if result:
            used_attack = result["attack"]
            if result.get("p") is not None:
                p, q = result["p"], result["q"]
                phi = (p - 1) * (q - 1)
                source["p"] = f"recovered via {used_attack}"
                source["q"] = f"recovered via {used_attack}"
                source["phi"] = "derived ((p−1)(q−1))"
            if result.get("d") is not None:
                d = result["d"]
                source["d"] = f"recovered via {used_attack}"
            if "plaintext_int" in result:
                plaintext_int = result["plaintext_int"]
                source["plaintext"] = f"recovered directly via {used_attack}"
            elif c_int is not None and d is not None:
                plaintext_int = pow(c_int, d, n)
                source["plaintext"] = "decrypted with recovered d"

    plaintext_text, plaintext_hex = None, None
    if plaintext_int is not None:
        raw = _int_to_bytes(plaintext_int)
        try:
            plaintext_text = raw.decode()
        except UnicodeDecodeError:
            plaintext_hex = raw.hex()

    if plaintext_int is not None:
        status = "decrypted"
        message = "Recovered the plaintext."
    elif d is not None:
        status = "key_recovered"
        message = "Recovered the private key, but no ciphertext was given to decrypt."
    elif ran_attacks:
        status = "attack_failed"
        message = "None of the attacks recovered the key. This n may be genuinely strong."
    else:
        status = "derived_only"
        message = "Showing everything derivable from what was given — no ciphertext or attack was needed/possible yet."

    math_steps = []
    for key, label in (("p", "p"), ("q", "q"), ("n", "n"), ("phi", "φ(n)"), ("e", "e"), ("d", "d")):
        value = {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}[key]
        if value is not None:
            tag = source.get(key)
            full_label = f"{label} ({tag})" if tag else label
            math_steps.append({"label": full_label, "value": str(value)})

    return {
        "status": status,
        "message": message,
        "n": str(n) if n is not None else None,
        "e": str(e) if e is not None else None,
        "d": str(d) if d is not None else None,
        "p": str(p) if p is not None else None,
        "q": str(q) if q is not None else None,
        "phi": str(phi) if phi is not None else None,
        "math_steps": math_steps,
        "ran_attacks": ran_attacks,
        "used_attack": used_attack,
        "attack_log": attack_log,
        "plaintext": plaintext_text,
        "plaintext_hex": plaintext_hex,
    }
