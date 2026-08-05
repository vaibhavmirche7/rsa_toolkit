"""
core/cracker.py — the "try everything" attack chain for the Crack a
Weak Key page. Ported from the original rsa_toolkit/auto_detection
CLI logic, but every attack now has an explicit cap so a single bad
request can't tie up the server:

    low_exponent  — only tried when e <= 5 and a ciphertext is given;
                    a handful of binary-search steps, effectively instant
    wiener        — naturally bounded by the continued-fraction expansion
                    of e/n (O(log n) convergents), no extra cap needed
    fermat        — capped by iteration count, not wall-clock
    factordb      — capped by a 10s network timeout
    general_factor— the dangerous one; runs in a subprocess with a hard
                    wall-clock cap and is killed if it overruns

`run_attacks()` always returns a full log (one entry per attack that
was even considered) so the caller can show a short, honest summary
of what was tried — this is the data behind the "post-hoc summary,
not a live log" decision.
"""

import time
import multiprocessing as mp
from math import gcd, isqrt

from sympy import mod_inverse

FERMAT_MAX_ITERATIONS = 2_000_000
FACTORDB_TIMEOUT_S = 10
GENERAL_FACTOR_TIMEOUT_S = 18


# ---------------------------------------------------------------------
# 1. Low public exponent (no padding, c < n) — instant when it applies
# ---------------------------------------------------------------------

def low_exponent_attack(c: int, e: int):
    low, high = 0, c
    while low <= high:
        mid = (low + high) // 2
        val = mid ** e
        if val == c:
            return mid
        elif val < c:
            low = mid + 1
        else:
            high = mid - 1
    return None


# ---------------------------------------------------------------------
# 2. Wiener's attack — small private exponent d
# ---------------------------------------------------------------------

def _continued_fraction(numerator, denominator):
    cf = []
    while denominator:
        cf.append(numerator // denominator)
        numerator, denominator = denominator, numerator % denominator
    return cf


def _convergents(cf):
    convergents = []
    for i in range(len(cf)):
        num = cf[i]
        den = 1
        for j in range(i - 1, -1, -1):
            num, den = cf[j] * num + den, num
        convergents.append((num, den))
    return convergents


def wiener_attack(n: int, e: int):
    cf = _continued_fraction(e, n)
    for k, d in _convergents(cf):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sq = isqrt(disc)
        if sq * sq != disc:
            continue
        p = (b + sq) // 2
        q = (b - sq) // 2
        if p * q == n:
            return d
    return None


# ---------------------------------------------------------------------
# 3. Fermat factorization — p, q close together
# ---------------------------------------------------------------------

def fermat_factor(n: int, max_iterations: int = FERMAT_MAX_ITERATIONS):
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iterations):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a + b, a - b
            if p * q == n and p != 1 and q != 1:
                return p, q
        a += 1
    return None


# ---------------------------------------------------------------------
# 4. factordb.com lookup — n has been factored before, publicly
# ---------------------------------------------------------------------

def factordb_lookup(n: int, timeout_s: float = FACTORDB_TIMEOUT_S):
    try:
        import requests
    except ImportError:
        return None, "requests library not installed"
    try:
        resp = requests.get("http://factordb.com/api", params={"query": str(n)}, timeout=timeout_s)
        data = resp.json()
        factors = data.get("factors", [])
        primes = []
        for factor, multiplicity in factors:
            primes.extend([int(factor)] * int(multiplicity))
        if len(primes) == 2:
            return (primes[0], primes[1]), None
        return None, "n not found on factordb (or not a 2-factor semiprime)"
    except Exception as exc:
        return None, f"factordb unreachable ({exc})"


# ---------------------------------------------------------------------
# 5. General factoring (sympy) — last resort, hard wall-clock cap
# ---------------------------------------------------------------------

def _general_factor_worker(n, out_queue):
    from sympy import factorint
    factors = factorint(n)
    primes = []
    for prime, mult in factors.items():
        primes.extend([prime] * mult)
    out_queue.put(primes if len(primes) == 2 else None)


def general_factor(n: int, timeout_s: float = GENERAL_FACTOR_TIMEOUT_S):
    ctx = mp.get_context("fork")
    q = ctx.Queue()
    proc = ctx.Process(target=_general_factor_worker, args=(n, q))
    proc.start()
    proc.join(timeout_s)
    if proc.is_alive():
        proc.terminate()
        proc.join(1)
        return None, f"timed out after {timeout_s}s"
    try:
        result = q.get_nowait()
    except Exception:
        return None, "factoring process exited without a result"
    if result is None:
        return None, "sympy could not find exactly two prime factors"
    return tuple(result), None


# ---------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------

def run_attacks(n: int, e: int, c: int = None):
    """Try every attack in order, cheapest/most-specific first. Returns
    (result, log) where result is {'attack','p','q','d'} on success or
    None, and log is a list of dicts describing every attack tried."""
    log = []

    def record(name, tried, success, elapsed_ms, note=""):
        log.append({"attack": name, "tried": tried, "success": success,
                     "time_ms": round(elapsed_ms, 1), "note": note})

    # --- low exponent shortcut (needs a ciphertext, no factoring at all) ---
    if c is not None and e is not None and e <= 5:
        t0 = time.perf_counter()
        m = low_exponent_attack(c, e)
        elapsed = (time.perf_counter() - t0) * 1000
        if m is not None:
            record("low_exponent", True, True, elapsed, "unpadded message recovered directly")
            return {"attack": "low_exponent", "p": None, "q": None, "d": None, "plaintext_int": m}, log
        record("low_exponent", True, False, elapsed)

    # --- wiener ---
    t0 = time.perf_counter()
    d = wiener_attack(n, e)
    elapsed = (time.perf_counter() - t0) * 1000
    if d is not None:
        record("wiener", True, True, elapsed, "small private exponent")
        return {"attack": "wiener", "p": None, "q": None, "d": d}, log
    record("wiener", True, False, elapsed)

    # --- fermat ---
    t0 = time.perf_counter()
    pq = fermat_factor(n)
    elapsed = (time.perf_counter() - t0) * 1000
    if pq is not None:
        p, q = pq
        phi = (p - 1) * (q - 1)
        d = mod_inverse(e, phi)
        record("fermat", True, True, elapsed, "p and q were close together")
        return {"attack": "fermat", "p": p, "q": q, "d": d}, log
    record("fermat", True, False, elapsed, f"no factor found in {FERMAT_MAX_ITERATIONS:,} iterations")

    # --- factordb ---
    t0 = time.perf_counter()
    pq, note = factordb_lookup(n)
    elapsed = (time.perf_counter() - t0) * 1000
    if pq is not None:
        p, q = pq
        phi = (p - 1) * (q - 1)
        d = mod_inverse(e, phi)
        record("factordb", True, True, elapsed, "n was previously factored publicly")
        return {"attack": "factordb", "p": p, "q": q, "d": d}, log
    record("factordb", True, False, elapsed, note or "not found")

    # --- general factoring ---
    t0 = time.perf_counter()
    pq, note = general_factor(n)
    elapsed = (time.perf_counter() - t0) * 1000
    if pq is not None:
        p, q = pq
        phi = (p - 1) * (q - 1)
        d = mod_inverse(e, phi)
        record("general_factor", True, True, elapsed, "brute-force factoring succeeded")
        return {"attack": "general_factor", "p": p, "q": q, "d": d}, log
    record("general_factor", True, False, elapsed, note or "gave up")

    return None, log
