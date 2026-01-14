# src/graph_crypto.py
from __future__ import annotations

from typing import Dict, List, Optional
import math
import random

# ---------------- helpers ----------------
def clean_upper_letters(s: str) -> str:
    return "".join(ch for ch in s.upper() if "A" <= ch <= "Z")

def a2n(ch: str) -> int:
    return ord(ch) - 64

def n2a(x: int) -> str:
    x = ((x - 1) % 26) + 1
    return chr(64 + x)

def encode_paper(s: str) -> List[int]:
    return [a2n(ch) for ch in clean_upper_letters(s)]

def decode_paper(nums: List[int]) -> str:
    return "".join(n2a(x) for x in nums)

def is_prime(p: int) -> bool:
    if p < 2:
        return False
    if p % 2 == 0:
        return p == 2
    r = int(p ** 0.5)
    for d in range(3, r + 1, 2):
        if p % d == 0:
            return False
    return True

def next_primes(count: int, start: int = 2) -> List[int]:
    res, x = [], max(2, start)
    while len(res) < count:
        if is_prime(x):
            res.append(x)
        x += 1
    return res

def egcd(a: int, b: int):
    if b == 0:
        return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)

def modinv(a: int, m: int) -> int:
    a %= m
    x, y, g = egcd(a, m)
    if g != 1:
        raise ValueError(f"no inverse for a={a} mod {m}")
    return x % m

def _nk_from_k(k: int) -> int:
    # enough primes to make a rows x cols table covering 26 letters
    return math.ceil(26 / k) + k


# ---------------- 1) Corona (paper exact; optional explicit b-values) ----------------
def encrypt_corona_paper(
    plaintext: str,
    shift_n: int = 5,
    m: int = 26,
    *,
    b_values: Optional[List[int]] = None
) -> Dict:
    vals = encode_paper(plaintext)
    if not vals:
        return {"scheme": "corona", "error": "No A–Z letters in plaintext."}
    a = [((x + shift_n - 1) % m) + 1 for x in vals]

    if b_values is not None:
        if len(b_values) != len(a):
            return {
                "scheme": "corona",
                "error": "b_values length must match number of A–Z letters.",
            }
        for ai, b in zip(a, b_values):
            if b <= m or math.gcd(ai, b) != 1:
                return {
                    "scheme": "corona",
                    "error": "Each b_i must be > 26 and coprime with shifted a_i.",
                }
        bs = [int(b) for b in b_values]
    else:
        # auto-pick primes > m and coprime with each shifted letter
        bs, p = [], max(29, m + 1)
        while len(bs) < len(a):
            if is_prime(p) and math.gcd(a[len(bs)], p) == 1:
                bs.append(p)
            p += 1

    # random cycle permutation
    order = list(range(len(a)))
    random.shuffle(order)
    main_cycle = [bs[i] for i in order]

    cs: List[int] = []
    for idx, i in enumerate(order):
        try:
            cs.append(modinv(a[i], main_cycle[idx]))
        except Exception:
            return {
                "scheme": "corona",
                "error": "Modular inverse failed; try different shift or b-values.",
            }

    # Build visualization data
    nodes, edges = [], []
    n = len(a)
    for i in range(n):
        nodes.append({"id": f"M{i}", "label": int(main_cycle[i])})
    for i in range(n):
        edges.append({"u": f"M{i}", "v": f"M{(i + 1) % n}", "weight": 1})
    for i in range(n):
        nodes.append({"id": f"T{i}", "label": int(cs[i])})
        edges.append({"u": f"M{i}", "v": f"T{i}", "weight": 1})

    # Recover (verifies round-trip); if impossible, report not crash
    try:
        pairs = sorted(
            [(nodes[i]["label"], nodes[n + i]["label"]) for i in range(n)],
            key=lambda t: t[0],
        )
        rec: List[int] = []
        for bi, ci in pairs:
            inv = modinv(ci, bi)
            inv_26 = ((inv - 1) % m) + 1
            w = ((inv_26 - shift_n - 1) % m) + 1
            rec.append(w)
        roundtrip = decode_paper(rec)
    except Exception:
        return {
            "scheme": "corona",
            "error": "Round-trip check failed (inconsistent parameters).",
        }

    return {
        "scheme": "corona",
        "params": {"shift_n": shift_n, "m": m, "b_values_used": main_cycle},
        "graph": {"nodes": nodes, "edges": edges},
        "main_cycle_b": main_cycle,
        "roundtrip": roundtrip,
    }


# ---------------- 2) Complete Bipartite (paper exact) ----------------
def encrypt_bipartite_paper(plaintext: str, k: int = 6) -> Dict:
    letters = encode_paper(plaintext)
    if not letters:
        return {"scheme": "bipartite", "error": "No A–Z letters in plaintext."}
    if not (3 <= k <= 12):
        return {"scheme": "bipartite", "error": "k must be 3..12."}

    n = _nk_from_k(k)
    rows, cols = n - k, k
    P = next_primes(n, start=2)
    R, C = P[:rows], P[rows:]

    # Deterministic A..Z table
    alpha = [n2a(i) for i in range(1, 27)]
    table, idx = [], 0
    for _ in range(rows):
        row = []
        for _ in range(cols):
            row.append(alpha[idx % 26])
            idx += 1
        table.append(row)

    flat = [ch for row in table for ch in row]
    positions = []
    for v in letters:
        ch = n2a(v)
        if ch in flat:
            pos = flat.index(ch)
            positions.append((pos // cols, pos % cols))
        else:
            return {"scheme": "bipartite", "error": "Internal table indexing error."}

    tokens = [R[r] * C[c] for (r, c) in positions]

    # Graph data (safe)
    nodes = [{"id": f"U{i}", "label": int(p)} for i, p in enumerate(R)]
    nodes += [{"id": f"V{j}", "label": int(p)} for j, p in enumerate(C)]
    edges = [
        {"u": f"U{i}", "v": f"V{j}", "weight": int(R[i] + C[j])}
        for i in range(rows)
        for j in range(cols)
    ]

    # Safe decode (no StopIteration)
    rec = []
    for t in tokens:
        found = False
        for i, p in enumerate(R):
            if t % p == 0:
                cj_val = t // p
                if cj_val in C:
                    j = C.index(cj_val)
                    rec.append(table[i][j])
                    found = True
                    break
        if not found:
            return {
                "scheme": "bipartite",
                "error": "Could not factor token back into (row,col) primes.",
            }

    return {
        "scheme": "bipartite",
        "params": {"k": k, "n": n, "rows": rows, "cols": cols},
        "table": table,
        "row_primes": R,
        "col_primes": C,
        "tokens": tokens,
        "graph": {"nodes": nodes, "edges": edges},
        "roundtrip": "".join(rec),
    }


# ---------------- 3) Star (paper exact) ----------------
def encrypt_star_paper(plaintext: str, k: int = 8) -> Dict:
    letters = encode_paper(plaintext)
    if not letters:
        return {"scheme": "star", "error": "No A–Z letters in plaintext."}
    if not (3 <= k <= 12):
        return {"scheme": "star", "error": "k must be 3..12."}

    n = _nk_from_k(k)
    rows, cols = n - k, k
    P = next_primes(n, start=2)
    R, C = P[:rows], P[rows:]

    alpha = [n2a(i) for i in range(1, 27)]
    table, idx = [], 0
    for _ in range(rows):
        row = []
        for _ in range(cols):
            row.append(alpha[idx % 26])
            idx += 1
        table.append(row)

    flat = [ch for row in table for ch in row]
    positions = []
    for v in letters:
        ch = n2a(v)
        if ch in flat:
            pos = flat.index(ch)
            positions.append((pos // cols, pos % cols))
        else:
            return {"scheme": "star", "error": "Internal table indexing error."}

    a_vals = [R[r] * C[c] for (r, c) in positions]

    nodes = [{"id": "H", "label": 0}]
    edges = []
    for i, aval in enumerate(a_vals, start=1):
        nodes.append({"id": f"L{i}", "label": int(aval)})
        edges.append({"u": "H", "v": f"L{i}", "weight": int(aval - (10 ** i))})

    # Recover safely
    sorted_edges = sorted(edges, key=lambda e: e["weight"])
    rec = []
    for i, e in enumerate(sorted_edges, start=1):
        aval = e["weight"] + (10 ** i)
        found = False
        for ri, p in enumerate(R):
            if aval % p == 0:
                cj_val = aval // p
                if cj_val in C:
                    cj = C.index(cj_val)
                    rec.append(table[ri][cj])
                    found = True
                    break
        if not found:
            return {
                "scheme": "star",
                "error": "Could not reconstruct letter from star edges.",
            }

    return {
        "scheme": "star",
        "params": {"k": k, "n": n, "rows": rows, "cols": cols},
        "table": table,
        "row_primes": R,
        "col_primes": C,
        "graph": {"nodes": nodes, "edges": edges},
        "a_values": a_vals,
        "roundtrip": "".join(rec),
    }


# -------- wrappers so old /graph-crypto (original) keeps working --------
def encrypt_corona(plaintext: str, shift: int = 7, b_base: int = 211):
    return encrypt_corona_paper(plaintext, shift_n=shift)

def decrypt_corona(artifact: dict) -> str:
    return artifact.get("roundtrip", "")

def encrypt_bipartite(plaintext: str, key_k: int = 6):
    return encrypt_bipartite_paper(plaintext, k=key_k)

def decrypt_bipartite(artifact: dict) -> str:
    return artifact.get("roundtrip", "")

def encrypt_star(plaintext: str):
    return encrypt_star_paper(plaintext)

def decrypt_star(artifact: dict) -> str:
    return artifact.get("roundtrip", "")
