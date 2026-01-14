# src/honey.py
import os, hmac, hashlib, struct, time
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- tiny, deterministic "note" DTE ----------
# Practical demo DTE that yields plausible text. Deterministic for a given seed.
_ADJ  = ["quick","helpful","secure","modern","robust","portable","simple","efficient","compact","resilient"]
_NOUN = ["system","service","gateway","module","agent","client","server","dataset","report","session"]
_VERB = ["processed","verified","synced","secured","rotated","migrated","scheduled","updated","backed up","indexed"]
_WHEN = ["today","yesterday","this morning","last night","earlier","just now","at 14:00","at 09:30","a moment ago","recently"]

def _prf(key: bytes, *parts: bytes) -> bytes:
    h = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        h.update(p)
    return h.digest()

def _drng(seed: bytes):
    """Deterministic byte generator from seed."""
    counter = 0
    while True:
        block = _prf(seed, struct.pack("!Q", counter))
        counter += 1
        for b in block:
            yield b

def _pick(gen, items):
    idx = next(gen) % len(items)      # 0..255 -> index
    return items[idx]

def dte_decode_note(seed: bytes) -> str:
    """
    Decode: seed -> plausible short operational note.
    Deterministic: same seed => same text.
    """
    g = _drng(seed)
    who  = f"{_pick(g,_ADJ)} {_pick(g,_NOUN)}"
    what = _pick(g,_VERB)
    when = _pick(g,_WHEN)
    extra = _pick(g, [
        "without anomalies", "with low latency", "under expected load",
        "using fallback route", "after key rotation", "with new policy",
        "after cache warmup", "via secure channel", "after reauth",
        "with audit trail"
    ])
    return f"{who} {what} {when} {extra}."

def dte_encode_note(text: str) -> bytes:
    """
    Demo 'encode': hash(text). Not distribution-perfect; adequate for demo.
    (Research-grade DTEs map messages to integers under a true prior.)
    """
    return hashlib.sha256(text.encode("utf-8")).digest()

# ---------- Honey AEAD wrapper (encrypt) ----------
def honey_encrypt_aesgcm_256(
    plaintext: bytes,
    ad: Optional[bytes]
) -> Tuple[bytes, bytes, bytes, bytes, bytes, float, str, str]:
    """
    Encrypt with AES-GCM. If later decrypted with a *wrong* key, clients can
    synthesize a realistic-looking decoy using DTE(seed = PRF(key, nonce|salt)).

    Returns a tuple compatible with your workbench:
      (ct_body, key, nonce, aad, tag, ms, algo, variant)

    Notes:
      * We include a small header 'HE1' + salt in the ciphertext body so
        decrypters can extract the salt to feed the DTE when auth fails.
      * The 16-byte GCM tag is returned separately (your UI expects that).
    """
    t0    = time.perf_counter()
    key   = os.urandom(32)   # 256-bit
    nonce = os.urandom(12)   # 96-bit GCM nonce
    salt  = os.urandom(8)    # decoy salt, stored alongside ciphertext
    aes   = AESGCM(key)

    aad   = (ad or b"") + b"|HE1|" + salt
    ct    = aes.encrypt(nonce, plaintext, aad)  # body || tag (16 bytes)
    tag   = ct[-16:]
    body  = ct[:-16]

    # Envelope: "HE1" + salt + body   (tag stays separate)
    he_body = b"HE1" + salt + body
    ms = (time.perf_counter() - t0) * 1000.0

    return (he_body, key, nonce, aad, tag, ms, "Honey-AESGCM", "256")

# ---------- (optional) reference decrypter for demo ----------
def honey_decrypt_aesgcm_256(key: bytes, he_body: bytes, nonce: bytes, aad: bytes, tag: bytes) -> str:
    """
    Try to decrypt. If GCM auth fails, return a DTE-generated decoy *without*
    signalling failure (the honey property).
    """
    try:
        if not (he_body.startswith(b"HE1") and len(he_body) >= 3 + 8):
            raise ValueError("Bad HE envelope")
        salt = he_body[3:11]
        body = he_body[11:]
        pt = AESGCM(key).decrypt(nonce, body + tag, aad)  # raises on wrong key
        return pt.decode("utf-8", errors="replace")
    except Exception:
        # Wrong key or malformed => decoy derived from (key, nonce, salt)
        if not (he_body.startswith(b"HE1") and len(he_body) >= 11):
            salt = b"\x00" * 8
        else:
            salt = he_body[3:11]
        seed = _prf(key, nonce, salt)
        return dte_decode_note(seed)
