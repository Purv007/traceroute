from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import os

from .util import now_ns, ns_to_ms
# NEW: honey encryption demo (decoy on wrong key)
from .honey import honey_encrypt_aesgcm_256


# All functions return:
# (ciphertext_without_tag, key, nonce, ad, tag, elapsed_ms, algo_name, variant)

def enc_aes_gcm(msg: bytes, key_bits: int, ad: bytes = b"CN-Py") -> tuple:
    """
    AES-GCM where we split out the 16-byte auth tag so the caller
    gets (ct, key, nonce, ad, tag, ...). AESGCM.encrypt returns ct||tag.
    """
    key = os.urandom(key_bits // 8)
    aes = AESGCM(key)
    nonce = os.urandom(12)

    t0 = now_ns()
    ct_all = aes.encrypt(nonce, msg, ad)   # ciphertext || tag (16 bytes)
    tag = ct_all[-16:]
    ct  = ct_all[:-16]

    # sanity check (reconcat for decrypt)
    _ = aes.decrypt(nonce, ct + tag, ad)

    ms = ns_to_ms(now_ns() - t0)
    return (ct, key, nonce, ad, tag, ms, "AES-GCM", str(key_bits))


def enc_chacha_poly(msg: bytes, ad: bytes = b"CN-Py") -> tuple:
    """
    ChaCha20-Poly1305 with tag split out (same convention as AES-GCM).
    """
    key = os.urandom(32)
    cc = ChaCha20Poly1305(key)
    nonce = os.urandom(12)

    t0 = now_ns()
    ct_all = cc.encrypt(nonce, msg, ad)    # ciphertext || tag (16 bytes)
    tag = ct_all[-16:]
    ct  = ct_all[:-16]

    _ = cc.decrypt(nonce, ct + tag, ad)

    ms = ns_to_ms(now_ns() - t0)
    return (ct, key, nonce, ad, tag, ms, "ChaCha20-Poly1305", "256")


def enc_aes_ctr_hmac(msg: bytes) -> tuple:
    """
    Encrypt-then-MAC demo: AES-CTR + HMAC-SHA256 (EtM).
    """
    key = os.urandom(16)   # 128-bit AES
    iv  = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    enc = cipher.encryptor()

    t0 = now_ns()
    ct = enc.update(msg) + enc.finalize()

    # EtM MAC
    hkey = os.urandom(32)
    h = hmac.HMAC(hkey, hashes.SHA256())
    h.update(ct)
    tag = h.finalize()

    # verify once to include cost
    hv = hmac.HMAC(hkey, hashes.SHA256())
    hv.update(ct)
    hv.verify(tag)

    ms = ns_to_ms(now_ns() - t0)
    # We return iv in the "nonce" slot; ad is None for this non-AEAD scheme
    return (ct, key, iv, None, tag, ms, "AES-CTR+HMAC", "128")


# NEW: Honey Encryption demo (AES-GCM based)
def enc_honey_aesgcm(msg: bytes, ad: bytes = b"CN-Py") -> tuple:
    """
    Honey-AESGCM 256:
    - Normal AES-GCM encryption.
    - If a wrong key is used during decryption (with our honey decrypter),
      a realistic-looking decoy is deterministically produced instead of an error.
    Returns the same tuple shape as the other algorithms.
    """
    return honey_encrypt_aesgcm_256(msg, ad)
