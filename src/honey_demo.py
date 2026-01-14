# honey_demo.py
import base64
from src.honey import honey_decrypt_aesgcm_256

# Paste the values from the UI:
CT_B64   = "..."  # ciphertext_b64 (the HE envelope)
KEY_B64  = "..."  # key_b64  (correct key)
NONCE_B64= "..."  # nonce_b64
AD_B64   = "..."  # ad_b64   (includes "HE1|<salt>" marker)
TAG_B64  = "..."  # tag_b64  (16 bytes)

ct    = base64.b64decode(CT_B64)
key   = base64.b64decode(KEY_B64)
nonce = base64.b64decode(NONCE_B64)
aad   = base64.b64decode(AD_B64)
tag   = base64.b64decode(TAG_B64)

# 1) Correct key -> original plaintext
print("RIGHT KEY  ->", honey_decrypt_aesgcm_256(key, ct, nonce, aad, tag))

# 2) Wrong key -> realistic-looking decoy (no exception)
wrong_key = b"\x00" * 32
print("WRONG KEY  ->", honey_decrypt_aesgcm_256(wrong_key, ct, nonce, aad, tag))

