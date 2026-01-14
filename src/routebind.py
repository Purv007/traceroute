# src/routebind.py
import hashlib, json, time

def canonicalize_hops(hops, take=8):
    """
    hops: list of dicts like {"ip":"1.2.3.4","rtt_ms":23.4,"asn":12345}
    take: cap first N hops for stability
    """
    slim = []
    for h in hops[:take]:
        slim.append({
            "ip": h.get("ip",""),
            "asn": int(h.get("asn") or 0),
            # bucket RTT to 5ms bins to reduce flapping noise
            "rtt5": int(round(float(h.get("rtt_ms") or 0)/5.0))
        })
    return slim

def route_fingerprint(hops, clock_quantum_s=60, take=8):
    """
    Stable-ish fingerprint: first N hops + coarse time bucket.
    """
    bucket = int(time.time()//clock_quantum_s)
    payload = {
        "bucket": bucket,
        "hops": canonicalize_hops(hops, take=take),
        "v": 1
    }
    raw = json.dumps(payload, separators=(",",":"), sort_keys=True).encode()
    h = hashlib.blake2s(raw, digest_size=32).digest()
    return h, payload  # (bytes, json-for-debug)
