import argparse
from .util import ensure_out, timestamp, b64
from .jsonio import write_json
from .crypto_algs import enc_aes_gcm, enc_chacha_poly, enc_aes_ctr_hmac

def typical_use(algo, scenario):
    if algo=="AES-GCM":
        return dict(web="TLS 1.3 / HTTPS", vpn="IPsec/QUIC (AES path)", wifi="WPA3 GCMP",
                    voip="SRTP AEAD", iot="If AES accel present").get(scenario,"General AEAD")
    if algo=="ChaCha20-Poly1305":
        return dict(web="TLS 1.3 (no AES accel)", vpn="WireGuard default", wifi="Alt to GCM",
                    voip="Low-latency AEAD", iot="Good on MCUs").get(scenario,"General AEAD")
    if algo=="AES-CTR+HMAC":
        return "Legacy/compat; use when AEAD unavailable"
    return "Protocol-specific"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True, choices=["web","vpn","wifi","voip","iot","general"])
    ap.add_argument("--repeat", type=int, default=15)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--msg")
    src.add_argument("--file")
    ap.add_argument("--title", default="CN Project: Side-by-Side (Python)")
    args=ap.parse_args()

    data = args.msg.encode() if args.msg else open(args.file,"rb").read()
    ensure_out()
    ts = timestamp()
    base = f"compare_{ts}_{args.scenario}"

    rows=[]
    def run(fn):
        times=[]; last=None
        for _ in range(args.repeat):
            last = fn()
            times.append(last[5])
        mean = sum(times)/len(times); p95 = sorted(times)[int((len(times)-1)*0.95)]
        ct,key,nonce,ad,tag,_,algo,variant = last
        r = dict(
            algo=algo, variant=variant, aead=(algo!="AES-CTR+HMAC"),
            integrity=("AEAD tag" if algo!="AES-CTR+HMAC" else "HMAC-SHA256"),
            nonceInfo=("12-byte nonce (unique)" if algo!="AES-CTR+HMAC" else "16-byte IV (unique)"),
            tagInfo=("16-byte (embedded)" if algo!="AES-CTR+HMAC" else "32-byte HMAC tag"),
            typicalUse=typical_use(algo, args.scenario),
            ciphertext_b64=b64(ct), key_b64=b64(key),
            nonce_b64=(None if nonce is None else b64(nonce)),
            ad_b64=(None if ad is None else b64(ad)),
            tag_b64=(None if tag is None else b64(tag)),
            mean_ms=mean, p95_ms=p95, ct_len=len(ct),
            preview=b64(ct)[:80]+"..."
        )
        rows.append(r)

    run(lambda: enc_aes_gcm(data,128,b"CN-Py-compare"))
    run(lambda: enc_aes_gcm(data,256,b"CN-Py-compare"))
    run(lambda: enc_chacha_poly(data,b"CN-Py-compare"))
    run(lambda: enc_aes_ctr_hmac(data))

    for r in rows:
        safe = r["algo"].replace("+","plus").replace("/","_")
        write_json(f"out/{base}_{safe}.json", r)
        with open(f"out/{base}_{safe}.b64","w",encoding="utf-8") as f: f.write(r["ciphertext_b64"])
    summary = dict(title=args.title, scenario=args.scenario, message_bytes=len(data), results=rows)
    write_json(f"out/{base}_summary.json", summary)

    md=[]
    md.append(f"# {args.title}\n")
    md.append(f"**Scenario:** {args.scenario.upper()}  |  **Input Size:** {len(data)} bytes  |  **Tested:** AES-GCM(128/256), ChaCha20-Poly1305, AES-CTR+HMAC\n")
    md.append("## 1) Side-by-side at a glance")
    md.append("| Algorithm | AEAD | Integrity | Nonce/IV | Tag | Typical use |")
    md.append("|---|:---:|---|---|---|---|")
    for r in rows:
        md.append(f"| {r['algo']} {r['variant']} | {'Yes' if r['aead'] else 'No'} | {r['integrity']} | {r['nonceInfo']} | {r['tagInfo']} | {r['typicalUse']} |")
    md.append("\n## 2) Performance (mean & p95, ms) + ciphertext previews")
    md.append("| Algorithm | Mean (ms) | p95 (ms) | Ciphertext preview |")
    md.append("|---|---:|---:|---|")
    for r in rows:
        md.append(f"| {r['algo']} {r['variant']} | {r['mean_ms']:.4f} | {r['p95_ms']:.4f} | `{r['preview']}` |")
    md.append("\n## 3) Why differences matter")
    md.append("- AEAD (AES-GCM, ChaCha20-Poly1305) = confidentiality + integrity with a unique 12-byte nonce per key; tag embedded.")
    md.append("- AES-CTR+HMAC = two steps (encrypt + MAC); correct but slower and easier to misuse.")
    text="\n".join(md)
    with open(f"out/{base}_report.md","w",encoding="utf-8") as f: f.write(text)
    print(f"Saved: out/{base}_report.md")

if __name__=="__main__":
    main()
