import argparse, os, pandas as pd
from .util import ensure_out, timestamp, b64
from .jsonio import write_json
from .crypto_algs import enc_aes_gcm, enc_chacha_poly, enc_aes_ctr_hmac

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True, choices=["web","vpn","wifi","voip","iot","general"])
    ap.add_argument("--repeat", type=int, default=12)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--msg")
    src.add_argument("--file")
    args = ap.parse_args()

    data = args.msg.encode() if args.msg else open(args.file,"rb").read()
    ensure_out()
    ts = timestamp()
    base = f"analysis_{ts}_{args.scenario}"


    results=[]
    for _ in range(args.repeat):
        for fn in (lambda: enc_aes_gcm(data,128,b"CN-Py-analyze"),
                   lambda: enc_aes_gcm(data,256,b"CN-Py-analyze"),
                   lambda: enc_chacha_poly(data,b"CN-Py-analyze"),
                   lambda: enc_aes_ctr_hmac(data)):
            ct,key,nonce,ad,tag,ms,algo,variant = fn()
            results.append(dict(
                algo=algo, variant=variant, ciphertext_b64=b64(ct), key_b64=b64(key),
                nonce_b64=(None if nonce is None else b64(nonce)),
                ad_b64=(None if ad is None else b64(ad)),
                tag_b64=(None if tag is None else b64(tag)),
                time_ms=ms, time_ms_mean=ms, time_ms_p95=ms,
                ciphertext_len=len(ct),
                ciphertext_preview=b64(ct)[:80]+"..."
            ))

    df = pd.DataFrame(results)
    agg = df.groupby(["algo","variant"]).agg(
        time_ms_mean=("time_ms","mean"),
        time_ms_p95=("time_ms", lambda x: x.quantile(0.95))
    ).reset_index()

    latest=[]
    for _,row in agg.iterrows():
        r = df[(df["algo"]==row["algo"])&(df["variant"]==row["variant"])].iloc[-1].to_dict()
        r["time_ms_mean"]=row["time_ms_mean"]; r["time_ms_p95"]=row["time_ms_p95"]
        latest.append(r)

    summary = dict(scenario=args.scenario, message_bytes=len(data), results=latest)
    write_json(f"out/{base}_summary.json", summary)

    lines=[]
    lines.append(f"# Analysis: {args.scenario.upper()}")
    lines.append(f"Input: {len(data)} bytes; repeat={args.repeat}")
    lines.append("")
    lines.append("| Algorithm | Mean (ms) | p95 (ms) | Preview |")
    lines.append("|---|---:|---:|---|")
    for r in latest:
        lines.append(f"| {r['algo']} {r['variant']} | {r['time_ms_mean']:.4f} | {r['time_ms_p95']:.4f} | `{r['ciphertext_preview']}` |")
    md = "\n".join(lines)
    with open(f"out/{base}_report.md","w",encoding="utf-8") as f: f.write(md)
    print(f"Saved: out/{base}_report.md")

if __name__=="__main__":
    main()
