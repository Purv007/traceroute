import argparse
from .util import ensure_out, timestamp, b64
from .jsonio import write_json
from .crypto_algs import enc_aes_gcm, enc_chacha_poly, enc_aes_ctr_hmac

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--problem", required=True)
    ap.add_argument("--title", default="CN Project: Applied Recommendation")
    ap.add_argument("--repeat", type=int, default=15)
    ap.add_argument("--scenario", choices=["web","vpn","wifi","voip","iot","general"])
    ap.add_argument("--all", action="store_true")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--msg")
    src.add_argument("--file")
    args=ap.parse_args()

    scenarios = ["web","vpn","wifi","voip","iot","general"] if args.all else [args.scenario]
    if not scenarios or scenarios==[None]:
        raise SystemExit("Provide --scenario or use --all")

    data = args.msg.encode() if args.msg else open(args.file,"rb").read()
    ensure_out()
    ts = timestamp()
    created=[]

    def run_for_scenario(scn):
        base = f"apply_{ts}_{scn}"
        rows=[]
        def run(fn, aead):
            times=[]; last=None
            for _ in range(args.repeat):
                last = fn()
                times.append(last[5])
            mean = sum(times)/len(times); p95=sorted(times)[int((len(times)-1)*0.95)]
            ct,key,nonce,ad,tag,_,algo,variant = last
            r = dict(algo=algo, variant=variant, aead=aead,
                     ciphertext_b64=b64(ct), key_b64=b64(key),
                     nonce_b64=(None if nonce is None else b64(nonce)),
                     ad_b64=(None if ad is None else b64(ad)),
                     tag_b64=(None if tag is None else b64(tag)),
                     time_ms_mean=mean, time_ms_p95=p95,
                     ciphertext_len=len(ct),
                     ciphertext_preview=b64(ct)[:80]+"...")
            rows.append(r)

        run(lambda: enc_aes_gcm(data,128,b"CN-Py-apply"), True)
        run(lambda: enc_aes_gcm(data,256,b"CN-Py-apply"), True)
        run(lambda: enc_chacha_poly(data,b"CN-Py-apply"), True)
        run(lambda: enc_aes_ctr_hmac(data), False)

        aeads=[r for r in rows if r["aead"]]
        pick=min(aeads, key=lambda r: r["time_ms_mean"])

        summary=dict(title=args.title, problem=args.problem, scenario=scn,
                     message_bytes=len(data), results=rows, recommendation=dict(
                         algorithm=f"{pick['algo']} {pick['variant']}",
                         reason="Fastest AEAD on this input (mean ms)"
                     ))
        write_json(f"out/{base}_summary.json", summary)
        for r in rows:
            safe = r["algo"].replace("+","plus").replace("/","_")
            write_json(f"out/{base}_{safe}.json", r)
            with open(f"out/{base}_{safe}.b64","w",encoding="utf-8") as f: f.write(r["ciphertext_b64"])

        md=[]
        md.append(f"# {args.title}")
        md.append(f"**Problem:** {args.problem}")
        md.append(f"**Scenario:** {scn.upper()}  |  **Input Size:** {len(data)} bytes  |  **Repeat:** {args.repeat}\n")
        md.append(f"**Recommendation:** **{pick['algo']} {pick['variant']}** — fastest AEAD on your data.\n")
        md.append("## Performance (mean & p95, ms)")
        md.append("| Algorithm | AEAD | Mean (ms) | p95 (ms) | Preview |")
        md.append("|---|:---:|---:|---:|---|")
        for r in rows:
            md.append(f"| {r['algo']} {r['variant']} | {'Yes' if r['aead'] else 'No'} | {r['time_ms_mean']:.4f} | {r['time_ms_p95']:.4f} | `{r['ciphertext_preview']}` |")
        text="\n".join(md)
        path=f"out/{base}_report.md"
        with open(path,"w",encoding="utf-8") as f: f.write(text)
        created.append(path)

    for scn in scenarios: run_for_scenario(scn)
    print("Reports:", *created, sep="\n")

if __name__=="__main__":
    main()
