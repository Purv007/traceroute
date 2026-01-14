# src/compare_multi.py
import argparse
from .util import ensure_out, timestamp, b64
from .crypto_algs import enc_aes_gcm, enc_chacha_poly, enc_aes_ctr_hmac

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", nargs="+", required=True,
                    choices=["web", "vpn", "wifi", "voip", "iot", "general"])
    ap.add_argument("--repeat", type=int, default=15)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--msg")
    src.add_argument("--file")
    ap.add_argument("--title", default="CN: Multi-Scenario Comparison")
    args = ap.parse_args()

    data = args.msg.encode() if args.msg else open(args.file, "rb").read()
    ensure_out()
    ts = timestamp()
    base = f"compare_multi_{ts}"

    rows = []

    def run_one(scn, fn):
        times = []
        last = None
        for _ in range(args.repeat):
            # expected tuple: (ct, key, nonce, aad, tag, elapsed_ms, algo, variant)
            last = fn()
            times.append(last[5])
        mean = sum(times) / len(times)
        p95 = sorted(times)[int((len(times) - 1) * 0.95)]
        ct, _, _, _, _, _, algo, variant = last
        # 60-char Base64 preview so the table stays compact
        preview = (b64(ct)[:60] + "...") if ct else "—"
        rows.append(dict(
            scenario=scn,
            algo=algo,
            variant=variant,
            mean_ms=mean,
            p95_ms=p95,
            aead=(algo != "AES-CTR+HMAC"),
            preview=preview
        ))

    for scn in args.scenarios:
        run_one(scn, lambda: enc_aes_gcm(data, 128, b"CN-Py-cm"))
        run_one(scn, lambda: enc_aes_gcm(data, 256, b"CN-Py-cm"))
        run_one(scn, lambda: enc_chacha_poly(data, b"CN-Py-cm"))
        run_one(scn, lambda: enc_aes_ctr_hmac(data))

    md = []
    md.append(f"# {args.title}\n")
    md.append(f"**Input Size:** {len(data)} bytes  |  **Scenarios:** {', '.join([s.upper() for s in args.scenarios])}\n")
    md.append("## A) Side-by-side performance across scenarios (mean & p95, ms)")
    md.append("| Scenario | Algorithm | Mean (ms) | p95 (ms) | AEAD | Preview |")
    md.append("|---|---|---:|---:|:---:|---|")
    for r in rows:
        md.append(f"| {r['scenario'].upper()} | {r['algo']} {r['variant']} | {r['mean_ms']:.4f} | {r['p95_ms']:.4f} | {'Yes' if r['aead'] else 'No'} | `{r['preview']}` |")

    md.append("\n## B) Fastest AEAD per scenario")
    md.append("| Scenario | Pick | Mean (ms) |")
    md.append("|---|---|---:|")
    by_scn = {}
    for r in rows:
        if not r["aead"]:
            continue
        if r["scenario"] not in by_scn or r["mean_ms"] < by_scn[r["scenario"]]["mean_ms"]:
            by_scn[r["scenario"]] = r
    for scn in args.scenarios:
        r = by_scn.get(scn)
        if r:
            md.append(f"| {scn.upper()} | {r['algo']} {r['variant']} | {r['mean_ms']:.4f} |")

    text = "\n".join(md)
    with open(f"out/{base}_report.md", "w", encoding="utf-8") as f:
        f.write(text)
    print(f"Saved: out/{base}_report.md")

if __name__ == "__main__":
    main()
