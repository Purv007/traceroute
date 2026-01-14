import argparse
from .jsonio import read_json
from .util import ensure_out, timestamp, write

def _to_float(*vals):
    for v in vals:
        if v is None: continue
        try: return float(v)
        except: pass
    return float("nan")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--files", nargs="+", required=True, help="*_summary.json from analyze/apply/compare")
    ap.add_argument("--title", default="CN: Comparison from Saved Summaries")
    args=ap.parse_args()

    ensure_out()
    ts=timestamp()
    rows=[]
    input_bytes=None

    for path in args.files:
        doc=read_json(path)
        scenario=str(doc.get("scenario","unknown")).lower()
        if "message_bytes" in doc:
            input_bytes = max(input_bytes or 0, int(doc["message_bytes"]))
        for r in doc.get("results", []):
            rows.append(dict(
                scenario=scenario,
                algo=r.get("algo"), variant=r.get("variant",""),
                mean=_to_float(r.get("time_ms_mean"), r.get("mean_ms")),
                p95=_to_float(r.get("time_ms_p95"), r.get("p95_ms")),
                aead=(r.get("algo") in ("AES-GCM","ChaCha20-Poly1305")),
                preview=(r.get("ciphertext_b64","")[:60]+"...")
            ))

    md=[]
    md.append(f"# {args.title}\n")
    if input_bytes is not None:
        md.append(f"**Input Size:** {input_bytes} bytes  |  **Files:** {', '.join(args.files)}\n")
    else:
        md.append(f"**Files:** {', '.join(args.files)}\n")

    md.append("## A) Side-by-side from saved runs")
    md.append("| Scenario | Algorithm | Mean (ms) | p95 (ms) | AEAD | Preview |")
    md.append("|---|---|---:|---:|:---:|---|")
    for r in sorted(rows, key=lambda x:(x["scenario"], x["algo"], x["variant"])):
        md.append(f"| {r['scenario'].upper()} | {r['algo']} {r['variant']} | {r['mean']:.4f} | {r['p95']:.4f} | {'Yes' if r['aead'] else 'No'} | `{r['preview']}` |")

    md.append("\n## B) Fastest AEAD per scenario")
    md.append("| Scenario | Pick | Mean (ms) |")
    md.append("|---|---|---:|")
    by_scn={}
    for r in rows:
        if not r["aead"]: continue
        sc=r["scenario"]
        if sc not in by_scn or r["mean"]<by_scn[sc]["mean"]:
            by_scn[sc]=r
    for sc,r in by_scn.items():
        md.append(f"| {sc.upper()} | {r['algo']} {r['variant']} | {r['mean']:.4f} |")

    path=f"out/compare_from_summaries_{ts}_report.md"
    write(path, "\n".join(md))
    print("Saved:", path)

if __name__=="__main__":
    main()
