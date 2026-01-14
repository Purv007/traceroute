
import os, sys, argparse
from .crypto_algs import enc_aes_gcm, enc_chacha_poly, enc_aes_ctr_hmac
from .util import ensure_out, b64, timestamp

ALGOS = {
    "aes-gcm-128": lambda msg, ad: enc_aes_gcm(msg, 128, ad),
    "aes-gcm-256": lambda msg, ad: enc_aes_gcm(msg, 256, ad),
    "chacha20-poly1305": lambda msg, ad: enc_chacha_poly(msg, ad),
    "aes-ctr+hmac": lambda msg, ad: enc_aes_ctr_hmac(msg),
}

SCENARIOS = ["web","wifi","vpn","voip","iot","general"]

def ask(prompt, default=None, validate=None):
    while True:
        s = input(f"{prompt}" + (f" [{default}]" if default is not None else "") + ": ").strip()
        if not s and default is not None:
            s = default
        if validate:
            ok, msg = validate(s)
            if ok: return s
            print(f"  -> {msg}")
        else:
            return s

def choose_many(prompt, options, default=None):
    print(f"{prompt} ({'/'.join(options)})")
    print("  - Enter comma-separated values (e.g., web,wifi)")
    if default: print(f"  - Press ENTER for default: {default}")
    s = input("> ").strip()
    if not s and default:
        s = default
    chosen = [x.strip().lower() for x in s.split(",") if x.strip()]
    for c in chosen:
        if c not in options:
            raise SystemExit(f"Unknown value: {c}")
    return chosen

def run_interactive():
    print("\n=== CN Encryption: Interactive Runner ===\n")

    # 1) What do you want to do?
    print("Select mode:")
    print("  1) Quick Encrypt (single run, show result immediately)")
    print("  2) Analyze (per-scenario summary report)")
    print("  3) Compare (side-by-side within ONE scenario)")
    print("  4) Compare-Multi (WEB vs WIFI vs ... in ONE file)")
    print("  5) Apply (problem statement → recommendation)")
    mode = ask("Enter 1/2/3/4/5", "2", lambda s: (s in {"1","2","3","4","5"}, "Choose 1..5"))

    # 2) Get input text
    print("\nProvide input:")
    method = ask("Type 'msg' to paste text OR 'file' to read from file", "msg",
                 lambda s: (s in {"msg","file"}, "Enter msg or file"))
    if method == "msg":
        msg = ask("Paste your message text").encode()
        src_label = "message"
    else:
        path = ask("Enter path to file (will be read as bytes)")
        with open(path, "rb") as f:
            msg = f.read()
        src_label = f"file:{path}"

    # 3) Common settings
    scenarios = SCENARIOS
    repeat = 15
    if mode == "4":  # multi
        scenarios = choose_many("Choose scenarios", SCENARIOS, default="web,wifi")
    else:
        sc = ask(f"Choose scenario {SCENARIOS}", "web", lambda s: (s in SCENARIOS, f"Pick one of {SCENARIOS}"))
        scenarios = [sc]

    try:
        r_in = ask("Repeat count (how many times to time each algo)", str(repeat))
        repeat = max(1, int(r_in))
    except:
        repeat = 15

    ensure_out()
    ts = timestamp()

    # 4) Modes
    if mode == "1":
        # Quick encrypt: let user pick algorithms and print JSON-ish output
        algos = choose_many("Pick algorithms", list(ALGOS.keys()), default="aes-gcm-128,chacha20-poly1305")
        ad = f"CN-UI-{scenarios[0]}".encode()
        rows = []
        for name in algos:
            times=[]; last=None
            for _ in range(repeat):
                last = ALGOS[name](msg, ad) if "aes-ctr" not in name else ALGOS[name](msg)
                times.append(last[5])
            mean = sum(times)/len(times); p95 = sorted(times)[int((len(times)-1)*0.95)]
            ct,key,nonce,ad_or_none,tag,_,algo,variant = last
            rows.append({
                "algo": algo, "variant": variant, "scenario": scenarios[0],
                "mean_ms": round(mean, 4), "p95_ms": round(p95, 4),
                "ciphertext_b64": b64(ct), "key_b64": b64(key),
                "nonce_b64": (None if nonce is None else b64(nonce)),
                "ad_b64": (None if ad_or_none is None else b64(ad_or_none)),
                "tag_b64": (None if tag is None else b64(tag)),
            })
        print("\n=== Result ===")
        import json; print(json.dumps({"input": src_label, "items": rows}, indent=2))
        # Save also to out/
        outp = f"out/quick_{ts}_{scenarios[0]}.json"
        with open(outp, "w", encoding="utf-8") as f: f.write(json.dumps({"input": src_label, "items": rows}, indent=2))
        print(f"\nSaved: {outp}")
        return

    # For report modes, reuse the Python implementations directly here
    def run_one_scenario(scn: str):
        rows = []
        def run(fn, aead: bool):
            times=[]; last=None
            for _ in range(repeat):
                last = fn()
                times.append(last[5])
            mean = sum(times)/len(times); p95 = sorted(times)[int((len(times)-1)*0.95)]
            ct,key,nonce,ad,tag,_,algo,variant = last
            rows.append(dict(algo=algo, variant=variant, aead=aead,
                             ciphertext_b64=b64(ct), key_b64=b64(key),
                             nonce_b64=(None if nonce is None else b64(nonce)),
                             ad_b64=(None if ad is None else b64(ad)),
                             tag_b64=(None if tag is None else b64(tag)),
                             time_ms_mean=mean, time_ms_p95=p95,
                             ciphertext_len=len(ct),
                             ciphertext_preview=b64(ct)[:80]+"..."))
        run(lambda: enc_aes_gcm(msg,128,f"CN-UI-{scn}".encode()), True)
        run(lambda: enc_aes_gcm(msg,256,f"CN-UI-{scn}".encode()), True)
        run(lambda: enc_chacha_poly(msg,f"CN-UI-{scn}".encode()), True)
        run(lambda: enc_aes_ctr_hmac(msg), False)
        return rows

    if mode == "2":  # analyze
        sc = scenarios[0]
        rows = run_one_scenario(sc)
        path = f"out/ui_analyze_{ts}_{sc}.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Analysis (Interactive)\n")
            f.write(f"**Scenario:** {sc.upper()}  |  **Input:** {src_label}  |  **Repeat:** {repeat}\n\n")
            f.write("| Algorithm | AEAD | Mean (ms) | p95 (ms) | Preview |\n|---|:---:|---:|---:|---|\n")
            for r in rows:
                f.write(f"| {r['algo']} {r['variant']} | {'Yes' if r['aead'] else 'No'} | {r['time_ms_mean']:.4f} | {r['time_ms_p95']:.4f} | `{r['ciphertext_preview']}` |\n")
        print(f"Saved: {path}")
        return

    if mode == "3":  # compare (within one scenario)
        sc = scenarios[0]
        rows = run_one_scenario(sc)
        path = f"out/ui_compare_{ts}_{sc}.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Side-by-side (Interactive)\n")
            f.write(f"**Scenario:** {sc.upper()}  |  **Input:** {src_label}  |  **Repeat:** {repeat}\n\n")
            f.write("| Algorithm | AEAD | Mean (ms) | p95 (ms) | Preview |\n|---|:---:|---:|---:|---|\n")
            for r in rows:
                f.write(f"| {r['algo']} {r['variant']} | {'Yes' if r['aead'] else 'No'} | {r['time_ms_mean']:.4f} | {r['time_ms_p95']:.4f} | `{r['ciphertext_preview']}` |\n")
        print(f"Saved: {path}")
        return

    if mode == "4":  # compare-multi
        acc=[]
        for sc in scenarios:
            rows = run_one_scenario(sc)
            for r in rows:
                acc.append((sc, r))
        path = f"out/ui_compare_multi_{ts}.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Multi-Scenario Comparison (Interactive)\n")
            f.write(f"**Input:** {src_label}  |  **Scenarios:** {', '.join([s.upper() for s in scenarios])}  |  **Repeat:** {repeat}\n\n")
            f.write("| Scenario | Algorithm | Mean (ms) | p95 (ms) | AEAD | Preview |\n|---|---|---:|---:|:---:|---|\n")
            for sc, r in acc:
                f.write(f"| {sc.upper()} | {r['algo']} {r['variant']} | {r['time_ms_mean']:.4f} | {r['time_ms_p95']:.4f} | {'Yes' if r['aead'] else 'No'} | `{r['ciphertext_preview']}` |\n")
        print(f"Saved: {path}")
        return

    if mode == "5":  # apply
        problem = ask("Describe your problem statement (one line)", "Protect chat over public internet")
        sc = scenarios[0]
        rows = run_one_scenario(sc)
        # pick fastest AEAD
        aeads = [r for r in rows if r["aead"]]
        pick = min(aeads, key=lambda r: r["time_ms_mean"])
        path = f"out/ui_apply_{ts}_{sc}.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Applied Recommendation (Interactive)\n")
            f.write(f"**Problem:** {problem}\n")
            f.write(f"**Scenario:** {sc.upper()}  |  **Input:** {src_label}  |  **Repeat:** {repeat}\n\n")
            f.write(f"**Recommendation:** **{pick['algo']} {pick['variant']}** — fastest AEAD on your data.\n\n")
            f.write("| Algorithm | AEAD | Mean (ms) | p95 (ms) | Preview |\n|---|:---:|---:|---:|---|\n")
            for r in rows:
                f.write(f"| {r['algo']} {r['variant']} | {'Yes' if r['aead'] else 'No'} | {r['time_ms_mean']:.4f} | {r['time_ms_p95']:.4f} | `{r['ciphertext_preview']}` |\n")
        print(f"Saved: {path}")
        return

if __name__ == "__main__":
    run_interactive()
