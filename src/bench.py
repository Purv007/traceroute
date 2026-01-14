import argparse, pandas as pd, os
from .util import ensure_out
from .crypto_algs import enc_aes_gcm, enc_chacha_poly, enc_aes_ctr_hmac

def run_case(size_kb: int, iters: int):
    msg = os.urandom(size_kb * 1024)
    rows=[]
    for _ in range(iters):
        for fn in (lambda: enc_aes_gcm(msg,128),
                   lambda: enc_aes_gcm(msg,256),
                   lambda: enc_chacha_poly(msg),
                   lambda: enc_aes_ctr_hmac(msg)):
            ct,key,nonce,ad,tag,ms,algo,variant = fn()
            rows.append(dict(name=algo,variant=variant,size_kb=size_kb,ms=ms,ct_len=len(ct)))
    return rows

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--iters", type=int, default=7)
    p.add_argument("--sizes", nargs="+", type=int, default=[64,256,1024,4096])
    args=p.parse_args()

    ensure_out()
    allrows=[]
    for s in args.sizes:
        allrows+=run_case(s, args.iters)

    df = pd.DataFrame(allrows)
    out = df.groupby(["name","variant","size_kb"]).agg(
        iters=("ms","count"),
        ms_per_kb=("ms", lambda x: (x.mean()/(df.loc[x.index,"size_kb"].iloc[0]))),
        mean_ms=("ms","mean"),
        p95_ms=("ms", lambda x: x.quantile(0.95))
    ).reset_index()

    df_out = out
    df_out.to_csv("out/results.csv", index=False)
    df_out.to_json("out/results.json", orient="records", indent=2)
    print("Wrote out/results.csv and out/results.json")

if __name__=="__main__":
    main()
