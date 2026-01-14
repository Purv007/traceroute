
import argparse, json, os
from .net_tools import run_traceroute, enrich_hops_with_geo

def main():
    ap = argparse.ArgumentParser(description="CN Project: Traceroute (+geo) with URL/host input")
    ap.add_argument("--target", required=True, help="Destination URL or host/IP (e.g., https://example.com or 8.8.8.8)")
    ap.add_argument("--max-hops", type=int, default=20)
    ap.add_argument("--geo", action="store_true", help="Enrich hops with country/city/lat/lon/ISP via ip-api.com (no key)")
    ap.add_argument("--out", default=None, help="Optional path to save JSON")
    args = ap.parse_args()

    result = run_traceroute(args.target, args.max_hops)
    if args.geo and "hops" in result:
        result["hops"] = enrich_hops_with_geo(result["hops"])

    print(json.dumps(result, indent=2))

    if args.out:
        os.makedirs("out", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(json.dumps(result, indent=2))
        print(f"Saved: {args.out}")

if __name__ == "__main__":
    main()
