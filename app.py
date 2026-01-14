# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
import os, time, re
from statistics import mean

# NEW: for Honey-Decrypt UI
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.honey import dte_decode_note, _prf  # DTE + PRF used for decoy path

# graph renderers (paper mode)
from src.graph_draw import draw_corona, draw_bipartite_table, draw_star

# crypto + helpers
from src.crypto_algs import (
    enc_aes_gcm,
    enc_chacha_poly,
    enc_aes_ctr_hmac,
    enc_honey_aesgcm,   # <-- NEW
)
from src.util import ensure_out, b64, timestamp
from src.net_tools import run_traceroute, enrich_hops_with_geo, normalize_target

# legacy + paper crypto funcs
from src.graph_crypto import (
    encrypt_corona, encrypt_bipartite, encrypt_star,
    decrypt_corona, decrypt_bipartite, decrypt_star,
    encrypt_corona_paper, encrypt_bipartite_paper, encrypt_star_paper
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")

SCENARIOS = ["web","wifi","vpn","voip","iot","general"]
ALGOS = [
    ("AES-GCM", "128", lambda m,a: enc_aes_gcm(m,128,a), True),
    ("AES-GCM", "256", lambda m,a: enc_aes_gcm(m,256,a), True),
    ("ChaCha20-Poly1305", "256", lambda m,a: enc_chacha_poly(m,a), True),
    ("Honey-AESGCM", "256", lambda m,a: enc_honey_aesgcm(m,a), True),  # NEW
    ("AES-CTR+HMAC", "128", lambda m,a: enc_aes_ctr_hmac(m), False),
]

# ---------------- AEAD Linter & Recommender ----------------

def _expected_nonce_len(algo: str) -> int | None:
    algo = (algo or "").lower()
    if "gcm" in algo: return 12   # 96-bit for AES-GCM (incl. Honey-AESGCM)
    if "chacha" in algo: return 12  # IETF ChaCha20-Poly1305
    return None

def b64_decode_len_safe(b64_str: str) -> int:
    """We only need the decoded length for linting."""
    import base64
    try:
        return len(base64.b64decode(b64_str + "=="))
    except Exception:
        return 0

def aead_misuse_linter(rows: list[dict], *, repeat: int, src_label: str, scenario: str):
    """
    Inspects the algorithm outputs and your run configuration to flag common AEAD mistakes.
    Returns a dict with .warnings (list of strings) and .per_algo (map).
    """
    warnings = []
    per_algo = {}

    # If message came from textbox and scenario is networking, encourage AD usage.
    expects_ad = scenario in {"web","wifi","vpn","voip"} or "file:" not in (src_label or "")

    for r in rows:
        algo = f"{r['algo']} {r['variant']}".strip()
        n_b64 = r.get("nonce_b64")
        t_b64 = r.get("tag_b64")
        ad_b64 = r.get("ad_b64")
        aead = r.get("aead", False)
        per = []

        if aead:
            # Nonce presence & length
            if not n_b64:
                per.append("❌ Nonce missing; AEAD requires a nonce.")
            else:
                n_len = b64_decode_len_safe(n_b64)        # fixed
                exp = _expected_nonce_len(r['algo'])
                if exp and n_len != exp:
                    per.append(f"⚠️ Nonce length is {n_len} bytes; {r['algo']} best-practice is {exp} bytes.")

            # Tag presence & size
            if not t_b64:
                per.append("❌ Authentication tag missing.")
            else:
                t_len = b64_decode_len_safe(t_b64)        # fixed
                if t_len < 16:
                    per.append(f"⚠️ Tag is {t_len} bytes (<16). Prefer 16 bytes (128-bit).")

            # AD binding
            if expects_ad and not ad_b64:
                per.append("⚠️ No Associated Data (AD). Bind context (e.g., headers/session) to prevent cut-and-paste.")

            # Nonce reuse sampling result (added by run_one_algo)
            if r.get("nonce_reuse"):
                per.append("❌ Nonce reused within the same run. Reuse breaks AEAD security.")

        else:
            # CTR+HMAC: check EtM order by description (our impl is EtM)
            per.append("ℹ️ Non-AEAD mode. Ensure Encrypt-then-MAC & unique IV per message.")

        if not per:
            per.append("✅ No obvious misuse detected.")
        per_algo[algo] = per

    # Aggregate unique warnings, preserve order
    seen = set()
    for msgs in per_algo.values():
        for msg in msgs:
            if msg not in seen:
                seen.add(msg)
                warnings.append(msg)

    return {"warnings": warnings, "per_algo": per_algo, "ok": all(w.startswith("✅") for w in warnings)}

def recommend_cipher(rows: list[dict], scenario: str):
    """
    Pick an AEAD based on measured speed and scenario, then explain WHY.
    """
    aeads = [r for r in rows if r["aead"]]
    if not aeads:
        pick = min(rows, key=lambda r: r["mean_ms"])
        return {
            "choice": pick,
            "rationale": "Only non-AEAD available; chose the fastest. Consider AEAD (AES-GCM or ChaCha20-Poly1305) for integrity."
        }

    # Base on performance
    fastest = min(aeads, key=lambda r: r["mean_ms"])

    # Nudge by scenario if speeds are close
    algo_pref = None
    if scenario in {"wifi","voip","iot"}:
        algo_pref = "chacha"  # great on devices without AES-NI
    elif scenario in {"web","vpn","general"}:
        algo_pref = "gcm"

    preferred = fastest
    if algo_pref:
        candidate = min((r for r in aeads if algo_pref in r["algo"].lower()),
                        key=lambda r: r["mean_ms"], default=None)
        if candidate and candidate["mean_ms"] <= fastest["mean_ms"] * 1.10:
            preferred = candidate

    # Rationale text
    why = []
    why.append(f"Measured latency: **{preferred['algo']} {preferred['variant']} ≈ {preferred['mean_ms']} ms (p95 {preferred['p95_ms']} ms)**.")
    if "gcm" in preferred["algo"].lower():
        why.append("AES-GCM is standard in TLS/VPNs and benefits from AES-NI on modern CPUs.")
    if "chacha" in preferred["algo"].lower():
        why.append("ChaCha20-Poly1305 shines on devices without AES acceleration (many mobiles/IoT).")
    if scenario in {"wifi","voip","iot"}:
        why.append("Scenario bias: wireless/IoT often lack AES-NI → ChaCha favored if performance is comparable.")
    else:
        why.append("Scenario bias: web/VPN commonly use AES-GCM and interop is excellent.")
    why.append("Both are AEAD: confidentiality + integrity in one pass with unique nonces per message.")
    return {"choice": preferred, "rationale": " ".join(why)}

# ---------------- timing runner ----------------

def run_one_algo(fn, msg: bytes, ad: bytes, repeat: int):
    """
    Run an encryption function multiple times.
    Returns timing stats + last material, and a nonce_reuse flag derived from the nonce set.
    """
    times=[]; last=None
    nonces=set()
    for _ in range(repeat):
        last = fn(msg, ad)  # (ct,key,nonce,ad_or_none,tag,ms,algo,variant)
        if last[2] is not None:
            nonces.add(b64(last[2]))
        times.append(last[5])

    mean_ms = round(sum(times)/len(times), 4)
    p95_ms  = round(sorted(times)[int((len(times)-1)*0.95)], 4)
    ct,key,nonce,ad_or_none,tag,_,algo,variant = last

    return {
        "algo": algo, "variant": variant,
        "aead": algo!="AES-CTR+HMAC",
        "mean_ms": mean_ms, "p95_ms": p95_ms,
        "ciphertext_b64": b64(ct), "key_b64": b64(key),
        "nonce_b64": (None if nonce is None else b64(nonce)),
        "ad_b64": (None if ad_or_none is None else b64(ad_or_none)),
        "tag_b64": (None if tag is None else b64(tag)),
        "preview": b64(ct)[:80]+"...",
        "nonce_reuse": (len(nonces) < max(1, len(times)))  # true if any reuse observed
    }

# ---------- helpers for graph/landing modes ----------

def _infer_graph_mode(req) -> str:
    m = (req.args.get("mode") or req.form.get("mode") or "").lower().strip()
    if m in ("paper", "original"): return m
    if any(k in req.form for k in ("shift_n", "b_values", "k")): return "paper"
    return "original"

def _infer_index_mode(form) -> str:
    """
    Robustly infer which tab was used on the / page based on posted fields.
    """
    m = (form.get("mode") or "").strip().lower()
    if m in {"analyze", "compare_multi", "apply", "quick"}:
        return m
    if form.getlist("scenarios"):
        return "compare_multi"
    if "problem" in form:
        return "apply"
    if form.get("quick") or form.get("quick_mode"):
        return "quick"
    return "analyze"

# ---------- Honey-Decrypt UI helper ----------

def _honey_try_decrypt_with_flag(key_b: bytes, he_body: bytes, nonce_b: bytes, aad_b: bytes, tag_b: bytes):
    """
    Attempt to decrypt Honey-AESGCM ciphertext.
    Returns (text, is_decoy, info_dict)
      - text: plaintext or decoy sentence
      - is_decoy: True if AEAD auth failed and we generated a decoy
      - info_dict: parsed fields for rendering (e.g., salt)
    """
    info = {"salt": None}
    try:
        if not (he_body.startswith(b"HE1") and len(he_body) >= 3 + 8):
            # Not a valid Honey envelope -> still produce decoy deterministically
            salt = b"\x00" * 8
            body = he_body
        else:
            salt = he_body[3:11]
            body = he_body[11:]
        info["salt"] = salt.hex()

        # Try real decrypt
        aes = AESGCM(key_b)
        pt = aes.decrypt(nonce_b, body + tag_b, aad_b)
        return pt.decode("utf-8", errors="replace"), False, info

    except Exception:
        # Auth failed (wrong key / tamper) -> deterministic decoy
        try:
            if he_body.startswith(b"HE1") and len(he_body) >= 3 + 8:
                salt = he_body[3:11]
            else:
                salt = b"\x00" * 8
            seed = _prf(key_b, nonce_b, salt)
            decoy = dte_decode_note(seed)
        except Exception:
            decoy = "secure client migrated this morning with audit trail."
        return decoy, True, info

# ---------------- routes ----------------

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # NEW: infer mode so tabs work even without hidden 'mode'
        mode = _infer_index_mode(request.form)

        text = (request.form.get("message") or "").strip()
        file = request.files.get("file")
        scenario_single = request.form.get("scenario", "web")
        scenarios_multi = request.form.getlist("scenarios")
        try:
            repeat = int(request.form.get("repeat","15"))
            if repeat < 1: raise ValueError()
        except ValueError:
            flash("Repeat must be a positive integer.", "error")
            return redirect(url_for("index"))

        if (not file or not getattr(file, "filename", "")) and not text:
            flash("Provide a message or upload a file.", "error")
            return redirect(url_for("index"))

        if file and file.filename:
            msg = file.read()
            src_label = f"file:{file.filename}"
        else:
            msg = text.encode()
            src_label = "message"

        ensure_out()

        if mode == "compare_multi":
            if not scenarios_multi:
                flash("Select at least one scenario in Compare-Multi mode.", "error")
                return redirect(url_for("index"))
            acc = []
            for sc in scenarios_multi:
                if sc not in SCENARIOS:
                    flash(f"Unknown scenario: {sc}", "error")
                    return redirect(url_for("index"))
                ad = f"CN-WEB-{sc}".encode()
                rows = [run_one_algo(fn, msg, ad, repeat) for _,_,fn,_ in ALGOS]
                for r in rows:
                    r2 = dict(r); r2["scenario"]=sc; acc.append(r2)
            return render_template("compare_multi.html", title="Compare-Multi",
                                   scenarios=scenarios_multi, repeat=repeat,
                                   src_label=src_label, msg_len=len(msg), rows=acc)

        elif mode == "analyze":
            sc = scenario_single if scenario_single in SCENARIOS else "web"
            ad = f"CN-WEB-{sc}".encode()
            rows = [run_one_algo(fn, msg, ad, repeat) for _,_,fn,_ in ALGOS]
            lint = aead_misuse_linter(rows, repeat=repeat, src_label=src_label, scenario=sc)
            return render_template("analyze.html", title="Analysis",
                                   scenario=sc, repeat=repeat,
                                   src_label=src_label, msg_len=len(msg),
                                   rows=rows, lint=lint)

        elif mode == "apply":
            sc = scenario_single if scenario_single in SCENARIOS else "web"
            problem = (request.form.get("problem") or "Protect chat over public internet").strip()
            ad = f"CN-APPLY-{sc}".encode()
            rows = [run_one_algo(fn, msg, ad, repeat) for _,_,fn,_ in ALGOS]
            lint = aead_misuse_linter(rows, repeat=repeat, src_label=src_label, scenario=sc)
            rec  = recommend_cipher(rows, sc)
            return render_template("apply.html", title="Apply",
                                   scenario=sc, repeat=repeat, problem=problem,
                                   src_label=src_label, msg_len=len(msg),
                                   rows=rows, lint=lint, rec=rec)

        elif mode == "quick":
            sc = scenario_single if scenario_single in SCENARIOS else "web"
            ad = f"CN-QUICK-{sc}".encode()
            rows = [run_one_algo(fn, msg, ad, repeat) for _,_,fn,_ in ALGOS]
            lint = aead_misuse_linter(rows, repeat=repeat, src_label=src_label, scenario=sc)
            rec  = recommend_cipher(rows, sc)
            return render_template("quick.html", title="Quick Encrypt",
                                   scenario=sc, repeat=repeat,
                                   src_label=src_label, msg_len=len(msg),
                                   rows=rows, lint=lint, rec=rec)

        else:
            flash("Unknown mode selected.", "error")
            return redirect(url_for("index"))

    return render_template("index.html", scenarios=SCENARIOS, title="CN Encryption Workbench")

@app.route("/traceroute", methods=["GET","POST"])
def traceroute():
    rows = None; host=""; max_hops=20; error=None; geo=False
    analytics=None
    if request.method == "POST":
        host = (request.form.get("host") or "").strip()
        geo = bool(request.form.get("geo"))
        try:
            max_hops = int(request.form.get("max_hops","20"))
        except:
            max_hops = 20
        if not host:
            error = "Enter a destination host/URL/IP."
        else:
            res = run_traceroute(host, max_hops)
            if res.get("error"):
                error = res["error"]
            else:
                rows = res.get("hops", [])
                if geo:
                    rows = enrich_hops_with_geo(rows)
                # simple analytics for chart/map pages
                rtts = [h["rtt_ms"] for h in rows if isinstance(h.get("rtt_ms"), (int,float))]
                analytics = {
                    "total_hops": len(rows),
                    "avg_ms": round(mean(rtts),2) if rtts else None,
                    "p95_ms": (round(sorted(rtts)[int((len(rtts)-1)*0.95)],2) if rtts else None),
                    "have_geo": any(h.get("lat") and h.get("lon") for h in rows)
                }
    return render_template("traceroute.html", title="Traceroute", host=host, max_hops=max_hops,
                           rows=rows, error=error, geo=geo, analytics=analytics)

# ---------- UNIFIED GRAPH-CRYPTO (Original + Paper modes) ----------
@app.route("/graph-crypto", methods=["GET","POST"], endpoint="graph_crypto")
def graph_crypto():
    """
    One page, two modes:
      - mode=original  -> existing behavior (wrappers)
      - mode=paper     -> exact research paper mode (with PNGs)
    """
    # Infer paper/original if hidden input missing:
    mode = _infer_graph_mode(request)

    result, err, img_path = None, None, None

    if request.method == "POST":
        scheme = request.form.get("scheme", "corona")
        text   = request.form.get("plaintext", "")

        # Ensure static/out exists before any draw_*
        os.makedirs(os.path.join("static", "out"), exist_ok=True)

        try:
            if mode == "paper":
                if scheme == "corona":
                    shift_n = int(request.form.get("shift_n", "5"))
                    b_str = (request.form.get("b_values", "") or "").strip()

                    # Robust parse: commas / spaces / semicolons, ignore empties
                    b_vals = None
                    if b_str:
                        try:
                            toks = [t for t in re.split(r"[\s,;]+", b_str) if t]
                            b_vals = [int(t) for t in toks]
                        except ValueError:
                            raise ValueError("b-values must be integers separated by comma/space (e.g., 31,71,51,49,41)")

                        # Check length vs letters (A..Z only, paper-mode ignores others)
                        letters = [ch for ch in text.upper() if "A" <= ch <= "Z"]
                        if len(b_vals) != len(letters):
                            raise ValueError(f"Provide exactly {len(letters)} b-values (you gave {len(b_vals)}).")

                    # Delegate to paper encryptor (does coprime and >26 checks)
                    result = encrypt_corona_paper(text, shift_n=shift_n, b_values=b_vals)
                    if result.get("error"):
                        raise ValueError(result["error"])
                    img_path = draw_corona(result)

                elif scheme == "bipartite":
                    # Validate k and surface errors
                    try:
                        k = int(request.form.get("k", "6"))
                    except ValueError:
                        raise ValueError("k must be an integer between 3 and 12.")
                    if not (3 <= k <= 12):
                        raise ValueError("k must be between 3 and 12 (paper constraint).")

                    result = encrypt_bipartite_paper(text, k=k)
                    if result.get("error"):
                        raise ValueError(result["error"])
                    img_path = draw_bipartite_table(result)

                else:  # star
                    try:
                        k = int(request.form.get("k", "8"))
                    except ValueError:
                        raise ValueError("k must be an integer between 3 and 12.")
                    if not (3 <= k <= 12):
                        raise ValueError("k must be between 3 and 12 (paper constraint).")

                    # Guard against empty plaintext after A–Z cleanup
                    letters_only = "".join(ch for ch in (text or "").upper() if "A" <= ch <= "Z")
                    if not letters_only:
                        raise ValueError("Star (paper) needs at least one A–Z letter in Plaintext.")

                    result = encrypt_star_paper(text, k=k)
                    if result.get("error"):
                        raise ValueError(result["error"])
                    img_path = draw_star(result)  # render Star PNG

            else:
                if scheme == "corona":
                    shift = int(request.form.get("shift","7"))
                    bbase = int(request.form.get("bbase","211"))
                    result = encrypt_corona(text, shift=shift, b_base=bbase)
                elif scheme == "bipartite":
                    k = int(request.form.get("key_k","6"))
                    result = encrypt_bipartite(text, key_k=k)
                else:
                    result = encrypt_star(text)

        except Exception as ex:
            err = str(ex)

    return render_template(
        "graph_crypto.html",
        mode=mode,
        result=result,
        err=err,
        img_path=img_path
    )

# ---------- Honey Decrypt (UI) ----------
@app.route("/honey-decrypt", methods=["GET", "POST"], endpoint="honey_decrypt")
def honey_decrypt_view():
    """
    UI to demonstrate Honey Encryption:
      - Paste Base64 bundle (ct, nonce, ad, tag) and a Base64 key.
      - Correct key -> authentic plaintext
      - Wrong key   -> realistic decoy (no error)
    """
    output = None
    is_decoy = None
    err = None

    # Accept prefilled fields (from Quick/Analyze “Open in Honey Decrypt” button)
    ciphertext_b64 = (request.form.get("ciphertext_b64") or "").strip()
    nonce_b64      = (request.form.get("nonce_b64") or "").strip()
    ad_b64         = (request.form.get("ad_b64") or "").strip()
    tag_b64        = (request.form.get("tag_b64") or "").strip()
    key_b64        = (request.form.get("key_b64") or "").strip()  # optional, user can try blanks/wrong key

    if request.method == "POST" and request.form.get("action") == "decrypt":
        try:
            if not (ciphertext_b64 and nonce_b64 and ad_b64 and tag_b64 and key_b64):
                raise ValueError("Paste all required Base64 fields (ciphertext, key, nonce, aad, tag).")

            he_body = b64decode(ciphertext_b64)
            nonce   = b64decode(nonce_b64)
            aad     = b64decode(ad_b64)
            tag     = b64decode(tag_b64)
            key     = b64decode(key_b64)

            output, is_decoy, info = _honey_try_decrypt_with_flag(key, he_body, nonce, aad, tag)

        except Exception as e:
            err = f"{type(e).__name__}: {e}"

    return render_template(
        "honey.html",
        title="Honey Decrypt",
        ciphertext_b64=ciphertext_b64,
        nonce_b64=nonce_b64,
        ad_b64=ad_b64,
        tag_b64=tag_b64,
        key_b64=key_b64,
        output=output,
        is_decoy=is_decoy,
        err=err
    )
