# Encryption Benchmark & Analysis Project (Python)

A clean, ready to run Python project that mirrors the Java implementation.  
The project benchmarks and compares modern authenticated encryption algorithms alongside a legacy construction. It generates detailed Markdown reports and JSON artifacts under the `out/` directory.

---

## Algorithms Implemented

### AES-GCM
- 128 and 256 bit keys  
- 12 byte nonce  
- AEAD tag embedded  

### ChaCha20-Poly1305
- 256 bit key  
- 12 byte nonce  
- AEAD tag embedded  

### AES-CTR + HMAC-SHA256
- Encrypt then MAC construction  
- 128 bit AES  
- 16 byte IV  
- 32 byte HMAC  

---

## Project Structure

```
src/            Core encryption, benchmarking, analysis, and comparison logic
out/            Generated Markdown reports and JSON summaries
app.py          Flask web application
requirements.txt Python dependencies
```

---

## Quick Start (Windows PowerShell)

```powershell
cd .\cn_encryption_python
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt

python -m src.bench --iters 7 --sizes 64 256 1024 4096
python -m src.analyze --scenario web --repeat 12 --msg "Encrypt THIS exact message"
python -m src.compare --scenario web --repeat 15 --msg "Encrypt THIS exact message" --title "CN Project: Side-by-Side (Web)"
python -m src.compare_multi --scenarios web wifi --repeat 15 --msg "Encrypt THIS exact message" --title "CN: Web vs WiFi"
python -m src.apply --problem "Protect chat over public internet" --scenario web --repeat 15 --msg "hello team"
python -m src.compare_from_summaries --files out\analysis_..._web_summary.json out\analysis_..._wifi_summary.json --title "CN: WEB vs WIFI (Saved)"
```

---

## macOS / Linux

```bash
cd ./cn_encryption_python
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -r requirements.txt

python -m src.bench --iters 7 --sizes 64 256 1024 4096
python -m src.analyze --scenario web --repeat 12 --msg "Encrypt THIS exact message"
python -m src.compare --scenario web --repeat 15 --msg "Encrypt THIS exact message" --title "CN Project: Side-by-Side (Web)"
python -m src.compare_multi --scenarios web wifi --repeat 15 --msg "Encrypt THIS exact message" --title "CN: Web vs WiFi"
python -m src.apply --problem "Protect chat over public internet" --scenario web --repeat 15 --msg "hello team"
python -m src.compare_from_summaries --files out/analysis_..._web_summary.json out/analysis_..._wifi_summary.json --title "CN: WEB vs WIFI (Saved)"
```

---

## Interactive Mode

The interactive assistant prompts for:
- Message or file  
- Scenario or scenarios  
- Repeat count  
- Mode selection  

Available modes:
- Analyze  
- Compare  
- Compare Multi  
- Apply  
- Quick Encrypt  

### Run

```bash
python -m src.ui
```

Outputs are saved under `out/` using filenames such as `ui_*.md` and `quick_*.json`.

---

## Web Frontend (Flask)

A minimal Tailwind styled web interface to run all modes in the browser.

### Run the Server

```bash
python app.py
```

Open: http://127.0.0.1:5000/

### Supported Modes
- Analyze single scenario  
- Compare Multi across Web, WiFi, VPN  
- Apply problem to recommendation  
- Quick Encrypt with artifacts and timings  

---

## Graph Based Symmetric Schemes

### Research Prototypes
- Corona  
- Complete Bipartite  
- Star  

Route: `/graph-crypto`  
Encrypts using the selected scheme, outputs a graph JSON ciphertext, and verifies round trip recovery.

### Exact Implementation as per Paper

Route: `/graph-crypto-paper`  
Implements Corona, Complete Bipartite, and Star schemes exactly as specified while preserving traceroute behavior.

