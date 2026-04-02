# Harpoon

Harpoon is a fire-and-forget web application penetration testing tool. You provide a target and Harpoon executes a stateful async pipeline for discovery, analysis, validation, and reporting.

## Architecture

- SQLite state engine (`harpoon/state.py`) with relational tables: `targets`, `subdomains`, `endpoints`, `technologies`, `parameters`, `vulnerabilities`
- Fully async execution (`harpoon/runner.py`) using `asyncio.create_subprocess_exec`
- Strict dependency gate (`harpoon/preflight.py`) that halts scans when required tools are missing, then prints **grouped install commands** (apt vs `go install` vs pip — most ProjectDiscovery tools are **not** `apt install` packages). If any missing tool needs `go install` and **`go` is not on PATH**, preflight also reports **`go`** and includes **`golang-go`** in the suggested `apt` line (skipped automatically when `go` is already available)
- Rich CLI telemetry (`harpoon/cli.py`) for phase banners, counters, estimates, and critical alerts
- Tailwind HTML reporting (`viewreport.py`) from SQLite + deterministic PoC output

## Toolchain Order

1. Passive recon: `subfinder`, `crt.sh`, `amass`, `chaos`
2. DNS/infra: `dnsx`, `cdncheck`, `naabu`, `asnmap`, `mapcidr`
3. HTTP and tech: `httpx`, `tlsx`
4. Discovery/crawl: `ffuf`, `katana`, `waybackurls`, `gau`, `shuffledns`, `alterx`
5. Parameter discovery: `paramspider`, `arjun`, `x8`
6. Validation and handoff: `sqlmap`, `nuclei`, `nikto`, `interactsh-client`, `notify`

Gobuster has been removed by design; ffuf is the primary content and parameter fuzzer.

## Requirements

- Python 3.10+
- SecLists at `/usr/share/seclists/`, or set `HARPOON_SECLISTS_DIR` to your checkout
- Or, if you cannot install SecLists: `export HARPOON_USE_BUNDLED_WORDLISTS=1` (uses `harpoon/wordlists/` only; narrower coverage)
- All external tools on your `PATH` (see pre-flight check). On **Windows**, run Harpoon from **WSL** or ensure the same binaries are visible to the Python you use
- One-shot installer (Debian/Ubuntu/Kali/WSL): `bash scripts/install_harpoon_tools.sh`
- Python dependencies: `pip install -r requirements.txt`

## Run

**Recommended on Linux/WSL** (adds `~/go/bin` and `~/.local/bin` to PATH and sources `.harpoon.env` if present):

```bash
bash scripts/run_harpoon.sh
```

Or run Python directly (you must export PATH yourself if tools live in `~/go/bin`):

```bash
cp .harpoon.env.example .harpoon.env   # edit values; loaded automatically before config
python3 main.py
```

`HARPOON_USE_BUNDLED_WORDLISTS=1` only satisfies the **SecLists** check. It does **not** install missing Go/Python tools — run `bash scripts/install_harpoon_tools.sh` for those.

## HTML Report

Harpoon generates an HTML report after scan completion.

Manual generation:

```bash
python viewreport.py --target example.com --db harpoon_logs/sessions/<session>/pipeline_state.db --poc-log harpoon_logs/sessions/<session>/poc_findings.json --serve
```

## Testing

```bash
pytest -q
```
