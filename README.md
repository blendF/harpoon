# Harpoon

Harpoon is a fire-and-forget web application penetration testing tool. You provide a target and Harpoon executes a stateful async pipeline for discovery, analysis, validation, and reporting.

## Architecture

- SQLite state engine (`harpoon/state.py`) with relational tables: `targets`, `subdomains`, `endpoints`, `technologies`, `parameters`, `vulnerabilities`
- Fully async execution (`harpoon/runner.py`) using `asyncio.create_subprocess_exec`
- Strict dependency gate (`harpoon/preflight.py`) that halts scans when required tools are missing
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
- SecLists available at `/usr/share/seclists/` (or set `HARPOON_SECLISTS_DIR`)
- ProjectDiscovery tools installed (see install block emitted by `harpoon/preflight.py`)
- Python dependencies in `requirements.txt`

## Run

```bash
python main.py
```

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
