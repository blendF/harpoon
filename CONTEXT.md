# Harpoon LLM Context

## What Harpoon Is

Harpoon is an automated web penetration testing orchestrator designed around strict, deterministic execution. The pipeline is async, stateful, and dependency-gated.

## Core Components

- `main.py`: async 10-phase orchestration entrypoint
- `harpoon/state.py`: SQLite-backed `PipelineStateManager`
- `harpoon/runner.py`: async subprocess runner (`run_tool`, `run_tool_json`)
- `harpoon/preflight.py`: strict dependency checker (halts on missing tools)
- `harpoon/cli.py`: Rich telemetry surface
- `harpoon/waf.py`: header + behavioral WAF detection (SQLi/XSS probes + cdncheck signal)
- `harpoon/poc_generator.py`: deterministic PoC generation with `curl` and raw request fields
- `viewreport.py`: Tailwind HTML report renderer from SQLite + PoC JSON

## SQLite Data Model

`PipelineStateManager` creates and writes:

1. `targets`
2. `subdomains`
3. `endpoints`
4. `technologies`
5. `parameters`
6. `vulnerabilities`

Session database path is set in `harpoon/config.py` under `SESSION_DB_PATH`.

## Scanner Layer

Each scanner is an async wrapper under `harpoon/scanners/` and calls `run_tool` or `run_tool_json`.

Notable modules:

- Existing: `subfinder_scan`, `crtsh_scan`, `amass_scan`, `dnsx_scan`, `httpx_scan`, `katana_scan`, `ffuf_scan`, `paramspider_scan`, `arjun_scan`, `sqlmap_scan`, `nuclei_scan`, `nikto_scan`
- Added: `naabu_scan`, `uncover_scan`, `tlsx_scan`, `asnmap_scan`, `mapcidr_scan`, `cdncheck_scan`, `shuffledns_scan`, `chaos_scan`, `alterx_scan`, `x8_scan`, `interactsh_scan`, `notify_scan`

Gobuster is removed.

## Output Model

Per run, Harpoon writes into a timestamped session folder:

- Logs: `harpoon_logs/sessions/<session>/...`
- SQLite DB: `pipeline_state.db`
- PoCs: `poc_findings.json`
- Snapshot: `pipeline_state_snapshot.json`
- HTML report: `harpoon_assessment_<target>.html`

## Testing

Pytest suite under `tests/` includes:

- `test_state.py`
- `test_preflight.py`
- `test_waf.py`
- `test_poc_generator.py`
- `test_runner.py`
- `test_scanners.py`
- `test_cli.py`
- `test_viewreport.py`
# Harpoon — Full Codebase Context for LLM Agents

This document provides complete architectural and implementation context for the Harpoon project. It is intended to be fed to an LLM so it can understand, modify, or extend the codebase without needing to read every file.

---

## What Harpoon Is

Harpoon is an autonomous, stateful, black-box web application penetration testing framework written in Python 3.10+. It orchestrates 15+ external security tools through a centralized state manager, executes a 10-phase pipeline from passive reconnaissance through vulnerability validation, and produces deterministic proof-of-concept (PoC) exploitation statements instead of blind exploitation.

It runs on Windows with WSL (Windows Subsystem for Linux) as the execution environment for Go-based security tools. The entry point is `main.py`.

---

## Architecture Overview

### Core Design Principles

1. **Stateful orchestration** — A central `PipelineStateManager` (in-memory Python dict) is the single source of truth. Every tool writes normalized entities into it; downstream tools read from it.
2. **Adaptive WAF evasion** — Multi-signal WAF detection (IP ranges, rDNS, HTTP headers, behavioral probes) dynamically controls tool execution: skipping noisy tools, throttling rates, appending tamper scripts.
3. **Deterministic PoC generation** — No blind exploitation (Metasploit removed). Nuclei JSONL and Sqlmap CSV outputs are parsed into actionable proof statements.
4. **Graceful degradation** — If any external tool is missing, it logs a skip message and the pipeline continues with whatever data the state contains.

### Pipeline Flow (10 Phases)

```
Target URL/IP
    │
    ▼
Pre-scan: DNS Recon (built-in) ── resolve IPs, detect CDN/WAF via headers
    │
    ▼
Phase 1: Passive Recon ── subfinder + crt.sh + amass (optional)
    │  → subdomains into state
    ▼
Phase 2: Active DNS + Infra Filtering ── dnsx (wildcard filter) + conditional Nmap
    │  → resolved hosts/IPs into state; Nmap skips CDN edge IPs
    ▼
Phase 3: HTTP Probing + WAF Detection ── httpx (tech fingerprinting) + WAF engine
    │  → live URLs, technology tags, WAF status into state
    ▼
Phase 4: Visual Recon ── gowitness (optional screenshots)
    │
    ▼
Phase 5: Directory/Vhost Discovery ── ffuf (primary) + gobuster (targeted secondary)
    │  → discovered paths and vhosts into state
    ▼
Phase 6: Advanced Crawling ── katana + waybackurls + gau + targeted ZAP
    │  → historical/SPA endpoints into state
    ▼
Phase 7: JS Analysis ── endpoint extraction + Shannon entropy secret detection
    │  → JS endpoints and high-entropy secrets into state
    ▼
Phase 8: Parameter Discovery ── paramspider + arjun + ffuf params
    │  → discovered parameters into state
    ▼
Phase 9: Validation ── Nuclei (JSONL, tech-tagged) + Sqlmap (tamper-aware) + Nikto (conditional skip)
    │  → validated findings
    ▼
Phase 10: PoC Generation + Manual Handoff ── parse Nuclei/Sqlmap output into PoC statements
    │
    ▼
Report Generation ── Markdown report + optional Ollama AI analysis
```

### WAF-Adaptive Policy

When `WAF_PRESENT == True` for a host:

| Tool | Behavior |
|------|----------|
| Nmap | Skipped if target IP is CDN edge |
| Nikto | Skipped entirely |
| ffuf | `-rate 2`, `-fs 42,0` (filter block pages) |
| Nuclei | `-rl 50 -c 10` (50 req/min, 10 concurrent) |
| Sqlmap | `--tamper=space2comment,randomcase` |

When no WAF: full concurrency, no tool skipping.

---

## Project Structure

```
harpoon/
├── main.py                          ← Entry point: 10-phase pipeline orchestration
├── requirements.txt                 ← Python deps (pyinstaller, paramspider, arjun, uro)
├── README.md                        ← User-facing docs
├── CONTEXT.md                       ← This file (LLM context)
├── HARPOONASCIIART.txt              ← CLI banner
├── LICENSE                          ← MIT
│
├── harpoon/                         ← Core package
│   ├── __init__.py                  ← Version (0.1.0)
│   ├── config.py                    ← All paths, log files, tool command env vars
│   ├── state.py                     ← PipelineStateManager class
│   ├── waf.py                       ← WAF detection engine + tool_policy()
│   ├── runner.py                    ← Subprocess execution (run_capture, run_capture_json)
│   ├── recon.py                     ← DNS lookup + CDN/WAF header detection
│   ├── report_stateful.py           ← Markdown report generator (10-phase layout)
│   ├── poc_generator.py             ← Nuclei JSONL + Sqlmap → PoC statements
│   ├── ollama_client.py             ← Ollama LLM integration for AI report section
│   ├── nuclei_context.py            ← Build Nuclei targets from state or log files
│   ├── spinner.py                   ← CLI spinner animation
│   ├── startup.py                   ← ASCII art display
│   ├── target.py                    ← User input (target URL, normalization)
│   ├── logs.py                      ← Log directory creation
│   ├── wordlist.txt                 ← 1,828-word directory wordlist
│   │
│   ├── data/
│   │   └── cdn_ranges.json          ← Cloudflare/Akamai/Fastly CIDR blocks
│   │
│   ├── wordlists/
│   │   ├── subdomains.txt           ← 522 subdomain entries
│   │   └── params.txt               ← 356 parameter name entries
│   │
│   ├── scanners/                    ← Tool wrapper modules
│   │   ├── subfinder_scan.py        ← Passive subdomain enumeration
│   │   ├── crtsh_scan.py            ← Certificate transparency API
│   │   ├── amass_scan.py            ← Deep passive recon (optional)
│   │   ├── dnsx_scan.py             ← Active DNS resolution + wildcard filter
│   │   ├── httpx_scan.py            ← HTTP probing + tech fingerprinting
│   │   ├── gowitness_scan.py        ← Visual screenshot recon (optional)
│   │   ├── ffuf_scan.py             ← Dir/vhost/param fuzzing (primary fuzzer)
│   │   ├── gobuster_scan.py         ← Targeted deep recursive dir scan
│   │   ├── katana_scan.py           ← Headless SPA/JS crawling
│   │   ├── wayback_scan.py          ← Historical URL mining (waybackurls + gau)
│   │   ├── js_analysis.py           ← JS endpoint extraction + entropy secrets
│   │   ├── paramspider_scan.py      ← Passive parameter discovery
│   │   ├── arjun_scan.py            ← Active hidden parameter discovery
│   │   ├── nmap_scan.py             ← Port/service scan (skips CDN IPs)
│   │   ├── zap_scan.py              ← Targeted OWASP ZAP active scan
│   │   ├── sqlmap_scan.py           ← SQL injection (WAF tamper-aware)
│   │   ├── nuclei_scan.py           ← Template CVE scanning (JSONL, state-driven)
│   │   └── nikto_scan.py            ← Web server scanner (skipped when WAF present)
│   │
│   └── parsers/
│       └── nmap_parser.py           ← Parse Nmap text → ServiceInfo dataclass list
```

---

## Key Modules in Detail

### `harpoon/state.py` — PipelineStateManager

Central in-memory state store. Thread-safe (uses `threading.RLock`).

**State keys:** `target`, `waf`, `subdomains`, `resolved_hosts`, `ips`, `ports`, `urls`, `technologies`, `paths`, `vhosts`, `params`, `js_files`, `secrets`, `nuclei_findings`, `sqlmap_findings`, `events`

**Key methods:**
- `add_subdomain(subdomain, source, confidence)` — deduped by value
- `add_resolved_host(host, ip, source)` — also adds IP
- `add_port(ip, port, protocol, service, product, version, source)` — deduped by `ip:port/proto`
- `add_url(url, source, status, title)` — deduped by URL
- `add_technology(host, technology, source)` — per-host tech list
- `add_path(url, path, source)` — deduped by full URL+path
- `add_vhost(vhost, source)` — deduped by value
- `add_param(url, param, method, source)` — deduped by `METHOD:url:param`
- `add_secret(secret_excerpt, entropy, location, source)` — high-entropy string findings
- `set_waf_status(host, is_present, vendor, confidence, recommended_rate)` — per-host WAF state
- `get_waf_status(host) -> dict` — read WAF state
- `get_targets_for_phase(phase) -> list[str]` — phase-aware target lists
- `get(key, default)` — raw state access
- `to_json() / save(path)` — serialize to JSON
- `from_json(text) / load(path)` — deserialize

Each entity carries metadata: `source` (which tool produced it), `confidence` (0.0–1.0), `timestamp` (UTC ISO).

### `harpoon/waf.py` — WAF Detection Engine

**`detect_waf(url, threshold_limit=600) -> WafResult`**

Multi-signal detection:
1. Baseline HTTP request → capture headers
2. Behavioral probe: send `/?id=1' OR '1'='1` → check for 403/406/429 status shift
3. Header signature matching against known vendors (Cloudflare, Akamai, Imperva, Fastly, Sucuri, CloudFront)
4. Confidence scoring: `>= 0.6` → WAF present

Returns `WafResult(host, is_present, vendor, confidence, baseline_status, probe_status, recommended_rate, evidence)`

**`tool_policy(waf_present) -> dict`** — Returns per-tool configuration overrides.

**`calculate_safe_rate(threshold_limit, window_seconds, safety_margin) -> int`** — Conservative rate calculation.

### `harpoon/runner.py` — Subprocess Engine

Three functions:
- `find_cmd(cmd) -> str | None` — `shutil.which()` wrapper
- `run_capture(argv, log_path, timeout, env, cwd) -> (code, stdout, stderr)` — blocking execution with combined log output
- `run_capture_json(argv, log_path, on_json, timeout, env, cwd) -> (code, list[dict], stderr)` — streaming JSON/JSONL parser with real-time callback

All output is written to log files in `=== stdout ===\n...\n=== stderr ===` format.

### `harpoon/poc_generator.py` — PoC Statement Generator

**`generate_pocs(nuclei_log, sqlmap_log, output_path) -> list[dict]`**

Parses:
- Nuclei JSONL: extracts `template-id`, `info.name`, `classification.cve-id`, `matched-at`, `curl-command`
- Sqlmap logs: extracts injectable parameter, DBMS type, payload

Generates statements in format:
```
Using and finding [CVE/Vulnerability Name] - you can exploit this vulnerability on this path: <URL> using the following proof of concept: <curl command or payload>
```

Writes `poc_findings.json` with `{"pocs": [...]}`.

### `harpoon/recon.py` — DNS Recon + CDN Detection

**`dns_lookup(host) -> ReconInfo`**

Detection chain (in order):
1. Resolve A records via `socket.getaddrinfo`
2. Reverse DNS per IP
3. Check IPs against hardcoded Cloudflare CIDR ranges
4. Check rDNS against vendor patterns (cloudfront, akamai, fastly, etc.)
5. **NEW:** Send HTTPS request, check response headers for `server: cloudflare`, `cf-ray`, and other vendor signatures

### `harpoon/nuclei_context.py` — Nuclei Target Builder

Two modes:
- `build_nuclei_targets(base_url, nmap_log, gobuster_log, host, targets_file, ...)` — legacy log-file parsing
- `build_nuclei_targets_from_state(state, base_url, host, targets_file)` — reads URLs, paths, vhosts, ports, and technologies from `PipelineStateManager`

Both return `(sorted_target_urls, sorted_template_tags)`.

---

## Scanner Modules

Every scanner follows the same pattern:
1. Try `find_cmd()` on Windows PATH
2. Fall back to WSL (`_wsl_has()` → `["wsl", "<tool>", ...]`)
3. If not found at all, write skip message to log and return gracefully
4. Build argv, execute via `run_capture()` or `run_capture_json()`
5. Parse output, return `(returncode, results, summary_message)`

| Scanner | External Tool | Phase | Returns |
|---------|--------------|-------|---------|
| `subfinder_scan` | subfinder | 1 | `(code, list[str] subdomains, msg)` |
| `crtsh_scan` | curl (to crt.sh API) | 1 | `(code, list[str] subdomains, msg)` |
| `amass_scan` | amass | 1 | `(code, list[str] subdomains, msg)` |
| `dnsx_scan` | dnsx | 2 | `(code, list[dict] {host, ips}, msg)` |
| `nmap_scan` | nmap | 2 | `(code, stdout, msg)` — skips CDN IPs |
| `httpx_scan` | httpx | 3 | `(code, list[dict] {url, host, status_code, title, tech}, msg)` |
| `gowitness_scan` | gowitness | 4 | `(code, msg)` |
| `ffuf_scan` | ffuf | 5,8 | `(code, msg)` + getter helpers |
| `gobuster_scan` | gobuster | 5 | `(code, msg)` |
| `katana_scan` | katana | 6 | `(code, list[str] urls, msg)` |
| `wayback_scan` | waybackurls, gau | 6 | `(code, list[str] urls, msg)` |
| `zap_scan` | OWASP ZAP | 6 | `(code, msg)` — targeted endpoint scanning |
| `js_analysis` | (pure Python) | 7 | `(list[str] endpoints, list[dict] secrets, msg)` |
| `paramspider_scan` | paramspider | 8 | `(code, list[str] param_names, msg)` |
| `arjun_scan` | arjun | 8 | `(code, list[str] params, msg)` |
| `sqlmap_scan` | sqlmap | 9 | `(code, msg)` — WAF tamper-aware |
| `nikto_scan` | nikto | 9 | `(code, msg)` — skipped when WAF present |
| `nuclei_scan` | nuclei | 9 | `(code, msg)` — JSONL output, state-driven targets |

---

## Configuration (`harpoon/config.py`)

### Log File Paths (all under `LOG_DIR = OUTPUT_DIR / "harpoon_logs"`)

| Constant | Filename |
|----------|----------|
| `STATE_PATH` | `pipeline_state.json` |
| `RECON_LOG` | `dns_recon.txt` |
| `SUBFINDER_LOG` | `subfinder_subdomains.jsonl` |
| `CRTSH_LOG` | `crtsh_subdomains.jsonl` |
| `AMASS_LOG` | `amass_subdomains.txt` |
| `DNSX_LOG` | `dnsx_resolved.jsonl` |
| `NMAP_LOG` | `nmap_scan.txt` |
| `HTTPX_LOG` | `httpx_probe.jsonl` |
| `GOWITNESS_LOG` | `gowitness_scan.txt` |
| `GOBUSTER_LOG` | `gobuster_enum.txt` |
| `FFUF_DIR_LOG` | `ffuf_dir.json` |
| `FFUF_VHOST_LOG` | `ffuf_vhost.json` |
| `FFUF_PARAMS_LOG` | `ffuf_params.json` |
| `KATANA_LOG` | `katana_endpoints.jsonl` |
| `WAYBACK_LOG` | `wayback_urls.txt` |
| `GAU_LOG` | `gau_urls.txt` |
| `URO_LOG` | `unique_urls.txt` |
| `ZAP_LOG` | `zap_scan.txt` |
| `SQLMAP_LOG` | `sqlmap_scan.txt` |
| `NUCLEI_LOG` | `nuclei_scan.txt` |
| `NIKTO_LOG` | `nikto_scan.txt` |
| `PARAMSPIDER_LOG` | `paramspider_params.txt` |
| `ARJUN_LOG` | `arjun_params.json` |
| `JS_ANALYSIS_LOG` | `js_analysis.txt` |
| `POC_LOG` | `poc_findings.json` |
| `REPORT_PATH` | `Harpoon_Report.md` |

### Tool Command Environment Variables

All overridable via `HARPOON_<TOOL>`:

`HARPOON_ZAP`, `HARPOON_SQLMAP`, `HARPOON_GOBUSTER`, `HARPOON_NMAP`, `HARPOON_NUCLEI`, `HARPOON_NIKTO`, `HARPOON_FFUF`, `HARPOON_SUBFINDER`, `HARPOON_AMASS`, `HARPOON_DNSX`, `HARPOON_HTTPX`, `HARPOON_GOWITNESS`, `HARPOON_KATANA`, `HARPOON_WAYBACKURLS`, `HARPOON_GAU`, `HARPOON_URO`, `HARPOON_PARAMSPIDER`, `HARPOON_ARJUN`, `HARPOON_OLLAMA`, `HARPOON_OLLAMA_MODEL`

---

## External Tool Dependencies

### Go-based (installed in WSL via `go install`)

| Tool | Purpose | Phase |
|------|---------|-------|
| subfinder | Passive subdomain enumeration | 1 |
| dnsx | Active DNS resolution + wildcard filtering | 2 |
| httpx | HTTP probing + technology fingerprinting | 3 |
| gowitness | Visual screenshot recon | 4 |
| katana | Headless SPA/JS crawling | 6 |
| waybackurls | Historical URL mining (Wayback Machine) | 6 |
| gau | Historical URL mining (multiple archives) | 6 |

### Python-based (installed via pip in WSL)

| Tool | Purpose | Phase |
|------|---------|-------|
| paramspider | Passive parameter discovery from archives | 8 |
| arjun | Active hidden parameter brute-force | 8 |
| uro | URL deduplication (optional, Python fallback exists) | 6 |

### Pre-existing tools (must be on PATH or WSL)

| Tool | Purpose | Phase |
|------|---------|-------|
| Nmap | Port/service scanning | 2 |
| Gobuster | Targeted directory recursion | 5 |
| ffuf | Primary dir/vhost/param fuzzer | 5, 8 |
| OWASP ZAP | Targeted web vulnerability scanning | 6 |
| Sqlmap | SQL injection validation | 9 |
| Nuclei | Template-based CVE scanning | 9 |
| Nikto | Web server misconfiguration scanner | 9 |
| Ollama | AI-assisted report analysis (optional) | Report |

---

## Data Flow Between Phases

```
Phase 1 (subfinder/crt.sh/amass)
    └─► state.subdomains[]

Phase 2 (dnsx → nmap)
    ├─► state.resolved_hosts[] (from dnsx)
    ├─► state.ips[] (from dnsx)
    └─► state.ports[] (from nmap)

Phase 3 (httpx → waf engine)
    ├─► state.urls[] (live endpoints)
    ├─► state.technologies{} (per-host tech tags)
    └─► state.waf{} (per-host WAF status)

Phase 5 (ffuf → gobuster)
    ├─► state.paths[] (discovered directories/files)
    └─► state.vhosts[] (discovered virtual hosts)

Phase 6 (katana/wayback/gau → ZAP)
    └─► state.urls[] (historical + crawled endpoints)

Phase 7 (JS analysis)
    ├─► state.paths[] (JS-extracted endpoints)
    └─► state.secrets[] (high-entropy strings)

Phase 8 (paramspider/arjun/ffuf-params)
    └─► state.params[] (discovered parameters)

Phase 9 (nuclei/sqlmap/nikto)
    ├─► nuclei reads from state (targets + tech tags)
    ├─► sqlmap reads from state (discovered params)
    └─► nikto conditional on state.waf{}

Phase 10 (PoC generator)
    └─► poc_findings.json (deterministic PoC statements)
```

---

## Report Output (`harpoon/report_stateful.py`)

The generated `Harpoon_Report.md` contains:

1. **Title** + target + date
2. **Executive Summary** + overall risk rating (CRITICAL/HIGH/MEDIUM/LOW)
3. **Toolchain Procedure** (numbered 1-10 phase list)
4. **Findings Snapshot** (counts: ports, dirs, vhosts, params, nuclei, PoCs)
5. **Open Services** (from Nmap)
6. **Nuclei Validation Results** (severity + matched URL)
7. **Actionable Proof of Exploitation** (deterministic PoC statements or "none generated")
8. **AI-Assisted Analysis** (optional, from Ollama)
9. **Raw Log Files** table

---

## Key Implementation Notes

- **WSL routing**: All Go tools are installed in WSL. Every scanner checks `find_cmd()` on Windows PATH first, then falls back to `subprocess.run(["wsl", "which", "<tool>"])`. When WSL is used, file paths are converted to `/mnt/c/...` format via `_wsl_path()`.
- **No Metasploit**: The `harpoon/exploit/` directory has been deleted. There is no blind exploitation. Phase 10 generates PoC statements for manual verification.
- **Thread safety**: `PipelineStateManager` uses `threading.RLock` for concurrent access during spinner-threaded tool execution.
- **JSON-first output**: Tools like httpx, dnsx, katana, and nuclei output JSONL which is parsed via `run_capture_json()` for real-time state updates.
- **Ollama integration**: Uses `qwen3.5:cloud` model (configurable via `HARPOON_OLLAMA_MODEL`). Prompt focuses on PoC analysis and WAF-adaptive behavior documentation.
