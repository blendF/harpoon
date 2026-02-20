# Harpoon – Automated Pentesting Tool

Harpoon is a **Windows-based, command-line** tool for automated web application penetration testing. It integrates multiple open-source security tools to perform scanning and exploitation of a given target. You provide the target's domain or IP; Harpoon runs the analysis and attack sequence and generates a consolidated report.

**Intended for authorized, professional use only.**

## Features

- **Startup**: Displays ASCII art from `HARPOONASCIIART.txt`
- **Target input**: Prompts for target IP or domain
- **Reconnaissance**: Nmap (network discovery)
- **Enumeration**: Gobuster (path discovery; handles wildcard/SPA responses)
- **Web application scanning**: OWASP ZAP, Sqlmap, Nuclei
- **Exploitation**: Metasploit (per discovered service)
- **LLM orchestration**: Uses local Ollama model `xploiter/the-xploiter` (when available) to help summarize findings and generate the report
- **Reporting**: Produces `Harpoon_Report.md` with summaries and consolidated tool outputs

All interactions are **CLI-only** (no GUI, no screenshots). The tool is designed for **offline operation** (no external API calls).

## Requirements

- **Python 3.10+** (for running from source)
- **Windows** (primary target; may run on Linux/macOS with the same tools installed)

### External tools (must be installed and on `PATH` unless noted)

| Tool | Purpose | Setup |
|------|---------|--------|
| **OWASP ZAP** | Web vulnerability scanning (headless/CLI) | Install [ZAP](https://www.zaproxy.org/download/) and add `zap.bat` (Windows) or `zap.sh` to PATH |
| **Sqlmap** | SQL injection testing | Install [sqlmap](https://sqlmap.org/) (e.g. `pip install sqlmap` or clone repo) and ensure `sqlmap` or `sqlmap.py` is on PATH |
| **Gobuster** | Path enumeration | Bundled in `tools/` or install from [Gobuster](https://github.com/OJ/gobuster) |
| **Nuclei** | CVE/template scanning | Uses Nmap + Gobuster context. Local: place `nuclei-dev/nuclei-dev/` in Harpoon; run `make build` or `go build -o bin/nuclei.exe ./cmd/nuclei` from that folder before first use. Or install from [Nuclei releases](https://github.com/projectdiscovery/nuclei/releases) and add to PATH. |
| **Nmap** | Port and service scanning | Install [Nmap](https://nmap.org/download.html) and add `nmap` to PATH |
| **Metasploit** | Exploitation framework | See [Metasploit setup](#metasploit-setup) below. Local: place `metasploit-framework-master/metasploit-framework-master/` in Harpoon; requires Ruby on PATH. |
| **Ollama** (optional) | LLM for report summarization | Install [Ollama](https://ollama.ai/), run `ollama pull qwen3.5:cloud` (or set `HARPOON_OLLAMA_MODEL`) |

### Metasploit setup

**Linux / macOS:**

```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
chmod 755 msfinstall && \
./msfinstall
```

**Windows:** Download the .msi from [windows.metasploit.com/metasploitframework-latest.msi](https://windows.metasploit.com/metasploitframework-latest.msi), run as Administrator, then add `C:\metasploit-framework\bin` to PATH. Or set `HARPOON_MSFCONSOLE=C:\metasploit-framework\bin\msfconsole.bat`.

**Local source:** Place `metasploit-framework-master/metasploit-framework-master/` inside the Harpoon project folder. Harpoon will run it via `ruby msfconsole`; ensure Ruby is on PATH.

Harpoon will skip the exploitation phase if Metasploit is not found; all other phases still run.

You can override with env vars: `HARPOON_ZAP`, `HARPOON_SQLMAP`, `HARPOON_GOBUSTER`, `HARPOON_NMAP`, `HARPOON_MSFCONSOLE`, `HARPOON_OLLAMA`, `HARPOON_OLLAMA_MODEL` (e.g. `qwen3.5:cloud`).

## Quick start (from source)

```bash
cd Harpoon
pip install -r requirements.txt
# Ensure HARPOONASCIIART.txt is in the project root (it is by default)
python main.py
```

You will be prompted for the target IP or domain. All output is written under `harpoon_logs/` and `Harpoon_Report.md` in the current directory.

## Building a standalone Windows executable

Using PyInstaller, you can bundle Harpoon and `HARPOONASCIIART.txt` into a single `.exe`:

```bash
pip install pyinstaller
pyinstaller harpoon.spec
```

The executable will be in `dist/`. Run it from a folder where you have write access; it will create `harpoon_logs/` and `Harpoon_Report.md` in the current directory. External tools (ZAP, sqlmap, gobuster, nmap, msfconsole, ollama) are **not** bundled; they must be installed separately and on `PATH`. To use local `metasploit-framework-master` or `nuclei-dev` folders, place them in the same directory as the exe and run the exe from that directory.

## Output files

- `harpoon_logs/nmap_scan.txt` – Reconnaissance (Nmap)  
- `harpoon_logs/gobuster_enum.txt` – Enumeration (Gobuster)  
- `harpoon_logs/zap_scan.txt` – Web scanning (OWASP ZAP)  
- `harpoon_logs/sqlmap_scan.txt` – Web scanning (Sqlmap)  
- `harpoon_logs/nuclei_scan.txt` – Web scanning (Nuclei)  
- `harpoon_logs/metasploit_exploits.txt` – Exploitation (Metasploit)  
- `Harpoon_Report.md` – Consolidated report (summaries + excerpts from each tool)

## License

MIT License. See [LICENSE](LICENSE).
