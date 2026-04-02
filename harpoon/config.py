"""Configuration and paths for Harpoon."""
from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

# Base paths: support both dev and PyInstaller bundle
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys._MEIPASS)
    OUTPUT_DIR = Path.cwd()
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
    OUTPUT_DIR = Path.cwd()

# ASCII art path (bundled in resources)
ASCII_ART_PATH = BASE_DIR / "HARPOONASCIIART.txt"
if not ASCII_ART_PATH.exists():
    ASCII_ART_PATH = OUTPUT_DIR / "HARPOONASCIIART.txt"

# Session paths
LOG_DIR = OUTPUT_DIR / "harpoon_logs"
SESSION_ROOT = LOG_DIR / "sessions"
_SESSION_NAME = os.environ.get("HARPOON_SESSION_NAME") or datetime.now().strftime("%Y%m%d_%H%M%S")
SESSION_DIR = SESSION_ROOT / _SESSION_NAME
SESSION_DB_PATH = SESSION_DIR / "pipeline_state.db"

# Output files
STATE_PATH = SESSION_DIR / "pipeline_state_snapshot.json"
ZAP_LOG = SESSION_DIR / "zap_scan.txt"
SQLMAP_LOG = SESSION_DIR / "sqlmap_scan.txt"
SQLMAP_URLS_FILE = SESSION_DIR / "sqlmap_urls.txt"
NMAP_LOG = SESSION_DIR / "nmap_scan.txt"
NUCLEI_LOG = SESSION_DIR / "nuclei_scan.jsonl"
NUCLEI_TARGETS_FILE = SESSION_DIR / "nuclei_targets.txt"
NIKTO_LOG = SESSION_DIR / "nikto_scan.txt"
FFUF_DIR_LOG = SESSION_DIR / "ffuf_dir.json"
FFUF_VHOST_LOG = SESSION_DIR / "ffuf_vhost.json"
FFUF_PARAMS_LOG = SESSION_DIR / "ffuf_params.json"
RECON_LOG = SESSION_DIR / "dns_recon.txt"
SUBFINDER_LOG = SESSION_DIR / "subfinder_subdomains.txt"
CRTSH_LOG = SESSION_DIR / "crtsh_subdomains.json"
AMASS_LOG = SESSION_DIR / "amass_subdomains.txt"
DNSX_LOG = SESSION_DIR / "dnsx_resolved.jsonl"
HTTPX_LOG = SESSION_DIR / "httpx_probe.jsonl"
GOWITNESS_LOG = SESSION_DIR / "gowitness_scan.txt"
KATANA_LOG = SESSION_DIR / "katana_endpoints.jsonl"
WAYBACK_LOG = SESSION_DIR / "wayback_urls.txt"
GAU_LOG = SESSION_DIR / "gau_urls.txt"
URO_LOG = SESSION_DIR / "unique_urls.txt"
PARAMSPIDER_LOG = SESSION_DIR / "paramspider_params.txt"
ARJUN_LOG = SESSION_DIR / "arjun_params.json"
JS_ANALYSIS_LOG = SESSION_DIR / "js_analysis.txt"
POC_LOG = SESSION_DIR / "poc_findings.json"

# New tool logs
NAABU_LOG = SESSION_DIR / "naabu_ports.jsonl"
UNCOVER_LOG = SESSION_DIR / "uncover_assets.jsonl"
TLSX_LOG = SESSION_DIR / "tlsx_fingerprints.jsonl"
ASNMAP_LOG = SESSION_DIR / "asnmap_ranges.txt"
MAPCIDR_LOG = SESSION_DIR / "mapcidr_ranges.txt"
CDNCHECK_LOG = SESSION_DIR / "cdncheck_result.jsonl"
SHUFFLEDNS_LOG = SESSION_DIR / "shuffledns_subdomains.txt"
CHAOS_LOG = SESSION_DIR / "chaos_subdomains.txt"
ALTERX_LOG = SESSION_DIR / "alterx_permutations.txt"
X8_LOG = SESSION_DIR / "x8_params.json"
INTERACTSH_LOG = SESSION_DIR / "interactsh_events.txt"
NOTIFY_LOG = SESSION_DIR / "notify_dispatch.txt"

REPORT_PATH = OUTPUT_DIR / "Harpoon_Report.md"
HTML_REPORT_GLOB = "harpoon_assessment_*.html"

# Local tool directories
NUCLEI_LOCAL = BASE_DIR / "nuclei-dev" / "nuclei-dev"
NUCLEI_LOCAL_CWD = OUTPUT_DIR / "nuclei-dev" / "nuclei-dev"
WORDLISTS_DIR = BASE_DIR / "harpoon" / "wordlists"
WORDLISTS_DIR_CWD = OUTPUT_DIR / "harpoon" / "wordlists"
NIKTO_LOCAL = BASE_DIR / "nikto" / "program"
NIKTO_LOCAL_CWD = OUTPUT_DIR / "nikto" / "program"

SECLISTS_DIR = Path(os.environ.get("HARPOON_SECLISTS_DIR", "/usr/share/seclists"))
SECLISTS_DISCOVERY = SECLISTS_DIR / "Discovery" / "Web-Content"
SECLISTS_DNS = SECLISTS_DIR / "Discovery" / "DNS"
SECLISTS_PARAMS = SECLISTS_DIR / "Discovery" / "Web-Content"

# Tool names (can be overridden via env)
ZAP_CMD = os.environ.get("HARPOON_ZAP", "zap.sh")
SQLMAP_CMD = os.environ.get("HARPOON_SQLMAP", "sqlmap")
NMAP_CMD = os.environ.get("HARPOON_NMAP", "nmap")
NUCLEI_CMD = os.environ.get("HARPOON_NUCLEI", "nuclei")
NIKTO_CMD = os.environ.get("HARPOON_NIKTO", "nikto")
FFUF_CMD = os.environ.get("HARPOON_FFUF", "ffuf")
SUBFINDER_CMD = os.environ.get("HARPOON_SUBFINDER", "subfinder")
AMASS_CMD = os.environ.get("HARPOON_AMASS", "amass")
DNSX_CMD = os.environ.get("HARPOON_DNSX", "dnsx")
HTTPX_CMD = os.environ.get("HARPOON_HTTPX", "httpx")
GOWITNESS_CMD = os.environ.get("HARPOON_GOWITNESS", "gowitness")
KATANA_CMD = os.environ.get("HARPOON_KATANA", "katana")
WAYBACKURLS_CMD = os.environ.get("HARPOON_WAYBACKURLS", "waybackurls")
GAU_CMD = os.environ.get("HARPOON_GAU", "gau")
URO_CMD = os.environ.get("HARPOON_URO", "uro")
PARAMSPIDER_CMD = os.environ.get("HARPOON_PARAMSPIDER", "paramspider")
ARJUN_CMD = os.environ.get("HARPOON_ARJUN", "arjun")
NAABU_CMD = os.environ.get("HARPOON_NAABU", "naabu")
UNCOVER_CMD = os.environ.get("HARPOON_UNCOVER", "uncover")
TLSX_CMD = os.environ.get("HARPOON_TLSX", "tlsx")
ASNMAP_CMD = os.environ.get("HARPOON_ASNMAP", "asnmap")
MAPCIDR_CMD = os.environ.get("HARPOON_MAPCIDR", "mapcidr")
CDNCHECK_CMD = os.environ.get("HARPOON_CDNCHECK", "cdncheck")
SHUFFLEDNS_CMD = os.environ.get("HARPOON_SHUFFLEDNS", "shuffledns")
CHAOS_CMD = os.environ.get("HARPOON_CHAOS", "chaos")
ALTERX_CMD = os.environ.get("HARPOON_ALTERX", "alterx")
X8_CMD = os.environ.get("HARPOON_X8", "x8")
INTERACTSH_CMD = os.environ.get("HARPOON_INTERACTSH", "interactsh-client")
NOTIFY_CMD = os.environ.get("HARPOON_NOTIFY", "notify")

OLLAMA_CMD = os.environ.get("HARPOON_OLLAMA", "ollama")
OLLAMA_MODEL = os.environ.get("HARPOON_OLLAMA_MODEL", "qwen3.5:cloud")
