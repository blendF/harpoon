"""Configuration and paths for Harpoon."""
import os
import sys
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

# Output file names (written to current working directory)
LOG_DIR = OUTPUT_DIR / "harpoon_logs"
STATE_PATH = LOG_DIR / "pipeline_state.json"
ZAP_LOG = LOG_DIR / "zap_scan.txt"
SQLMAP_LOG = LOG_DIR / "sqlmap_scan.txt"
SQLMAP_URLS_FILE = LOG_DIR / "sqlmap_urls.txt"
GOBUSTER_LOG = LOG_DIR / "gobuster_enum.txt"
NMAP_LOG = LOG_DIR / "nmap_scan.txt"
NUCLEI_LOG = LOG_DIR / "nuclei_scan.txt"
NUCLEI_TARGETS_FILE = LOG_DIR / "nuclei_targets.txt"
NIKTO_LOG = LOG_DIR / "nikto_scan.txt"
FFUF_DIR_LOG = LOG_DIR / "ffuf_dir.json"
FFUF_VHOST_LOG = LOG_DIR / "ffuf_vhost.json"
FFUF_PARAMS_LOG = LOG_DIR / "ffuf_params.json"
RECON_LOG = LOG_DIR / "dns_recon.txt"
SUBFINDER_LOG = LOG_DIR / "subfinder_subdomains.jsonl"
CRTSH_LOG = LOG_DIR / "crtsh_subdomains.jsonl"
AMASS_LOG = LOG_DIR / "amass_subdomains.txt"
DNSX_LOG = LOG_DIR / "dnsx_resolved.jsonl"
HTTPX_LOG = LOG_DIR / "httpx_probe.jsonl"
GOWITNESS_LOG = LOG_DIR / "gowitness_scan.txt"
KATANA_LOG = LOG_DIR / "katana_endpoints.jsonl"
WAYBACK_LOG = LOG_DIR / "wayback_urls.txt"
GAU_LOG = LOG_DIR / "gau_urls.txt"
URO_LOG = LOG_DIR / "unique_urls.txt"
PARAMSPIDER_LOG = LOG_DIR / "paramspider_params.txt"
ARJUN_LOG = LOG_DIR / "arjun_params.json"
JS_ANALYSIS_LOG = LOG_DIR / "js_analysis.txt"
POC_LOG = LOG_DIR / "poc_findings.json"
REPORT_PATH = OUTPUT_DIR / "Harpoon_Report.md"

# Local tool directories (sibling to Harpoon when run from project root)
# Check BASE_DIR first (dev), then OUTPUT_DIR (frozen exe run from project folder)
NUCLEI_LOCAL = BASE_DIR / "nuclei-dev" / "nuclei-dev"
NUCLEI_LOCAL_CWD = OUTPUT_DIR / "nuclei-dev" / "nuclei-dev"
WORDLISTS_DIR = BASE_DIR / "harpoon" / "wordlists"
WORDLISTS_DIR_CWD = OUTPUT_DIR / "harpoon" / "wordlists"
NIKTO_LOCAL = BASE_DIR / "nikto" / "program"
NIKTO_LOCAL_CWD = OUTPUT_DIR / "nikto" / "program"

# Tool names (can be overridden via env or config)
ZAP_CMD = os.environ.get("HARPOON_ZAP", "zap.sh")  # or zap.bat on Windows
SQLMAP_CMD = os.environ.get("HARPOON_SQLMAP", "sqlmap")
GOBUSTER_CMD = os.environ.get("HARPOON_GOBUSTER", "gobuster")
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
OLLAMA_CMD = os.environ.get("HARPOON_OLLAMA", "ollama")
OLLAMA_MODEL = os.environ.get("HARPOON_OLLAMA_MODEL", "qwen3.5:cloud")
