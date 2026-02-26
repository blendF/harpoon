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
ZAP_LOG = LOG_DIR / "zap_scan.txt"
SQLMAP_LOG = LOG_DIR / "sqlmap_scan.txt"
SQLMAP_URLS_FILE = LOG_DIR / "sqlmap_urls.txt"
GOBUSTER_LOG = LOG_DIR / "gobuster_enum.txt"
NMAP_LOG = LOG_DIR / "nmap_scan.txt"
NUCLEI_LOG = LOG_DIR / "nuclei_scan.txt"
NUCLEI_TARGETS_FILE = LOG_DIR / "nuclei_targets.txt"
MSF_LOG = LOG_DIR / "metasploit_exploits.txt"
NIKTO_LOG = LOG_DIR / "nikto_scan.txt"
FFUF_DIR_LOG = LOG_DIR / "ffuf_dir.json"
FFUF_VHOST_LOG = LOG_DIR / "ffuf_vhost.json"
FFUF_PARAMS_LOG = LOG_DIR / "ffuf_params.json"
RECON_LOG = LOG_DIR / "dns_recon.txt"
REPORT_PATH = OUTPUT_DIR / "Harpoon_Report.md"

# Local tool directories (sibling to Harpoon when run from project root)
# Check BASE_DIR first (dev), then OUTPUT_DIR (frozen exe run from project folder)
MSF_LOCAL = BASE_DIR / "metasploit-framework-master" / "metasploit-framework-master"
MSF_LOCAL_CWD = OUTPUT_DIR / "metasploit-framework-master" / "metasploit-framework-master"
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
MSFCONSOLE_CMD = os.environ.get("HARPOON_MSFCONSOLE", "msfconsole")
NIKTO_CMD = os.environ.get("HARPOON_NIKTO", "nikto")
FFUF_CMD = os.environ.get("HARPOON_FFUF", "ffuf")
OLLAMA_CMD = os.environ.get("HARPOON_OLLAMA", "ollama")
OLLAMA_MODEL = os.environ.get("HARPOON_OLLAMA_MODEL", "qwen3.5:cloud")
