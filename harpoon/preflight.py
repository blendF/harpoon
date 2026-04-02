"""Strict dependency checker: halt if any required tool is missing."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from harpoon.cli import error
from harpoon.config import SECLISTS_DIR

REQUIRED_TOOLS = [
    "subfinder",
    "crtsh",
    "amass",
    "dnsx",
    "httpx",
    "naabu",
    "uncover",
    "tlsx",
    "asnmap",
    "mapcidr",
    "cdncheck",
    "shuffledns",
    "chaos",
    "alterx",
    "x8",
    "interactsh-client",
    "notify",
    "katana",
    "waybackurls",
    "gau",
    "paramspider",
    "arjun",
    "ffuf",
    "sqlmap",
    "nuclei",
    "nikto",
    "nmap",
    "zap.sh",
]


def _has_tool(tool: str) -> bool:
    if tool == "crtsh":
        return True
    if tool == "zap.sh":
        if shutil.which("zap.sh") or shutil.which("zap.bat"):
            return True
        try:
            return subprocess.run(["wsl", "which", "zap.sh"], capture_output=True, timeout=10).returncode == 0
        except Exception:
            return False
    if shutil.which(tool):
        return True
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def _install_block() -> str:
    return """\
sudo apt update && sudo apt install -y seclists nmap sqlmap nikto
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/Sh1Yo/x8/cmd/x8@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
pip install git+https://github.com/devanshbatham/ParamSpider.git arjun rich
"""


def check_dependencies() -> None:
    missing = [tool for tool in REQUIRED_TOOLS if not _has_tool(tool)]
    if not Path(SECLISTS_DIR).exists():
        missing.append("seclists")
    if missing:
        error(f"Pre-flight failed. Missing dependencies: {', '.join(sorted(set(missing)))}")
        print(_install_block())
        sys.exit(1)
