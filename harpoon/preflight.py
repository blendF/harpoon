"""Strict dependency checker: halt if any required tool is missing."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from harpoon.cli import error, warn
from harpoon.config import BASE_DIR, SECLISTS_DIR, WORDLISTS_DIR

# Logical tool id -> any of these executables on PATH (or extra file checks below)
TOOL_CANDIDATES: dict[str, list[str]] = {
    "subfinder": ["subfinder"],
    "crtsh": [],  # uses curl; checked separately
    "amass": ["amass"],
    "dnsx": ["dnsx"],
    "httpx": ["httpx"],
    "naabu": ["naabu"],
    "uncover": ["uncover"],
    "tlsx": ["tlsx"],
    "asnmap": ["asnmap"],
    "mapcidr": ["mapcidr"],
    "cdncheck": ["cdncheck"],
    "shuffledns": ["shuffledns"],
    "chaos": ["chaos", "chaos-client"],
    "alterx": ["alterx"],
    "x8": ["x8"],
    "interactsh-client": ["interactsh-client", "interactsh"],
    "notify": ["notify"],
    "katana": ["katana"],
    "waybackurls": ["waybackurls"],
    "gau": ["gau"],
    "paramspider": ["paramspider"],
    "arjun": ["arjun"],
    "ffuf": ["ffuf"],
    "sqlmap": ["sqlmap", "sqlmap.py"],
    "nuclei": ["nuclei"],
    "nikto": ["nikto", "nikto.pl"],
    "nmap": ["nmap"],
    "zap.sh": ["zap.sh", "zap", "zap.bat"],
}

# Order must match pipeline expectations
REQUIRED_TOOLS: list[str] = [
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

_ZAP_EXTRA_PATHS = [
    Path("/usr/share/zaproxy/zap.sh"),
    Path("/usr/bin/zaproxy"),
    Path("/opt/zaproxy/zap.sh"),
]

_CURL_CANDIDATES = ["curl"]


def _on_windows() -> bool:
    return sys.platform in ("win32", "cygwin")


def _wsl_which(name: str) -> bool:
    try:
        r = subprocess.run(
            ["wsl", "-e", "which", name],
            capture_output=True,
            timeout=15,
            text=True,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _has_curl() -> bool:
    for name in _CURL_CANDIDATES:
        if shutil.which(name):
            return True
        if _on_windows() and _wsl_which(name):
            return True
    return False


def _local_bin(name: str) -> bool:
    home = Path.home()
    for d in (home / ".local" / "bin", home / "go" / "bin"):
        p = d / name
        if p.is_file():
            return True
        if _on_windows() and (d / f"{name}.exe").is_file():
            return True
    return False


def _has_tool(logical: str) -> bool:
    if logical == "crtsh":
        return _has_curl()

    if logical == "zap.sh":
        for p in _ZAP_EXTRA_PATHS:
            if p.is_file():
                return True

    names = TOOL_CANDIDATES.get(logical, [logical])
    for name in names:
        if shutil.which(name):
            return True
        if _local_bin(name):
            return True
        if _on_windows() and _wsl_which(name):
            return True

    return False


def _seclists_present() -> bool:
    env = os.environ.get("HARPOON_SECLISTS_DIR", "").strip()
    if env and Path(env).is_dir():
        return True
    for candidate in (SECLISTS_DIR, Path("/usr/share/seclists")):
        if candidate and Path(candidate).is_dir():
            return True
    # Allow bundled wordlists as explicit opt-in (no SecLists install)
    if os.environ.get("HARPOON_USE_BUNDLED_WORDLISTS", "").strip() in ("1", "true", "yes"):
        if WORDLISTS_DIR.is_dir() and any(WORDLISTS_DIR.iterdir()):
            return True
    return False


def install_script_path() -> Path | None:
    """Path to optional installer script (repo root)."""
    p = BASE_DIR / "scripts" / "install_harpoon_tools.sh"
    return p if p.is_file() else None


def find_missing_dependencies() -> list[str]:
    missing = [t for t in REQUIRED_TOOLS if not _has_tool(t)]
    if not _seclists_present():
        missing.append("seclists")
    return sorted(set(missing))


def check_dependencies() -> None:
    missing = find_missing_dependencies()
    if not missing:
        return

    error("Pre-flight failed: some required tools or SecLists are missing.")
    warn(f"Missing ({len(missing)}): {', '.join(missing)}")

    script = install_script_path()
    if script:
        warn("Install everything on Debian/Ubuntu/Kali/WSL with:")
        warn(f"  bash {script}")
    else:
        warn("Clone the Harpoon repo so scripts/install_harpoon_tools.sh is available, or install tools manually.")

    warn("If SecLists is installed elsewhere, set: export HARPOON_SECLISTS_DIR=/path/to/seclists")
    warn("To use only bundled wordlists (no SecLists): export HARPOON_USE_BUNDLED_WORDLISTS=1")

    if _on_windows():
        warn("On Windows, either add tools to PATH or run Harpoon inside WSL so the same binaries are visible.")

    sys.exit(1)
