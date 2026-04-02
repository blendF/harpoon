"""Passive subdomain enumeration via subfinder."""
from __future__ import annotations

import subprocess
from pathlib import Path

from harpoon.config import SUBFINDER_CMD, SUBFINDER_LOG
from harpoon.runner import find_cmd, run_tool


def _wsl_has(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_subfinder(domain: str, log_path: Path = SUBFINDER_LOG, timeout: int = 180) -> tuple[int, list[str], str]:
    cmd = find_cmd("subfinder") or find_cmd(SUBFINDER_CMD.split()[0])
    if not cmd and _wsl_has("subfinder"):
        cmd = "WSL"
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "subfinder not found. Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            encoding="utf-8",
        )
        return -1, [], "subfinder not found; skipped."

    argv = ["wsl", "subfinder", "-d", domain, "-silent"] if cmd == "WSL" else [cmd, "-d", domain, "-silent"]
    code, out, err = await run_tool(argv, log_path, timeout=timeout)
    subdomains = sorted({ln.strip().lower() for ln in out.splitlines() if ln.strip()})
    if code == 0:
        return 0, subdomains, f"subfinder discovered {len(subdomains)} subdomain(s)."
    return code, subdomains, f"subfinder finished with code {code}."

