"""Subdomain expansion via chaos."""
from __future__ import annotations

import subprocess
from pathlib import Path

from harpoon.config import CHAOS_CMD, CHAOS_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_chaos(domain: str, log_path: Path = CHAOS_LOG, timeout: int = 120) -> tuple[int, list[str], str]:
    cmd = find_cmd("chaos") or find_cmd(CHAOS_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "chaos"] if _has_wsl("chaos") else [])
    if not argv_prefix:
        log_path.write_text("chaos not found", encoding="utf-8")
        return -1, [], "chaos not found"
    code, out, err = await run_tool(argv_prefix + ["-d", domain, "-silent"], log_path, timeout=timeout)
    subs = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return code, subs, f"chaos discovered {len(subs)} hosts"
