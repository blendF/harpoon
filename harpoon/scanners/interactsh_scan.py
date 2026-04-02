"""OOB event collection via interactsh-client."""
from __future__ import annotations

import subprocess
from pathlib import Path

from harpoon.config import INTERACTSH_CMD, INTERACTSH_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_interactsh(log_path: Path = INTERACTSH_LOG, timeout: int = 60) -> tuple[int, str, str]:
    cmd = find_cmd("interactsh-client") or find_cmd(INTERACTSH_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "interactsh-client"] if _has_wsl("interactsh-client") else [])
    if not argv_prefix:
        log_path.write_text("interactsh-client not found", encoding="utf-8")
        return -1, "", "interactsh-client not found"
    code, out, err = await run_tool(argv_prefix + ["-json"], log_path, timeout=timeout)
    return code, out, "interactsh collection complete"
