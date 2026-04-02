"""Notification dispatch via notify."""
from __future__ import annotations

import subprocess
from pathlib import Path

from harpoon.config import NOTIFY_CMD, NOTIFY_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_notify(message: str, log_path: Path = NOTIFY_LOG, timeout: int = 30) -> tuple[int, str]:
    cmd = find_cmd("notify") or find_cmd(NOTIFY_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "notify"] if _has_wsl("notify") else [])
    if not argv_prefix:
        log_path.write_text("notify not found", encoding="utf-8")
        return -1, "notify not found"
    code, out, err = await run_tool(argv_prefix + ["-silent"], log_path, timeout=timeout, env={"HARPOON_NOTIFY_MESSAGE": message})
    return code, "notify dispatched" if code == 0 else f"notify failed ({code})"
