"""Asset dorking via uncover."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from harpoon.config import UNCOVER_CMD, UNCOVER_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_uncover(query: str, log_path: Path = UNCOVER_LOG, timeout: int = 120) -> tuple[int, list[dict], str]:
    cmd = find_cmd("uncover") or find_cmd(UNCOVER_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "uncover"] if _has_wsl("uncover") else [])
    if not argv_prefix:
        log_path.write_text("uncover not found", encoding="utf-8")
        return -1, [], "uncover not found"
    argv = argv_prefix + ["-q", query, "-json", "-silent"]
    code, out, err = await run_tool(argv, log_path, timeout=timeout)
    rows: list[dict] = []
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return code, rows, f"uncover returned {len(rows)} entries"
