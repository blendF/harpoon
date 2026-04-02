"""Port discovery via naabu."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from harpoon.config import NAABU_CMD, NAABU_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_naabu(targets: list[str], log_path: Path = NAABU_LOG, timeout: int = 300) -> tuple[int, list[dict], str]:
    cmd = find_cmd("naabu") or find_cmd(NAABU_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "naabu"] if _has_wsl("naabu") else [])
    if not argv_prefix:
        log_path.write_text("naabu not found", encoding="utf-8")
        return -1, [], "naabu not found"
    target_file = log_path.with_name("naabu_targets.txt")
    target_file.write_text("\n".join(sorted(set(targets))), encoding="utf-8")
    argv = argv_prefix + ["-list", str(target_file), "-json"]
    code, out, err = await run_tool(argv, log_path, timeout=timeout)
    rows: list[dict] = []
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return code, rows, f"naabu discovered {len(rows)} ports"
