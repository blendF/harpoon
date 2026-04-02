"""Active parameter discovery via x8."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from harpoon.config import X8_CMD, X8_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_x8(url: str, wordlist: str, log_path: Path = X8_LOG, timeout: int = 180) -> tuple[int, list[str], str]:
    cmd = find_cmd("x8") or find_cmd(X8_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "x8"] if _has_wsl("x8") else [])
    if not argv_prefix:
        log_path.write_text("x8 not found", encoding="utf-8")
        return -1, [], "x8 not found"
    argv = argv_prefix + ["-u", url, "-w", wordlist, "-o", str(log_path), "-q"]
    code, out, err = await run_tool(argv, log_path.with_suffix(".log"), timeout=timeout)
    params: list[str] = []
    if log_path.exists():
        raw = log_path.read_text(encoding="utf-8", errors="replace")
        for line in raw.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("name"):
                params.append(str(obj["name"]))
    return code, sorted(set(params)), f"x8 discovered {len(set(params))} parameters"
