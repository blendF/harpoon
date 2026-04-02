"""TLS fingerprinting via tlsx."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from harpoon.config import TLSX_CMD, TLSX_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_tlsx(targets: list[str], log_path: Path = TLSX_LOG, timeout: int = 180) -> tuple[int, list[dict], str]:
    cmd = find_cmd("tlsx") or find_cmd(TLSX_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "tlsx"] if _has_wsl("tlsx") else [])
    if not argv_prefix:
        log_path.write_text("tlsx not found", encoding="utf-8")
        return -1, [], "tlsx not found"
    target_file = log_path.with_name("tlsx_targets.txt")
    target_file.write_text("\n".join(sorted(set(targets))), encoding="utf-8")
    argv = argv_prefix + ["-list", str(target_file), "-json", "-silent"]
    code, out, err = await run_tool(argv, log_path, timeout=timeout)
    rows: list[dict] = []
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return code, rows, f"tlsx processed {len(rows)} endpoints"
