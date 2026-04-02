"""CDN/WAF detection via cdncheck."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from harpoon.config import CDNCHECK_CMD, CDNCHECK_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_cdncheck(target: str, log_path: Path = CDNCHECK_LOG, timeout: int = 90) -> tuple[int, dict, str]:
    cmd = find_cmd("cdncheck") or find_cmd(CDNCHECK_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "cdncheck"] if _has_wsl("cdncheck") else [])
    if not argv_prefix:
        log_path.write_text("cdncheck not found", encoding="utf-8")
        return -1, {}, "cdncheck not found"
    argv = argv_prefix + ["-host", target, "-json", "-silent"]
    code, out, err = await run_tool(argv, log_path, timeout=timeout)
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return code, obj, "cdncheck completed"
    return code, {}, "cdncheck completed (no structured result)"
