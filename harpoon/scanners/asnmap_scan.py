"""ASN mapping via asnmap."""
from __future__ import annotations

import subprocess
from pathlib import Path

from harpoon.config import ASNMAP_CMD, ASNMAP_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_asnmap(target: str, log_path: Path = ASNMAP_LOG, timeout: int = 120) -> tuple[int, list[str], str]:
    cmd = find_cmd("asnmap") or find_cmd(ASNMAP_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "asnmap"] if _has_wsl("asnmap") else [])
    if not argv_prefix:
        log_path.write_text("asnmap not found", encoding="utf-8")
        return -1, [], "asnmap not found"
    code, out, err = await run_tool(argv_prefix + ["-target", target, "-silent"], log_path, timeout=timeout)
    ranges = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return code, ranges, f"asnmap mapped {len(ranges)} ranges"
