"""Subdomain permutation generation via alterx."""
from __future__ import annotations

import subprocess
from pathlib import Path

from harpoon.config import ALTERX_CMD, ALTERX_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_alterx(base_names: list[str], log_path: Path = ALTERX_LOG, timeout: int = 120) -> tuple[int, list[str], str]:
    cmd = find_cmd("alterx") or find_cmd(ALTERX_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "alterx"] if _has_wsl("alterx") else [])
    if not argv_prefix:
        log_path.write_text("alterx not found", encoding="utf-8")
        return -1, [], "alterx not found"
    src = log_path.with_name("alterx_input.txt")
    src.write_text("\n".join(sorted(set(base_names))), encoding="utf-8")
    code, out, err = await run_tool(argv_prefix + ["-l", str(src)], log_path, timeout=timeout)
    candidates = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return code, candidates, f"alterx generated {len(candidates)} permutations"
