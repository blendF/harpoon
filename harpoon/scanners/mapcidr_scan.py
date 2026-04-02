"""CIDR manipulation via mapcidr."""
from __future__ import annotations

import subprocess
from pathlib import Path

from harpoon.config import MAPCIDR_CMD, MAPCIDR_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_mapcidr(cidr_ranges: list[str], log_path: Path = MAPCIDR_LOG, timeout: int = 120) -> tuple[int, list[str], str]:
    cmd = find_cmd("mapcidr") or find_cmd(MAPCIDR_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "mapcidr"] if _has_wsl("mapcidr") else [])
    if not argv_prefix:
        log_path.write_text("mapcidr not found", encoding="utf-8")
        return -1, [], "mapcidr not found"
    src = log_path.with_name("mapcidr_input.txt")
    src.write_text("\n".join(cidr_ranges), encoding="utf-8")
    code, out, err = await run_tool(argv_prefix + ["-silent", "-list", str(src)], log_path, timeout=timeout)
    ips = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return code, ips, f"mapcidr produced {len(ips)} IPs"
