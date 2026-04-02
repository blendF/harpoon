"""Active DNS brute force via shuffledns."""
from __future__ import annotations

import subprocess
from pathlib import Path

from harpoon.config import SHUFFLEDNS_CMD, SHUFFLEDNS_LOG
from harpoon.runner import find_cmd, run_tool


def _has_wsl(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


async def run_shuffledns(domain: str, wordlist: str, log_path: Path = SHUFFLEDNS_LOG, timeout: int = 300) -> tuple[int, list[str], str]:
    cmd = find_cmd("shuffledns") or find_cmd(SHUFFLEDNS_CMD.split()[0])
    argv_prefix = [cmd] if cmd else (["wsl", "shuffledns"] if _has_wsl("shuffledns") else [])
    if not argv_prefix:
        log_path.write_text("shuffledns not found", encoding="utf-8")
        return -1, [], "shuffledns not found"
    out_file = log_path.with_name("shuffledns_out.txt")
    argv = argv_prefix + ["-d", domain, "-w", wordlist, "-o", str(out_file), "-silent"]
    code, out, err = await run_tool(argv, log_path, timeout=timeout)
    subs = []
    if out_file.exists():
        subs = [ln.strip() for ln in out_file.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    return code, subs, f"shuffledns discovered {len(subs)} hosts"
