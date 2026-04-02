"""Passive parameter discovery via paramspider."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from harpoon.config import PARAMSPIDER_CMD, PARAMSPIDER_LOG
from harpoon.runner import find_cmd, run_tool


def _wsl_has(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


_PARAM_RE = re.compile(r"[?&]([A-Za-z0-9_\-]{1,80})=")


async def run_paramspider(domain: str, log_path: Path = PARAMSPIDER_LOG, timeout: int = 240) -> tuple[int, list[str], str]:
    cmd = find_cmd("paramspider") or find_cmd(PARAMSPIDER_CMD.split()[0])
    use_wsl = False
    if not cmd and _wsl_has("paramspider"):
        use_wsl = True
    if not cmd and not use_wsl:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("paramspider not found. Install with: pip install paramspider", encoding="utf-8")
        return -1, [], "paramspider not found; skipped."

    argv = ["wsl", "paramspider", "--domain", domain, "--quiet"] if use_wsl else [cmd, "--domain", domain, "--quiet"]
    code, out, err = await run_tool(argv, log_path, timeout=timeout)
    params = sorted(set(_PARAM_RE.findall(out + "\n" + err)))
    if code == 0:
        return 0, params, f"paramspider discovered {len(params)} parameter name(s)."
    return code, params, f"paramspider finished with code {code}."

