"""Optional visual reconnaissance via gowitness."""
from __future__ import annotations

import subprocess
from pathlib import Path

from harpoon.config import GOWITNESS_CMD, GOWITNESS_LOG, LOG_DIR
from harpoon.runner import find_cmd, run_capture


def _wsl_has(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def run_gowitness(targets: list[str], log_path: Path = GOWITNESS_LOG, timeout: int = 420) -> tuple[int, str]:
    cmd = find_cmd("gowitness") or find_cmd(GOWITNESS_CMD.split()[0])
    use_wsl = False
    if not cmd and _wsl_has("gowitness"):
        cmd = "wsl"
        use_wsl = True
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "gowitness not found. Install with: go install github.com/sensepost/gowitness@latest",
            encoding="utf-8",
        )
        return -1, "gowitness not found; optional phase skipped."

    if not targets:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("No targets provided to gowitness.", encoding="utf-8")
        return 0, "gowitness skipped (no targets)."

    targets_file = log_path.with_name("gowitness_targets.txt")
    targets_file.write_text("\n".join(sorted(set(targets))), encoding="utf-8")
    out_dir = LOG_DIR / "screenshots"
    out_dir.mkdir(parents=True, exist_ok=True)

    argv = [
        cmd,
        "file",
        "-f",
        str(targets_file),
        "--screenshot-path",
        str(out_dir),
    ]
    code, out, err = run_capture(argv, log_path, timeout=timeout)
    if code == 0:
        return 0, f"gowitness captured screenshots for {len(set(targets))} target(s)."
    return code, f"gowitness finished with code {code}."

