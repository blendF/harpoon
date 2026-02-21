"""Nmap port/service scan; save output to file."""
import os
from pathlib import Path

from harpoon.config import NMAP_CMD, NMAP_LOG
from harpoon.runner import find_cmd, run_capture

# Common Windows Nmap paths (subprocess may not inherit full PATH)
NMAP_WIN_PATHS = [
    Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Nmap" / "nmap.exe",
    Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Nmap" / "nmap.exe",
]


def run_nmap(
    target: str,
    log_path: Path = NMAP_LOG,
    timeout: int = 600,
) -> tuple[int, str, str]:
    """
    Run Nmap against target (IP or hostname). Save output to log_path.
    Returns (returncode, stdout, summary_message).
    """
    cmd = find_cmd("nmap") or find_cmd(NMAP_CMD.split()[0])
    if not cmd:
        cmd = next((str(p) for p in NMAP_WIN_PATHS if p.exists()), None)
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "Nmap not found. Install Nmap and add to PATH, or set HARPOON_NMAP.",
            encoding="utf-8",
        )
        return -1, "", "Nmap not found; see log."

    # Strip URL scheme if present for Nmap
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    argv = [cmd, "-sV", "-sC", "-O", "-v", "--reason", host]
    code, out, err = run_capture(argv, log_path, timeout=timeout)
    msg = "Nmap scan complete." if code == 0 else f"Nmap finished with code {code}."
    return code, out, msg
