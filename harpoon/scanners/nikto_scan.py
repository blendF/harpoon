"""Nikto web server scanner; save output to file."""
import os
import subprocess
from pathlib import Path

from harpoon.config import NIKTO_CMD, NIKTO_LOCAL, NIKTO_LOCAL_CWD, NIKTO_LOG
from harpoon.runner import find_cmd, run_capture

NIKTO_WIN_PATHS = [
    Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Nikto" / "nikto.pl",
    Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Nikto" / "nikto.pl",
]


def _wsl_has_nikto() -> bool:
    """Check if WSL has nikto available."""
    try:
        r = subprocess.run(
            ["wsl", "which", "nikto"],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


def _find_nikto() -> tuple[list[str], str | None, bool]:
    """Locate Nikto: PATH → local project copy (with Perl) → Windows paths → WSL.

    Returns (argv_prefix, display_name, uses_wsl).
    """
    # 1. Directly on PATH (Linux / Kali / manually added)
    direct = find_cmd("nikto") or find_cmd("nikto.pl") or find_cmd(NIKTO_CMD.split()[0])
    if direct:
        return [direct], direct, False

    # 2. Local project copy (nikto/program/nikto.pl alongside Harpoon) — requires native Perl
    perl = find_cmd("perl")
    if perl:
        for root in (NIKTO_LOCAL, NIKTO_LOCAL_CWD):
            script = root / "nikto.pl"
            if script.exists():
                return [perl, str(script)], str(script), False

    # 3. Common Windows install paths
    for p in NIKTO_WIN_PATHS:
        if p.exists():
            if perl:
                return [perl, str(p)], str(p), False
            return [str(p)], str(p), False

    # 4. WSL fallback — nikto installed inside WSL
    if _wsl_has_nikto():
        return ["wsl", "nikto"], "nikto (WSL)", True

    return [], None, False


def run_nikto(
    target_url: str,
    log_path: Path = NIKTO_LOG,
    timeout: int = 600,
) -> tuple[int, str]:
    """
    Run Nikto against target_url.
    Saves output to log_path. Returns (returncode, summary_message).
    """
    argv_prefix, display, uses_wsl = _find_nikto()
    if not argv_prefix:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "Nikto not found. Install Nikto and add to PATH, or set HARPOON_NIKTO.\n"
            "Download: https://github.com/sullo/nikto",
            encoding="utf-8",
        )
        return -1, "Nikto not found; see log."

    argv = argv_prefix + ["-h", target_url, "-nointeractive", "-C", "all"]

    via = " (via WSL)" if uses_wsl else ""
    header = (
        f"# Nikto: {display}{via}\n"
        f"# Target: {target_url}\n"
        f"# Command: {' '.join(argv)}\n\n"
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(header, encoding="utf-8")

    code, out, err = run_capture(argv, log_path, timeout=timeout)

    try:
        existing = log_path.read_text(encoding="utf-8", errors="replace")
        log_path.write_text(header + existing, encoding="utf-8", errors="replace")
    except OSError:
        pass

    if code == 0:
        msg = "Nikto scan complete."
    elif code == -1 and "Timeout" in err:
        msg = f"Nikto timed out after {timeout}s."
    else:
        msg = f"Nikto finished with code {code}."
    return code, msg
