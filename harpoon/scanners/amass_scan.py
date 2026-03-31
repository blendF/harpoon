"""Optional passive+active asset mapping via amass."""
from __future__ import annotations

from pathlib import Path

from harpoon.config import AMASS_CMD, AMASS_LOG
from harpoon.runner import find_cmd, run_capture


def run_amass(domain: str, log_path: Path = AMASS_LOG, timeout: int = 420) -> tuple[int, list[str], str]:
    cmd = find_cmd("amass") or find_cmd(AMASS_CMD.split()[0])
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "amass not found. Install with: go install -v github.com/owasp-amass/amass/v4/...@master",
            encoding="utf-8",
        )
        return -1, [], "amass not found; optional tool skipped."

    argv = [cmd, "enum", "-passive", "-d", domain]
    code, out, err = run_capture(argv, log_path, timeout=timeout)
    subdomains = sorted({ln.strip().lower() for ln in out.splitlines() if ln.strip() and "." in ln})
    if code == 0:
        return 0, subdomains, f"amass discovered {len(subdomains)} subdomain(s)."
    return code, subdomains, f"amass finished with code {code}."

