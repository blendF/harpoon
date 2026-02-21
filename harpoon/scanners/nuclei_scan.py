"""Nuclei vulnerability scan with context from Nmap and Gobuster."""
import subprocess
from pathlib import Path

from harpoon.config import (
    GOBUSTER_LOG,
    NMAP_LOG,
    NUCLEI_CMD,
    NUCLEI_LOG,
    NUCLEI_LOCAL,
    NUCLEI_LOCAL_CWD,
    NUCLEI_TARGETS_FILE,
)
from harpoon.nuclei_context import build_nuclei_targets
from harpoon.runner import find_cmd, run_capture


def _find_nuclei() -> str | None:
    """Locate the Nuclei binary: local build → PATH → env override."""
    for root in (NUCLEI_LOCAL, NUCLEI_LOCAL_CWD):
        for name in ("nuclei.exe", "nuclei"):
            p = root / "bin" / name
            if p.exists():
                return str(p)
    return find_cmd("nuclei") or find_cmd(NUCLEI_CMD.split()[0])


def _ensure_templates(cmd: str) -> None:
    """Run -update-templates so first-run users get template data."""
    try:
        subprocess.run(
            [cmd, "-update-templates"],
            capture_output=True,
            timeout=120,
        )
    except Exception:
        pass


def run_nuclei(
    base_url: str,
    host: str,
    log_path: Path = NUCLEI_LOG,
    nmap_log: Path = NMAP_LOG,
    gobuster_log: Path = GOBUSTER_LOG,
    targets_file: Path = NUCLEI_TARGETS_FILE,
    timeout: int = 600,
    is_cdn: bool = False,
) -> tuple[int, str]:
    """
    Run Nuclei with context from Nmap and Gobuster.
    Builds target list (base URL + discovered paths + HTTP ports) and template tags
    from detected services, so Nuclei knows where and what to attack.
    When is_cdn=True, rate-limits requests to avoid WAF blocks.
    """
    cmd = _find_nuclei()
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "Nuclei not found. Install from https://github.com/projectdiscovery/nuclei/releases and add to PATH.",
            encoding="utf-8",
        )
        return -1, "Nuclei not found; see log."

    _ensure_templates(cmd)

    targets, tags = build_nuclei_targets(
        base_url=base_url,
        nmap_log_path=nmap_log,
        gobuster_log_path=gobuster_log,
        host=host,
        targets_file=targets_file,
    )

    argv = [
        cmd,
        "-l", str(targets_file),
        "-severity", "critical,high,medium",
        "-no-interactsh",
        "-stats",
        "-timeout", "30" if is_cdn else "15",
    ]
    if is_cdn:
        argv.extend(["-rl", "50"])
    if tags:
        argv.extend(["-tags", ",".join(tags[:15])])

    cdn_note = f"# CDN/WAF mode: rate-limited to 50 req/s, timeout 30s\n" if is_cdn else ""
    header = (
        f"# Nuclei binary: {cmd}\n"
        f"# Targets ({len(targets)}): {targets_file}\n"
        f"# Tags: {','.join(tags[:10])}\n"
        f"{cdn_note}"
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
        msg = f"Scan complete ({len(targets)} targets, tags: {','.join(tags[:5])})."
    elif code == -1 and "Timeout" in err:
        msg = f"Nuclei timed out after {timeout}s ({len(targets)} targets scanned)."
    else:
        msg = f"Finished with code {code}."
    return code, msg
