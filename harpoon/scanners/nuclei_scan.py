"""Nuclei vulnerability scan with context from Nmap and Gobuster."""
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


def run_nuclei(
    base_url: str,
    host: str,
    log_path: Path = NUCLEI_LOG,
    nmap_log: Path = NMAP_LOG,
    gobuster_log: Path = GOBUSTER_LOG,
    targets_file: Path = NUCLEI_TARGETS_FILE,
    timeout: int = 600,
) -> tuple[int, str]:
    """
    Run Nuclei with context from Nmap and Gobuster.
    Builds target list (base URL + discovered paths + HTTP ports) and template tags
    from detected services, so Nuclei knows where and what to attack.
    """
    cmd = None
    for root in (NUCLEI_LOCAL, NUCLEI_LOCAL_CWD):
        for name in ("nuclei.exe", "nuclei"):
            p = root / "bin" / name
            if p.exists():
                cmd = str(p)
                break
        if cmd:
            break
    if not cmd:
        cmd = find_cmd("nuclei") or find_cmd(NUCLEI_CMD.split()[0])
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "Nuclei not found. Install from https://github.com/projectdiscovery/nuclei/releases and add to PATH.",
            encoding="utf-8",
        )
        return -1, "Nuclei not found; see log."

    targets, tags = build_nuclei_targets(
        base_url=base_url,
        nmap_log_path=nmap_log,
        gobuster_log_path=gobuster_log,
        host=host,
        targets_file=targets_file,
    )

    # -l: target list; -tags: filter by detected tech; -severity: critical,high,medium
    argv = [
        cmd,
        "-l", str(targets_file),
        "-silent",
        "-severity", "critical,high,medium",
    ]
    if tags:
        argv.extend(["-tags", ",".join(tags[:15])])  # Limit tags to avoid overly narrow scan

    code, out, err = run_capture(argv, log_path, timeout=timeout)
    # Prepend context to log for report/audit
    header = f"# Nuclei context: {len(targets)} targets, tags={','.join(tags[:10])}\n# Targets: {targets_file}\n\n"
    try:
        existing = log_path.read_text(encoding="utf-8", errors="replace")
        log_path.write_text(header + existing, encoding="utf-8", errors="replace")
    except OSError:
        pass
    msg = f"Scan complete ({len(targets)} targets, tags: {','.join(tags[:5])}…)." if code == 0 else f"Finished with code {code}."
    return code, msg
