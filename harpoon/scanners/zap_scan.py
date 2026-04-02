"""OWASP ZAP headless/CLI scan; save output to file."""
import os
from pathlib import Path

from harpoon.config import ZAP_CMD, ZAP_LOG
from harpoon.runner import find_cmd, run_tool

# Common Windows ZAP install path (winget)
ZAP_DIR = Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "ZAP" / "Zed Attack Proxy"
ZAP_WIN_PATHS = [ZAP_DIR / "zap.bat", ZAP_DIR / "ZAP.exe"]


async def run_zap(
    target_url: str,
    log_path: Path = ZAP_LOG,
    timeout: int = 600,
    endpoints: list[str] | None = None,
) -> tuple[int, str]:
    """
    Run OWASP ZAP in headless mode against target_url.
    Saves output to log_path. Returns (returncode, summary_message).
    """
    cmd = find_cmd("zap.sh") or find_cmd("zap.bat") or find_cmd(ZAP_CMD.split()[0])
    if not cmd:
        for p in ZAP_WIN_PATHS:
            if p.exists():
                cmd = str(p)
                break
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "OWASP ZAP not found. Install ZAP and add to PATH, or set HARPOON_ZAP.",
            encoding="utf-8",
        )
        return -1, "OWASP ZAP not found; see log."

    # ZAP headless baseline: -cmd -quickurl URL -quickprogress
    # If endpoint list is provided, scan only high-value discovered endpoints.
    zap_cwd = Path(cmd).parent if Path(cmd).is_file() else None
    targets = [target_url]
    if endpoints:
        targeted = [e for e in endpoints if e.startswith(("http://", "https://"))]
        if targeted:
            targets = targeted[:25]

    aggregate_lines: list[str] = []
    final_code = 0
    per_target_timeout = max(60, timeout // max(len(targets), 1))
    for idx, t in enumerate(targets):
        part_log = log_path.with_name(f"zap_scan_{idx}.txt")
        argv = [cmd, "-cmd", "-quickurl", t, "-quickprogress"]
        code, out, err = await run_tool(argv, part_log, timeout=per_target_timeout, cwd=zap_cwd)
        final_code = code if code != 0 and final_code == 0 else final_code
        aggregate_lines.append(f"## Target: {t}")
        aggregate_lines.append(part_log.read_text(encoding="utf-8", errors="replace"))
        aggregate_lines.append("")

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("\n".join(aggregate_lines), encoding="utf-8", errors="replace")
    msg = (
        f"OWASP ZAP targeted scan complete ({len(targets)} target(s))."
        if final_code == 0
        else f"OWASP ZAP finished with code {final_code}."
    )
    return final_code, msg
