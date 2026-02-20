"""OWASP ZAP headless/CLI scan; save output to file."""
import os
from pathlib import Path

from harpoon.config import ZAP_CMD, ZAP_LOG
from harpoon.runner import find_cmd, run_capture

# Common Windows ZAP install path (winget)
ZAP_DIR = Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "ZAP" / "Zed Attack Proxy"
ZAP_WIN_PATHS = [ZAP_DIR / "zap.bat", ZAP_DIR / "ZAP.exe"]


def run_zap(target_url: str, log_path: Path = ZAP_LOG, timeout: int = 600) -> tuple[int, str]:
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

    # ZAP headless baseline: -cmd -quickurl URL -quickout report
    # zap.bat must run from ZAP dir so java -jar zap-*.jar finds the JAR
    zap_cwd = Path(cmd).parent if Path(cmd).is_file() else None
    argv = [cmd, "-cmd", "-quickurl", target_url, "-quickprogress"]
    code, out, err = run_capture(argv, log_path, timeout=timeout, cwd=zap_cwd)
    msg = "OWASP ZAP scan complete." if code == 0 else f"OWASP ZAP finished with code {code}."
    return code, msg
