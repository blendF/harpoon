"""Active hidden parameter discovery via arjun."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from harpoon.config import ARJUN_CMD, ARJUN_LOG
from harpoon.runner import find_cmd, run_capture


def _wsl_has(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def run_arjun(urls: list[str], log_path: Path = ARJUN_LOG, timeout: int = 360) -> tuple[int, list[str], str]:
    cmd = find_cmd("arjun") or find_cmd(ARJUN_CMD.split()[0])
    use_wsl = False
    if not cmd and _wsl_has("arjun"):
        use_wsl = True
    if not cmd and not use_wsl:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("arjun not found. Install with: pip install arjun", encoding="utf-8")
        return -1, [], "arjun not found; skipped."

    if not urls:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("No URLs provided to arjun.", encoding="utf-8")
        return 0, [], "arjun skipped (no URLs)."

    # Arjun is commonly run one URL at a time; keep it deterministic and resilient.
    all_params: set[str] = set()
    logs: list[str] = []
    per_target_timeout = max(30, timeout // max(len(urls), 1))
    final_code = 0

    for idx, url in enumerate(urls[:20]):
        part_json = log_path.with_name(f"arjun_{idx}.json")
        argv = ["wsl", "arjun", "-u", url, "-oJ", str(part_json), "--passive"] if use_wsl else [cmd, "-u", url, "-oJ", str(part_json), "--passive"]
        code, out, err = run_capture(argv, part_json.with_suffix(".log"), timeout=per_target_timeout)
        if code != 0 and final_code == 0:
            final_code = code
        logs.append(f"# URL: {url}\n{out}\n{err}")
        if part_json.exists():
            try:
                data = json.loads(part_json.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict):
                    for vals in data.values():
                        if isinstance(vals, list):
                            for p in vals:
                                if isinstance(p, str) and p:
                                    all_params.add(p)
            except json.JSONDecodeError:
                pass

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("\n\n".join(logs), encoding="utf-8")
    if final_code == 0:
        return 0, sorted(all_params), f"arjun discovered {len(all_params)} hidden parameter(s)."
    return final_code, sorted(all_params), f"arjun finished with code {final_code}."

