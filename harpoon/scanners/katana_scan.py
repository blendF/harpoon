"""SPA/headless crawling via katana."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from harpoon.config import KATANA_CMD, KATANA_LOG
from harpoon.runner import find_cmd, run_capture_json


def _wsl_has(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def _wsl_path(p: str) -> str:
    p = p.replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def run_katana(targets: list[str], log_path: Path = KATANA_LOG, timeout: int = 420) -> tuple[int, list[str], str]:
    cmd = find_cmd("katana") or find_cmd(KATANA_CMD.split()[0])
    use_wsl = False
    if not cmd and _wsl_has("katana"):
        cmd = "wsl"
        use_wsl = True
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "katana not found. Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest",
            encoding="utf-8",
        )
        return -1, [], "katana not found; skipped."

    if not targets:
        return 0, [], "katana skipped (no targets)."

    input_file = log_path.with_name("katana_input.txt")
    input_file.write_text("\n".join(sorted(set(targets))), encoding="utf-8")
    input_path = _wsl_path(str(input_file)) if use_wsl else str(input_file)
    base_args = ["-list", input_path, "-silent", "-jc", "-jsonl"]
    argv = ["wsl", "katana"] + base_args if use_wsl else [cmd] + base_args
    code, parsed, err = run_capture_json(argv, log_path, timeout=timeout)

    urls: set[str] = set()
    for obj in parsed:
        for key in ("url", "request", "endpoint"):
            v = obj.get(key)
            if isinstance(v, str) and v.startswith(("http://", "https://")):
                urls.add(v)
    if not urls:
        # fallback parse
        try:
            for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    o = json.loads(line)
                    u = o.get("url")
                    if isinstance(u, str) and u.startswith(("http://", "https://")):
                        urls.add(u)
        except Exception:
            pass
    if code == 0:
        return 0, sorted(urls), f"katana discovered {len(urls)} endpoint(s)."
    return code, sorted(urls), f"katana finished with code {code}."

