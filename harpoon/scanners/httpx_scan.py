"""HTTP probing and tech fingerprinting via httpx."""
from __future__ import annotations

import subprocess
from pathlib import Path
from urllib.parse import urlparse

from harpoon.config import HTTPX_CMD, HTTPX_LOG
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


def run_httpx(targets: list[str], log_path: Path = HTTPX_LOG, timeout: int = 300) -> tuple[int, list[dict], str]:
    cmd = find_cmd("httpx") or find_cmd(HTTPX_CMD.split()[0])
    use_wsl = False
    if not cmd and _wsl_has("httpx"):
        cmd = "wsl"
        use_wsl = True
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "httpx not found. Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            encoding="utf-8",
        )
        return -1, [], "httpx not found; skipped."

    if not targets:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("No targets provided to httpx.", encoding="utf-8")
        return 0, [], "httpx skipped (no targets)."

    input_file = log_path.with_name("httpx_input.txt")
    input_file.write_text("\n".join(sorted(set(targets))), encoding="utf-8")
    input_path = _wsl_path(str(input_file)) if use_wsl else str(input_file)
    base_args = [
        "-l", input_path, "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-json",
    ]
    argv = ["wsl", "httpx"] + base_args if use_wsl else [cmd] + base_args

    code, parsed, err = run_capture_json(argv, log_path, timeout=timeout)
    results: list[dict] = []
    for item in parsed:
        url = item.get("url") or item.get("input")
        if not url:
            continue
        parsed_url = urlparse(url)
        host = parsed_url.netloc or parsed_url.path
        techs = item.get("tech", []) or item.get("technologies", [])
        if isinstance(techs, str):
            techs = [techs]
        results.append(
            {
                "url": url,
                "host": host,
                "status_code": item.get("status_code") or item.get("status-code") or 0,
                "title": item.get("title", ""),
                "tech": [str(t) for t in techs],
            }
        )

    if code == 0:
        return 0, results, f"httpx probed {len(results)} live web endpoint(s)."
    return code, results, f"httpx finished with code {code}."

