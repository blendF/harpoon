"""Active DNS resolution and wildcard filtering via dnsx."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from harpoon.config import DNSX_CMD, DNSX_LOG
from harpoon.runner import find_cmd, run_tool_json


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


async def run_dnsx(subdomains: list[str], log_path: Path = DNSX_LOG, timeout: int = 240) -> tuple[int, list[dict], str]:
    cmd = find_cmd("dnsx") or find_cmd(DNSX_CMD.split()[0])
    use_wsl = False
    if not cmd and _wsl_has("dnsx"):
        cmd = "wsl"
        use_wsl = True
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "dnsx not found. Install with: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            encoding="utf-8",
        )
        return -1, [], "dnsx not found; skipped."

    input_file = log_path.with_name("dnsx_input.txt")
    input_file.write_text("\n".join(sorted(set(subdomains))), encoding="utf-8")
    input_path = _wsl_path(str(input_file)) if use_wsl else str(input_file)

    base_args = ["-l", input_path, "-silent", "-a", "-resp-only", "-json"]
    if subdomains:
        base_args.extend(["-wd", subdomains[0].split(".", 1)[-1]])
    argv = ["wsl", "dnsx"] + base_args if use_wsl else [cmd] + base_args
    code, parsed, err = await run_tool_json(argv, log_path, timeout=timeout)

    resolved: list[dict] = []
    for item in parsed:
        host = item.get("host") or item.get("input")
        ips = item.get("a") or item.get("ip") or []
        if isinstance(ips, str):
            ips = [ips]
        if host and ips:
            resolved.append({"host": host, "ips": ips})

    # fallback parsing if dnsx emitted plain lines
    if not resolved:
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    obj = json.loads(line)
                    host = obj.get("host") or obj.get("input")
                    ips = obj.get("a") or obj.get("ip") or []
                    if isinstance(ips, str):
                        ips = [ips]
                    if host and ips:
                        resolved.append({"host": host, "ips": ips})
        except OSError:
            pass

    if code == 0:
        return 0, resolved, f"dnsx resolved {len(resolved)} host(s)."
    return code, resolved, f"dnsx finished with code {code}."

