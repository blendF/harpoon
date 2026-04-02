"""Certificate transparency subdomain enumeration via crt.sh API."""
from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

from harpoon.config import CRTSH_LOG
from harpoon.runner import run_tool


async def run_crtsh(domain: str, log_path: Path = CRTSH_LOG, timeout: int = 30) -> tuple[int, list[str], str]:
    query = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    code, raw, err = await run_tool(["curl", "-s", "--max-time", str(timeout), url], log_path, timeout=timeout + 5)
    if code != 0 and "Command not found" in err:
        code, raw, err = await run_tool(["wsl", "curl", "-s", "--max-time", str(timeout), url], log_path, timeout=timeout + 5)
    if code != 0 and not raw.strip():
        log_path.write_text(f"crt.sh query failed: {err}", encoding="utf-8")
        return -1, [], "crt.sh query failed."

    try:
        data = json.loads(raw) if raw.strip() else []
        found: set[str] = set()
        for row in data:
            name_val = str(row.get("name_value", "")).lower()
            for token in name_val.splitlines():
                token = token.strip().lstrip("*.")
                if token and token.endswith(domain.lower()):
                    found.add(token)
        subdomains = sorted(found)
        log_path.write_text(json.dumps({"url": url, "count": len(subdomains), "subdomains": subdomains}, indent=2), encoding="utf-8")
        return 0, subdomains, f"crt.sh discovered {len(subdomains)} certificate subdomain(s)."
    except (json.JSONDecodeError, KeyError) as exc:
        log_path.write_text(f"crt.sh parse error: {exc}\nRaw: {raw[:500]}", encoding="utf-8")
        return -1, [], "crt.sh parse failed."

