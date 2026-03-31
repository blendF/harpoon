"""Certificate transparency subdomain enumeration via crt.sh API."""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path

from harpoon.config import CRTSH_LOG


def run_crtsh(domain: str, log_path: Path = CRTSH_LOG, timeout: int = 30) -> tuple[int, list[str], str]:
    query = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"

    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Harpoon/Stateful"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw) if raw.strip() else []
        found: set[str] = set()
        for row in data:
            name_val = str(row.get("name_value", "")).lower()
            for token in name_val.splitlines():
                token = token.strip().lstrip("*.")  # normalize wildcard cert entries
                if token and token.endswith(domain.lower()):
                    found.add(token)
        subdomains = sorted(found)
        log_path.write_text(json.dumps({"url": url, "count": len(subdomains), "subdomains": subdomains}, indent=2), encoding="utf-8")
        return 0, subdomains, f"crt.sh discovered {len(subdomains)} certificate subdomain(s)."
    except Exception as exc:
        log_path.write_text(f"crt.sh query failed: {exc}", encoding="utf-8")
        return -1, [], "crt.sh query failed; skipped."

