"""JavaScript endpoint and secret entropy analysis."""
from __future__ import annotations

import asyncio
import math
import re
import urllib.request
from collections import Counter
from pathlib import Path

from harpoon.config import JS_ANALYSIS_LOG


_STRING_RE = re.compile(r"['\"]([A-Za-z0-9_\-\/\+=\.]{12,})['\"]")
_JS_ENDPOINT_RE = re.compile(r"""["'](\/[A-Za-z0-9_\-\/\.\?=&]+)["']""")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _fetch_text(url: str, timeout: int = 10) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Harpoon/Stateful"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


async def analyze_js_urls(js_urls: list[str], log_path: Path = JS_ANALYSIS_LOG) -> tuple[list[str], list[dict], str]:
    discovered_endpoints: set[str] = set()
    potential_secrets: list[dict] = []
    lines: list[str] = []

    for js_url in js_urls[:100]:
        try:
            text = await asyncio.to_thread(_fetch_text, js_url)
        except Exception as exc:
            lines.append(f"[error] {js_url} -> {exc}")
            continue

        for m in _JS_ENDPOINT_RE.finditer(text):
            endpoint = m.group(1).strip()
            if endpoint.startswith("/"):
                discovered_endpoints.add(endpoint)

        for m in _STRING_RE.finditer(text):
            token = m.group(1)
            entropy = shannon_entropy(token)
            if entropy >= 4.5:
                potential_secrets.append(
                    {
                        "url": js_url,
                        "secret_excerpt": token[:120],
                        "entropy": round(entropy, 3),
                    }
                )

    log_path.parent.mkdir(parents=True, exist_ok=True)
    lines.append(f"js_files_scanned={len(js_urls)}")
    lines.append(f"discovered_endpoints={len(discovered_endpoints)}")
    lines.append(f"potential_high_entropy_strings={len(potential_secrets)}")
    for sec in potential_secrets[:50]:
        lines.append(f"[secret] {sec['url']} entropy={sec['entropy']} sample={sec['secret_excerpt']}")
    log_path.write_text("\n".join(lines), encoding="utf-8")
    return sorted(discovered_endpoints), potential_secrets, f"JS analysis found {len(potential_secrets)} potential secret(s)."

