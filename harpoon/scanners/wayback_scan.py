"""Historical URL mining via waybackurls + gau + dedup."""
from __future__ import annotations

import subprocess
from pathlib import Path

from harpoon.config import GAU_CMD, GAU_LOG, URO_CMD, URO_LOG, WAYBACKURLS_CMD, WAYBACK_LOG
from harpoon.runner import find_cmd, run_capture


def _wsl_has(tool: str) -> bool:
    try:
        return subprocess.run(["wsl", "which", tool], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def run_waybackurls(domain: str, timeout: int = 120) -> tuple[int, list[str], str]:
    wayback_cmd = find_cmd("waybackurls") or find_cmd(WAYBACKURLS_CMD.split()[0])
    use_wsl = False
    if not wayback_cmd and _wsl_has("waybackurls"):
        use_wsl = True
    if not wayback_cmd and not use_wsl:
        WAYBACK_LOG.parent.mkdir(parents=True, exist_ok=True)
        WAYBACK_LOG.write_text("waybackurls not found.", encoding="utf-8")
        return -1, [], "waybackurls not found; skipped."
    argv = ["wsl", "waybackurls", domain] if use_wsl else [wayback_cmd, domain]
    code, out, err = run_capture(argv, WAYBACK_LOG, timeout=timeout)
    urls = sorted({ln.strip() for ln in out.splitlines() if ln.strip().startswith(("http://", "https://"))})
    return code, urls, f"waybackurls discovered {len(urls)} URL(s)." if code == 0 else f"waybackurls finished with code {code}."


def run_gau(domain: str, timeout: int = 120) -> tuple[int, list[str], str]:
    gau_cmd = find_cmd("gau") or find_cmd(GAU_CMD.split()[0])
    use_wsl = False
    if not gau_cmd and _wsl_has("gau"):
        use_wsl = True
    if not gau_cmd and not use_wsl:
        GAU_LOG.parent.mkdir(parents=True, exist_ok=True)
        GAU_LOG.write_text("gau not found.", encoding="utf-8")
        return -1, [], "gau not found; skipped."
    argv = ["wsl", "gau", domain] if use_wsl else [gau_cmd, domain]
    code, out, err = run_capture(argv, GAU_LOG, timeout=timeout)
    urls = sorted({ln.strip() for ln in out.splitlines() if ln.strip().startswith(("http://", "https://"))})
    return code, urls, f"gau discovered {len(urls)} URL(s)." if code == 0 else f"gau finished with code {code}."


def dedupe_urls(urls: list[str]) -> list[str]:
    # Lightweight internal substitute for uro/anew for portability.
    deduped: list[str] = []
    seen: set[str] = set()
    for u in urls:
        no_frag = u.split("#", 1)[0]
        if no_frag not in seen:
            seen.add(no_frag)
            deduped.append(no_frag)
    URO_LOG.parent.mkdir(parents=True, exist_ok=True)
    URO_LOG.write_text("\n".join(deduped), encoding="utf-8")
    return deduped

