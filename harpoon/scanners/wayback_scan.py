"""Historical URL mining via waybackurls + gau + dedup."""
from __future__ import annotations

from pathlib import Path

from harpoon.config import GAU_CMD, GAU_LOG, URO_CMD, URO_LOG, WAYBACKURLS_CMD, WAYBACK_LOG
from harpoon.runner import find_cmd, run_capture


def _run_url_tool(cmd_name: str, arg: str, log_path: Path, timeout: int = 120) -> tuple[int, list[str]]:
    cmd = find_cmd(cmd_name)
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(f"{cmd_name} not found.", encoding="utf-8")
        return -1, []
    code, out, err = run_capture([cmd, arg], log_path, timeout=timeout)
    urls = sorted({ln.strip() for ln in out.splitlines() if ln.strip().startswith(("http://", "https://"))})
    return code, urls


def run_waybackurls(domain: str, timeout: int = 120) -> tuple[int, list[str], str]:
    wayback_cmd = find_cmd("waybackurls") or find_cmd(WAYBACKURLS_CMD.split()[0])
    if not wayback_cmd:
        WAYBACK_LOG.parent.mkdir(parents=True, exist_ok=True)
        WAYBACK_LOG.write_text("waybackurls not found.", encoding="utf-8")
        return -1, [], "waybackurls not found; skipped."
    code, out, err = run_capture([wayback_cmd, domain], WAYBACK_LOG, timeout=timeout)
    urls = sorted({ln.strip() for ln in out.splitlines() if ln.strip().startswith(("http://", "https://"))})
    return code, urls, f"waybackurls discovered {len(urls)} URL(s)." if code == 0 else f"waybackurls finished with code {code}."


def run_gau(domain: str, timeout: int = 120) -> tuple[int, list[str], str]:
    gau_cmd = find_cmd("gau") or find_cmd(GAU_CMD.split()[0])
    if not gau_cmd:
        GAU_LOG.parent.mkdir(parents=True, exist_ok=True)
        GAU_LOG.write_text("gau not found.", encoding="utf-8")
        return -1, [], "gau not found; skipped."
    code, out, err = run_capture([gau_cmd, domain], GAU_LOG, timeout=timeout)
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

