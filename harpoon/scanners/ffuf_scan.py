"""ffuf scanner wrappers for directory, vhost, and parameter fuzzing."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from harpoon.config import FFUF_CMD, FFUF_DIR_LOG, FFUF_PARAMS_LOG, FFUF_VHOST_LOG, GOBUSTER_LOG
from harpoon.runner import find_cmd, run_capture

SUBDOMAINS_WL = Path(__file__).resolve().parent.parent / "wordlists" / "subdomains.txt"
PARAMS_WL = Path(__file__).resolve().parent.parent / "wordlists" / "params.txt"
HARPOON_DIR_WL = Path(__file__).resolve().parent.parent / "wordlist.txt"
ADMIN_DIR_WL = Path(__file__).resolve().parent.parent / "wordlists" / "params.txt"


def _wsl_has_ffuf() -> bool:
    try:
        r = subprocess.run(["wsl", "which", "ffuf"], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _find_ffuf() -> tuple[list[str], str | None, bool]:
    direct = find_cmd("ffuf") or find_cmd(FFUF_CMD.split()[0])
    if direct:
        return [direct], direct, False
    if _wsl_has_ffuf():
        return ["wsl", "ffuf"], "ffuf (WSL)", True
    return [], None, False


def _wsl_path(win_path: str) -> str:
    p = win_path.replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def _resolve_wordlist(wl_path: Path, uses_wsl: bool) -> str | None:
    if not wl_path.exists():
        return None
    s = str(wl_path)
    return _wsl_path(s) if uses_wsl else s


def _parse_ffuf_json(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    try:
        data = json.loads(log_path.read_text(encoding="utf-8", errors="replace"))
        return data.get("results", [])
    except (json.JSONDecodeError, KeyError, OSError):
        return []


def _select_dir_wordlist(technology_tags: list[str] | None) -> Path:
    """Tech-aware wordlist selection, defaulting to bundled generic list."""
    tags = {t.lower() for t in (technology_tags or [])}
    if "java" in tags or "tomcat" in tags:
        # Keep current bundle-only behavior while preserving extension point.
        return HARPOON_DIR_WL
    if "php" in tags or "wordpress" in tags:
        return HARPOON_DIR_WL
    return HARPOON_DIR_WL


def _ffuf_rate_args(is_waf: bool) -> list[str]:
    # Proposal mandates strict WAF-safe mode.
    return ["-rate", "2", "-fs", "42,0"] if is_waf else []


def run_ffuf_dir(
    target_url: str,
    log_path: Path = FFUF_DIR_LOG,
    timeout: int = 300,
    is_cdn: bool = False,
    technology_tags: list[str] | None = None,
) -> tuple[int, str]:
    argv_prefix, _, uses_wsl = _find_ffuf()
    if not argv_prefix:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps({"error": "ffuf not found."}), encoding="utf-8")
        return -1, "ffuf not found; see log."

    wl = _resolve_wordlist(_select_dir_wordlist(technology_tags), uses_wsl)
    if not wl:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps({"error": "ffuf dir wordlist not found."}), encoding="utf-8")
        return -1, "ffuf dir wordlist not found."

    base = target_url.rstrip("/")
    out_path = _wsl_path(str(log_path)) if uses_wsl else str(log_path)
    threads = "10" if is_cdn else "50"
    argv = argv_prefix + [
        "-u",
        f"{base}/FUZZ",
        "-w",
        wl,
        "-mc",
        "200,204,301,302,403",
        "-t",
        threads,
        "-o",
        out_path,
        "-of",
        "json",
        "-s",
    ]
    argv.extend(_ffuf_rate_args(is_cdn))
    code, _out, err = run_capture(argv, log_path.with_suffix(".log"), timeout=timeout)
    count = len(_parse_ffuf_json(log_path))
    if code == 0 or count > 0:
        return 0, f"ffuf dir: {count} path(s) discovered."
    return code, "ffuf dir timed out." if "Timeout" in err else f"ffuf dir finished with code {code}."


def run_ffuf_vhost(
    target_url: str,
    domain: str,
    log_path: Path = FFUF_VHOST_LOG,
    timeout: int = 300,
    is_cdn: bool = False,
) -> tuple[int, str]:
    argv_prefix, _, uses_wsl = _find_ffuf()
    if not argv_prefix:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps({"error": "ffuf not found."}), encoding="utf-8")
        return -1, "ffuf not found; see log."

    wl = _resolve_wordlist(SUBDOMAINS_WL, uses_wsl)
    if not wl:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps({"error": "Subdomain wordlist not found."}), encoding="utf-8")
        return -1, "ffuf subdomain wordlist not found."

    out_path = _wsl_path(str(log_path)) if uses_wsl else str(log_path)
    threads = "10" if is_cdn else "40"
    argv = argv_prefix + [
        "-u",
        target_url,
        "-H",
        f"Host: FUZZ.{domain}",
        "-w",
        wl,
        "-mc",
        "200,204,301,302,403",
        "-t",
        threads,
        "-o",
        out_path,
        "-of",
        "json",
        "-ac",
        "-s",
    ]
    argv.extend(_ffuf_rate_args(is_cdn))
    code, _out, err = run_capture(argv, log_path.with_suffix(".log"), timeout=timeout)
    count = len(_parse_ffuf_json(log_path))
    if code == 0 or count > 0:
        return 0, f"ffuf vhost: {count} subdomain(s) discovered."
    return code, "ffuf vhost timed out." if "Timeout" in err else f"ffuf vhost finished with code {code}."


def _collect_fuzz_targets(
    base_url: str,
    gobuster_log: Path = GOBUSTER_LOG,
    ffuf_dir_log: Path = FFUF_DIR_LOG,
    seeded_urls: list[str] | None = None,
    max_targets: int = 20,
) -> list[str]:
    base = base_url.rstrip("/")
    targets: list[str] = [base]
    if seeded_urls:
        for u in seeded_urls:
            if u not in targets:
                targets.append(u)
    try:
        from harpoon.nuclei_context import parse_gobuster_paths
        if gobuster_log.exists():
            text = gobuster_log.read_text(encoding="utf-8", errors="replace")
            for p in parse_gobuster_paths(text):
                u = f"{base}{p}" if p.startswith("/") else f"{base}/{p}"
                if u not in targets:
                    targets.append(u)
    except Exception:
        pass
    for row in _parse_ffuf_json(ffuf_dir_log):
        u = row.get("url", "")
        if u and u not in targets:
            targets.append(u)
        if len(targets) >= max_targets:
            break
    return targets[:max_targets]


def run_ffuf_params(
    target_url: str,
    log_path: Path = FFUF_PARAMS_LOG,
    gobuster_log: Path = GOBUSTER_LOG,
    ffuf_dir_log: Path = FFUF_DIR_LOG,
    timeout: int = 300,
    is_cdn: bool = False,
    seeded_urls: list[str] | None = None,
) -> tuple[int, str]:
    argv_prefix, _, uses_wsl = _find_ffuf()
    if not argv_prefix:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps({"error": "ffuf not found."}), encoding="utf-8")
        return -1, "ffuf not found; see log."

    wl = _resolve_wordlist(PARAMS_WL, uses_wsl)
    if not wl:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps({"error": "Params wordlist not found."}), encoding="utf-8")
        return -1, "ffuf params wordlist not found."

    targets = _collect_fuzz_targets(target_url, gobuster_log, ffuf_dir_log, seeded_urls=seeded_urls, max_targets=10)
    threads = "10" if is_cdn else "40"
    per_target_timeout = max(20, timeout // max(len(targets), 1))
    all_results: list[dict] = []

    for idx, url in enumerate(targets):
        for mode, fuzz_url, extra in [
            ("GET", f"{url}?FUZZ=harpoon", []),
            ("POST", url, ["-X", "POST", "-d", "FUZZ=harpoon"]),
        ]:
            part_json = log_path.with_name(f"ffuf_params_{idx}_{mode.lower()}.json")
            out_path = _wsl_path(str(part_json)) if uses_wsl else str(part_json)
            argv = argv_prefix + [
                "-u",
                fuzz_url,
                "-w",
                wl,
                "-mc",
                "200,204,301,302,403",
                "-t",
                threads,
                "-o",
                out_path,
                "-of",
                "json",
                "-ac",
                "-s",
            ] + extra
            argv.extend(_ffuf_rate_args(is_cdn))
            run_capture(argv, part_json.with_suffix(".log"), timeout=per_target_timeout)
            for row in _parse_ffuf_json(part_json):
                row["_mode"] = mode
                row["_target"] = url
                all_results.append(row)

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(json.dumps({"results": all_results, "commandName": "ffuf-params"}, indent=2), encoding="utf-8")
    if all_results:
        return 0, f"ffuf params: {len(all_results)} parameter(s) discovered across {len(targets)} page(s)."
    return 0, f"ffuf params: no hidden parameters found ({len(targets)} page(s) tested)."


def get_ffuf_discovered_paths(log_path: Path = FFUF_DIR_LOG) -> list[str]:
    paths: list[str] = []
    for row in _parse_ffuf_json(log_path):
        url = row.get("url", "")
        if url:
            p = urlparse(url).path
            if p and p not in paths:
                paths.append(p)
    return paths[:100]


def get_ffuf_discovered_vhosts(log_path: Path = FFUF_VHOST_LOG) -> list[str]:
    vhosts: list[str] = []
    for row in _parse_ffuf_json(log_path):
        host = row.get("input", {}).get("FUZZ", "") or row.get("host", "")
        if host and host not in vhosts:
            vhosts.append(host)
    return vhosts[:100]


def get_ffuf_discovered_params(log_path: Path = FFUF_PARAMS_LOG) -> list[dict]:
    out: list[dict] = []
    for row in _parse_ffuf_json(log_path):
        p = row.get("input", {}).get("FUZZ", "")
        if p:
            out.append(
                {
                    "param": p,
                    "mode": row.get("_mode", "GET"),
                    "target": row.get("_target", ""),
                    "status": row.get("status", 0),
                    "length": row.get("length", 0),
                }
            )
    return out[:300]
