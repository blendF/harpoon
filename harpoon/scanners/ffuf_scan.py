"""ffuf (Fuzz Faster U Fool) scanner: dir/file, vhost, and parameter fuzzing."""
import json
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from harpoon.config import (
    FFUF_CMD,
    FFUF_DIR_LOG,
    FFUF_PARAMS_LOG,
    FFUF_VHOST_LOG,
    GOBUSTER_LOG,
)
from harpoon.runner import find_cmd, run_capture

SUBDOMAINS_WL = Path(__file__).resolve().parent.parent / "wordlists" / "subdomains.txt"
PARAMS_WL = Path(__file__).resolve().parent.parent / "wordlists" / "params.txt"
HARPOON_DIR_WL = Path(__file__).resolve().parent.parent / "wordlist.txt"


def _wsl_has_ffuf() -> bool:
    try:
        r = subprocess.run(["wsl", "which", "ffuf"], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _find_ffuf() -> tuple[list[str], str | None, bool]:
    """Locate ffuf: PATH -> WSL. Returns (argv_prefix, display, uses_wsl)."""
    direct = find_cmd("ffuf") or find_cmd(FFUF_CMD.split()[0])
    if direct:
        return [direct], direct, False
    if _wsl_has_ffuf():
        return ["wsl", "ffuf"], "ffuf (WSL)", True
    return [], None, False


def _wsl_path(win_path: str) -> str:
    """Convert a Windows path to WSL /mnt/ path."""
    p = win_path.replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def _calibrate_response_size(argv_prefix: list[str], url: str, uses_wsl: bool) -> int | None:
    """Make a single request to measure default response size for filtering."""
    try:
        argv = argv_prefix + [
            "-u", url, "-w", "-",
            "-mc", "all", "-t", "1", "-s",
        ]
        r = subprocess.run(
            argv, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=15,
            input="CALIBRATION_PROBE_HARPOON\n",
        )
        for line in r.stdout.strip().splitlines():
            parts = line.split()
            for p in parts:
                if p.isdigit() and int(p) > 0:
                    return int(p)
    except Exception:
        pass
    return None


def _resolve_wordlist(wl_path: Path, uses_wsl: bool) -> str | None:
    """Return wordlist path, converting to WSL path if needed."""
    if not wl_path.exists():
        return None
    s = str(wl_path)
    return _wsl_path(s) if uses_wsl else s


def _parse_ffuf_json(log_path: Path) -> list[dict]:
    """Parse ffuf JSON output and return list of result dicts."""
    if not log_path.exists():
        return []
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)
        return data.get("results", [])
    except (json.JSONDecodeError, KeyError, OSError):
        return []


# ---------------------------------------------------------------------------
# Directory / file fuzzing
# ---------------------------------------------------------------------------

def run_ffuf_dir(
    target_url: str,
    log_path: Path = FFUF_DIR_LOG,
    timeout: int = 300,
    is_cdn: bool = False,
) -> tuple[int, str]:
    """Fuzz directories/files. Returns (returncode, summary_message)."""
    argv_prefix, display, uses_wsl = _find_ffuf()
    if not argv_prefix:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            json.dumps({"error": "ffuf not found. Install ffuf and add to PATH, or set HARPOON_FFUF."}),
            encoding="utf-8",
        )
        return -1, "ffuf not found; see log."

    wl = _resolve_wordlist(HARPOON_DIR_WL, uses_wsl)
    if not wl:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps({"error": "Wordlist not found."}), encoding="utf-8")
        return -1, "ffuf wordlist not found."

    base = target_url.rstrip("/")
    fuzz_url = f"{base}/FUZZ"
    out_path = str(log_path)
    if uses_wsl:
        out_path = _wsl_path(out_path)

    threads = "20" if is_cdn else "50"
    argv = argv_prefix + [
        "-u", fuzz_url, "-w", wl,
        "-mc", "all", "-fc", "404",
        "-t", threads,
        "-o", out_path, "-of", "json",
        "-s",
    ]
    if is_cdn:
        argv.extend(["-rate", "100"])

    log_path.parent.mkdir(parents=True, exist_ok=True)
    code, _out, err = run_capture(argv, log_path.with_suffix(".log"), timeout=timeout)

    results = _parse_ffuf_json(log_path)
    count = len(results)
    if code == 0 or count > 0:
        return 0, f"ffuf dir: {count} path(s) discovered."
    if "Timeout" in err:
        return -1, f"ffuf dir timed out after {timeout}s."
    return code, f"ffuf dir finished with code {code}."


# ---------------------------------------------------------------------------
# Virtual host / subdomain discovery
# ---------------------------------------------------------------------------

def run_ffuf_vhost(
    target_url: str,
    domain: str,
    log_path: Path = FFUF_VHOST_LOG,
    timeout: int = 300,
    is_cdn: bool = False,
) -> tuple[int, str]:
    """Fuzz virtual hosts via Host header. Returns (returncode, summary_message)."""
    argv_prefix, display, uses_wsl = _find_ffuf()
    if not argv_prefix:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            json.dumps({"error": "ffuf not found."}), encoding="utf-8",
        )
        return -1, "ffuf not found; see log."

    wl = _resolve_wordlist(SUBDOMAINS_WL, uses_wsl)
    if not wl:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps({"error": "Subdomain wordlist not found."}), encoding="utf-8")
        return -1, "ffuf subdomain wordlist not found."

    out_path = str(log_path)
    if uses_wsl:
        out_path = _wsl_path(out_path)

    threads = "20" if is_cdn else "40"
    host_header = f"Host: FUZZ.{domain}"

    argv = argv_prefix + [
        "-u", target_url,
        "-H", host_header,
        "-w", wl,
        "-mc", "all",
        "-t", threads,
        "-o", out_path, "-of", "json",
        "-ac",
        "-s",
    ]
    if is_cdn:
        argv.extend(["-rate", "100"])

    log_path.parent.mkdir(parents=True, exist_ok=True)
    code, _out, err = run_capture(argv, log_path.with_suffix(".log"), timeout=timeout)

    results = _parse_ffuf_json(log_path)
    count = len(results)
    if code == 0 or count > 0:
        return 0, f"ffuf vhost: {count} subdomain(s) discovered."
    if "Timeout" in err:
        return -1, f"ffuf vhost timed out after {timeout}s."
    return code, f"ffuf vhost finished with code {code}."


# ---------------------------------------------------------------------------
# Parameter fuzzing (GET + POST)
# ---------------------------------------------------------------------------

def _collect_fuzz_targets(
    base_url: str,
    gobuster_log: Path = GOBUSTER_LOG,
    ffuf_dir_log: Path = FFUF_DIR_LOG,
    max_targets: int = 10,
) -> list[str]:
    """Gather URLs to parameter-fuzz: base URL + top discovered paths."""
    base = base_url.rstrip("/")
    targets: list[str] = [base]

    from harpoon.nuclei_context import parse_gobuster_paths
    if gobuster_log.exists():
        try:
            text = gobuster_log.read_text(encoding="utf-8", errors="replace")
            for p in parse_gobuster_paths(text)[:max_targets]:
                url = f"{base}{p}" if p.startswith("/") else f"{base}/{p}"
                if url not in targets:
                    targets.append(url)
        except OSError:
            pass

    for r in _parse_ffuf_json(ffuf_dir_log):
        u = r.get("url", "")
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
) -> tuple[int, str]:
    """Fuzz GET and POST parameters across discovered pages. Returns (returncode, summary_message)."""
    argv_prefix, display, uses_wsl = _find_ffuf()
    if not argv_prefix:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            json.dumps({"error": "ffuf not found."}), encoding="utf-8",
        )
        return -1, "ffuf not found; see log."

    wl = _resolve_wordlist(PARAMS_WL, uses_wsl)
    if not wl:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps({"error": "Params wordlist not found."}), encoding="utf-8")
        return -1, "ffuf params wordlist not found."

    fuzz_targets = _collect_fuzz_targets(target_url, gobuster_log, ffuf_dir_log, max_targets=5)

    all_results: list[dict] = []
    threads = "20" if is_cdn else "40"
    per_target_timeout = timeout // max(len(fuzz_targets), 1)

    for i, url in enumerate(fuzz_targets):
        for mode_label, fuzz_url, extra_args in [
            ("GET", f"{url}?FUZZ=harpoon", []),
            ("POST", url, ["-X", "POST", "-d", "FUZZ=harpoon"]),
        ]:
            part_log = log_path.with_name(f"ffuf_params_{i}_{mode_label.lower()}.json")
            part_out = str(part_log)
            if uses_wsl:
                part_out = _wsl_path(part_out)

            argv = argv_prefix + [
                "-u", fuzz_url, "-w", wl,
                "-mc", "all",
                "-t", threads,
                "-o", part_out, "-of", "json",
                "-ac",
                "-s",
            ] + extra_args
            if is_cdn:
                argv.extend(["-rate", "100"])

            run_capture(argv, part_log.with_suffix(".log"), timeout=per_target_timeout)

            for r in _parse_ffuf_json(part_log):
                r["_mode"] = mode_label
                r["_target"] = url
                all_results.append(r)

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        json.dumps({"results": all_results, "commandName": "ffuf-params"}, indent=2),
        encoding="utf-8",
    )

    count = len(all_results)
    if count > 0:
        return 0, f"ffuf params: {count} parameter(s) discovered across {len(fuzz_targets)} page(s)."
    return 0, f"ffuf params: no hidden parameters found ({len(fuzz_targets)} page(s) tested)."


# ---------------------------------------------------------------------------
# Helpers for downstream consumers
# ---------------------------------------------------------------------------

def get_ffuf_discovered_paths(log_path: Path = FFUF_DIR_LOG) -> list[str]:
    """Extract discovered URL paths from ffuf dir results."""
    paths: list[str] = []
    for r in _parse_ffuf_json(log_path):
        url = r.get("url", "")
        if url:
            parsed = urlparse(url)
            if parsed.path and parsed.path not in paths:
                paths.append(parsed.path)
    return paths[:50]


def get_ffuf_discovered_vhosts(log_path: Path = FFUF_VHOST_LOG) -> list[str]:
    """Extract discovered vhost names from ffuf vhost results."""
    vhosts: list[str] = []
    for r in _parse_ffuf_json(log_path):
        host = r.get("input", {}).get("FUZZ", "") or r.get("host", "")
        if host and host not in vhosts:
            vhosts.append(host)
    return vhosts[:50]


def get_ffuf_discovered_params(log_path: Path = FFUF_PARAMS_LOG) -> list[dict]:
    """Extract discovered parameters from ffuf params results."""
    params: list[dict] = []
    for r in _parse_ffuf_json(log_path):
        param = r.get("input", {}).get("FUZZ", "")
        if param:
            params.append({
                "param": param,
                "mode": r.get("_mode", "GET"),
                "target": r.get("_target", ""),
                "status": r.get("status", 0),
                "length": r.get("length", 0),
            })
    return params[:100]
