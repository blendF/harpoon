"""Sqlmap scan; save output to file."""
from pathlib import Path

from harpoon.config import GOBUSTER_LOG, SQLMAP_CMD, SQLMAP_LOG, SQLMAP_URLS_FILE
from harpoon.nuclei_context import parse_gobuster_paths
from harpoon.runner import find_cmd, run_capture


def run_sqlmap(
    target_url: str,
    log_path: Path = SQLMAP_LOG,
    gobuster_log: Path | None = GOBUSTER_LOG,
    urls_file: Path = SQLMAP_URLS_FILE,
    timeout: int = 300,
    waf_present: bool = False,
    discovered_params: list[dict] | None = None,
    output_dir: Path | None = None,
) -> tuple[int, str]:
    """
    Run sqlmap against target_url. If gobuster_log exists and has paths,
    also test discovered URLs (base + path) for SQL injection.
    """
    cmd = find_cmd("sqlmap") or find_cmd("sqlmap.py") or find_cmd(SQLMAP_CMD.split()[0])
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "Sqlmap not found. Install sqlmap and add to PATH, or set HARPOON_SQLMAP.",
            encoding="utf-8",
        )
        return -1, "Sqlmap not found; see log."

    base = target_url.rstrip("/")
    urls: list[str] = [base]

    if gobuster_log and gobuster_log.exists():
        try:
            text = gobuster_log.read_text(encoding="utf-8", errors="replace")
            paths = parse_gobuster_paths(text)
            for p in paths[:15]:
                url = f"{base}{p}" if p.startswith("/") else f"{base}/{p}"
                if url not in urls:
                    urls.append(url)
        except OSError:
            pass

    if discovered_params:
        for item in discovered_params[:40]:
            p = item.get("param", "")
            u = item.get("target", "") or base
            if p and u:
                glue = "&" if "?" in u else "?"
                url = f"{u}{glue}{p}=1"
                if url not in urls:
                    urls.append(url)

    if len(urls) > 1:
        urls_file.parent.mkdir(parents=True, exist_ok=True)
        urls_file.write_text("\n".join(urls), encoding="utf-8", errors="replace")
        argv = [
            cmd, "-m", str(urls_file), "--batch",
            "--forms", "--crawl=2", "--level=3", "--risk=2",
            "-v", "3", "--dump-format=CSV",
        ]
    else:
        argv = [
            cmd, "-u", target_url, "--batch",
            "--forms", "--crawl=3", "--level=3", "--risk=2",
            "-v", "3", "--dump-format=CSV",
        ]
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        argv.extend(["--output-dir", str(output_dir)])
    if waf_present:
        argv.extend(["--tamper=space2comment,randomcase"])

    code, out, err = run_capture(argv, log_path, timeout=timeout)
    msg = "Sqlmap scan complete." if code == 0 else f"Sqlmap finished with code {code}."
    return code, msg
