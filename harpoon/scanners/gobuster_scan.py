"""Gobuster directory/file enumeration; save to file, show only completion message."""
import re
from pathlib import Path

from harpoon.config import BASE_DIR, GOBUSTER_CMD, GOBUSTER_LOG, LOG_DIR
from harpoon.runner import find_cmd, run_capture

# Bundled tools path (when Gobuster is in Harpoon/tools/)
GOBUSTER_BUNDLED = BASE_DIR / "tools" / "gobuster.exe"

# Bundled wordlist shipped with Harpoon (harpoon/wordlist.txt)
HARPOON_WORDLIST = Path(__file__).resolve().parent.parent / "wordlist.txt"
COMMON_WORDLIST_LINUX = "/usr/share/wordlists/dirb/common.txt"


def _append_note(log_path: Path, note: str) -> None:
    """Append a note to the log file for report parsing."""
    try:
        existing = log_path.read_text(encoding="utf-8", errors="replace")
        log_path.write_text(existing.rstrip() + "\n\n" + note, encoding="utf-8", errors="replace")
    except OSError:
        pass


def _get_wordlist_path(wordlist: str | None) -> str:
    """Return path to wordlist: explicit arg -> bundled harpoon/wordlist.txt -> Linux default -> tiny fallback."""
    if wordlist and Path(wordlist).exists():
        return wordlist
    if HARPOON_WORDLIST.exists():
        return str(HARPOON_WORDLIST)
    if Path(COMMON_WORDLIST_LINUX).exists():
        return COMMON_WORDLIST_LINUX
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    wl_path = LOG_DIR / "gobuster_wordlist_fallback.txt"
    words = [
        "admin", "login", "api", "static", "assets", "backup", "tmp", "test", "config",
        "dashboard", "user", "users", "auth", "signin", "signup", "register", "account",
        "v1", "v2", "docs", "swagger", "health", "status", "debug",
        "upload", "uploads", "files", "media", "images", "css", "js", "fonts",
        ".git", ".env", "robots.txt", "sitemap.xml",
    ]
    wl_path.write_text("\n".join(words), encoding="utf-8")
    return str(wl_path)


def run_gobuster(
    target_url: str,
    log_path: Path = GOBUSTER_LOG,
    timeout: int = 300,
    wordlist: str | None = None,
) -> tuple[int, str]:
    """
    Run gobuster dir against target. Save full output to log_path.
    Retries with --exclude-length if server uses wildcard responses (same length for 404s).
    """
    cmd = (
        str(GOBUSTER_BUNDLED) if GOBUSTER_BUNDLED.exists()
        else find_cmd("gobuster")
        or find_cmd(GOBUSTER_CMD.split()[0])
    )
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "Gobuster not found. Install gobuster and add to PATH, or set HARPOON_GOBUSTER.",
            encoding="utf-8",
        )
        return -1, "Gobuster not found; see log."

    wl = _get_wordlist_path(wordlist)
    base_argv = [
        cmd, "dir", "-u", target_url, "-w", wl, "-t", "15",
        "-k", "--follow-redirect", "-e",
        "--status-codes-blacklist", "404",
    ]

    def _run(extra_args: list) -> tuple[int, str, str]:
        argv = base_argv + extra_args
        code, out, err = run_capture(argv, log_path, timeout=timeout)
        return code, out, err

    # Run without -q first to capture errors; use -q only if we need cleaner output
    # (gobuster v3 prints wildcard/503 errors to stderr)
    code, out, err = _run([])
    if code == 0:
        return 0, "Enumeration complete."

    # Retry with --exclude-length when server returns same response for all paths (wildcard/SPA/503)
    # Gobuster prints e.g. "503 (Length: 567). Please exclude the response length..."
    combined = f"{out}\n{err}"
    match = re.search(r"\(Length:\s*(\d+)\)|Length:\s*(\d+)", combined)
    length = match.group(1) or match.group(2) if match else None
    if length:
        code2, out2, err2 = _run(["--exclude-length", length])
        if code2 == 0:
            _append_note(log_path, "Note: Server returned same length for all paths; enumeration used --exclude-length.")
            return 0, "Enumeration complete."
        code, out, err = code2, out2, err2

    # If 503 detected, also try excluding that status code (target may be overloaded/down)
    if "503" in combined and "status code" in combined.lower():
        code3, out3, err3 = _run(["--status-codes-blacklist", "404,503"])
        if code3 == 0:
            _append_note(log_path, "Note: Target returned HTTP 503; enumeration completed with excluded responses.")
            return 0, "Enumeration complete (target returned 503; results may be limited)."
        code, out, err = code3, out3, err3

    return code, f"Finished with code {code}. See {log_path}."
