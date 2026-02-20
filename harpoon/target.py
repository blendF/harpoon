"""Target input: prompt user for IP or domain."""
import re
import socket


def prompt_target() -> str:
    """Prompt for target IP or domain; return stripped non-empty string."""
    while True:
        try:
            raw = input("Enter target IP address or domain name: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            raise SystemExit(0)
        if raw:
            return raw
        print("Please enter a non-empty target.")


def prompt_lhost(default: str | None = None) -> str:
    """
    Prompt for LHOST (attacker IP for reverse shells). Used by Metasploit.
    If empty, use default or auto-detect primary interface IP.
    """
    if default:
        hint = f" [default: {default}]"
    else:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            default = s.getsockname()[0]
            s.close()
            hint = f" [default: {default}]"
        except OSError:
            default = "127.0.0.1"
            hint = f" [default: {default}]"
    try:
        raw = input(f"Enter LHOST for reverse shells{hint} (or press Enter to use default): ").strip()
    except (EOFError, KeyboardInterrupt):
        return default or "127.0.0.1"
    return raw if raw else (default or "127.0.0.1")


def normalize_target(target: str) -> str:
    """Ensure target has a URL scheme for web tools if missing."""
    t = target.strip()
    if not re.match(r"^https?://", t, re.IGNORECASE):
        return f"http://{t}"
    return t


def normalize_target_https(target: str) -> str:
    """Return HTTPS URL for targets that typically use it (domains). Use for tools that need it."""
    t = target.strip()
    if not re.match(r"^https?://", t, re.IGNORECASE):
        return f"https://{t}"
    if t.lower().startswith("http://"):
        t = t.replace("http://", "https://", 1)
    return t


def url_for_web_scan(target: str) -> str:
    """Return base URL for web scanners: strip hash (#), ensure scheme, trailing slash."""
    t = target.strip()
    if not re.match(r"^https?://", t, re.IGNORECASE):
        t = f"https://{t}"
    elif t.lower().startswith("http://"):
        t = t.replace("http://", "https://", 1)
    base = t.split("#")[0].rstrip("/") or t.split("#")[0]
    return base + "/" if base else base
