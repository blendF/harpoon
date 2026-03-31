"""Nmap port/service scan; save output to file."""
import os
import ipaddress
import json
from pathlib import Path

from harpoon.config import NMAP_CMD, NMAP_LOG
from harpoon.runner import find_cmd, run_capture

# Common Windows Nmap paths (subprocess may not inherit full PATH)
NMAP_WIN_PATHS = [
    Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Nmap" / "nmap.exe",
    Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Nmap" / "nmap.exe",
]

CDN_RANGES_PATH = Path(__file__).resolve().parent.parent / "data" / "cdn_ranges.json"


def _load_cdn_nets() -> list[ipaddress._BaseNetwork]:
    try:
        data = json.loads(CDN_RANGES_PATH.read_text(encoding="utf-8"))
        nets: list[ipaddress._BaseNetwork] = []
        for ranges in data.values():
            for cidr in ranges:
                try:
                    nets.append(ipaddress.ip_network(cidr))
                except ValueError:
                    continue
        return nets
    except (OSError, json.JSONDecodeError):
        return []


def _is_cdn_ip(ip: str, cdn_nets: list[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in cdn_nets)


def run_nmap(
    target: str | list[str],
    log_path: Path = NMAP_LOG,
    timeout: int = 600,
) -> tuple[int, str, str]:
    """
    Run Nmap against target (IP or hostname). Save output to log_path.
    Returns (returncode, stdout, summary_message).
    """
    cmd = find_cmd("nmap") or find_cmd(NMAP_CMD.split()[0])
    if not cmd:
        cmd = next((str(p) for p in NMAP_WIN_PATHS if p.exists()), None)
    if not cmd:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "Nmap not found. Install Nmap and add to PATH, or set HARPOON_NMAP.",
            encoding="utf-8",
        )
        return -1, "", "Nmap not found; see log."

    if isinstance(target, list):
        raw_hosts = [t.strip() for t in target if t and t.strip()]
    else:
        raw_hosts = [target]
    hosts = [h.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0] for h in raw_hosts]
    hosts = [h for h in hosts if h]

    cdn_nets = _load_cdn_nets()
    filtered = [h for h in hosts if not _is_cdn_ip(h, cdn_nets)]
    if not filtered:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "Nmap skipped: all candidate hosts map to CDN/WAF ranges.",
            encoding="utf-8",
        )
        return 0, "", "Nmap skipped (CDN edge IPs only)."

    argv = [cmd, "-sV", "-sC", "-O", "-v", "--reason"] + filtered
    code, out, err = run_capture(argv, log_path, timeout=timeout)
    msg = "Nmap scan complete." if code == 0 else f"Nmap finished with code {code}."
    return code, out, msg
