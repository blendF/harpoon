"""Parse Nmap output to extract open ports and services."""
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str

    @property
    def search_term(self) -> str:
        """Term to search in Metasploit (e.g. 'telnet', 'apache 2.4')."""
        s = self.service.lower()
        if self.product:
            s = f"{self.product} {self.version}".strip().lower() or s
        return s or str(self.port)


def parse_nmap_output(text: str) -> list[ServiceInfo]:
    """
    Parse Nmap -sV (and similar) output. Extract port, protocol, state, service name.
    """
    results: list[ServiceInfo] = []
    # Pattern for: "port/tcp  open  service  product version"
    # or "port/tcp  open  service"
    line_re = re.compile(
        r"^\s*(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$",
        re.IGNORECASE,
    )
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "Nmap" in line and "scan" in line.lower():
            continue
        if "PORT" in line and "STATE" in line:  # header line
            continue
        m = line_re.match(line)
        if m and m.group(3).lower() in ("open", "open|filtered"):
            port = int(m.group(1))
            proto = m.group(2).lower()
            state = m.group(3)
            service = (m.group(4) or "").strip()
            rest = (m.group(5) or "").strip()
            product, version = "", ""
            if rest:
                # Try to split product version (e.g. "Apache httpd 2.4.41")
                parts = rest.split(None, 1)
                product = parts[0] if parts else ""
                version = parts[1] if len(parts) > 1 else ""
            results.append(
                ServiceInfo(
                    port=port,
                    protocol=proto,
                    state=state,
                    service=service,
                    product=product,
                    version=version,
                )
            )
    return results


def parse_nmap_report_file(path: str) -> list[ServiceInfo]:
    """Read Nmap log file and return list of ServiceInfo."""
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        return []
    return parse_nmap_output(p.read_text(encoding="utf-8", errors="replace"))
