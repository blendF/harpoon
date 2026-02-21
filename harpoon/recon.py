"""Pre-scan DNS resolution and CDN/WAF detection."""
import ipaddress
import socket
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ReconInfo:
    host: str
    ips: list[str] = field(default_factory=list)
    reverse_dns: dict[str, str] = field(default_factory=dict)
    cdn_name: str = ""
    is_cdn: bool = False

    def summary_lines(self) -> list[str]:
        lines = [f"Host: {self.host}"]
        if self.ips:
            lines.append(f"Resolved IP(s): {', '.join(self.ips)}")
        for ip, rdns in self.reverse_dns.items():
            if rdns and rdns != ip:
                lines.append(f"  {ip} -> {rdns}")
        if self.is_cdn:
            lines.append(f"CDN/WAF detected: {self.cdn_name}")
        else:
            lines.append("CDN/WAF: None detected (direct host)")
        return lines


# Cloudflare IPv4 ranges (AS13335)
_CLOUDFLARE_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

_CLOUDFLARE_NETS = [ipaddress.ip_network(r) for r in _CLOUDFLARE_RANGES]

# Reverse-DNS patterns → CDN name
_RDNS_PATTERNS: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "cloudfront.net": "AWS CloudFront",
    "akamaiedge.net": "Akamai",
    "akamai.net": "Akamai",
    "fastly": "Fastly",
    "incapdns": "Imperva / Incapsula",
    "edgecastcdn": "Edgecast / Verizon",
    "sucuri": "Sucuri WAF",
    "stackpath": "StackPath",
    "azureedge.net": "Azure CDN",
    "googleapis.com": "Google Cloud CDN",
}


def _check_cloudflare_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _CLOUDFLARE_NETS)


def _detect_cdn_from_rdns(rdns: str) -> str:
    """Return CDN name if reverse DNS matches a known pattern, else empty string."""
    rdns_lower = rdns.lower()
    for pattern, name in _RDNS_PATTERNS.items():
        if pattern in rdns_lower:
            return name
    return ""


def dns_lookup(host: str) -> ReconInfo:
    """
    Resolve hostname, perform reverse DNS, and detect CDN/WAF.
    Works with both domain names and raw IPs.
    """
    info = ReconInfo(host=host)

    # Resolve hostname to IP(s)
    try:
        results = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        seen: set[str] = set()
        for _fam, _type, _proto, _canon, (ip, _port) in results:
            if ip not in seen:
                seen.add(ip)
                info.ips.append(ip)
    except socket.gaierror:
        return info

    # Reverse DNS for each resolved IP
    for ip in info.ips:
        try:
            rdns, _, _ = socket.gethostbyaddr(ip)
            info.reverse_dns[ip] = rdns
        except (socket.herror, socket.gaierror, OSError):
            info.reverse_dns[ip] = ""

    # Detect CDN/WAF: check IP ranges first, then reverse DNS
    for ip in info.ips:
        if _check_cloudflare_ip(ip):
            info.is_cdn = True
            info.cdn_name = "Cloudflare"
            return info

    for ip, rdns in info.reverse_dns.items():
        cdn = _detect_cdn_from_rdns(rdns)
        if cdn:
            info.is_cdn = True
            info.cdn_name = cdn
            return info

    return info


def save_recon_log(info: ReconInfo, log_path: Path) -> None:
    """Write DNS recon results to log file."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("\n".join(info.summary_lines()), encoding="utf-8")
