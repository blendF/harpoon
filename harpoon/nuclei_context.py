"""
Build Nuclei scan context from Nmap, Gobuster, and target URL.
Provides target URLs and template tags so Nuclei knows where and what to attack.
"""
import re
from pathlib import Path

from harpoon.parsers.nmap_parser import ServiceInfo, parse_nmap_report_file

# Map Nmap service/product names to Nuclei template tags (lowercase)
# See: nuclei -tl (list tags) or https://github.com/projectdiscovery/nuclei-templates
SERVICE_TO_TAGS: dict[str, list[str]] = {
    "apache": ["apache", "httpd"],
    "httpd": ["apache", "httpd"],
    "nginx": ["nginx"],
    "tomcat": ["tomcat", "java"],
    "jetty": ["jetty", "java"],
    "jboss": ["jboss", "java"],
    "weblogic": ["weblogic", "java"],
    "iis": ["iis", "microsoft"],
    "cloudflare": ["cloudflare", "cdn"],
    "wordpress": ["wordpress", "cms"],
    "joomla": ["joomla", "cms"],
    "drupal": ["drupal", "cms"],
    "php": ["php"],
    "node": ["node", "nodejs"],
    "express": ["express", "nodejs"],
    "flask": ["flask", "python"],
    "django": ["django", "python"],
    "rails": ["rails", "ruby"],
    "spring": ["spring", "java"],
    "elasticsearch": ["elasticsearch"],
    "kibana": ["kibana"],
    "grafana": ["grafana"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "jira": ["jira"],
    "confluence": ["confluence"],
    "redis": ["redis"],
    "mysql": ["mysql", "database"],
    "postgresql": ["postgresql", "postgres", "database"],
    "mongodb": ["mongodb", "database"],
    "ssh": ["ssh"],
    "ftp": ["ftp"],
    "smtp": ["smtp", "mail"],
    "rdp": ["rdp", "microsoft"],
}


def _tags_for_service(svc: ServiceInfo) -> list[str]:
    """Return Nuclei tags for a given Nmap service."""
    tags: set[str] = set()
    combined = f"{svc.service} {svc.product} {svc.version}".lower()
    for key, tag_list in SERVICE_TO_TAGS.items():
        if key in combined:
            tags.update(tag_list)
    if not tags and (svc.service in ("http", "https", "ssl") or "http" in svc.service):
        tags.add("generic")
    return sorted(tags)


def get_http_urls_from_nmap(
    host: str,
    services: list[ServiceInfo],
    use_https: bool = True,
) -> list[str]:
    """
    Build HTTP(S) URLs from Nmap services.
    Only includes ports that typically serve web content.
    """
    urls: list[str] = []
    scheme = "https" if use_https else "http"
    http_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000}
    http_services = {"http", "https", "ssl", "http-proxy", "http-alt", "ssl/http"}

    for svc in services:
        if svc.protocol != "tcp":
            continue
        svc_lower = svc.service.lower()
        is_http = (
            svc.port in http_ports
            or svc_lower in http_services
            or "http" in svc_lower
            or "ssl" in svc_lower
        )
        if not is_http:
            continue
        if svc.port == 443 or (svc.port == 80 and use_https):
            url = f"https://{host}:{svc.port}"
        elif svc.port == 80:
            url = f"http://{host}:{svc.port}"
        else:
            url = f"{scheme}://{host}:{svc.port}"
        if url not in urls:
            urls.append(url)
    return urls


def parse_gobuster_paths(text: str) -> list[str]:
    """
    Extract discovered paths from Gobuster output.
    Supports: "/path (Status: 200)" and "path (Status: 200) [Size: 123]"
    """
    paths: list[str] = []
    for m in re.finditer(r"(?:^|\s)(/?)(\S+?)\s+\(Status:\s*\d+\)", text):
        prefix, path = m.group(1), m.group(2)
        p = f"/{path}" if not path.startswith("/") else path
        if p not in paths and not p.startswith("//"):
            paths.append(p)
    return paths[:50]  # Limit to avoid huge target list


def build_nuclei_targets(
    base_url: str,
    nmap_log_path: Path,
    gobuster_log_path: Path,
    host: str,
    targets_file: Path,
) -> tuple[list[str], list[str]]:
    """
    Build Nuclei target list and template tags from recon data.
    Returns (list of target URLs, list of template tags).
    """
    base_url = base_url.rstrip("/")
    targets: set[str] = {base_url}
    all_tags: set[str] = {"cve", "generic"}

    # Add base URL paths from Gobuster
    if gobuster_log_path.exists():
        gob_text = gobuster_log_path.read_text(encoding="utf-8", errors="replace")
        paths = parse_gobuster_paths(gob_text)
        for p in paths:
            targets.add(f"{base_url}{p}" if p.startswith("/") else f"{base_url}/{p}")

    # Add HTTP URLs from Nmap (prioritize non-standard ports to avoid duplicate scans)
    services = parse_nmap_report_file(str(nmap_log_path))
    nmap_urls = get_http_urls_from_nmap(host, services)
    for u in nmap_urls:
        targets.add(u)

    # Map services to Nuclei tags
    for svc in services:
        all_tags.update(_tags_for_service(svc))

    # Write targets file
    targets_file.parent.mkdir(parents=True, exist_ok=True)
    targets_file.write_text("\n".join(sorted(targets)), encoding="utf-8", errors="replace")

    return list(sorted(targets)), sorted(all_tags)
