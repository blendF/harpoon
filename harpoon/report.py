"""Generate Harpoon_Report.md – human-readable, stage-based, actionable findings."""
import json
import re
import html
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

from harpoon.config import FFUF_DIR_LOG, FFUF_PARAMS_LOG, FFUF_VHOST_LOG, GOBUSTER_LOG, NMAP_LOG, NIKTO_LOG, NUCLEI_LOG, RECON_LOG, REPORT_PATH, MSF_LOG, SQLMAP_LOG, ZAP_LOG
from harpoon.ollama_client import ollama_summarize_findings


def _strip_html(text: str) -> str:
    if not text:
        return ""
    s = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(s).strip()


def _parse_zap_failure(text: str) -> str | None:
    """Return human-readable ZAP failure reason if scan failed (503, connection refused, etc.)."""
    t = (text or "").lower()
    if "503" in text and ("response" in t or "code" in t):
        return "Target returned HTTP 503 (Service Unavailable). ZAP could not crawl or attack the site."
    if "failed to attack" in t or "failed to access" in t:
        for code in ("400", "401", "403", "404", "500", "502", "503", "504"):
            if code in text:
                return f"Target returned HTTP {code}. ZAP could not complete the scan."
        return "ZAP could not attack the target URL. Check target availability."
    if "connection refused" in t or "connection reset" in t:
        return "Connection refused or reset. Target may be down or blocking requests."
    return None


def _parse_zap_alerts(text: str) -> list[dict]:
    alerts: list[dict] = []
    start = text.find("<?xml") if "<?xml" in text else text.find("<OWASPZAPReport")
    if start < 0:
        return alerts
    end = text.find("</OWASPZAPReport>")
    if end <= start:
        return alerts
    xml_str = text[start : end + len("</OWASPZAPReport>")]
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return alerts
    seen: set[str] = set()
    for item in root.iter("alertitem"):
        name = (item.findtext("name") or item.findtext("alert") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        risk = (item.findtext("riskdesc") or "").strip()
        sol = _strip_html(item.findtext("solution") or "")
        uris = list({inst.findtext("uri") or "" for inst in item.iter("instance") if inst.findtext("uri")})
        alerts.append({"name": name, "risk": risk, "solution": sol, "uris": uris[:5]})
    return alerts


def _parse_recon_result(text: str) -> tuple[list[str], str, bool]:
    """Return (resolved_ips, cdn_name, is_cdn) from dns_recon.txt."""
    ips: list[str] = []
    cdn_name = ""
    is_cdn = False
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("Resolved IP(s):"):
            ips = [ip.strip() for ip in line.split(":", 1)[1].split(",") if ip.strip()]
        elif line.startswith("CDN/WAF detected:"):
            cdn_name = line.split(":", 1)[1].strip()
            is_cdn = True
    return ips, cdn_name, is_cdn


def _parse_nmap_ports(text: str) -> list[tuple[str, str, str, str]]:
    """Return [(port, proto, service, version_info), ...]"""
    ports: list[tuple[str, str, str, str]] = []
    for m in re.finditer(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(.*)", text):
        svc = m.group(3).split("|")[0].strip()
        version = m.group(4).strip() if m.group(4) else ""
        ports.append((m.group(1), m.group(2), svc, version))
    return ports


_PORT_RISK: dict[str, str] = {
    "21": "FTP may allow anonymous access or cleartext credential interception.",
    "22": "SSH brute-force is common; ensure key-based auth and fail2ban.",
    "23": "Telnet transmits credentials in cleartext — critical risk.",
    "25": "SMTP open relay can be abused for spam/phishing campaigns.",
    "53": "Open DNS resolver can be abused for amplification DDoS attacks.",
    "80": "HTTP (unencrypted) exposes session tokens and user data in transit.",
    "110": "POP3 cleartext — credentials can be sniffed on the network.",
    "135": "MSRPC — common target for Windows lateral movement.",
    "139": "NetBIOS — enables enumeration of shares, users, and system info.",
    "143": "IMAP cleartext — same risk as POP3.",
    "443": "HTTPS — generally safe but check TLS version and cipher suite.",
    "445": "SMB — high-value target for ransomware (EternalBlue/WannaCry).",
    "1433": "MSSQL — database access if credentials are weak or default.",
    "3306": "MySQL — database access if exposed without IP filtering.",
    "3389": "RDP — brute-force and BlueKeep (CVE-2019-0708) risk.",
    "5432": "PostgreSQL — database access if exposed.",
    "5900": "VNC — often runs without authentication.",
    "6379": "Redis — default config allows unauthenticated access.",
    "8080": "HTTP alt — often admin panels or dev servers with weak auth.",
    "8443": "HTTPS alt — check for management interfaces.",
    "27017": "MongoDB — default install has no authentication.",
}


def _parse_sqlmap_result(text: str) -> tuple[str, str]:
    """Return (status, detail) - e.g. ('safe', 'No injection points') or ('at_risk', 'SQLi found')"""
    if "injectable" in text.lower() or "vulnerable" in text.lower():
        return "at_risk", "SQL injection vulnerability detected. Input validation is insufficient."
    if "no usable links" in text.lower():
        return "limited", "No URL parameters or form fields with injectable patterns were discovered during automated crawl. Manual testing of specific input fields recommended."
    return "safe", "No SQL injection vulnerabilities identified in tested parameters."


def _parse_gobuster_result(text: str) -> tuple[str, str]:
    if "gobuster not found" in (text or "").lower():
        return "skipped", "Gobuster was not found. Install from https://github.com/OJ/gobuster/releases (e.g. go install github.com/OJ/gobuster/v3@latest) and add to PATH."
    dirs = re.findall(r"^/(\S+)\s+\(Status:\s*(\d+)\)", text, re.M)
    if dirs:
        paths = ", ".join(f"/{d}" for d, _ in dirs[:20])
        return "findings", f"Discovered {len(dirs)} path(s): {paths}"
    if "503" in (text or "") or "target returned http 503" in (text or "").lower():
        return "limited", "Target returned HTTP 503 for all paths; enumeration was skipped or produced no results. Retry when target is available."
    if "exclude" in (text or "").lower() or "wildcard" in (text or "").lower():
        return "limited", "Server uses redirects or wildcard responses; automated enumeration was constrained."
    return "none", "No additional paths discovered beyond the base URL."


def _parse_nuclei_result(text: str) -> tuple[str, list[str], bool]:
    """Return (status, list of finding lines, nuclei_not_found)."""
    findings: list[str] = []
    t = (text or "").lower()
    nuclei_not_found = "nuclei not found" in t or ("not found" in t and "install" in t and "path" in t)
    for line in (text or "").splitlines():
        line = line.strip()
        if "[" in line and "]" in line and ("CVE-" in line or "critical" in line.lower() or "high" in line.lower() or "medium" in line.lower()):
            findings.append(line[:200])
    if not findings:
        if nuclei_not_found:
            return "skipped", [], True
        return "safe", [], False
    return "findings", findings[:15], False


def _parse_exploitation_result(text: str) -> tuple[str, str]:
    if "not found" in text.lower():
        return "skipped", "Automated exploitation was not performed (framework not available)."
    if "session" in text.lower() or "shell" in text.lower() or "meterpreter" in text.lower():
        return "at_risk", "Possible remote access obtained. Immediate remediation required."
    return "safe", "No successful exploitation; services appear patched or properly configured."


def _parse_nikto_result(text: str) -> tuple[str, list[str]]:
    """Return (status, list_of_findings) from Nikto output."""
    t = (text or "").lower()
    if "nikto not found" in t or ("not found" in t and "install" in t and "path" in t):
        return "skipped", []
    findings: list[str] = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith(("=== stdout", "=== stderr", "# Nikto", "# Target:", "# Command:")):
            continue
        if stripped.startswith("+") and len(stripped) > 2:
            content = stripped[1:].strip()
            if content.startswith("-"):
                content = content[1:].strip()
            if not content:
                continue
            skip_prefixes = ("Target IP:", "Target Hostname:", "Target Port:",
                             "Start Time:", "End Time:", "host(s) tested",
                             "Scan terminated:", "0 host")
            if any(content.startswith(s) for s in skip_prefixes):
                continue
            if "host(s) tested" in content:
                continue
            findings.append(content[:200])
    if findings:
        return "findings", findings[:25]
    return "safe", []


def _parse_ffuf_json(path: Path) -> list[dict]:
    """Load ffuf JSON results from log file."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return data.get("results", [])
    except (json.JSONDecodeError, OSError):
        return []


def _parse_ffuf_dir_result(log_path: Path) -> tuple[str, list[str]]:
    """Return (status, list_of_paths) from ffuf dir JSON."""
    results = _parse_ffuf_json(log_path)
    if not results:
        if log_path.exists():
            try:
                data = json.loads(log_path.read_text(encoding="utf-8", errors="replace"))
                if "error" in data and "not found" in data["error"].lower():
                    return "skipped", []
            except (json.JSONDecodeError, OSError):
                pass
        return "safe", []
    paths = []
    for r in results[:30]:
        url = r.get("url", "")
        status = r.get("status", 0)
        length = r.get("length", 0)
        if url:
            paths.append(f"{url} (Status: {status}, Size: {length})")
    return "findings", paths


def _parse_ffuf_vhost_result(log_path: Path) -> tuple[str, list[str]]:
    """Return (status, list_of_vhosts) from ffuf vhost JSON."""
    results = _parse_ffuf_json(log_path)
    if not results:
        return "safe", []
    vhosts = []
    for r in results[:20]:
        host = r.get("input", {}).get("FUZZ", "") or r.get("host", "")
        status = r.get("status", 0)
        if host:
            vhosts.append(f"{host} (Status: {status})")
    return "findings", vhosts


def _parse_ffuf_params_result(log_path: Path) -> tuple[str, list[str]]:
    """Return (status, list_of_param_descriptions) from ffuf params JSON."""
    results = _parse_ffuf_json(log_path)
    if not results:
        return "safe", []
    params = []
    for r in results[:30]:
        param = r.get("input", {}).get("FUZZ", "")
        mode = r.get("_mode", "GET")
        target = r.get("_target", "")
        status = r.get("status", 0)
        if param:
            params.append(f"{mode} `{param}` on {target} (Status: {status})")
    return "findings", params


def _risk_to_status(risk: str) -> str:
    r = (risk or "").lower()
    if "critical" in r or "high" in r:
        return "At Risk"
    if "medium" in r:
        return "Review Recommended"
    if "low" in r:
        return "Low Priority"
    return "Informational"


_ZAP_IMPACT_MAP: dict[str, str] = {
    "sql injection": "An attacker could read, modify, or delete the entire database, exfiltrate user credentials, and potentially execute OS commands on the database server.",
    "cross site scripting": "An attacker can inject malicious scripts that steal session tokens, redirect users to phishing pages, or perform actions on behalf of authenticated users.",
    "xss": "Session hijacking, credential theft, defacement, and phishing via injected scripts.",
    "remote code execution": "Full server compromise — an attacker can execute arbitrary commands, install backdoors, pivot to internal networks, and exfiltrate all data.",
    "path traversal": "An attacker can read arbitrary files from the server, including configuration files, source code, and credentials (e.g., /etc/passwd, .env).",
    "directory browsing": "Exposed directory listings reveal internal file structure, backup files, and potentially sensitive documents.",
    "csrf": "An attacker can force authenticated users to perform unwanted actions (e.g., change password, transfer funds) without their knowledge.",
    "missing anti-clickjacking": "The page can be embedded in a malicious iframe, tricking users into clicking hidden elements (e.g., 'like' buttons, fund transfers).",
    "x-frame-options": "The page can be embedded in a malicious iframe, tricking users into clicking hidden elements.",
    "content security policy": "Without CSP, the browser cannot prevent inline script injection, increasing XSS impact.",
    "strict-transport-security": "Without HSTS, users can be downgraded from HTTPS to HTTP via MITM, exposing session tokens.",
    "cookie without secure flag": "Session cookies are sent over unencrypted HTTP, allowing session hijacking via network sniffing.",
    "cookie without httponly flag": "Session cookies can be stolen via XSS (document.cookie), enabling session hijacking.",
    "server leaks version": "Knowing the exact server version lets attackers search for known CVEs targeting that version.",
    "information disclosure": "Leaked internal data (stack traces, debug info, version numbers) helps attackers plan targeted exploits.",
    "insecure authentication": "Credentials or session tokens may be intercepted or brute-forced, granting unauthorized access.",
    "open redirect": "Attackers can craft trusted-looking URLs that redirect users to phishing sites to harvest credentials.",
}


def _zap_impact_text(alert_name: str) -> str:
    name_lower = alert_name.lower()
    for key, impact in _ZAP_IMPACT_MAP.items():
        if key in name_lower:
            return impact
    return ""


def _build_sections(
    target: str,
    zap_alerts: list,
    zap_failure: str | None,
    nmap_ports: list,
    nuclei_status: str,
    nuclei_findings: list,
    nuclei_not_found: bool,
    sqlmap_status: str,
    sqlmap_detail: str,
    gobuster_status: str,
    gobuster_detail: str,
    exploit_status: str,
    exploit_detail: str,
    nikto_status: str = "safe",
    nikto_findings: list[str] | None = None,
    ffuf_dir_status: str = "safe",
    ffuf_dir_findings: list[str] | None = None,
    ffuf_vhost_status: str = "safe",
    ffuf_vhost_findings: list[str] | None = None,
    ffuf_params_status: str = "safe",
    ffuf_params_findings: list[str] | None = None,
    recon_ips: list[str] | None = None,
    recon_cdn_name: str = "",
    recon_is_cdn: bool = False,
) -> list[str]:
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    sections = [
        "# Penetration Test Report",
        "",
        f"**Target:** {target}",
        f"**Date:** {date_str}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "This report presents findings from an automated penetration test, organized by phase. "
        "Each finding includes its security impact and recommended actions.",
        "",
        "---",
        "",
        "## Phase 1: Reconnaissance",
        "",
        "### DNS Recon",
        "",
    ]

    if recon_ips:
        sections.append(f"**Resolved IP(s):** {', '.join(recon_ips)}")
        sections.append("")
    else:
        sections.append("*Hostname could not be resolved.*")
        sections.append("")

    if recon_is_cdn:
        sections.append(f"**CDN/WAF Detected:** {recon_cdn_name}")
        sections.append("")
        sections.append(
            f"*The target is behind {recon_cdn_name}. "
            "The origin server IP is hidden. Scan results may be affected by WAF rules "
            "(rate-limiting, request blocking, challenge pages). "
            "Nuclei was rate-limited to avoid being blocked.*"
        )
    else:
        sections.append("**CDN/WAF:** None detected (direct host)")

    sections.append("")
    sections.append("### Network Discovery")
    sections.append("")

    if nmap_ports:
        sections.append("**Open ports and services:**")
        sections.append("")
        sections.append("| Port | Protocol | Service | Version / Details |")
        sections.append("|------|----------|---------|-------------------|")
        for port, proto, svc, ver in nmap_ports[:20]:
            sections.append(f"| {port} | {proto} | {svc} | {ver[:80]} |")
        sections.append("")

        risky_ports = [(p, s, _PORT_RISK[p]) for p, _, s, _ in nmap_ports if p in _PORT_RISK]
        if risky_ports:
            sections.append("**Risk assessment per open port:**")
            sections.append("")
            for port, svc, risk in risky_ports:
                sections.append(f"- **Port {port} ({svc}):** {risk}")
            sections.append("")

        sections.append("*Action:* Close or firewall every port not strictly required. "
                        "For remaining services, enforce strong authentication and keep versions patched.")
    else:
        sections.append("*No open ports identified or scan data unavailable.*")
    sections.append("")
    sections.append("### Path Enumeration (Directory Brute-Force)")
    sections.append("")
    sections.append(f"**Status:** {gobuster_status.replace('_', ' ').title()}")
    sections.append("")
    sections.append(gobuster_detail)
    sections.append("")
    if gobuster_status == "findings":
        sections.append("**Real-world impact:** Exposed paths may reveal admin panels, API endpoints, "
                        "backup files, configuration files (.env, .git), or debug interfaces. "
                        "Each of these can be leveraged for unauthorized access or information disclosure.")
        sections.append("")
        sections.append("*Action:* Review every discovered path. Remove or restrict access to admin panels, "
                        "backup files, and development endpoints. Ensure .git, .env, and config files are not web-accessible.")
    sections.append("")

    if ffuf_dir_status == "skipped":
        sections.append("### ffuf Directory Fuzzing – Not Run")
        sections.append("")
        sections.append("*ffuf was not found. Install from https://github.com/ffuf/ffuf and add to PATH, or set HARPOON_FFUF.*")
        sections.append("")
    elif ffuf_dir_findings:
        sections.append("### Fast Directory/File Fuzzing (ffuf)")
        sections.append("")
        sections.append(f"ffuf discovered {len(ffuf_dir_findings)} additional path(s):")
        sections.append("")
        for f in (ffuf_dir_findings or []):
            sections.append(f"- {f}")
        sections.append("")
    elif ffuf_dir_status == "safe":
        sections.append("### Fast Directory/File Fuzzing (ffuf)")
        sections.append("")
        sections.append("*No additional paths discovered beyond Gobuster results.*")
        sections.append("")

    if ffuf_vhost_findings:
        sections.append("### Virtual Host / Subdomain Discovery (ffuf)")
        sections.append("")
        sections.append(f"ffuf discovered {len(ffuf_vhost_findings)} virtual host(s) / subdomain(s):")
        sections.append("")
        for f in (ffuf_vhost_findings or []):
            sections.append(f"- {f}")
        sections.append("")
        sections.append("**Real-world impact:** Hidden subdomains may host staging/dev environments, "
                        "admin panels, internal APIs, or legacy applications with weaker security controls.")
        sections.append("")
        sections.append("*Action:* Investigate each discovered subdomain. Ensure dev/staging environments "
                        "are not publicly accessible and apply the same security controls as production.")
        sections.append("")
    elif ffuf_vhost_status == "safe":
        sections.append("### Virtual Host / Subdomain Discovery (ffuf)")
        sections.append("")
        sections.append("*No additional virtual hosts or subdomains discovered.*")
        sections.append("")

    sections.append("---")
    sections.append("")
    sections.append("## Phase 2: Web Application Scanning")
    sections.append("")

    if zap_failure:
        sections.append("### OWASP ZAP – Scan Limitation")
        sections.append("")
        sections.append(f"*{zap_failure}*")
        sections.append("")
        sections.append("*Action:* Retry when target is available, or use a different target.")
        sections.append("")

    if zap_alerts:
        at_risk = [a for a in zap_alerts if _risk_to_status(a.get("risk", "")) == "At Risk"]
        review = [a for a in zap_alerts if _risk_to_status(a.get("risk", "")) == "Review Recommended"]
        low = [a for a in zap_alerts if _risk_to_status(a.get("risk", "")) in ("Low Priority", "Informational")]

        if at_risk:
            sections.append("### Critical / High Risk Findings")
            sections.append("")
            for a in at_risk:
                sections.append(f"#### {a['name']}")
                sections.append("")
                sections.append(f"**Severity:** {a.get('risk', 'High')}")
                sections.append("")
                if a.get("uris"):
                    sections.append(f"**Affected endpoints:** {', '.join(a['uris'][:5])}")
                    sections.append("")
                impact = _zap_impact_text(a["name"])
                if impact:
                    sections.append(f"**Real-world impact:** {impact}")
                    sections.append("")
                if a.get("solution"):
                    sections.append(f"**Remediation:** {a['solution'][:500]}")
                    sections.append("")
        if review:
            sections.append("### Medium Risk – Review Recommended")
            sections.append("")
            for a in review:
                sections.append(f"#### {a['name']}")
                sections.append("")
                sections.append(f"**Severity:** {a.get('risk', 'Medium')}")
                sections.append("")
                if a.get("uris"):
                    sections.append(f"**Affected endpoints:** {', '.join(a['uris'][:5])}")
                    sections.append("")
                impact = _zap_impact_text(a["name"])
                if impact:
                    sections.append(f"**Real-world impact:** {impact}")
                    sections.append("")
                if a.get("solution"):
                    sections.append(f"**Remediation:** {a['solution'][:400]}")
                    sections.append("")
        if low:
            sections.append("### Low Priority / Informational")
            sections.append("")
            for a in low[:10]:
                sections.append(f"- {a['name']} — {a.get('risk', 'Info')}")
            if len(low) > 10:
                sections.append(f"- *...and {len(low) - 10} more (see harpoon_logs/zap_report.txt)*")
            sections.append("")
    elif not zap_failure:
        sections.append("*No web vulnerabilities identified or scan data unavailable.*")
        sections.append("")

    if nikto_status == "skipped":
        sections.append("### Nikto – Not Run")
        sections.append("")
        sections.append("*Nikto was not found on PATH. Install from https://github.com/sullo/nikto and add to PATH, or set HARPOON_NIKTO.*")
        sections.append("")
    elif nikto_findings:
        sections.append("### Web Server Findings (Nikto)")
        sections.append("")
        sections.append("Nikto identified the following web server issues:")
        sections.append("")
        for f in (nikto_findings or []):
            sections.append(f"- {f}")
        sections.append("")
        sections.append("*Action:* Review each finding. Update server software, remove default files, "
                        "and disable unnecessary HTTP methods. Restrict server version disclosure in response headers.")
        sections.append("")
    elif nikto_status == "safe":
        sections.append("### Web Server Scanning (Nikto)")
        sections.append("")
        sections.append("*No notable web server misconfigurations or outdated components identified.*")
        sections.append("")

    if ffuf_params_findings:
        sections.append("### Parameter Discovery (ffuf)")
        sections.append("")
        sections.append(f"ffuf discovered {len(ffuf_params_findings)} hidden parameter(s):")
        sections.append("")
        for f in (ffuf_params_findings or []):
            sections.append(f"- {f}")
        sections.append("")
        sections.append("**Real-world impact:** Hidden parameters may accept unvalidated input, "
                        "enabling injection attacks (SQLi, XSS, SSRF, LFI) or exposing debug/admin functionality.")
        sections.append("")
        sections.append("*Action:* Test each discovered parameter for injection vulnerabilities. "
                        "Apply input validation, parameterized queries, and output encoding.")
        sections.append("")
    elif ffuf_params_status == "safe":
        sections.append("### Parameter Discovery (ffuf)")
        sections.append("")
        sections.append("*No hidden parameters discovered on tested pages.*")
        sections.append("")

    if nuclei_not_found:
        sections.append("### Nuclei – Not Run")
        sections.append("")
        sections.append("*Nuclei was not found on PATH. Install from https://github.com/projectdiscovery/nuclei/releases and add to PATH for template-based vulnerability scanning.*")
        sections.append("")

    if nuclei_findings:
        sections.append("### Template-Based Vulnerability Findings (Nuclei)")
        sections.append("")
        sections.append("Nuclei matched the following known vulnerability templates against the target:")
        sections.append("")
        for f in nuclei_findings[:15]:
            sev = "Unknown"
            for s in ("critical", "high", "medium"):
                if s in f.lower():
                    sev = s.capitalize()
                    break
            cve_match = re.search(r"(CVE-\d{4}-\d+)", f)
            cve_id = cve_match.group(1) if cve_match else None
            sections.append(f"- **[{sev}]** {f}")
            if cve_id:
                sections.append(f"  - Reference: https://nvd.nist.gov/vuln/detail/{cve_id}")
            if sev == "Critical":
                sections.append("  - **Impact if exploited:** Full system compromise, data exfiltration, or remote code execution is possible.")
            elif sev == "High":
                sections.append("  - **Impact if exploited:** Significant data exposure, privilege escalation, or service disruption.")
            elif sev == "Medium":
                sections.append("  - **Impact if exploited:** Information leakage or configuration weakness that aids further attacks.")
            sections.append("")
        sections.append("*Action:* Prioritize Critical and High findings for immediate patching. Cross-reference CVE IDs with vendor advisories for specific fix versions.")
        sections.append("")
    elif nuclei_status == "safe" and not nuclei_not_found:
        sections.append("### Template-Based Scanning")
        sections.append("")
        sections.append("*No known CVEs or misconfigurations matched against the target. This does not guarantee safety — manual testing is still recommended.*")
        sections.append("")

    sections.append("---")
    sections.append("")
    sections.append("## Phase 3: Input Validation Testing (SQL Injection)")
    sections.append("")
    sections.append(f"**Status:** {sqlmap_status.replace('_', ' ').title()}")
    sections.append("")
    sections.append(sqlmap_detail)
    sections.append("")
    if sqlmap_status == "at_risk":
        sections.append("**Real-world impact:** A confirmed SQL injection allows an attacker to:")
        sections.append("- Dump the entire database (usernames, passwords, PII, financial records)")
        sections.append("- Bypass authentication and log in as any user including admin")
        sections.append("- Modify or delete data (e.g., deface content, manipulate transactions)")
        sections.append("- In some configurations, execute OS commands on the database server")
        sections.append("")
        sections.append("*Action:* **URGENT** — Implement parameterized queries / prepared statements for ALL database interactions. "
                        "Apply input validation and output encoding. Conduct code review of all data access layers.")
    elif sqlmap_status == "limited":
        sections.append("*Action:* Automated crawl did not find injectable parameters. Manually test input fields "
                        "(search bars, login forms, URL query parameters, API endpoints) for SQL injection. "
                        "Use Burp Suite or manual Sqlmap with specific `-p` parameter targeting.")
    sections.append("")
    sections.append("---")
    sections.append("")
    sections.append("## Phase 4: Exploitation (Metasploit)")
    sections.append("")
    sections.append(f"**Status:** {exploit_status.replace('_', ' ').title()}")
    sections.append("")
    sections.append(exploit_detail)
    sections.append("")
    if exploit_status == "at_risk":
        sections.append("**Real-world impact:** A successful exploit means an attacker achieved remote access to the target system. "
                        "Depending on the payload, this could mean:")
        sections.append("- **Reverse shell / Meterpreter session:** Full interactive command execution on the server")
        sections.append("- **Data exfiltration:** Access to files, databases, environment variables, and secrets")
        sections.append("- **Lateral movement:** Pivot from the compromised host to internal network assets")
        sections.append("- **Persistence:** Install backdoors, create accounts, or modify startup scripts")
        sections.append("")
        sections.append("*Action:* **CRITICAL** — Isolate the affected system immediately. "
                        "Patch the exploited vulnerability, rotate all credentials on the host, "
                        "and conduct forensic analysis to determine if the vulnerability was previously exploited.")
        sections.append("")
    elif exploit_status == "safe":
        sections.append("*No automated exploits succeeded. Services appear patched or properly configured. "
                        "Manual exploitation attempts with custom payloads may still find weaknesses.*")
        sections.append("")
    sections.append("---")
    sections.append("")
    sections.append("## Appendix A: Tools Used")
    sections.append("")
    sections.append("| Tool | Abbreviation | Purpose |")
    sections.append("|------|--------------|---------|")
    sections.append("| Nmap | Network Mapper | Port scan, service detection, OS fingerprint |")
    sections.append("| Gobuster | Dir enum | Directory/file enumeration |")
    sections.append("| OWASP ZAP | ZAP (Zed Attack Proxy) | Web app vulnerability scanning |")
    sections.append("| Sqlmap | SQLi | SQL injection testing |")
    sections.append("| Nuclei | CVE/templates | Template-based vulnerability scanning |")
    sections.append("| ffuf | Fuzz Faster U Fool | Directory, vhost, and parameter fuzzing |")
    sections.append("| Nikto | Web scanner | Web server misconfiguration and vulnerability scanner |")
    sections.append("| Metasploit Framework | MSF | Exploitation framework |")
    sections.append("")
    sections.append("---")
    sections.append("")
    sections.append("## Overall Risk Rating")
    sections.append("")
    high_count = len([a for a in zap_alerts if "high" in (a.get("risk", "")).lower() or "critical" in (a.get("risk", "")).lower()])
    nuclei_crit = len([f for f in nuclei_findings if "critical" in f.lower() or "high" in f.lower()])
    nikto_count = len(nikto_findings or [])
    if exploit_status == "at_risk" or sqlmap_status == "at_risk":
        sections.append("### CRITICAL")
        sections.append("")
        sections.append("Active exploitation was successful or SQL injection was confirmed. "
                        "The target is actively vulnerable to attacks that can result in full data breach, "
                        "system takeover, or service destruction. **Immediate remediation required.**")
    elif high_count > 0 or nuclei_crit > 0:
        sections.append("### HIGH")
        sections.append("")
        sections.append(f"Found {high_count + nuclei_crit} high/critical severity finding(s) across web scanning "
                        "and template-based detection. These vulnerabilities are known to be exploitable "
                        "and should be patched before an attacker discovers them.")
    elif nikto_count > 5:
        sections.append("### HIGH")
        sections.append("")
        sections.append(f"Nikto identified {nikto_count} web server issue(s) including potential misconfigurations, "
                        "outdated software, or dangerous defaults. Review and remediate each finding.")
    elif nmap_ports:
        sections.append("### MEDIUM")
        sections.append("")
        sections.append("No critical vulnerabilities were confirmed, but exposed services increase the attack surface. "
                        "Harden configurations and reduce exposed ports.")
    else:
        sections.append("### LOW")
        sections.append("")
        sections.append("No significant vulnerabilities were identified in this automated assessment. "
                        "Manual penetration testing is recommended for comprehensive coverage.")
    sections.append("")
    sections.append("---")
    sections.append("")
    sections.append("## Appendix B: Raw Logs")
    sections.append("")
    sections.append("Full verbose tool output is stored in `harpoon_logs/` for in-depth technical review:")
    sections.append("")
    sections.append("| Log File | Contents |")
    sections.append("|----------|----------|")
    sections.append("| `nmap_scan.txt` | Port scan, service versions, OS detection, NSE script output |")
    sections.append("| `gobuster_enum.txt` | Directory/file brute-force results with status codes |")
    sections.append("| `zap_report.txt` | OWASP ZAP spider + active scan alerts (XML) |")
    sections.append("| `sqlmap_scan.txt` | SQL injection test payloads, responses, and detection details |")
    sections.append("| `nuclei_scan.txt` | CVE/misconfiguration template matches with severity |")
    sections.append("| `nikto_scan.txt` | Nikto web server scan findings |")
    sections.append("| `ffuf_dir.json` | ffuf directory/file fuzzing results |")
    sections.append("| `ffuf_vhost.json` | ffuf virtual host/subdomain discovery |")
    sections.append("| `ffuf_params.json` | ffuf parameter fuzzing results |")
    sections.append("| `msf_exploit.txt` | Metasploit module execution, session attempts, exploit output |")
    sections.append("| `dns_recon.txt` | DNS resolution, reverse DNS, CDN/WAF detection |")
    sections.append("")
    return sections


def read_excerpt(path: Path, max_chars: int = 8000) -> str:
    if not path.exists():
        return "(No output file found.)"
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars]
    except OSError:
        return "(Error reading file.)"


def generate_report(
    target: str,
    report_path: Path = REPORT_PATH,
    use_ollama: bool = True,
) -> None:
    """Write Harpoon_Report.md – stage-based, human-readable, actionable."""
    recon_text = read_excerpt(RECON_LOG, 10_000) if RECON_LOG.exists() else ""
    zap_text = read_excerpt(ZAP_LOG, 500_000) if ZAP_LOG.exists() else ""
    nmap_text = read_excerpt(NMAP_LOG, 100_000) if NMAP_LOG.exists() else ""
    nuclei_text = read_excerpt(NUCLEI_LOG, 100_000) if NUCLEI_LOG.exists() else ""
    sqlmap_text = read_excerpt(SQLMAP_LOG, 100_000) if SQLMAP_LOG.exists() else ""
    gobuster_text = read_excerpt(GOBUSTER_LOG, 50_000) if GOBUSTER_LOG.exists() else ""
    msf_text = read_excerpt(MSF_LOG, 50_000) if MSF_LOG.exists() else ""
    nikto_text = read_excerpt(NIKTO_LOG, 100_000) if NIKTO_LOG.exists() else ""

    recon_ips, recon_cdn_name, recon_is_cdn = _parse_recon_result(recon_text)
    zap_alerts = _parse_zap_alerts(zap_text)
    zap_failure = _parse_zap_failure(zap_text)
    nmap_ports = _parse_nmap_ports(nmap_text)
    nuclei_status, nuclei_findings, nuclei_not_found = _parse_nuclei_result(nuclei_text)
    sqlmap_status, sqlmap_detail = _parse_sqlmap_result(sqlmap_text)
    gobuster_status, gobuster_detail = _parse_gobuster_result(gobuster_text)
    exploit_status, exploit_detail = _parse_exploitation_result(msf_text)
    nikto_status, nikto_findings = _parse_nikto_result(nikto_text)
    ffuf_dir_status, ffuf_dir_findings = _parse_ffuf_dir_result(FFUF_DIR_LOG)
    ffuf_vhost_status, ffuf_vhost_findings = _parse_ffuf_vhost_result(FFUF_VHOST_LOG)
    ffuf_params_status, ffuf_params_findings = _parse_ffuf_params_result(FFUF_PARAMS_LOG)

    ollama_summary = ""
    if use_ollama:
        log_paths = {"ZAP": ZAP_LOG, "Nuclei": NUCLEI_LOG, "Sqlmap": SQLMAP_LOG, "Gobuster": GOBUSTER_LOG, "Nmap": NMAP_LOG, "Nikto": NIKTO_LOG, "ffuf-dir": FFUF_DIR_LOG, "ffuf-vhost": FFUF_VHOST_LOG, "ffuf-params": FFUF_PARAMS_LOG, "Metasploit": MSF_LOG}
        ollama_summary = ollama_summarize_findings(log_paths)

    sections = _build_sections(
        target, zap_alerts, zap_failure, nmap_ports,
        nuclei_status, nuclei_findings, nuclei_not_found,
        sqlmap_status, sqlmap_detail,
        gobuster_status, gobuster_detail,
        exploit_status, exploit_detail,
        nikto_status=nikto_status,
        nikto_findings=nikto_findings,
        ffuf_dir_status=ffuf_dir_status,
        ffuf_dir_findings=ffuf_dir_findings,
        ffuf_vhost_status=ffuf_vhost_status,
        ffuf_vhost_findings=ffuf_vhost_findings,
        ffuf_params_status=ffuf_params_status,
        ffuf_params_findings=ffuf_params_findings,
        recon_ips=recon_ips,
        recon_cdn_name=recon_cdn_name,
        recon_is_cdn=recon_is_cdn,
    )

    if ollama_summary:
        ai_section = [
            "",
            "---",
            "",
            "## AI-Assisted Analysis (qwen3.5:cloud)",
            "",
            ollama_summary,
            "",
        ]
        for i, s in enumerate(sections):
            if "Overall Risk Rating" in s:
                for j, line in enumerate(ai_section):
                    sections.insert(i + j, line)
                break

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(sections), encoding="utf-8", errors="replace")
