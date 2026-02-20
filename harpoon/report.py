"""Generate Harpoon_Report.md – human-readable, stage-based, actionable findings."""
import re
import html
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

from harpoon.config import GOBUSTER_LOG, NMAP_LOG, NUCLEI_LOG, REPORT_PATH, MSF_LOG, SQLMAP_LOG, ZAP_LOG
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


def _parse_nmap_ports(text: str) -> list[tuple[str, str, str]]:
    """Return [(port, proto, service), ...]"""
    ports: list[tuple[str, str, str]] = []
    for m in re.finditer(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", text):
        ports.append((m.group(1), m.group(2), m.group(3).split("|")[0].strip()))
    return ports


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


def _risk_to_status(risk: str) -> str:
    r = (risk or "").lower()
    if "critical" in r or "high" in r:
        return "At Risk"
    if "medium" in r:
        return "Review Recommended"
    if "low" in r:
        return "Low Priority"
    return "Informational"


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
        "### Network Discovery",
        "",
    ]

    if nmap_ports:
        sections.append("**Open ports and services:**")
        sections.append("")
        sections.append("| Port | Protocol | Service |")
        sections.append("|------|----------|---------|")
        for port, proto, svc in nmap_ports[:15]:
            sections.append(f"| {port} | {proto} | {svc} |")
        sections.append("")
        sections.append("*Action:* Ensure only necessary ports are exposed. Close or restrict access to unused services.")
    else:
        sections.append("*No open ports identified or scan data unavailable.*")
    sections.append("")
    sections.append("### Path Enumeration")
    sections.append("")
    sections.append(f"**Status:** {gobuster_status.replace('_', ' ').title()}")
    sections.append("")
    sections.append(gobuster_detail)
    sections.append("")
    if gobuster_status == "findings":
        sections.append("*Action:* Review discovered paths for sensitive or unintended exposure.")
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
            sections.append("### At Risk")
            sections.append("")
            for a in at_risk:
                sections.append(f"- **{a['name']}**")
                if a.get("uris"):
                    sections.append(f"  - Affected: {', '.join(a['uris'][:3])}")
                if a.get("solution"):
                    sections.append(f"  - *Remediation:* {a['solution'][:400]}")
                sections.append("")
        if review:
            sections.append("### Review Recommended")
            sections.append("")
            for a in review:
                sections.append(f"- **{a['name']}**")
                if a.get("uris"):
                    sections.append(f"  - Affected: {', '.join(a['uris'][:3])}")
                if a.get("solution"):
                    sections.append(f"  - *Remediation:* {a['solution'][:300]}")
                sections.append("")
        if low:
            sections.append("### Low Priority / Informational")
            sections.append("")
            for a in low[:8]:
                sections.append(f"- {a['name']}")
            if len(low) > 8:
                sections.append(f"- *...and {len(low) - 8} more (see raw logs)*")
            sections.append("")
    elif not zap_failure:
        sections.append("*No web vulnerabilities identified or scan data unavailable.*")
        sections.append("")

    if nuclei_not_found:
        sections.append("### Nuclei – Not Run")
        sections.append("")
        sections.append("*Nuclei was not found on PATH. Install from https://github.com/projectdiscovery/nuclei/releases and add to PATH for template-based vulnerability scanning.*")
        sections.append("")

    if nuclei_findings:
        sections.append("### Template-Based Findings")
        sections.append("")
        for f in nuclei_findings[:10]:
            sections.append(f"- {f}")
        sections.append("")

    sections.append("---")
    sections.append("")
    sections.append("## Phase 3: Input Validation Testing")
    sections.append("")
    sections.append(f"**Status:** {sqlmap_status.replace('_', ' ').title()}")
    sections.append("")
    sections.append(sqlmap_detail)
    sections.append("")
    if sqlmap_status == "at_risk":
        sections.append("*Action:* Implement parameterized queries and input sanitization. Conduct manual review of all user inputs.")
    elif sqlmap_status == "limited":
        sections.append("*Action:* Manually test input fields (search, login, forms) for SQL injection.")
    sections.append("")
    sections.append("---")
    sections.append("")
    sections.append("## Phase 4: Exploitation")
    sections.append("")
    sections.append(f"**Status:** {exploit_status.replace('_', ' ').title()}")
    sections.append("")
    sections.append(exploit_detail)
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
    sections.append("| Metasploit Framework | MSF | Exploitation framework |")
    sections.append("")
    sections.append("---")
    sections.append("")
    sections.append("## Appendix B: Raw Logs")
    sections.append("")
    sections.append("*Detailed tool output is stored in `harpoon_logs/` for technical review.*")
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
    zap_text = read_excerpt(ZAP_LOG, 500_000) if ZAP_LOG.exists() else ""
    nmap_text = read_excerpt(NMAP_LOG, 100_000) if NMAP_LOG.exists() else ""
    nuclei_text = read_excerpt(NUCLEI_LOG, 100_000) if NUCLEI_LOG.exists() else ""
    sqlmap_text = read_excerpt(SQLMAP_LOG, 100_000) if SQLMAP_LOG.exists() else ""
    gobuster_text = read_excerpt(GOBUSTER_LOG, 50_000) if GOBUSTER_LOG.exists() else ""
    msf_text = read_excerpt(MSF_LOG, 50_000) if MSF_LOG.exists() else ""

    zap_alerts = _parse_zap_alerts(zap_text)
    zap_failure = _parse_zap_failure(zap_text)
    nmap_ports = _parse_nmap_ports(nmap_text)
    nuclei_status, nuclei_findings, nuclei_not_found = _parse_nuclei_result(nuclei_text)
    sqlmap_status, sqlmap_detail = _parse_sqlmap_result(sqlmap_text)
    gobuster_status, gobuster_detail = _parse_gobuster_result(gobuster_text)
    exploit_status, exploit_detail = _parse_exploitation_result(msf_text)

    ollama_summary = ""
    if use_ollama:
        log_paths = {"ZAP": ZAP_LOG, "Nuclei": NUCLEI_LOG, "Sqlmap": SQLMAP_LOG, "Gobuster": GOBUSTER_LOG, "Nmap": NMAP_LOG, "Metasploit": MSF_LOG}
        ollama_summary = ollama_summarize_findings(log_paths)

    sections = _build_sections(
        target, zap_alerts, zap_failure, nmap_ports,
        nuclei_status, nuclei_findings, nuclei_not_found,
        sqlmap_status, sqlmap_detail,
        gobuster_status, gobuster_detail,
        exploit_status, exploit_detail,
    )

    # Insert Ollama (the-xploiter) summary after Executive Summary intro if available
    if ollama_summary:
        for i, s in enumerate(sections):
            if "organized by phase" in s:
                sections.insert(i + 2, ollama_summary)
                sections.insert(i + 3, "")
                break

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(sections), encoding="utf-8", errors="replace")
