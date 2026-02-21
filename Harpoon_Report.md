# Penetration Test Report

**Target:** https://juice-shop.herokuapp.com/
**Date:** 2026-02-21 01:56

---

## Executive Summary

This report presents findings from an automated penetration test, organized by phase. Each finding includes its security impact and recommended actions.

---

## Phase 1: Reconnaissance

### DNS Recon

**Resolved IP(s):** 54.220.192.176, 54.73.53.134, 46.137.15.86

**CDN/WAF:** None detected (direct host)

### Network Discovery

**Open ports and services:**

| Port | Protocol | Service |
|------|----------|---------|
| 80 | tcp | http |
| 443 | tcp | ssl/https |

*Action:* Ensure only necessary ports are exposed. Close or restrict access to unused services.

### Path Enumeration

**Status:** Limited

Server uses redirects or wildcard responses; automated enumeration was constrained.


---

## Phase 2: Web Application Scanning

### At Risk

- **Content Security Policy (CSP) Header Not Set**
  - Affected: https://juice-shop.herokuapp.com/ftp/encrypt.pyc, https://juice-shop.herokuapp.com/ftp/package-lock.json.bak, https://juice-shop.herokuapp.com/sitemap.xml
  - *Remediation:* Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

- **Strict-Transport-Security Header Not Set**
  - Affected: https://juice-shop.herokuapp.com/assets/public/favicon_js.ico, https://juice-shop.herokuapp.com/runtime.js, https://juice-shop.herokuapp.com/
  - *Remediation:* Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.

### Review Recommended

- **Cross-Domain Misconfiguration**
  - Affected: https://juice-shop.herokuapp.com/, https://juice-shop.herokuapp.com/polyfills.js, https://juice-shop.herokuapp.com/robots.txt
  - *Remediation:* Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).  Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Or

- **Cross-Domain JavaScript Source File Inclusion**
  - Affected: https://juice-shop.herokuapp.com/, https://juice-shop.herokuapp.com/sitemap.xml
  - *Remediation:* Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.

- **Modern Web Application**
  - Affected: https://juice-shop.herokuapp.com/, https://juice-shop.herokuapp.com/sitemap.xml
  - *Remediation:* This is an informational alert and so no changes are required.

### Low Priority / Informational

- Timestamp Disclosure - Unix
- Information Disclosure - Suspicious Comments
- Re-examine Cache-control Directives

---

## Phase 3: Input Validation Testing

**Status:** Limited

No URL parameters or form fields with injectable patterns were discovered during automated crawl. Manual testing of specific input fields recommended.

*Action:* Manually test input fields (search, login, forms) for SQL injection.

---

## Phase 4: Exploitation

**Status:** At Risk

Possible remote access obtained. Immediate remediation required.

---

## Appendix A: Tools Used

| Tool | Abbreviation | Purpose |
|------|--------------|---------|
| Nmap | Network Mapper | Port scan, service detection, OS fingerprint |
| Gobuster | Dir enum | Directory/file enumeration |
| OWASP ZAP | ZAP (Zed Attack Proxy) | Web app vulnerability scanning |
| Sqlmap | SQLi | SQL injection testing |
| Nuclei | CVE/templates | Template-based vulnerability scanning |
| Metasploit Framework | MSF | Exploitation framework |

---

## Appendix B: Raw Logs

*Detailed tool output is stored in `harpoon_logs/` for technical review.*
