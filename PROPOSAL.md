# Harpoon – Improvement Proposal

**Author:** Blendi "blendFpwn" Ferizi  
**Date:** 2026-02-18

---

## Summary

This document proposes improvements to Harpoon, an automated web application penetration testing tool. The changes focus on user experience, architectural clarity, and reliability.

---

## 1. Stage-Based Console Output (Implemented)

**Proposal:** Replace tool names with penetration testing phases in all console output.

| Before | After |
|--------|-------|
| Running Nmap… | Reconnaissance on target: example.com |
| Running Gobuster… | Enumeration on target: example.com |
| Running OWASP ZAP… | Web application scanning on target: example.com |
| Running Metasploit… | Exploitation on target: example.com |

**Rationale:** Users think in terms of pentest stages, not individual tools. This aligns the interface with industry terminology (OSSTMM, PTES, etc.).

---

## 2. Execution Order (Implemented)

**Proposal:** Reorder phases to follow a logical attack flow:

1. **Reconnaissance** – Network discovery (ports, services)
2. **Enumeration** – Path and resource discovery
3. **Web Application Scanning** – Vulnerability assessment
4. **Exploitation** – Automated exploit attempts
5. **Reporting** – Consolidated findings

**Rationale:** Recon informs enumeration; enumeration informs web scanning; all inform exploitation. This order minimizes redundant work and respects dependencies.

---

## 3. Nuclei Integration (Implemented)

**Proposal:** Add Nuclei as a vulnerability scanner in the web application scanning phase.

**Rationale:** Nuclei provides template-based CVE and misconfiguration detection, complementing OWASP ZAP’s active scanning. It is fast, well-maintained, and widely used.

**Setup:** Install from [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei/releases). Run `nuclei -update-templates` before first use.

---

## 4. Gobuster Wildcard Handling (Implemented)

**Proposal:** Handle servers that return the same response (e.g. 200 + fixed length) for non-existing paths (SPAs, wildcards).

**Implementation:**
- Parse Gobuster error output for `Length: XXXXX`
- Retry with `--exclude-length XXXXX` when detected
- Expand bundled wordlist for better coverage

**Rationale:** Many modern apps (React, Vue, etc.) serve a single HTML shell for all routes. Gobuster fails without exclude-length; automatic retry improves reliability.

---

## 5. Spinning Loading Animation (Implemented)

**Proposal:** Replace static "Running…" text with a spinning animation (`|`, `/`, `-`, `\`) during long-running phases.

**Rationale:** Provides clear feedback that the process is active without implying false progress (unlike 0–100% bars that may be inaccurate).

---

## 6. Report Structure (Already Implemented)

- Phase-based sections (Reconnaissance, Web Scanning, Input Validation, Exploitation)
- No tool names in main report body
- Findings grouped by risk (At Risk, Review Recommended, Low Priority)
- Actionable recommendations per finding

---

## 7. Future Considerations

- **Metasploit bundling:** Document installer path; consider optional bundled installer for Windows
- **Ollama integration:** Use the-xploiter for dynamic workflow decisions (e.g. which phase to emphasize based on recon)
- **Config file:** Allow users to enable/disable phases, set timeouts, wordlist paths
- **Resume support:** Save state between runs for long targets

---

## Installation Requirements (Updated)

| Phase | Requirement |
|-------|-------------|
| Reconnaissance | Nmap |
| Enumeration | Gobuster (bundled in `tools/`) |
| Web Scanning | OWASP ZAP, Sqlmap, Nuclei |
| Exploitation | Metasploit Framework |
| Reporting | Ollama + xploiter/the-xploiter (optional) |

---

*Harpoon – Fire and forget web-app penetration testing.*
