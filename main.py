#!/usr/bin/env python3
"""
Harpoon – Automated Pentesting Tool
Fire and forget web-app penetration testing.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harpoon.startup import show_ascii_art
from harpoon.target import normalize_target, normalize_target_https, prompt_lhost, prompt_target, url_for_web_scan
from harpoon.logs import ensure_log_dir
from harpoon.spinner import run_with_spinner
from harpoon.config import (
    GOBUSTER_LOG,
    NMAP_LOG,
    NUCLEI_LOG,
    RECON_LOG,
    REPORT_PATH,
    SQLMAP_LOG,
    ZAP_LOG,
    MSF_LOG,
)
from harpoon.scanners.zap_scan import run_zap
from harpoon.scanners.sqlmap_scan import run_sqlmap
from harpoon.scanners.gobuster_scan import run_gobuster
from harpoon.scanners.nmap_scan import run_nmap
from harpoon.scanners.nuclei_scan import run_nuclei
from harpoon.parsers.nmap_parser import parse_nmap_report_file
from harpoon.exploit.metasploit_runner import run_metasploit_for_services
from harpoon.recon import dns_lookup, save_recon_log
from harpoon.report import generate_report


def main() -> None:
    show_ascii_art()
    print()
    target_raw = prompt_target()
    lhost = prompt_lhost()
    target_url = normalize_target(target_raw)
    target_url_https = normalize_target_https(target_raw)
    target_host = target_url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    ensure_log_dir()

    web_url = url_for_web_scan(target_raw)

    # Pre-scan: DNS Recon & CDN/WAF Detection
    print(f"DNS Recon on target: {target_host}")
    recon_info = dns_lookup(target_host)
    save_recon_log(recon_info, RECON_LOG)
    if recon_info.ips:
        print(f"  Resolved IP(s): {', '.join(recon_info.ips)}")
    else:
        print("  Could not resolve hostname.")
    if recon_info.is_cdn:
        print(f"  WARNING: Target appears to be behind {recon_info.cdn_name}.")
        print("  Scans may be rate-limited or blocked by WAF. Adjusting scan parameters.")
    else:
        print("  Direct host (no CDN/WAF detected)")
    print()

    # Phase 1: Reconnaissance
    def do_recon():
        return run_nmap(target_url, log_path=NMAP_LOG)

    print(f"Phase 1 – Reconnaissance on target: {target_host}")
    print("  [Nmap – Network Mapper]  Est. 3–10 min")
    code, _out, msg = run_with_spinner("  ", do_recon)
    print("  done." if code == 0 else f"  {msg}")

    # Phase 2: Enumeration
    def do_enum():
        return run_gobuster(target_url_https)

    print(f"\nPhase 2 – Enumeration on target: {target_host}")
    print("  [Gobuster – Dir/File brute-force]  Est. 2–5 min (1,800 words)")
    code, msg = run_with_spinner("  ", do_enum)
    print(f"  {msg}")

    # Phase 3: Web Application Scanning
    print(f"\nPhase 3 – Web Application Scanning on target: {target_host}")

    print("  [OWASP ZAP – Zed Attack Proxy]  Est. 5–15 min")
    def do_zap():
        return run_zap(web_url)
    code, _ = run_with_spinner("  ", do_zap)
    print("  done." if code == 0 else "  Scan encountered issues.")

    print("  [Sqlmap – SQL injection testing]  Est. 2–5 min")
    def do_sqlmap():
        return run_sqlmap(target_url_https, gobuster_log=GOBUSTER_LOG)
    code, _ = run_with_spinner("  ", do_sqlmap)
    print("  done." if code == 0 else "  Scan encountered issues.")

    cdn_note = " (CDN rate-limited)" if recon_info.is_cdn else ""
    print(f"  [Nuclei – Template-based vuln scanner]  Est. 5–10 min{cdn_note}")
    def do_nuclei():
        return run_nuclei(
            base_url=web_url,
            host=target_host,
            nmap_log=NMAP_LOG,
            gobuster_log=GOBUSTER_LOG,
            is_cdn=recon_info.is_cdn,
        )
    code, nuclei_msg = run_with_spinner("  ", do_nuclei)
    print(f"  {nuclei_msg}")

    # Phase 4: Exploitation
    services = parse_nmap_report_file(str(NMAP_LOG))
    if services:
        print(f"\nPhase 4 – Exploitation on target: {target_host}")
        print(f"  [Metasploit Framework – MSF]  Est. 1–3 min per service ({len(services)} services)")

        def do_msf():
            return run_metasploit_for_services(
                target_host, services, lhost=lhost, log_path=MSF_LOG,
                nuclei_log=NUCLEI_LOG,
            )

        exploit_success, msf_msg = run_with_spinner("  ", do_msf)
        print(f"  {msf_msg}")
        if exploit_success:
            print("  Stopping after possible compromise.")
    else:
        print("\nPhase 4 – Exploitation: skipped (no exploitable services identified).")

    # Report: generate immediately, then enhance with Ollama
    run_with_spinner("Generating report… ", lambda: generate_report(target_raw, report_path=REPORT_PATH, use_ollama=False))
    print("done.")
    print(f"Report: {REPORT_PATH.absolute()}")

    from harpoon.ollama_client import ollama_available
    from harpoon.config import OLLAMA_MODEL
    if ollama_available():
        print(f"Enhancing report with AI-assisted analysis ({OLLAMA_MODEL})…  Est. 1–3 min")
        print("  Generating technical analysis with real-world impact assessment…", end=" ", flush=True)
        try:
            generate_report(target_raw, report_path=REPORT_PATH, use_ollama=True)
            print("done.")
        except Exception:
            print("skipped (timeout or error).")


if __name__ == "__main__":
    main()
