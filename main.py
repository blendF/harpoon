#!/usr/bin/env python3
"""
Harpoon – Autonomous Stateful Black-Box Pentesting Framework.
"""
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harpoon.startup import show_ascii_art
from harpoon.target import normalize_target, normalize_target_https, prompt_target, url_for_web_scan
from harpoon.logs import ensure_log_dir
from harpoon.spinner import run_with_spinner
from harpoon.config import (
    AMASS_LOG,
    ARJUN_LOG,
    DNSX_LOG,
    FFUF_DIR_LOG,
    FFUF_PARAMS_LOG,
    FFUF_VHOST_LOG,
    GOBUSTER_LOG,
    HTTPX_LOG,
    JS_ANALYSIS_LOG,
    KATANA_LOG,
    NIKTO_LOG,
    NMAP_LOG,
    NUCLEI_LOG,
    PARAMSPIDER_LOG,
    POC_LOG,
    RECON_LOG,
    REPORT_PATH,
    SQLMAP_LOG,
    STATE_PATH,
    SUBFINDER_LOG,
    WAYBACK_LOG,
    ZAP_LOG,
)
from harpoon.scanners.subfinder_scan import run_subfinder
from harpoon.scanners.crtsh_scan import run_crtsh
from harpoon.scanners.amass_scan import run_amass
from harpoon.scanners.dnsx_scan import run_dnsx
from harpoon.scanners.httpx_scan import run_httpx
from harpoon.scanners.gowitness_scan import run_gowitness
from harpoon.scanners.ffuf_scan import (
    run_ffuf_dir,
    run_ffuf_params,
    run_ffuf_vhost,
    get_ffuf_discovered_paths,
    get_ffuf_discovered_params,
)
from harpoon.scanners.gobuster_scan import run_gobuster
from harpoon.scanners.katana_scan import run_katana
from harpoon.scanners.wayback_scan import run_waybackurls, run_gau, dedupe_urls
from harpoon.scanners.js_analysis import analyze_js_urls
from harpoon.scanners.paramspider_scan import run_paramspider
from harpoon.scanners.arjun_scan import run_arjun
from harpoon.scanners.nmap_scan import run_nmap
from harpoon.scanners.zap_scan import run_zap
from harpoon.scanners.sqlmap_scan import run_sqlmap
from harpoon.scanners.nuclei_scan import run_nuclei
from harpoon.scanners.nikto_scan import run_nikto
from harpoon.parsers.nmap_parser import parse_nmap_report_file
from harpoon.recon import dns_lookup, save_recon_log
from harpoon.report_stateful import generate_report
from harpoon.state import PipelineStateManager
from harpoon.waf import detect_waf
from harpoon.poc_generator import generate_pocs


def main() -> None:
    show_ascii_art()
    print()
    target_raw = prompt_target()
    target_url = normalize_target(target_raw)
    target_url_https = normalize_target_https(target_raw)
    target_host = target_url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    ensure_log_dir()
    state = PipelineStateManager(target=target_url_https)

    web_url = url_for_web_scan(target_raw)

    # Pre-scan: baseline DNS and lightweight CDN hinting
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

    # Phase 1: Passive Recon
    print(f"Phase 1 – Passive Reconnaissance on target: {target_host}")
    state.add_subdomain(target_host, source="seed")
    print("  [subfinder]")
    code, subs1, msg = run_with_spinner("  ", lambda: run_subfinder(target_host, log_path=SUBFINDER_LOG))
    print(f"  {msg}")
    print("  [crt.sh]")
    code, subs2, msg = run_with_spinner("  ", lambda: run_crtsh(target_host))
    print(f"  {msg}")
    print("  [amass - optional]")
    code, subs3, msg = run_with_spinner("  ", lambda: run_amass(target_host, log_path=AMASS_LOG))
    print(f"  {msg}")
    for sub in set(subs1 + subs2 + subs3 + [target_host]):
        state.add_subdomain(sub, source="passive-recon")

    # Phase 2: Active DNS and conditional Nmap
    print(f"\nPhase 2 – Active DNS + Infra Filtering on target: {target_host}")
    subdomain_list = [s["value"] for s in state.get("subdomains", []) if s.get("value")]
    code, resolved, msg = run_with_spinner("  ", lambda: run_dnsx(subdomain_list, log_path=DNSX_LOG))
    print(f"  {msg}")
    resolved_ips: list[str] = []
    for row in resolved:
        host = row.get("host", "")
        for ip in row.get("ips", []):
            state.add_resolved_host(host=host, ip=ip, source="dnsx")
            resolved_ips.append(ip)
    nmap_targets = sorted(set(resolved_ips)) or [target_host]
    print("  [Nmap – only non-CDN origins]")
    code, _out, nmap_msg = run_with_spinner("  ", lambda: run_nmap(nmap_targets, log_path=NMAP_LOG))
    print(f"  {nmap_msg}")
    for svc in parse_nmap_report_file(str(NMAP_LOG)):
        target_ip = nmap_targets[0] if nmap_targets else target_host
        state.add_port(target_ip, svc.port, svc.protocol, svc.service, svc.product, svc.version, source="nmap")

    # Phase 3: HTTP probing + WAF detection
    print(f"\nPhase 3 – HTTP Probing + WAF Fingerprinting on target: {target_host}")
    probe_targets = [f"https://{h}" for h in subdomain_list[:200]] or [web_url]
    code, httpx_results, msg = run_with_spinner("  ", lambda: run_httpx(probe_targets, log_path=HTTPX_LOG))
    print(f"  {msg}")
    all_techs: set[str] = set()
    for r in httpx_results:
        state.add_url(r["url"], source="httpx", status=r.get("status_code"), title=r.get("title", ""))
        for t in r.get("tech", []):
            state.add_technology(r["host"], str(t), source="httpx")
            all_techs.add(str(t).lower())
    waf_result = detect_waf(web_url)
    state.set_waf_status(
        target_host,
        waf_result.is_present,
        vendor=waf_result.vendor,
        confidence=waf_result.confidence,
        recommended_rate=waf_result.recommended_rate,
        source="waf-engine",
    )
    print(
        f"  WAF detected: {waf_result.is_present}"
        + (f" ({waf_result.vendor}, confidence={waf_result.confidence})" if waf_result.is_present else "")
    )

    # Phase 4: Visual Recon
    print(f"\nPhase 4 – Visual Reconnaissance on target: {target_host}")
    urls_for_visual = [u["url"] for u in state.get("urls", []) if u.get("url")] or [web_url]
    code, msg = run_with_spinner("  ", lambda: run_gowitness(urls_for_visual))
    print(f"  {msg}")

    # Phase 5: Directory/Vhost discovery
    print(f"\nPhase 5 – Directory and Content Discovery on target: {target_host}")
    waf_present = bool(state.get_waf_status(target_host).get("is_present", False))
    code, msg = run_with_spinner("  ", lambda: run_ffuf_dir(target_url_https, is_cdn=waf_present, technology_tags=list(all_techs)))
    print(f"  {msg}")
    for p in get_ffuf_discovered_paths(FFUF_DIR_LOG):
        state.add_path(target_url_https.rstrip("/"), p, source="ffuf-dir")

    code, msg = run_with_spinner("  ", lambda: run_ffuf_vhost(web_url, domain=target_host, is_cdn=waf_present))
    print(f"  {msg}")
    from harpoon.scanners.ffuf_scan import get_ffuf_discovered_vhosts
    for v in get_ffuf_discovered_vhosts(FFUF_VHOST_LOG):
        state.add_vhost(v, source="ffuf-vhost")

    high_value_paths = [p["path"] for p in state.get("paths", []) if p.get("path")]
    code, msg = run_with_spinner("  ", lambda: run_gobuster(target_url_https, high_value_paths=high_value_paths))
    print(f"  {msg}")

    # Phase 6: Advanced crawling + historical mining + targeted ZAP
    print(f"\nPhase 6 – Advanced Crawling + Historical Mining on target: {target_host}")
    crawl_targets = [u["url"] for u in state.get("urls", []) if u.get("url")] or [web_url]
    code, katana_urls, msg = run_with_spinner("  ", lambda: run_katana(crawl_targets, log_path=KATANA_LOG))
    print(f"  {msg}")
    code, wb_urls, msg = run_with_spinner("  ", lambda: run_waybackurls(target_host))
    print(f"  {msg}")
    code, gau_urls, msg = run_with_spinner("  ", lambda: run_gau(target_host))
    print(f"  {msg}")
    historical_urls = dedupe_urls(katana_urls + wb_urls + gau_urls)
    for u in historical_urls[:500]:
        state.add_url(u, source="historical")
    code, msg = run_with_spinner("  ", lambda: run_zap(web_url, log_path=ZAP_LOG, endpoints=historical_urls))
    print(f"  {msg}")

    # Phase 7: JS analysis
    print(f"\nPhase 7 – JavaScript Analysis on target: {target_host}")
    js_urls = [u for u in historical_urls if ".js" in urlparse(u).path.lower()]
    endpoints, secrets, msg = run_with_spinner("  ", lambda: analyze_js_urls(js_urls, log_path=JS_ANALYSIS_LOG))
    print(f"  {msg}")
    for p in endpoints:
        state.add_path(target_url_https.rstrip("/"), p, source="js-analysis")
    for sec in secrets:
        state.add_secret(sec.get("secret_excerpt", ""), float(sec.get("entropy", 0.0)), sec.get("url", ""), source="js-analysis")

    # Phase 8: Parameter discovery
    print(f"\nPhase 8 – Parameter Discovery on target: {target_host}")
    code, passive_params, msg = run_with_spinner("  ", lambda: run_paramspider(target_host, log_path=PARAMSPIDER_LOG))
    print(f"  {msg}")
    seed_urls = [u for u in historical_urls[:30] if "?" not in u]
    code, arjun_params, msg = run_with_spinner("  ", lambda: run_arjun(seed_urls, log_path=ARJUN_LOG))
    print(f"  {msg}")
    discovered_param_names = sorted(set(passive_params + arjun_params))
    for u in seed_urls[:20]:
        for p in discovered_param_names[:50]:
            state.add_param(u, p, "GET", source="param-discovery", confidence=0.7)
    code, msg = run_with_spinner(
        "  ",
        lambda: run_ffuf_params(
            target_url_https,
            gobuster_log=GOBUSTER_LOG,
            ffuf_dir_log=FFUF_DIR_LOG,
            is_cdn=waf_present,
            seeded_urls=seed_urls,
        ),
    )
    print(f"  {msg}")
    for row in get_ffuf_discovered_params(FFUF_PARAMS_LOG):
        state.add_param(row.get("target", target_url_https), row.get("param", ""), row.get("mode", "GET"), source="ffuf-params")

    # Phase 9: Validation engines
    print(f"\nPhase 9 – Automated Validation on target: {target_host}")
    code, sqlmap_msg = run_with_spinner(
        "  ",
        lambda: run_sqlmap(
            target_url_https,
            log_path=SQLMAP_LOG,
            gobuster_log=GOBUSTER_LOG,
            waf_present=waf_present,
            discovered_params=[p for p in state.get("params", [])],
            output_dir=Path(SQLMAP_LOG.parent / "sqlmap_output"),
        ),
    )
    print(f"  {sqlmap_msg}")
    code, nikto_msg = run_with_spinner("  ", lambda: run_nikto(web_url, log_path=NIKTO_LOG, skip_if_waf=waf_present))
    print(f"  {nikto_msg}")
    code, nuclei_msg = run_with_spinner(
        "  ",
        lambda: run_nuclei(
            base_url=web_url,
            host=target_host,
            log_path=NUCLEI_LOG,
            nmap_log=NMAP_LOG,
            gobuster_log=GOBUSTER_LOG,
            is_cdn=waf_present,
            ffuf_dir_log=FFUF_DIR_LOG,
            ffuf_vhost_log=FFUF_VHOST_LOG,
            state_manager=state,
            waf_present=waf_present,
            tech_tags=list(all_techs),
        ),
    )
    print(f"  {nuclei_msg}")

    # Stage 10 handoff + PoC generation
    print("\nPhase 10 – Manual Exploitation Handoff")
    pocs = generate_pocs(NUCLEI_LOG, SQLMAP_LOG, output_path=POC_LOG)
    print(f"  Generated {len(pocs)} deterministic PoC statement(s).")
    state.save(STATE_PATH)

    # Report: generate immediately, then enhance with Ollama
    run_with_spinner(
        "Generating report… ",
        lambda: generate_report(
            target_raw,
            report_path=REPORT_PATH,
            use_ollama=False,
            state_path=STATE_PATH,
            poc_log=POC_LOG,
        ),
    )
    print("done.")
    print(f"Report: {REPORT_PATH.absolute()}")

    from harpoon.ollama_client import ollama_available
    from harpoon.config import OLLAMA_MODEL
    if ollama_available():
        print(f"Enhancing report with AI-assisted analysis ({OLLAMA_MODEL})…  Est. 1–3 min")
        print("  Generating technical analysis with real-world impact assessment…", end=" ", flush=True)
        try:
            generate_report(
                target_raw,
                report_path=REPORT_PATH,
                use_ollama=True,
                state_path=STATE_PATH,
                poc_log=POC_LOG,
            )
            print("done.")
        except Exception:
            print("skipped (timeout or error).")


if __name__ == "__main__":
    main()
