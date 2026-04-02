#!/usr/bin/env python3
"""Harpoon – Async Stateful Black-Box Pentesting Framework."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harpoon.cli import Counters, critical, estimate_duration, info, phase_banner, success, warn
from harpoon.config import (
    ARJUN_LOG,
    DNSX_LOG,
    FFUF_DIR_LOG,
    FFUF_PARAMS_LOG,
    FFUF_VHOST_LOG,
    HTTPX_LOG,
    JS_ANALYSIS_LOG,
    KATANA_LOG,
    NIKTO_LOG,
    NMAP_LOG,
    NUCLEI_LOG,
    PARAMSPIDER_LOG,
    POC_LOG,
    RECON_LOG,
    SESSION_DB_PATH,
    SQLMAP_LOG,
    STATE_PATH,
    SUBFINDER_LOG,
)
from harpoon.logs import ensure_log_dir
from harpoon.poc_generator import generate_pocs
from harpoon.preflight import check_dependencies
from harpoon.recon import dns_lookup, save_recon_log
from harpoon.scanners.amass_scan import run_amass
from harpoon.scanners.arjun_scan import run_arjun
from harpoon.scanners.cdncheck_scan import run_cdncheck
from harpoon.scanners.crtsh_scan import run_crtsh
from harpoon.scanners.dnsx_scan import run_dnsx
from harpoon.scanners.ffuf_scan import get_ffuf_discovered_params, get_ffuf_discovered_paths, get_ffuf_discovered_vhosts, run_ffuf_dir, run_ffuf_params, run_ffuf_vhost
from harpoon.scanners.gowitness_scan import run_gowitness
from harpoon.scanners.httpx_scan import run_httpx
from harpoon.scanners.js_analysis import analyze_js_urls
from harpoon.scanners.katana_scan import run_katana
from harpoon.scanners.nikto_scan import run_nikto
from harpoon.scanners.nmap_scan import run_nmap
from harpoon.scanners.nuclei_scan import run_nuclei
from harpoon.scanners.paramspider_scan import run_paramspider
from harpoon.scanners.sqlmap_scan import run_sqlmap
from harpoon.scanners.subfinder_scan import run_subfinder
from harpoon.scanners.wayback_scan import dedupe_urls, run_gau, run_waybackurls
from harpoon.startup import show_ascii_art
from harpoon.state import PipelineStateManager
from harpoon.target import normalize_target, normalize_target_https, prompt_target, url_for_web_scan
from harpoon.waf import detect_waf
from viewreport import generate_html_report


async def main() -> None:
    show_ascii_art()
    ensure_log_dir()
    check_dependencies()

    target_raw = prompt_target()
    target_url = normalize_target(target_raw)
    target_url_https = normalize_target_https(target_raw)
    target_host = target_url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    web_url = url_for_web_scan(target_raw)
    state = PipelineStateManager(target=target_host, db_path=SESSION_DB_PATH)
    counters = Counters()

    phase_banner("Phase 0 - DNS Recon")
    recon_info = dns_lookup(target_host)
    save_recon_log(recon_info, RECON_LOG)
    info(f"resolved_ips={len(recon_info.ips)} cdn={recon_info.cdn_name or 'none'}")

    phase_banner("Phase 1 - Passive Recon")
    state.add_subdomain(target_host, source="seed")
    tasks = [run_subfinder(target_host, log_path=SUBFINDER_LOG), run_crtsh(target_host), run_amass(target_host)]
    (_c1, subs1, _m1), (_c2, subs2, _m2), (_c3, subs3, _m3) = await asyncio.gather(*tasks)
    for sub in sorted(set(subs1 + subs2 + subs3 + [target_host])):
        state.add_subdomain(sub, source="passive-recon")
    counters.subdomains = len(state.get("subdomains"))
    counters.show()

    phase_banner("Phase 2 - Active DNS + Infra")
    subdomain_list = [s["value"] for s in state.get("subdomains", []) if s.get("value")]
    _, resolved, msg = await run_dnsx(subdomain_list, log_path=DNSX_LOG)
    info(msg)
    resolved_ips: list[str] = []
    for row in resolved:
        host = row.get("host", "")
        for ip in row.get("ips", []):
            state.add_resolved_host(host=host, ip=ip, source="dnsx")
            resolved_ips.append(ip)
    _, nmap_out, nmap_msg = await run_nmap(sorted(set(resolved_ips)) or [target_host], log_path=NMAP_LOG)
    info(nmap_msg)

    phase_banner("Phase 3 - HTTP + WAF Detection")
    probe_targets = [f"https://{h}" for h in subdomain_list[:200]] or [web_url]
    _, httpx_results, msg = await run_httpx(probe_targets, log_path=HTTPX_LOG)
    info(msg)
    all_techs: set[str] = set()
    for r in httpx_results:
        state.add_url(r["url"], source="httpx", status=r.get("status_code"))
        for t in r.get("tech", []):
            state.add_technology(r["host"], str(t), source="httpx")
            all_techs.add(str(t).lower())
    _, cdn_data, _ = await run_cdncheck(target_host)
    waf_result = detect_waf(web_url, cdncheck_result=cdn_data)
    state.set_waf_status(target_host, waf_result.is_present, vendor=waf_result.vendor, confidence=waf_result.confidence, recommended_rate=waf_result.recommended_rate, source="waf-engine")
    warn(f"WAF detected={waf_result.is_present} vendor={waf_result.vendor or 'n/a'}")

    phase_banner("Phase 4 - Visual Recon")
    urls_for_visual = [u["url"] for u in state.get("urls", []) if u.get("url")] or [web_url]
    _code, visual_msg = await run_gowitness(urls_for_visual)
    info(visual_msg)

    phase_banner("Phase 5 - ffuf Discovery")
    waf_present = bool(state.get_waf_status(target_host).get("is_present", False))
    info(f"estimated_minutes={estimate_duration(counters.subdomains, waf_present)}")
    _, msg = await run_ffuf_dir(target_url_https, is_cdn=waf_present, technology_tags=list(all_techs))
    info(msg)
    for p in get_ffuf_discovered_paths(FFUF_DIR_LOG):
        state.add_path(target_url_https.rstrip("/"), p, source="ffuf-dir")
    _, msg = await run_ffuf_vhost(web_url, domain=target_host, is_cdn=waf_present)
    info(msg)
    for v in get_ffuf_discovered_vhosts(FFUF_VHOST_LOG):
        state.add_vhost(v, source="ffuf-vhost")

    phase_banner("Phase 6 - Crawl + History")
    crawl_targets = [u["url"] for u in state.get("urls", []) if u.get("url")] or [web_url]
    _, katana_urls, _ = await run_katana(crawl_targets, log_path=KATANA_LOG)
    _, wb_urls, _ = await run_waybackurls(target_host)
    _, gau_urls, _ = await run_gau(target_host)
    historical_urls = dedupe_urls(katana_urls + wb_urls + gau_urls)
    for u in historical_urls[:500]:
        state.add_url(u, source="historical")
    counters.endpoints = len(state.get("urls"))
    counters.show()

    phase_banner("Phase 7 - JS Analysis")
    js_urls = [u for u in historical_urls if ".js" in urlparse(u).path.lower()]
    endpoints, secrets, msg = await analyze_js_urls(js_urls, log_path=JS_ANALYSIS_LOG)
    info(msg)
    for p in endpoints:
        state.add_path(target_url_https.rstrip("/"), p, source="js-analysis")
    for sec in secrets:
        state.add_secret(sec.get("secret_excerpt", ""), float(sec.get("entropy", 0.0)), sec.get("url", ""), source="js-analysis")

    phase_banner("Phase 8 - Parameter Discovery")
    _, passive_params, _ = await run_paramspider(target_host, log_path=PARAMSPIDER_LOG)
    seed_urls = [u for u in historical_urls[:30] if "?" not in u]
    _, arjun_params, _ = await run_arjun(seed_urls, log_path=ARJUN_LOG)
    discovered_param_names = sorted(set(passive_params + arjun_params))
    for u in seed_urls[:20]:
        for p in discovered_param_names[:50]:
            state.add_param(u, p, "GET", source="param-discovery", confidence=0.7)
    _, msg = await run_ffuf_params(target_url_https, ffuf_dir_log=FFUF_DIR_LOG, is_cdn=waf_present, seeded_urls=seed_urls)
    info(msg)
    for row in get_ffuf_discovered_params(FFUF_PARAMS_LOG):
        state.add_param(row.get("target", target_url_https), row.get("param", ""), row.get("mode", "GET"), source="ffuf-params")
    counters.params = len(state.get("params"))
    counters.show()

    phase_banner("Phase 9 - Validation")
    _, sqlmap_msg = await run_sqlmap(
        target_url_https,
        log_path=SQLMAP_LOG,
        waf_present=waf_present,
        discovered_params=[p for p in state.get("params", [])],
        output_dir=Path(SQLMAP_LOG.parent / "sqlmap_output"),
    )
    info(sqlmap_msg)
    _, nikto_msg = await run_nikto(web_url, log_path=NIKTO_LOG, skip_if_waf=waf_present)
    info(nikto_msg)
    _, nuclei_msg = await run_nuclei(
        base_url=web_url,
        host=target_host,
        log_path=NUCLEI_LOG,
        nmap_log=NMAP_LOG,
        is_cdn=waf_present,
        ffuf_dir_log=FFUF_DIR_LOG,
        ffuf_vhost_log=FFUF_VHOST_LOG,
        state_manager=state,
        waf_present=waf_present,
        tech_tags=list(all_techs),
    )
    info(nuclei_msg)
    if "critical" in Path(NUCLEI_LOG).read_text(encoding="utf-8", errors="replace").lower():
        critical("Critical vulnerability signatures detected in Nuclei output")

    phase_banner("Phase 10 - PoC + Reporting")
    pocs = generate_pocs(NUCLEI_LOG, SQLMAP_LOG, output_path=POC_LOG)
    counters.vulns = len(pocs)
    counters.show()
    state.save(STATE_PATH)
    report_path = generate_html_report(target_host, SESSION_DB_PATH, POC_LOG)
    success(f"HTML report generated: {report_path}")


if __name__ == "__main__":
    asyncio.run(main())
