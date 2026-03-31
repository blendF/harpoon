"""Generate Harpoon_Report.md for the stateful 10-phase architecture."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from harpoon.config import (
    FFUF_DIR_LOG,
    FFUF_PARAMS_LOG,
    FFUF_VHOST_LOG,
    HTTPX_LOG,
    KATANA_LOG,
    NIKTO_LOG,
    NMAP_LOG,
    NUCLEI_LOG,
    POC_LOG,
    RECON_LOG,
    REPORT_PATH,
    SQLMAP_LOG,
    ZAP_LOG,
)
from harpoon.ollama_client import ollama_summarize_findings


def _read(path: Path, max_chars: int = 200_000) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars]
    except OSError:
        return ""


def _parse_nmap_ports(text: str) -> list[str]:
    ports: list[str] = []
    for m in re.finditer(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(.*)", text):
        ports.append(f"{m.group(1)}/{m.group(2)} {m.group(3)} {m.group(4).strip()}".strip())
    return ports[:40]


def _parse_nuclei_jsonl(text: str) -> list[dict]:
    findings: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {})
        findings.append(
            {
                "name": info.get("name", obj.get("template-id", "")),
                "severity": info.get("severity", "unknown"),
                "matched_at": obj.get("matched-at", obj.get("host", "")),
            }
        )
    return findings


def _parse_ffuf_json(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace")).get("results", [])
    except (json.JSONDecodeError, OSError):
        return []


def _overall_rating(nuclei_findings: list[dict], sqlmap_text: str, pocs: list[dict]) -> str:
    if any("sql injection" in p.get("name", "").lower() for p in pocs) or "injectable" in sqlmap_text.lower():
        return "CRITICAL"
    severities = [f.get("severity", "").lower() for f in nuclei_findings]
    if any(s in ("critical", "high") for s in severities):
        return "HIGH"
    if nuclei_findings or pocs:
        return "MEDIUM"
    return "LOW"


def generate_report(
    target: str,
    report_path: Path = REPORT_PATH,
    use_ollama: bool = True,
    state_path: Path | None = None,
    poc_log: Path = POC_LOG,
) -> None:
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    nmap_text = _read(NMAP_LOG, 120_000)
    sqlmap_text = _read(SQLMAP_LOG, 250_000)
    nuclei_text = _read(NUCLEI_LOG, 250_000)
    ports = _parse_nmap_ports(nmap_text)
    nuclei_findings = _parse_nuclei_jsonl(nuclei_text)
    ffuf_dir = _parse_ffuf_json(FFUF_DIR_LOG)
    ffuf_vhost = _parse_ffuf_json(FFUF_VHOST_LOG)
    ffuf_params = _parse_ffuf_json(FFUF_PARAMS_LOG)

    pocs: list[dict] = []
    if poc_log.exists():
        try:
            pocs = json.loads(poc_log.read_text(encoding="utf-8", errors="replace")).get("pocs", [])
        except (json.JSONDecodeError, OSError):
            pocs = []

    overall = _overall_rating(nuclei_findings, sqlmap_text, pocs)
    sections: list[str] = [
        "# Harpoon Stateful Pentest Report",
        "",
        f"**Target:** {target}",
        f"**Date:** {date_str}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "Assessment executed through a stateful 10-phase black-box pipeline with adaptive WAF policy and deterministic PoC generation.",
        "",
        f"**Overall Risk Rating:** {overall}",
        "",
        "## Toolchain Procedure (1 -> 10)",
        "",
        "1. Passive recon (subfinder, crt.sh, amass)",
        "2. Active DNS + infra filtering (dnsx + conditional nmap)",
        "3. HTTP probing + WAF detection (httpx + behavioral probe)",
        "4. Visual recon (gowitness)",
        "5. Directory/vhost fuzzing (ffuf primary, gobuster targeted)",
        "6. Advanced crawling + historical mining (katana + archives)",
        "7. JS analysis (endpoint + entropy secret detection)",
        "8. Parameter discovery (paramspider/arjun/ffuf params)",
        "9. Validation (nuclei, sqlmap, nikto conditional)",
        "10. Manual exploitation handoff + PoC statements",
        "",
        "---",
        "",
        "## Findings Snapshot",
        "",
        f"- Nmap open services: {len(ports)}",
        f"- ffuf dir findings: {len(ffuf_dir)}",
        f"- ffuf vhost findings: {len(ffuf_vhost)}",
        f"- ffuf params findings: {len(ffuf_params)}",
        f"- Nuclei findings: {len(nuclei_findings)}",
        f"- Generated PoCs: {len(pocs)}",
        "",
        "## Actionable Proof of Exploitation",
        "",
    ]
    if pocs:
        for p in pocs[:40]:
            sections.append(f"- {p.get('poc_statement', '')}")
    else:
        sections.append("*No deterministic PoCs generated from current validation outputs.*")
    sections.append("")

    if use_ollama:
        ai = ollama_summarize_findings(
            {
                "Recon": RECON_LOG,
                "Nmap": NMAP_LOG,
                "httpx": HTTPX_LOG,
                "ffuf-dir": FFUF_DIR_LOG,
                "ffuf-vhost": FFUF_VHOST_LOG,
                "ffuf-params": FFUF_PARAMS_LOG,
                "Katana": KATANA_LOG,
                "ZAP": ZAP_LOG,
                "Sqlmap": SQLMAP_LOG,
                "Nuclei": NUCLEI_LOG,
                "Nikto": NIKTO_LOG,
                "PoC": poc_log,
            }
        )
        if ai:
            sections.extend(["---", "", "## AI-Assisted Analysis", "", ai, ""])

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(sections), encoding="utf-8", errors="replace")

