"""Deterministic PoC extraction from Nuclei JSONL and Sqlmap output."""
from __future__ import annotations

import json
import re
from pathlib import Path

from harpoon.config import POC_LOG


def _parse_nuclei_jsonl(nuclei_log: Path) -> list[dict]:
    findings: list[dict] = []
    if not nuclei_log.exists():
        return findings
    for line in nuclei_log.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {}) if isinstance(obj, dict) else {}
        classification = info.get("classification", {}) if isinstance(info, dict) else {}
        cve = classification.get("cve-id") or classification.get("cve")
        findings.append(
            {
                "type": "nuclei",
                "template_id": obj.get("template-id", ""),
                "name": info.get("name", obj.get("template-id", "Unknown finding")),
                "cve": cve if isinstance(cve, str) else "",
                "matched_at": obj.get("matched-at", obj.get("host", "")),
                "curl_command": obj.get("curl-command", ""),
                "raw_http_request": obj.get("request", ""),
                "severity": info.get("severity", ""),
            }
        )
    return findings


def _parse_sqlmap_log(sqlmap_log: Path) -> list[dict]:
    findings: list[dict] = []
    if not sqlmap_log.exists():
        return findings
    text = sqlmap_log.read_text(encoding="utf-8", errors="replace")
    if "injectable" not in text.lower() and "is vulnerable" not in text.lower():
        return findings

    param_match = re.search(r"Parameter:\s*([^\s]+)\s*\(", text, re.IGNORECASE)
    dbms_match = re.search(r"back-end DBMS:\s*(.+)", text, re.IGNORECASE)
    payload_match = re.search(r"Payload:\s*(.+)", text)
    url_match = re.search(r"testing URL '([^']+)'", text)

    findings.append(
        {
            "type": "sqlmap",
            "name": "SQL Injection",
            "cve": "",
            "matched_at": url_match.group(1).strip() if url_match else "",
            "parameter": param_match.group(1).strip() if param_match else "",
            "dbms": dbms_match.group(1).strip() if dbms_match else "",
            "payload": payload_match.group(1).strip() if payload_match else "",
            "curl_command": f"curl -i '{url_match.group(1).strip() if url_match else ''}'",
            "raw_http_request": "",
            "severity": "high",
        }
    )
    return findings


def generate_pocs(
    nuclei_log: Path,
    sqlmap_log: Path,
    output_path: Path = POC_LOG,
) -> list[dict]:
    findings = _parse_nuclei_jsonl(nuclei_log) + _parse_sqlmap_log(sqlmap_log)
    poc_entries: list[dict] = []
    for item in findings:
        name = item.get("name", "Unknown")
        cve = item.get("cve", "")
        vuln_ref = f"{name} ({cve})" if cve else name
        path = item.get("matched_at", "unknown target")
        curl_cmd = item.get("curl_command") or ""
        raw_http = item.get("raw_http_request") or ""
        proof = curl_cmd or item.get("payload") or "Refer to raw logs for request reproduction."
        statement = (
            f"Using and finding [{vuln_ref}] - you can exploit this vulnerability "
            f"on this path: {path} using the following proof of concept: {proof}"
        )
        poc_entries.append(
            {
                **item,
                "curl_command": curl_cmd,
                "raw_http_request": raw_http,
                "poc_statement": statement,
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"pocs": poc_entries}, indent=2), encoding="utf-8")
    return poc_entries

