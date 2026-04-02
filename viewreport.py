"""Generate a dark-themed HTML report from Harpoon SQLite state."""
from __future__ import annotations

import argparse
import json
import sqlite3
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


def _load_rows(conn: sqlite3.Connection, sql: str) -> list[sqlite3.Row]:
    cur = conn.execute(sql)
    return cur.fetchall()


def _severity_rank(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(sev.lower(), 5)


def generate_html_report(target: str, db_path: Path, poc_log: Path, output_path: Path | None = None) -> Path:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    subdomains = _load_rows(conn, "SELECT * FROM subdomains ORDER BY subdomain")
    endpoints = _load_rows(
        conn,
        """
        SELECT e.*, s.subdomain
        FROM endpoints e
        JOIN subdomains s ON s.id = e.subdomain_id
        ORDER BY e.id
        """,
    )
    vulns = _load_rows(
        conn,
        """
        SELECT v.*, e.url
        FROM vulnerabilities v
        JOIN endpoints e ON e.id = v.endpoint_id
        ORDER BY v.id
        """,
    )
    vulns_sorted = sorted(vulns, key=lambda v: _severity_rank(str(v["severity"] or "info")))

    pocs: list[dict] = []
    if poc_log.exists():
        try:
            pocs = json.loads(poc_log.read_text(encoding="utf-8", errors="replace")).get("pocs", [])
        except (json.JSONDecodeError, OSError):
            pocs = []

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns_sorted:
        sev = str(v["severity"] or "").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    out = output_path or Path.cwd() / f"harpoon_assessment_{target.replace('.', '_')}.html"
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Harpoon Assessment - {target}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100">
  <div class="max-w-6xl mx-auto p-8 space-y-8">
    <header class="space-y-2">
      <h1 class="text-3xl font-bold">Harpoon Security Assessment</h1>
      <p class="text-slate-400">Target: {target}</p>
    </header>

    <section class="grid grid-cols-1 md:grid-cols-4 gap-4">
      <div class="bg-slate-900 rounded p-4"><div class="text-slate-400 text-sm">Subdomains</div><div class="text-2xl font-semibold">{len(subdomains)}</div></div>
      <div class="bg-slate-900 rounded p-4"><div class="text-slate-400 text-sm">Live Endpoints</div><div class="text-2xl font-semibold">{len(endpoints)}</div></div>
      <div class="bg-slate-900 rounded p-4"><div class="text-slate-400 text-sm">Vulnerabilities</div><div class="text-2xl font-semibold">{len(vulns_sorted)}</div></div>
      <div class="bg-slate-900 rounded p-4"><div class="text-slate-400 text-sm">PoCs</div><div class="text-2xl font-semibold">{len(pocs)}</div></div>
    </section>

    <section class="bg-slate-900 rounded p-6">
      <h2 class="text-xl font-semibold mb-4">Executive Summary</h2>
      <p class="text-slate-300">This assessment maps exposed assets, validates vulnerabilities, and provides deterministic proofs of exploitation.</p>
      <p class="text-slate-300 mt-2">Severity breakdown: critical={sev_counts['critical']}, high={sev_counts['high']}, medium={sev_counts['medium']}, low={sev_counts['low']}.</p>
    </section>

    <section class="bg-slate-900 rounded p-6">
      <h2 class="text-xl font-semibold mb-4">Attack Surface Mapping</h2>
      <div class="overflow-auto">
        <table class="w-full text-sm">
          <thead><tr class="text-left text-slate-400"><th class="py-2">Subdomain</th><th>IP</th><th>Alive</th><th>CDN</th></tr></thead>
          <tbody>
            {''.join(f"<tr><td class='py-2'>{r['subdomain']}</td><td>{r['ip_address'] or ''}</td><td>{'yes' if r['is_alive'] else 'no'}</td><td>{r['cdn_provider'] or ''}</td></tr>" for r in subdomains)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="bg-slate-900 rounded p-6 space-y-4">
      <h2 class="text-xl font-semibold">Vulnerability Findings</h2>
      {''.join(f"<article class='border border-slate-700 rounded p-4'><h3 class='font-semibold'>{v['vuln_name']}</h3><p class='text-slate-300 text-sm'>Severity: {v['severity'] or 'unknown'}</p><p class='text-slate-400 text-sm break-all'>{v['url']}</p><pre class='bg-slate-950 p-3 rounded mt-2 text-xs overflow-auto'>{(v['poc_string'] or '').replace('<','&lt;')}</pre></article>" for v in vulns_sorted) or "<p class='text-slate-400'>No vulnerabilities recorded in SQLite.</p>"}
    </section>

    <section class="bg-slate-900 rounded p-6 space-y-4">
      <h2 class="text-xl font-semibold">Deterministic PoC</h2>
      {''.join(f"<article class='border border-slate-700 rounded p-4'><p class='text-slate-300 text-sm'>{p.get('name','finding')}</p><pre class='bg-slate-950 p-3 rounded mt-2 text-xs overflow-auto'>{(p.get('curl_command') or p.get('raw_http_request') or p.get('poc_statement','')).replace('<','&lt;')}</pre></article>" for p in pocs) or "<p class='text-slate-400'>No PoCs generated.</p>"}
    </section>

    <section class="bg-slate-900 rounded p-6">
      <h2 class="text-xl font-semibold mb-4">Remediation Guidance</h2>
      <ul class="list-disc ml-6 text-slate-300 space-y-1">
        <li>Patch vulnerable components and frameworks to current versions.</li>
        <li>Harden input validation and parameterized query usage across endpoints.</li>
        <li>Deploy strict WAF policies and tune false-positive controls.</li>
        <li>Add security regression testing into CI/CD before deployment.</li>
      </ul>
    </section>
  </div>
</body>
</html>
"""
    out.write_text(html, encoding="utf-8")
    return out


def _serve(path: Path, port: int) -> None:
    import os

    os.chdir(str(path.parent))
    server = ThreadingHTTPServer(("127.0.0.1", port), SimpleHTTPRequestHandler)
    print(f"Serving report at http://127.0.0.1:{port}/{path.name}")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Harpoon HTML report from SQLite state.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--poc-log", required=True)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    report = generate_html_report(args.target, Path(args.db), Path(args.poc_log))
    print(report)
    if args.serve:
        _serve(report, args.port)


if __name__ == "__main__":
    main()
