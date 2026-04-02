import sqlite3
from pathlib import Path

from viewreport import generate_html_report


def test_viewreport_generation(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        """
        CREATE TABLE targets (id INTEGER PRIMARY KEY, domain TEXT, scan_status TEXT, start_time TEXT);
        CREATE TABLE subdomains (id INTEGER PRIMARY KEY, subdomain TEXT, ip_address TEXT, is_alive INTEGER, cdn_provider TEXT);
        CREATE TABLE endpoints (id INTEGER PRIMARY KEY, subdomain_id INTEGER, url TEXT, status_code INTEGER, content_length INTEGER);
        CREATE TABLE vulnerabilities (id INTEGER PRIMARY KEY, endpoint_id INTEGER, vuln_name TEXT, severity TEXT, poc_string TEXT);
        """
    )
    conn.execute("INSERT INTO subdomains VALUES (1,'api.example.com','1.2.3.4',1,'Cloudflare')")
    conn.execute("INSERT INTO endpoints VALUES (1,1,'https://api.example.com',200,100)")
    conn.execute("INSERT INTO vulnerabilities VALUES (1,1,'SQL Injection','high','curl ...')")
    conn.commit()
    conn.close()

    poc = tmp_path / "poc.json"
    poc.write_text('{"pocs":[{"name":"SQL Injection","curl_command":"curl https://api.example.com"}]}', encoding="utf-8")
    html = generate_html_report("example.com", db, poc, output_path=tmp_path / "report.html")
    text = html.read_text(encoding="utf-8")
    assert "Executive Summary" in text
    assert "Deterministic PoC" in text
