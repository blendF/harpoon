from pathlib import Path

from harpoon.poc_generator import generate_pocs


def test_generate_pocs_includes_curl_and_raw(tmp_path: Path) -> None:
    nuclei = tmp_path / "nuclei.jsonl"
    sqlmap = tmp_path / "sqlmap.txt"
    out = tmp_path / "poc.json"

    nuclei.write_text(
        '{"template-id":"xss","info":{"name":"XSS","severity":"high"},"matched-at":"https://a/b","curl-command":"curl https://a/b","request":"GET /b HTTP/1.1"}\n',
        encoding="utf-8",
    )
    sqlmap.write_text("testing URL 'https://a/b'\nParameter: id (GET)\ninjectable", encoding="utf-8")
    pocs = generate_pocs(nuclei, sqlmap, out)
    assert pocs
    assert any("curl" in (p.get("curl_command", "")) for p in pocs)
