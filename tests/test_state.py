from pathlib import Path

from harpoon.state import PipelineStateManager


def test_sqlite_schema_and_queries(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    state = PipelineStateManager("example.com", db_path=db)
    state.add_subdomain("api.example.com", source="test")
    state.add_resolved_host("api.example.com", "1.2.3.4", source="dnsx")
    state.add_url("https://api.example.com/login", source="httpx", status=200)
    state.add_param("https://api.example.com/login", "id", "GET", source="x8")
    state.set_waf_status("api.example.com", True, vendor="Cloudflare")

    assert "api.example.com" in state.get_alive_subdomains()
    endpoints = state.get_endpoints_with_params()
    assert endpoints and endpoints[0]["param"] == "id"
    waf = state.get_waf_status("api.example.com")
    assert waf["is_present"] is True
