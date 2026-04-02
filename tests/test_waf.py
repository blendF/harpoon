from harpoon.waf import detect_waf


def test_waf_detection_with_xss_and_cdn_signal(monkeypatch):
    calls = {"n": 0}

    def fake_fetch(_url: str, timeout: int = 10):
        calls["n"] += 1
        if calls["n"] == 1:
            return 200, {"server": "nginx"}
        if calls["n"] == 2:
            return 403, {"server": "cloudflare"}
        return 403, {"cf-ray": "abc"}

    monkeypatch.setattr("harpoon.waf._fetch_status_and_headers", fake_fetch)
    result = detect_waf("https://example.com", cdncheck_result={"provider": "Cloudflare"})
    assert result.is_present is True
    assert result.vendor
