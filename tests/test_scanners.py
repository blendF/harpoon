from harpoon.scanners.ffuf_scan import _tech_extensions


def test_ffuf_tech_extensions() -> None:
    exts = _tech_extensions(["IIS", "PHP", "Java"])
    assert ".aspx" in exts
    assert ".php" in exts
    assert ".jsp" in exts
