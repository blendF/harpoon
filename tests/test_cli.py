from harpoon.cli import Counters, estimate_duration


def test_estimated_duration_increases_with_waf() -> None:
    no_waf = estimate_duration(20, False)
    with_waf = estimate_duration(20, True)
    assert with_waf >= no_waf


def test_counters_object() -> None:
    c = Counters()
    c.subdomains = 3
    c.endpoints = 5
    c.params = 2
    c.vulns = 1
    c.show()
