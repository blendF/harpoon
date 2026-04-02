"""WAF detection and adaptive tool-parameter policy."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse
import urllib.request
import urllib.error


_HEADER_VENDOR_MAP: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "incapsula": "Imperva / Incapsula",
    "imperva": "Imperva / Incapsula",
    "fastly": "Fastly",
    "sucuri": "Sucuri",
    "aws cloudfront": "AWS CloudFront",
}


@dataclass
class WafResult:
    host: str
    is_present: bool
    vendor: str
    confidence: float
    baseline_status: int
    probe_status: int
    recommended_rate: int
    evidence: list[str]


def calculate_safe_rate(
    threshold_limit: int,
    window_seconds: int = 300,
    safety_margin: int = 10,
) -> int:
    """
    Conservative rate calculator: requests/second that stays under threshold.

    max_rate = (threshold_limit - safety_margin) / window_seconds
    """
    effective = max(1, threshold_limit - max(0, safety_margin))
    return max(1, int(effective / max(1, window_seconds)))


def _fetch_status_and_headers(url: str, timeout: int = 10) -> tuple[int, dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "Harpoon/Stateful"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return int(getattr(resp, "status", 200)), headers
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        return int(exc.code), headers
    except Exception:
        return 0, {}


def _match_vendor(headers: dict[str, str]) -> tuple[str, float, list[str]]:
    evidence: list[str] = []
    vendor = ""
    conf = 0.0
    joined = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    for sig, name in _HEADER_VENDOR_MAP.items():
        if sig in joined:
            vendor = name
            conf = max(conf, 0.75)
            evidence.append(f"header_signature:{sig}")
    return vendor, conf, evidence


def detect_waf(url: str, threshold_limit: int = 600, cdncheck_result: dict | None = None) -> WafResult:
    """
    Multi-signal WAF detection:
    1) Header/vendor signatures
    2) Behavioral probe status-shift with suspicious payload
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    base_url = f"{parsed.scheme or 'https'}://{parsed.netloc or parsed.path}"
    host = parsed.netloc or parsed.path

    baseline_status, baseline_headers = _fetch_status_and_headers(base_url)
    sqli_probe_url = f"{base_url.rstrip('/')}/?id=1' OR '1'='1"
    xss_probe_url = f"{base_url.rstrip('/')}/?q=<script>alert(1)</script>"
    probe_status, probe_headers = _fetch_status_and_headers(sqli_probe_url)
    xss_status, xss_headers = _fetch_status_and_headers(xss_probe_url)

    vendor, confidence, evidence = _match_vendor(baseline_headers)
    probe_vendor, probe_conf, probe_evidence = _match_vendor(probe_headers)
    if probe_conf > confidence:
        vendor, confidence = probe_vendor, probe_conf
    evidence.extend(probe_evidence)
    xss_vendor, xss_conf, xss_evidence = _match_vendor(xss_headers)
    if xss_conf > confidence:
        vendor, confidence = xss_vendor, xss_conf
    evidence.extend(xss_evidence)

    if cdncheck_result:
        cdn_name = str(cdncheck_result.get("cdn") or cdncheck_result.get("provider") or "").strip()
        if cdn_name:
            vendor = cdn_name
            confidence = max(confidence, 0.85)
            evidence.append(f"cdncheck:{cdn_name}")

    behavior_hit = baseline_status in (200, 301, 302) and probe_status in (403, 406, 429)
    if behavior_hit:
        confidence = max(confidence, 0.8)
        evidence.append(f"status_shift:{baseline_status}->{probe_status}")
    xss_behavior_hit = baseline_status in (200, 301, 302) and xss_status in (403, 406, 429)
    if xss_behavior_hit:
        confidence = max(confidence, 0.82)
        evidence.append(f"xss_status_shift:{baseline_status}->{xss_status}")

    if baseline_status == 0 and probe_status == 0:
        confidence = max(confidence, 0.4)
        evidence.append("network_error_during_probe")

    is_present = confidence >= 0.6
    rate = calculate_safe_rate(threshold_limit=threshold_limit, window_seconds=300, safety_margin=20)
    if is_present:
        rate = min(rate, 2)  # proposal-required strict ffuf throttle
    else:
        rate = max(25, rate)

    return WafResult(
        host=host,
        is_present=is_present,
        vendor=vendor or ("Unknown WAF" if is_present else ""),
        confidence=round(confidence, 3),
        baseline_status=baseline_status,
        probe_status=max(probe_status, xss_status),
        recommended_rate=rate,
        evidence=evidence,
    )


def tool_policy(waf_present: bool) -> dict[str, dict[str, str | bool]]:
    """Return centralized policy rules for downstream scanner wrappers."""
    if waf_present:
        return {
            "nmap": {"skip_on_cdn": True},
            "nikto": {"skip": True},
            "ffuf": {"rate": "2", "filters": "-fs 42,0"},
            "nuclei": {"rate_limit": "50", "concurrency": "10"},
            "sqlmap": {"tamper": "space2comment,randomcase"},
        }
    return {
        "nmap": {"skip_on_cdn": False},
        "nikto": {"skip": False},
        "ffuf": {"rate": "0", "filters": ""},
        "nuclei": {"rate_limit": "0", "concurrency": "25"},
        "sqlmap": {"tamper": ""},
    }

