"""Central state manager for Harpoon's orchestration pipeline."""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Entity:
    """Generic state entity with provenance metadata."""

    value: Any
    source: str
    confidence: float = 1.0
    timestamp: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


class PipelineStateManager:
    """
    In-memory source-of-truth for all discovered targets and findings.

    The state manager intentionally stores normalized entities as dictionaries
    with source/confidence/timestamp metadata so downstream phases can make
    deterministic decisions even when some tools are unavailable.
    """

    def __init__(self, target: str) -> None:
        self.target = target
        self._lock = threading.RLock()
        self._state: dict[str, Any] = {
            "target": target,
            "waf": {},
            "subdomains": [],
            "resolved_hosts": [],  # [{"host": str, "ip": str, ...meta}]
            "ips": [],
            "ports": [],  # [{"ip": str, "port": int, "protocol": str, ...meta}]
            "urls": [],  # [{"url": str, "status": int, "title": str, ...meta}]
            "technologies": {},  # {host: [techs]}
            "paths": [],  # [{"url": str, "path": str, ...meta}]
            "vhosts": [],
            "params": [],  # [{"url": str, "param": str, "method": "GET/POST", ...meta}]
            "js_files": [],
            "secrets": [],
            "nuclei_findings": [],
            "sqlmap_findings": [],
            "events": [],
        }

    def _append_unique(self, key: str, value: dict[str, Any], dedup_field: str) -> None:
        with self._lock:
            existing = {item.get(dedup_field) for item in self._state[key]}
            if value.get(dedup_field) not in existing:
                self._state[key].append(value)

    def add_event(self, phase: str, message: str, source: str) -> None:
        with self._lock:
            self._state["events"].append(
                {
                    "phase": phase,
                    "message": message,
                    "source": source,
                    "timestamp": _utc_now(),
                }
            )

    def add_subdomain(self, subdomain: str, source: str, confidence: float = 1.0) -> None:
        self._append_unique(
            "subdomains",
            Entity(subdomain.strip().lower(), source, confidence).to_dict(),
            "value",
        )

    def add_ip(self, ip: str, source: str, confidence: float = 1.0) -> None:
        self._append_unique("ips", Entity(ip, source, confidence).to_dict(), "value")

    def add_resolved_host(self, host: str, ip: str, source: str, confidence: float = 1.0) -> None:
        self._append_unique(
            "resolved_hosts",
            {
                "host": host.strip().lower(),
                "ip": ip,
                "source": source,
                "confidence": confidence,
                "timestamp": _utc_now(),
            },
            "host",
        )
        self.add_ip(ip, source, confidence)

    def add_port(
        self,
        ip: str,
        port: int,
        protocol: str,
        service: str = "",
        product: str = "",
        version: str = "",
        source: str = "nmap",
        confidence: float = 1.0,
    ) -> None:
        dedup = f"{ip}:{port}/{protocol}"
        self._append_unique(
            "ports",
            {
                "dedup": dedup,
                "ip": ip,
                "port": int(port),
                "protocol": protocol.lower(),
                "service": service,
                "product": product,
                "version": version,
                "source": source,
                "confidence": confidence,
                "timestamp": _utc_now(),
            },
            "dedup",
        )

    def add_url(
        self,
        url: str,
        source: str,
        status: int | None = None,
        title: str = "",
        confidence: float = 1.0,
    ) -> None:
        self._append_unique(
            "urls",
            {
                "url": url.strip(),
                "status": status,
                "title": title,
                "source": source,
                "confidence": confidence,
                "timestamp": _utc_now(),
            },
            "url",
        )

    def add_technology(self, host: str, technology: str, source: str, confidence: float = 1.0) -> None:
        host_key = host.strip().lower()
        tech = technology.strip().lower()
        with self._lock:
            if host_key not in self._state["technologies"]:
                self._state["technologies"][host_key] = []
            entries = {e["tech"] for e in self._state["technologies"][host_key]}
            if tech not in entries:
                self._state["technologies"][host_key].append(
                    {
                        "tech": tech,
                        "source": source,
                        "confidence": confidence,
                        "timestamp": _utc_now(),
                    }
                )

    def add_path(self, url: str, path: str, source: str, confidence: float = 1.0) -> None:
        dedup = f"{url.rstrip('/')}{path if path.startswith('/') else '/' + path}"
        self._append_unique(
            "paths",
            {
                "url": url.rstrip("/"),
                "path": path if path.startswith("/") else f"/{path}",
                "dedup": dedup,
                "source": source,
                "confidence": confidence,
                "timestamp": _utc_now(),
            },
            "dedup",
        )

    def add_vhost(self, vhost: str, source: str, confidence: float = 1.0) -> None:
        self._append_unique(
            "vhosts",
            Entity(vhost.strip().lower(), source, confidence).to_dict(),
            "value",
        )

    def add_param(
        self,
        url: str,
        param: str,
        method: str,
        source: str,
        confidence: float = 1.0,
    ) -> None:
        dedup = f"{method.upper()}:{url}:{param}"
        self._append_unique(
            "params",
            {
                "url": url,
                "param": param,
                "method": method.upper(),
                "dedup": dedup,
                "source": source,
                "confidence": confidence,
                "timestamp": _utc_now(),
            },
            "dedup",
        )

    def add_js_file(self, js_url: str, source: str) -> None:
        self._append_unique(
            "js_files",
            Entity(js_url.strip(), source, 1.0).to_dict(),
            "value",
        )

    def add_secret(
        self,
        secret_excerpt: str,
        entropy: float,
        location: str,
        source: str,
    ) -> None:
        dedup = f"{location}:{secret_excerpt[:40]}"
        self._append_unique(
            "secrets",
            {
                "dedup": dedup,
                "location": location,
                "secret_excerpt": secret_excerpt[:200],
                "entropy": round(float(entropy), 3),
                "source": source,
                "timestamp": _utc_now(),
            },
            "dedup",
        )

    def set_waf_status(
        self,
        host: str,
        is_present: bool,
        vendor: str = "",
        confidence: float = 0.0,
        recommended_rate: int = 0,
        source: str = "waf-engine",
    ) -> None:
        with self._lock:
            self._state["waf"][host.lower()] = {
                "is_present": is_present,
                "vendor": vendor,
                "confidence": confidence,
                "recommended_rate": recommended_rate,
                "source": source,
                "timestamp": _utc_now(),
            }

    def get_waf_status(self, host: str) -> dict[str, Any]:
        with self._lock:
            return dict(self._state["waf"].get(host.lower(), {}))

    def get_targets_for_phase(self, phase: str) -> list[str]:
        with self._lock:
            phase_l = phase.lower()
            if phase_l in ("http-probe", "httpx", "katana", "zap"):
                return [u["url"] for u in self._state["urls"]]
            if phase_l in ("ffuf-dir", "gobuster"):
                return [u["url"] for u in self._state["urls"]] or [self.target]
            if phase_l in ("ffuf-params", "sqlmap"):
                urls = [p["url"].rstrip("/") + p["path"] for p in self._state["paths"]]
                return sorted(set(urls))[:50] or [self.target]
            if phase_l in ("nuclei",):
                targets = [u["url"] for u in self._state["urls"]]
                targets.extend([p["url"].rstrip("/") + p["path"] for p in self._state["paths"]])
                targets.extend([v["value"] for v in self._state["vhosts"]])
                return sorted(set(targets))
            return [self.target]

    def to_json(self) -> str:
        with self._lock:
            return json.dumps(self._state, indent=2, ensure_ascii=True)

    def get(self, key: str, default: Any | None = None) -> Any:
        with self._lock:
            return self._state.get(key, default if default is not None else [])

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def from_json(cls, text: str) -> "PipelineStateManager":
        data = json.loads(text)
        state = cls(target=data.get("target", ""))
        state._state = data
        return state

    @classmethod
    def load(cls, path: Path, default_target: str = "") -> "PipelineStateManager":
        if not path.exists():
            return cls(default_target)
        try:
            return cls.from_json(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return cls(default_target)

