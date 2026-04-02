"""SQLite-backed central state manager for Harpoon."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from harpoon.config import SESSION_DB_PATH


class PipelineStateManager:
    """Central pipeline state persisted in SQLite."""

    def __init__(self, target: str, db_path: Path | None = None) -> None:
        self.target = target.strip().lower()
        self.db_path = db_path or SESSION_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()
        self._ports: list[dict[str, Any]] = []
        self._paths: list[dict[str, Any]] = []
        self._vhosts: list[dict[str, Any]] = []
        self._events: list[dict[str, Any]] = []
        self._upsert_target(self.target)

    def _create_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    scan_status TEXT NOT NULL DEFAULT 'running',
                    start_time TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subdomain TEXT UNIQUE NOT NULL,
                    ip_address TEXT,
                    is_alive INTEGER DEFAULT 0,
                    cdn_provider TEXT
                );

                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subdomain_id INTEGER NOT NULL,
                    url TEXT UNIQUE NOT NULL,
                    status_code INTEGER,
                    content_length INTEGER,
                    FOREIGN KEY (subdomain_id) REFERENCES subdomains(id)
                );

                CREATE TABLE IF NOT EXISTS technologies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint_id INTEGER NOT NULL,
                    tech_name TEXT NOT NULL,
                    version TEXT,
                    is_waf INTEGER DEFAULT 0,
                    UNIQUE(endpoint_id, tech_name, version),
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
                );

                CREATE TABLE IF NOT EXISTS parameters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint_id INTEGER NOT NULL,
                    param_name TEXT NOT NULL,
                    input_type TEXT,
                    UNIQUE(endpoint_id, param_name, input_type),
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
                );

                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint_id INTEGER NOT NULL,
                    vuln_name TEXT NOT NULL,
                    severity TEXT,
                    poc_string TEXT,
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
                );
                """
            )

    def _upsert_target(self, domain: str, scan_status: str = "running") -> int:
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO targets(domain, scan_status) VALUES(?, ?)",
                (domain, scan_status),
            )
        row = self._conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
        return int(row["id"]) if row else 0

    def _upsert_subdomain(self, subdomain: str, ip_address: str = "", is_alive: bool = False, cdn_provider: str = "") -> int:
        sub = subdomain.strip().lower()
        with self._conn:
            self._conn.execute("INSERT OR IGNORE INTO subdomains(subdomain) VALUES(?)", (sub,))
            self._conn.execute(
                """
                UPDATE subdomains
                SET ip_address = COALESCE(NULLIF(?, ''), ip_address),
                    is_alive = CASE WHEN ? THEN 1 ELSE is_alive END,
                    cdn_provider = COALESCE(NULLIF(?, ''), cdn_provider)
                WHERE subdomain = ?
                """,
                (ip_address, 1 if is_alive else 0, cdn_provider, sub),
            )
        row = self._conn.execute("SELECT id FROM subdomains WHERE subdomain = ?", (sub,)).fetchone()
        return int(row["id"]) if row else 0

    def _ensure_endpoint(self, url: str, status_code: int | None = None, content_length: int | None = None) -> int:
        parsed = urlparse(url)
        host = (parsed.netloc or parsed.path).split(":")[0].strip().lower()
        subdomain_id = self._upsert_subdomain(host, is_alive=True)
        with self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO endpoints(subdomain_id, url, status_code, content_length)
                VALUES(?, ?, ?, ?)
                """,
                (subdomain_id, url.strip(), status_code, content_length),
            )
            self._conn.execute(
                """
                UPDATE endpoints
                SET status_code = COALESCE(?, status_code),
                    content_length = COALESCE(?, content_length)
                WHERE url = ?
                """,
                (status_code, content_length, url.strip()),
            )
        row = self._conn.execute("SELECT id FROM endpoints WHERE url = ?", (url.strip(),)).fetchone()
        return int(row["id"]) if row else 0

    def add_event(self, phase: str, message: str, source: str) -> None:
        with self._lock:
            self._events.append({"phase": phase, "message": message, "source": source})

    def add_subdomain(self, subdomain: str, source: str = "unknown", confidence: float = 1.0) -> None:
        _ = (source, confidence)
        with self._lock:
            self._upsert_subdomain(subdomain)

    def add_ip(self, ip: str, source: str = "unknown", confidence: float = 1.0) -> None:
        _ = (source, confidence)

    def add_resolved_host(self, host: str, ip: str, source: str = "dnsx", confidence: float = 1.0) -> None:
        _ = (source, confidence)
        with self._lock:
            self._upsert_subdomain(host, ip_address=ip, is_alive=True)

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
        with self._lock:
            self._ports.append(
                {
                    "ip": ip,
                    "port": int(port),
                    "protocol": protocol.lower(),
                    "service": service,
                    "product": product,
                    "version": version,
                    "source": source,
                    "confidence": confidence,
                }
            )

    def add_url(self, url: str, source: str = "unknown", status: int | None = None, title: str = "", confidence: float = 1.0) -> None:
        _ = (source, title, confidence)
        with self._lock:
            self._ensure_endpoint(url, status_code=status)

    def add_technology(self, host: str, technology: str, source: str = "unknown", confidence: float = 1.0, version: str = "") -> None:
        _ = (source, confidence)
        with self._lock:
            endpoint_row = self._conn.execute(
                "SELECT id FROM endpoints WHERE url LIKE ? ORDER BY id DESC LIMIT 1",
                (f"%{host.strip().lower()}%",),
            ).fetchone()
            endpoint_id = int(endpoint_row["id"]) if endpoint_row else self._ensure_endpoint(f"https://{host.strip().lower()}")
            with self._conn:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO technologies(endpoint_id, tech_name, version, is_waf)
                    VALUES(?, ?, ?, 0)
                    """,
                    (endpoint_id, technology.strip().lower(), version.strip()),
                )

    def add_path(self, url: str, path: str, source: str = "unknown", confidence: float = 1.0) -> None:
        full = f"{url.rstrip('/')}/{path.lstrip('/')}"
        with self._lock:
            self._ensure_endpoint(full)
            self._paths.append({"url": url.rstrip("/"), "path": f"/{path.lstrip('/')}", "source": source, "confidence": confidence})

    def add_vhost(self, vhost: str, source: str = "unknown", confidence: float = 1.0) -> None:
        with self._lock:
            self._vhosts.append({"value": vhost.strip().lower(), "source": source, "confidence": confidence})

    def add_param(self, url: str, param: str, method: str, source: str = "unknown", confidence: float = 1.0) -> None:
        _ = (source, confidence)
        endpoint_id = self._ensure_endpoint(url)
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO parameters(endpoint_id, param_name, input_type) VALUES(?, ?, ?)",
                (endpoint_id, param.strip(), method.upper().strip()),
            )

    def add_secret(self, secret_excerpt: str, entropy: float, location: str, source: str = "js-analysis") -> None:
        endpoint_id = self._ensure_endpoint(location if location.startswith(("http://", "https://")) else f"https://{self.target}")
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO vulnerabilities(endpoint_id, vuln_name, severity, poc_string)
                VALUES(?, ?, ?, ?)
                """,
                (endpoint_id, "Potential Secret Exposure", "medium", f"{source}: entropy={round(float(entropy), 3)} sample={secret_excerpt[:120]}"),
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
        _ = (confidence, recommended_rate, source)
        endpoint_id = self._ensure_endpoint(f"https://{host.strip().lower()}")
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO technologies(endpoint_id, tech_name, version, is_waf)
                VALUES(?, ?, ?, ?)
                """,
                (endpoint_id, vendor or "unknown-waf", "", 1 if is_present else 0),
            )
            self._upsert_subdomain(host, is_alive=True, cdn_provider=vendor if is_present else "")

    def get_waf_status(self, host: str) -> dict[str, Any]:
        row = self._conn.execute(
            """
            SELECT t.tech_name AS vendor, t.is_waf, s.cdn_provider
            FROM technologies t
            JOIN endpoints e ON e.id = t.endpoint_id
            JOIN subdomains s ON s.id = e.subdomain_id
            WHERE s.subdomain = ? AND t.is_waf = 1
            ORDER BY t.id DESC
            LIMIT 1
            """,
            (host.strip().lower(),),
        ).fetchone()
        if not row:
            return {"is_present": False, "vendor": ""}
        return {"is_present": bool(row["is_waf"]), "vendor": row["vendor"] or row["cdn_provider"] or ""}

    def get_alive_subdomains(self) -> list[str]:
        rows = self._conn.execute("SELECT subdomain FROM subdomains WHERE is_alive = 1 ORDER BY subdomain").fetchall()
        return [str(r["subdomain"]) for r in rows]

    def get_endpoints_with_params(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT e.url, p.param_name, p.input_type
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            ORDER BY e.url, p.param_name
            """
        ).fetchall()
        return [{"url": str(r["url"]), "param": str(r["param_name"]), "method": str(r["input_type"] or "GET")} for r in rows]

    def get_targets_for_phase(self, phase: str) -> list[str]:
        phase_l = phase.lower()
        if phase_l in ("http-probe", "httpx", "katana", "zap", "ffuf-dir", "nuclei"):
            urls = [r["url"] for r in self._conn.execute("SELECT url FROM endpoints ORDER BY id").fetchall()]
            return urls or [f"https://{self.target}"]
        if phase_l in ("ffuf-params", "sqlmap"):
            rows = self.get_endpoints_with_params()
            return sorted({r["url"] for r in rows}) or [f"https://{self.target}"]
        return [f"https://{self.target}"]

    def get(self, key: str, default: Any | None = None) -> Any:
        if key == "subdomains":
            rows = self._conn.execute("SELECT subdomain, ip_address, is_alive, cdn_provider FROM subdomains ORDER BY subdomain").fetchall()
            return [{"value": str(r["subdomain"]), "ip": r["ip_address"], "is_alive": bool(r["is_alive"]), "cdn_provider": r["cdn_provider"] or ""} for r in rows]
        if key == "urls":
            rows = self._conn.execute("SELECT url, status_code, content_length FROM endpoints ORDER BY id").fetchall()
            return [{"url": str(r["url"]), "status": r["status_code"], "content_length": r["content_length"]} for r in rows]
        if key == "technologies":
            rows = self._conn.execute(
                """
                SELECT s.subdomain, t.tech_name, t.version, t.is_waf
                FROM technologies t
                JOIN endpoints e ON e.id = t.endpoint_id
                JOIN subdomains s ON s.id = e.subdomain_id
                ORDER BY s.subdomain, t.tech_name
                """
            ).fetchall()
            out: dict[str, list[dict[str, Any]]] = {}
            for row in rows:
                host = str(row["subdomain"])
                out.setdefault(host, []).append({"tech": str(row["tech_name"]), "version": row["version"] or "", "is_waf": bool(row["is_waf"])})
            return out
        if key == "params":
            return self.get_endpoints_with_params()
        if key == "ports":
            return list(self._ports)
        if key == "paths":
            return list(self._paths)
        if key == "vhosts":
            return list(self._vhosts)
        if key == "events":
            return list(self._events)
        return default if default is not None else []

    def to_json(self) -> str:
        snapshot = {
            "target": self.target,
            "db_path": str(self.db_path),
            "subdomains": self.get("subdomains"),
            "urls": self.get("urls"),
            "technologies": self.get("technologies"),
            "params": self.get("params"),
            "ports": self.get("ports"),
            "paths": self.get("paths"),
            "vhosts": self.get("vhosts"),
        }
        return json.dumps(snapshot, indent=2, ensure_ascii=True)

    def save(self, path: Path) -> None:
        self._conn.commit()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")

    def close(self) -> None:
        try:
            self._conn.commit()
            self._conn.close()
        except sqlite3.Error:
            pass

