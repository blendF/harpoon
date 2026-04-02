"""Rich-powered CLI telemetry utilities."""
from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic

from rich.console import Console
from rich.panel import Panel

console = Console()


def phase_banner(name: str) -> None:
    console.print(Panel.fit(f"[bold cyan]{name}[/bold cyan]"))


def info(msg: str) -> None:
    console.print(f"[cyan][*][/cyan] {msg}")


def success(msg: str) -> None:
    console.print(f"[green][+][/green] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow][!][/yellow] {msg}")


def error(msg: str) -> None:
    console.print(f"[red][-][/red] {msg}")


def critical(msg: str) -> None:
    console.print(f"[bold red blink][CRITICAL][/bold red blink] {msg}")


def estimate_duration(subdomain_count: int, waf_present: bool) -> int:
    base = max(3, subdomain_count // 5)
    return base * (2 if waf_present else 1)


@dataclass
class Counters:
    """Lightweight real-time counters."""

    started_at: float = field(default_factory=monotonic)
    subdomains: int = 0
    endpoints: int = 0
    params: int = 0
    vulns: int = 0

    def show(self) -> None:
        elapsed = int(monotonic() - self.started_at)
        console.print(
            f"[dim]assets[/dim] subdomains={self.subdomains} endpoints={self.endpoints} "
            f"params={self.params} vulns={self.vulns} elapsed={elapsed}s"
        )
