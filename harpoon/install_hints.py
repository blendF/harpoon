"""
Map missing Harpoon dependencies to real install commands.

Many tools (ProjectDiscovery, etc.) are Go binaries — they are NOT Debian packages.
`apt install alterx` / `apt install asnmap` will fail on typical Kali/Ubuntu repos.
"""
from __future__ import annotations

from dataclasses import dataclass

# Python venv install lines — keep in sync with scripts/setup.sh (pip block after `python3 -m venv .venv`).
VENV_PIP_HINT_LINES: tuple[str, ...] = (
    "   .venv/bin/pip install --upgrade pip",
    '   .venv/bin/pip install "pyinstaller>=6.10.0" rich aiosqlite arjun uro pytest pytest-asyncio',
    '   .venv/bin/pip install "paramspider @ git+https://github.com/devanshbatham/ParamSpider.git"',
)


@dataclass(frozen=True)
class _Recipe:
    apt: tuple[str, ...] = ()
    go_install: str | None = None
    pip: tuple[str, ...] = ()
    # Extra install lines when this tool is missing (e.g. Rust release binary, no go install).
    extra_hints: tuple[str, ...] = ()


# Harpoon logical tool id -> how to install
_RECIPES: dict[str, _Recipe] = {
    "subfinder": _Recipe(go_install="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "crtsh": _Recipe(apt=("curl",)),
    "amass": _Recipe(apt=("amass",)),
    "dnsx": _Recipe(go_install="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "httpx": _Recipe(go_install="github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "naabu": _Recipe(go_install="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "uncover": _Recipe(go_install="github.com/projectdiscovery/uncover/cmd/uncover@latest"),
    "tlsx": _Recipe(go_install="github.com/projectdiscovery/tlsx/cmd/tlsx@latest"),
    "asnmap": _Recipe(go_install="github.com/projectdiscovery/asnmap/cmd/asnmap@latest"),
    "mapcidr": _Recipe(go_install="github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"),
    "cdncheck": _Recipe(go_install="github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"),
    "shuffledns": _Recipe(go_install="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"),
    "chaos": _Recipe(go_install="github.com/projectdiscovery/chaos-client/cmd/chaos@latest"),
    "alterx": _Recipe(go_install="github.com/projectdiscovery/alterx/cmd/alterx@latest"),
    "x8": _Recipe(
        extra_hints=(
            "Upstream x8 is Rust; `go install github.com/Sh1Yo/x8/cmd/x8` no longer exists.",
            "Linux x86_64 — release binary into your Go bin dir (on PATH with run_harpoon.sh):",
            'mkdir -p "$HOME/go/bin" && curl -fsSL "https://github.com/Sh1Yo/x8/releases/download/v4.3.0/x86_64-linux-x8.gz" | gunzip -c > "$HOME/go/bin/x8" && chmod +x "$HOME/go/bin/x8"',
            "Other arches: `cargo install x8` (add ~/.cargo/bin to PATH) or see https://github.com/Sh1Yo/x8/releases",
        ),
    ),
    "interactsh-client": _Recipe(go_install="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    "notify": _Recipe(go_install="github.com/projectdiscovery/notify/cmd/notify@latest"),
    "katana": _Recipe(go_install="github.com/projectdiscovery/katana/cmd/katana@latest"),
    "waybackurls": _Recipe(go_install="github.com/tomnomnom/waybackurls@latest"),
    "gau": _Recipe(go_install="github.com/lc/gau/v2/cmd/gau@latest"),
    "paramspider": _Recipe(pip=("git+https://github.com/devanshbatham/ParamSpider.git",)),
    "arjun": _Recipe(apt=("arjun",), pip=("arjun",)),
    "ffuf": _Recipe(apt=("ffuf",), go_install="github.com/ffuf/ffuf/v2@latest"),
    "sqlmap": _Recipe(apt=("sqlmap",)),
    "nuclei": _Recipe(apt=("nuclei",), go_install="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "nikto": _Recipe(apt=("nikto",)),
    "nmap": _Recipe(apt=("nmap",)),
    "zap.sh": _Recipe(apt=("zaproxy",)),
    "seclists": _Recipe(apt=("seclists",)),
    # Pseudo-id when the Go compiler is required but not on PATH
    "go": _Recipe(apt=("golang-go",)),
}


def missing_requires_go_install(missing_tool_ids: list[str]) -> bool:
    """True if any missing Harpoon tool is normally installed via `go install`."""
    for name in missing_tool_ids:
        if name in ("seclists", "go"):
            continue
        r = _RECIPES.get(name)
        if r and r.go_install:
            return True
    return False


def format_install_hints(missing: list[str]) -> list[str]:
    """Return human-readable lines (suitable for Rich warn/info)."""
    lines: list[str] = []
    missing_set = set(missing)
    if not missing_set:
        return lines

    lines.append("── Install commands for what is missing ──")

    apt_pkgs: set[str] = set()
    go_rows: list[tuple[str, str]] = []
    pip_specs: set[str] = set()
    extra_hint_blocks: list[tuple[str, tuple[str, ...]]] = []
    for name in sorted(missing_set):
        r = _RECIPES.get(name)
        if not r:
            continue
        apt_pkgs.update(r.apt)
        if r.go_install:
            go_rows.append((name, r.go_install))
        for p in r.pip:
            pip_specs.add(p)
        if r.extra_hints:
            extra_hint_blocks.append((name, r.extra_hints))

    # Only mention installing the Go *compiler* when preflight added pseudo-dependency "go".
    if "go" in missing_set:
        lines.append(
            "The `go` compiler is not on your PATH but is required to build several missing tools. "
            "Install it first (Debian/Kali: package golang-go, in the apt line below), then run the `go install` commands."
        )
    elif go_rows:
        lines.append(
            "Note: several missing tools are Go binaries (alterx, dnsx, …) — usually no apt package; use section (2) `go install`."
        )
        lines.append(
            "If `go install` fails with pcap.h / gopacket: "
            "`sudo apt install -y libpcap-dev pkg-config build-essential`, then retry the failed `go install` line(s)."
        )

    if apt_pkgs:
        lines.append("1) Apt packages (Debian/Kali/Ubuntu) — one line:")
        lines.append(f"   sudo apt update && sudo apt install -y {' '.join(sorted(apt_pkgs))}")

    if go_rows:
        lines.append("2) Go tools — run these (add Go bin to PATH afterward):")
        lines.append('   export PATH="$PATH:$(go env GOPATH)/bin"')
        for logical, mod in go_rows:
            lines.append(f"   go install -v {mod}   # missing: {logical}")

    for logical, hints in extra_hint_blocks:
        lines.append(f"Install {logical} (not via go install above):")
        for h in hints:
            lines.append(f"   {h}")

    if pip_specs:
        lines.append(
            "3) Python venv (Kali/Debian PEP 668 blocks `pip install --user` on system Python). "
            "Easiest: `bash scripts/setup.sh` from the repo root. Manual equivalent:"
        )
        lines.append("   sudo apt install -y python3-venv git   # if needed")
        lines.append("   python3 -m venv .venv")
        lines.extend(VENV_PIP_HINT_LINES)

    if "seclists" in missing_set:
        lines.append("SecLists: bundled mode → set HARPOON_USE_BUNDLED_WORDLISTS=1 in .harpoon.env (no apt seclists needed).")

    lines.append(
        "4) Then run with PATH that includes the repo’s .venv/bin and $HOME/go/bin "
        "(scripts/run_harpoon.sh adds .venv/bin, ~/.cargo/bin, ~/.local/bin automatically)."
    )

    return lines
