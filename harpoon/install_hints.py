"""
Map missing Harpoon dependencies to real install commands.

Many tools (ProjectDiscovery, etc.) are Go binaries — they are NOT Debian packages.
`apt install alterx` / `apt install asnmap` will fail on typical Kali/Ubuntu repos.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _Recipe:
    apt: tuple[str, ...] = ()
    go_install: str | None = None
    pip: tuple[str, ...] = ()


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
    "x8": _Recipe(go_install="github.com/Sh1Yo/x8/cmd/x8@latest"),
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
    for name in sorted(missing_set):
        r = _RECIPES.get(name)
        if not r:
            continue
        apt_pkgs.update(r.apt)
        if r.go_install:
            go_rows.append((name, r.go_install))
        for p in r.pip:
            pip_specs.add(p)

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

    if apt_pkgs:
        lines.append("1) Apt packages (Debian/Kali/Ubuntu) — one line:")
        lines.append(f"   sudo apt update && sudo apt install -y {' '.join(sorted(apt_pkgs))}")

    if go_rows:
        lines.append("2) Go tools — run these (add Go bin to PATH afterward):")
        lines.append('   export PATH="$PATH:$(go env GOPATH)/bin"')
        for logical, mod in go_rows:
            lines.append(f"   go install -v {mod}   # missing: {logical}")

    if pip_specs:
        lines.append("3) Python CLI — user install:")
        lines.append(f"   python3 -m pip install --user {' '.join(sorted(pip_specs))}")

    if "seclists" in missing_set:
        lines.append("SecLists: bundled mode → set HARPOON_USE_BUNDLED_WORDLISTS=1 in .harpoon.env (no apt seclists needed).")

    lines.append('4) Then ensure PATH includes: $HOME/go/bin and $HOME/.local/bin (see scripts/run_harpoon.sh).')

    return lines
