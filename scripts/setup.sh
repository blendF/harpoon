#!/usr/bin/env bash
# Harpoon setup: Debian/Ubuntu/Kali/WSL — OS packages, Go/ProjectDiscovery tools, Rust x8, Python venv.
# Run from repo root or scripts/:  bash scripts/setup.sh
#
# Python packages installed below must stay in sync with harpoon/install_hints.py (VENV_PIP_HINT_LINES).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Harpoon: installing OS packages (needs sudo)"
sudo apt-get update
# libpcap-dev + build-essential: CGO (e.g. naabu / gopacket → pcap.h).
# python3-venv: PEP 668 safe installs. git: ParamSpider via pip from GitHub.
sudo apt-get install -y \
  build-essential pkg-config libpcap-dev \
  python3-venv git \
  seclists nmap sqlmap nikto curl golang-go python3-pip zaproxy || true

echo "==> Harpoon: Go toolchain paths (add to ~/.profile if missing)"
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

echo "==> Harpoon: ProjectDiscovery + related Go tools"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
echo "==> Harpoon: x8 (Rust release binary; upstream is not go install–able)"
mkdir -p "$GOPATH/bin"
_arch="$(uname -m)"
if [[ "$_arch" == "x86_64" ]] || [[ "$_arch" == "amd64" ]]; then
  curl -fsSL "https://github.com/Sh1Yo/x8/releases/download/v4.3.0/x86_64-linux-x8.gz" | gunzip -c >"$GOPATH/bin/x8"
  chmod +x "$GOPATH/bin/x8"
else
  echo "    (!) No bundled x8 binary for ${_arch}; use: cargo install x8   (needs rustc/cargo), or https://github.com/Sh1Yo/x8/releases"
  if command -v cargo >/dev/null 2>&1; then
    cargo install x8 --locked || echo "    (!) cargo install x8 failed — try https://github.com/Sh1Yo/x8/releases"
  fi
fi
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/sensepost/gowitness@latest

echo "==> Harpoon: Python venv in repo (PEP 668 / externally-managed system Python)"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# --- Keep in sync with harpoon/install_hints.VENV_PIP_HINT_LINES ---
.venv/bin/pip install --upgrade pip
.venv/bin/pip install "pyinstaller>=6.10.0" rich aiosqlite arjun uro pytest pytest-asyncio
.venv/bin/pip install "paramspider @ git+https://github.com/devanshbatham/ParamSpider.git"

echo "==> Done. Run Harpoon from the repo root:"
echo "    bash scripts/run_harpoon.sh"
echo "Or activate the venv and set PATH for Go tools:"
echo "    source .venv/bin/activate"
echo "    export PATH=\"\$PATH:\$HOME/go/bin:\$HOME/.local/bin\""
echo "    python3 main.py"
