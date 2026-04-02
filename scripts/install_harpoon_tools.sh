#!/usr/bin/env bash
# Harpoon dependency installer (Debian/Ubuntu/Kali/WSL).
# Run from repo root:  bash scripts/install_harpoon_tools.sh
set -euo pipefail

echo "==> Harpoon: installing OS packages (needs sudo)"
sudo apt-get update
sudo apt-get install -y seclists nmap sqlmap nikto curl golang-go python3-pip zaproxy || true

echo "==> Harpoon: Go toolchain paths (add to ~/.profile if missing)"
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

echo "==> Harpoon: ProjectDiscovery + related Go tools"
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
go install -v github.com/Sh1Yo/x8/cmd/x8@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/sensepost/gowitness@latest

echo "==> Harpoon: Python tools (user install)"
python3 -m pip install --user --upgrade pip
python3 -m pip install --user "git+https://github.com/devanshbatham/ParamSpider.git" arjun rich

echo "==> Done. Ensure these are on your PATH:"
echo "    export PATH=\"\$PATH:\$HOME/go/bin:\$HOME/.local/bin\""
echo "Then run: python3 main.py"
