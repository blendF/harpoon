# PyInstaller spec for Harpoon – single Windows executable
# Run: pyinstaller harpoon.spec

import sys

block_cipher = None

# Bundle HARPOONASCIIART.txt so the exe can show it from sys._MEIPASS
added_files = [
    ('HARPOONASCIIART.txt', '.'),
]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=added_files,
    hiddenimports=['harpoon', 'harpoon.config', 'harpoon.startup', 'harpoon.target', 'harpoon.logs',
                   'harpoon.runner', 'harpoon.report', 'harpoon.ollama_client', 'harpoon.spinner',
                   'harpoon.nuclei_context',
                   'harpoon.scanners', 'harpoon.scanners.zap_scan', 'harpoon.scanners.sqlmap_scan',
                   'harpoon.scanners.gobuster_scan', 'harpoon.scanners.nmap_scan', 'harpoon.scanners.nuclei_scan',
                   'harpoon.parsers', 'harpoon.parsers.nmap_parser',
                   'harpoon.exploit', 'harpoon.exploit.metasploit_runner'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Harpoon',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,   # CLI
)
