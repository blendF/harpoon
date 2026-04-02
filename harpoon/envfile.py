"""Load optional repo-local environment defaults before other harpoon imports."""
from __future__ import annotations

import os
from pathlib import Path


def load_harpoon_env(repo_root: Path) -> Path | None:
    """
    Read .harpoon.env or harpoon.env from repo root.

    Only sets variables that are not already present in os.environ
    (interactive exports and the shell take precedence).

    Supports optional ``export KEY=value`` lines.
    """
    for fname in (".harpoon.env", "harpoon.env"):
        path = repo_root / fname
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
        return path
    return None
