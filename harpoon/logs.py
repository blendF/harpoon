"""Ensure log directory exists and provide helpers."""
from pathlib import Path

from harpoon.config import LOG_DIR


def ensure_log_dir() -> Path:
    """Create harpoon_logs if needed; return LOG_DIR."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR
