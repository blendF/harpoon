"""Ollama LLM for report summarization. Uses qwen3.5:cloud by default (no API key needed)."""
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from harpoon.config import OLLAMA_CMD, OLLAMA_MODEL
from harpoon.runner import find_cmd

# Timeout for Ollama (qwen3.5:cloud needs internet; reduce if it hangs)
OLLAMA_TIMEOUT = int(os.environ.get("HARPOON_OLLAMA_TIMEOUT", "120"))


def ollama_available() -> bool:
    return bool(find_cmd("ollama") or find_cmd(OLLAMA_CMD.split()[0]))


def query_ollama(prompt: str, model: str = OLLAMA_MODEL, timeout: int = OLLAMA_TIMEOUT) -> Optional[str]:
    """
    Send prompt to Ollama model. Uses stdin or temp file to avoid encoding/limit issues.
    qwen3.5:cloud runs via Ollama cloud (internet required, no separate API key).
    """
    cmd = find_cmd("ollama") or find_cmd(OLLAMA_CMD.split()[0])
    if not cmd:
        return None
    try:
        # Use temp file on Windows to avoid stdin encoding/buffer issues with large prompts
        use_file = os.name == "nt" and len(prompt) > 8000
        if use_file:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".txt", delete=False) as f:
                f.write(prompt)
                tmp_path = f.name
            try:
                with open(tmp_path, "r", encoding="utf-8") as stdin_f:
                    result = subprocess.run(
                        [cmd, "run", model],
                        stdin=stdin_f,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=timeout,
                    )
            finally:
                os.unlink(tmp_path)
        else:
            result = subprocess.run(
                [cmd, "run", model],
                input=prompt,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
        return None
    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def ollama_summarize_findings(log_paths: dict[str, Path]) -> str:
    """Ask Ollama to summarize scan findings from log files for the report."""
    if not ollama_available():
        return ""
    excerpts: list[str] = []
    for name, path in log_paths.items():
        if path.exists():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                # Keep excerpts short to avoid slow responses
                excerpts.append(f"[{name}]\n{text[:800]}")
            except OSError:
                pass
    if not excerpts:
        return ""
    prompt = (
        "Summarize these pentest scan results in 2-3 short paragraphs. "
        "What is at risk, what is safe, key actions needed. Be direct.\n\n"
        + "\n\n".join(excerpts)
    )
    return query_ollama(prompt, timeout=OLLAMA_TIMEOUT) or ""
