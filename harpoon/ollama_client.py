"""Ollama LLM for report summarization. Uses qwen3.5:cloud by default (no API key needed)."""
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from harpoon.config import OLLAMA_CMD, OLLAMA_MODEL
from harpoon.runner import find_cmd

# Timeout for Ollama (qwen3.5:cloud needs internet; reduce if it hangs)
OLLAMA_TIMEOUT = int(os.environ.get("HARPOON_OLLAMA_TIMEOUT", "180"))


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
    """Ask Ollama to produce a detailed, PoC-focused pentest analysis."""
    if not ollama_available():
        return ""
    excerpts: list[str] = []
    for name, path in log_paths.items():
        if path.exists():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                excerpts.append(f"=== {name} Tool Output ===\n{text[:2000]}")
            except OSError:
                pass
    if not excerpts:
        return ""
    prompt = (
        "You are a senior application security architect writing the AI-assisted analysis "
        "section of a stateful black-box pentest report.\n\n"
        "Inputs contain multi-phase recon/fuzz/validation outputs plus deterministic PoC data. "
        "Write a concise technical analysis with this structure:\n"
        "1) Critical findings and validated exploitability\n"
        "2) WAF/defense behavior and how scan policy adapted\n"
        "3) Actionable remediation prioritized by business impact\n"
        "4) Manual testing recommendations for business-logic abuse (Phase 10 handoff)\n\n"
        "Use concrete evidence from logs: CVE IDs, vulnerable paths, parameters, services, "
        "and PoC request snippets. Avoid generic statements.\n\n"
        + "\n\n".join(excerpts)
    )
    return query_ollama(prompt, timeout=OLLAMA_TIMEOUT) or ""
