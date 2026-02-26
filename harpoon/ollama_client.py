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
    """Ask Ollama to produce a detailed, technical penetration test analysis."""
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
        "You are a senior penetration tester writing the AI-assisted analysis section "
        "of a penetration test report. The audience is both security engineers and "
        "management who need to understand business risk.\n\n"
        "Below are raw outputs from automated security tools run against a target. "
        "Analyze them and write a detailed report section following this structure:\n\n"
        "1. **Critical Findings** – List each vulnerability found. For each one:\n"
        "   - Technical description (CVE ID if available, affected component, attack vector)\n"
        "   - Real-world impact if exploited (e.g., 'An attacker could exfiltrate the "
        "entire user database', 'Remote code execution allows full server takeover')\n"
        "   - Severity rating (Critical / High / Medium)\n"
        "   - Recommended remediation steps\n\n"
        "2. **Attack Surface Summary** – What ports, services, and paths are exposed. "
        "Which ones are unnecessary and should be hardened.\n\n"
        "3. **Positive Findings** – What defenses are working (e.g., no SQL injection found, "
        "CDN/WAF in place, no default credentials detected).\n\n"
        "4. **Priority Actions** – A numbered list of the top 5 most urgent actions, "
        "ordered by severity and exploitability.\n\n"
        "Be technical and specific. Reference actual ports, paths, CVEs, and service "
        "versions from the scan data. Do not be vague.\n\n"
        + "\n\n".join(excerpts)
    )
    return query_ollama(prompt, timeout=OLLAMA_TIMEOUT) or ""
