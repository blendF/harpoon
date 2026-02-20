"""Generic runner: run a command, capture output, write to file."""
import shutil
import subprocess
from pathlib import Path
from typing import Optional


def find_cmd(cmd: str) -> Optional[str]:
    """Return full path if command exists in PATH, else None."""
    return shutil.which(cmd)


def run_capture(
    argv: list,
    log_path: Path,
    timeout: Optional[int] = None,
    env: Optional[dict] = None,
    cwd: Optional[Path] = None,
) -> tuple[int, str, str]:
    """
    Run argv, write stdout+stderr to log_path, return (returncode, stdout, stderr).
    Uses UTF-8 to avoid Windows cp1252 decode errors.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env={**(env or {}), **__import__("os").environ},
        )
        out, err = result.stdout or "", result.stderr or ""
        combined = f"=== stdout ===\n{out}\n=== stderr ===\n{err}"
        log_path.write_text(combined, encoding="utf-8", errors="replace")
        return result.returncode, out, err
    except subprocess.TimeoutExpired:
        log_path.write_text("Command timed out.", encoding="utf-8")
        return -1, "", "Timeout"
    except FileNotFoundError:
        log_path.write_text(f"Command not found: {argv[0]}", encoding="utf-8")
        return -1, "", "Command not found"
    except Exception as e:
        log_path.write_text(str(e), encoding="utf-8")
        return -1, "", str(e)
