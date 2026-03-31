"""Generic runner: run commands, capture output, and stream JSON lines."""
import shutil
import subprocess
import json
from pathlib import Path
from typing import Callable, Optional, Any


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


def run_capture_json(
    argv: list[str],
    log_path: Path,
    on_json: Callable[[dict[str, Any]], None] | None = None,
    timeout: Optional[int] = None,
    env: Optional[dict] = None,
    cwd: Optional[Path] = None,
) -> tuple[int, list[dict[str, Any]], str]:
    """
    Run command and parse JSON/JSONL lines from stdout in near real-time.

    Returns (returncode, parsed_objects, stderr_text).
    Raw combined output still gets written to log_path for traceability.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    parsed: list[dict[str, Any]] = []
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(cwd) if cwd else None,
            env={**__import__("os").environ, **(env or {})},
        )

        assert proc.stdout is not None
        assert proc.stderr is not None

        for raw_line in proc.stdout:
            line = raw_line.rstrip("\n")
            stdout_lines.append(line)
            striped = line.strip()
            if not striped:
                continue
            try:
                obj = json.loads(striped)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                parsed.append(obj)
                if on_json:
                    try:
                        on_json(obj)
                    except Exception:
                        # Never crash pipeline on callback failures.
                        pass

        # collect stderr after stdout drain
        stderr_lines = proc.stderr.read().splitlines()
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()  # type: ignore[name-defined]
        except Exception:
            pass
        log_path.write_text("Command timed out.", encoding="utf-8")
        return -1, parsed, "Timeout"
    except FileNotFoundError:
        log_path.write_text(f"Command not found: {argv[0]}", encoding="utf-8")
        return -1, parsed, "Command not found"
    except Exception as e:
        log_path.write_text(str(e), encoding="utf-8")
        return -1, parsed, str(e)

    combined = (
        "=== stdout ===\n"
        + "\n".join(stdout_lines)
        + "\n=== stderr ===\n"
        + "\n".join(stderr_lines)
    )
    log_path.write_text(combined, encoding="utf-8", errors="replace")
    return code, parsed, "\n".join(stderr_lines)
