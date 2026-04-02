"""Async command runner for Harpoon."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path
from typing import Any, Callable


def find_cmd(cmd: str) -> str | None:
    """Return full path if command exists in PATH, else None."""
    return shutil.which(cmd)


async def run_tool(
    argv: list[str],
    log_path: Path,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> tuple[int, str, str]:
    """Run command asynchronously and write combined output to log."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env={**os.environ, **(env or {})},
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            log_path.write_text("Command timed out.", encoding="utf-8")
            return -1, "", "Timeout"
    except FileNotFoundError:
        log_path.write_text(f"Command not found: {argv[0]}", encoding="utf-8")
        return -1, "", "Command not found"
    except Exception as exc:
        log_path.write_text(str(exc), encoding="utf-8")
        return -1, "", str(exc)

    out = stdout_b.decode("utf-8", errors="replace") if stdout_b else ""
    err = stderr_b.decode("utf-8", errors="replace") if stderr_b else ""
    combined = f"=== stdout ===\n{out}\n=== stderr ===\n{err}"
    log_path.write_text(combined, encoding="utf-8", errors="replace")
    return int(proc.returncode or 0), out, err


async def run_tool_json(
    argv: list[str],
    log_path: Path,
    on_json: Callable[[dict[str, Any]], None] | None = None,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> tuple[int, list[dict[str, Any]], str]:
    """Run command asynchronously and parse JSON/JSONL stdout lines."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    parsed: list[dict[str, Any]] = []
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env={**os.environ, **(env or {})},
        )

        async def _drain_stdout() -> None:
            assert proc.stdout is not None
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                stdout_lines.append(line)
                s = line.strip()
                if not s:
                    continue
                try:
                    obj = json.loads(s)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    parsed.append(obj)
                    if on_json:
                        try:
                            on_json(obj)
                        except Exception:
                            pass

        async def _drain_stderr() -> None:
            assert proc.stderr is not None
            while True:
                raw = await proc.stderr.readline()
                if not raw:
                    break
                stderr_lines.append(raw.decode("utf-8", errors="replace").rstrip("\n"))

        tasks = [asyncio.create_task(_drain_stdout()), asyncio.create_task(_drain_stderr())]
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
            await asyncio.gather(*tasks)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            for task in tasks:
                task.cancel()
            log_path.write_text("Command timed out.", encoding="utf-8")
            return -1, parsed, "Timeout"
    except FileNotFoundError:
        log_path.write_text(f"Command not found: {argv[0]}", encoding="utf-8")
        return -1, parsed, "Command not found"
    except Exception as exc:
        log_path.write_text(str(exc), encoding="utf-8")
        return -1, parsed, str(exc)

    combined = "=== stdout ===\n" + "\n".join(stdout_lines) + "\n=== stderr ===\n" + "\n".join(stderr_lines)
    log_path.write_text(combined, encoding="utf-8", errors="replace")
    return int(proc.returncode or 0), parsed, "\n".join(stderr_lines)
