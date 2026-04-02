from pathlib import Path

import pytest

from harpoon.runner import run_tool, run_tool_json


@pytest.mark.asyncio
async def test_run_tool(tmp_path: Path) -> None:
    log = tmp_path / "cmd.log"
    code, out, err = await run_tool(["python", "-c", "print('ok')"], log, timeout=10)
    assert code == 0
    assert "ok" in out


@pytest.mark.asyncio
async def test_run_tool_json(tmp_path: Path) -> None:
    log = tmp_path / "json.log"
    code, rows, err = await run_tool_json(
        ["python", "-c", "import json;print(json.dumps({'a':1}))"],
        log,
        timeout=10,
    )
    assert code == 0
    assert rows and rows[0]["a"] == 1
