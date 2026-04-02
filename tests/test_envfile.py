import os
from pathlib import Path

import pytest

from harpoon.envfile import load_harpoon_env


def test_load_harpoon_env_sets_only_missing_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HARPOON_USE_BUNDLED_WORDLISTS", raising=False)
    monkeypatch.delenv("HARPOON_FOO", raising=False)
    env_path = tmp_path / ".harpoon.env"
    env_path.write_text(
        "HARPOON_USE_BUNDLED_WORDLISTS=1\n"
        "HARPOON_FOO=from_file\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HARPOON_FOO", "from_shell")
    load_harpoon_env(tmp_path)
    assert os.environ["HARPOON_USE_BUNDLED_WORDLISTS"] == "1"
    assert os.environ["HARPOON_FOO"] == "from_shell"
