import pytest

from harpoon import preflight


def test_preflight_halts_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight, "_has_tool", lambda _tool: False)
    monkeypatch.setattr(preflight, "_seclists_present", lambda: False)
    with pytest.raises(SystemExit):
        preflight.check_dependencies()
