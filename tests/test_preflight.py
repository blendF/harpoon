import pytest

from harpoon import preflight


def test_preflight_halts_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight, "_has_tool", lambda _tool: False)
    monkeypatch.setattr(preflight, "_seclists_present", lambda: False)
    monkeypatch.setattr(preflight, "_has_go", lambda: False)
    with pytest.raises(SystemExit):
        preflight.check_dependencies()


def test_find_missing_includes_go_when_compiler_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight, "_has_tool", lambda t: t != "subfinder")
    monkeypatch.setattr(preflight, "_seclists_present", lambda: True)
    monkeypatch.setattr(preflight, "_has_go", lambda: False)
    # subfinder missing -> needs go install -> go compiler missing
    missing = preflight.find_missing_dependencies()
    assert "go" in missing
    assert "subfinder" in missing
