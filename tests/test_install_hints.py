from harpoon.install_hints import format_install_hints, missing_requires_go_install


def test_hints_include_go_for_alterx_not_apt_only() -> None:
    lines = "\n".join(format_install_hints(["alterx", "arjun"]))
    assert "go install" in lines
    assert "alterx/cmd/alterx" in lines
    assert "apt install" in lines.lower() or "sudo apt" in lines
    assert "arjun" in lines


def test_hints_seclists_bundled_note() -> None:
    text = "\n".join(format_install_hints(["seclists"]))
    assert "HARPOON_USE_BUNDLED_WORDLISTS" in text


def test_hints_go_pseudo_adds_golang_go_apt() -> None:
    text = "\n".join(format_install_hints(["go", "alterx"]))
    assert "golang-go" in text
    assert "go compiler" in text.lower() or "`go`" in text


def test_missing_requires_go_install() -> None:
    assert missing_requires_go_install(["alterx", "arjun"]) is True
    assert missing_requires_go_install(["arjun"]) is False
    assert missing_requires_go_install(["seclists"]) is False
