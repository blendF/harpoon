from harpoon.install_hints import format_install_hints


def test_hints_include_go_for_alterx_not_apt_only() -> None:
    lines = "\n".join(format_install_hints(["alterx", "arjun"]))
    assert "go install" in lines
    assert "alterx/cmd/alterx" in lines
    assert "apt install" in lines.lower() or "sudo apt" in lines
    assert "arjun" in lines


def test_hints_seclists_bundled_note() -> None:
    text = "\n".join(format_install_hints(["seclists"]))
    assert "HARPOON_USE_BUNDLED_WORDLISTS" in text
