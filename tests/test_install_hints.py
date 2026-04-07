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


def test_hints_x8_is_rust_release_not_go_install() -> None:
    text = "\n".join(format_install_hints(["x8"]))
    assert "go install" not in text or "no longer" in text
    assert "x86_64-linux-x8.gz" in text
    assert "Sh1Yo/x8/releases" in text


def test_hints_pip_section_points_to_setup_sh() -> None:
    text = "\n".join(format_install_hints(["paramspider"]))
    assert "scripts/setup.sh" in text
    assert "requirements.txt" not in text
    assert "devanshbatham/ParamSpider" in text
