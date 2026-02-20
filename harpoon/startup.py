"""Startup: display ASCII art from HARPOONASCIIART.txt."""
from harpoon.config import ASCII_ART_PATH

AUTHOR = 'Blendi "blendFpwn" Ferizi'
SLOGAN = "Fire and forget web-app penetration testing tool."


def show_ascii_art() -> None:
    """Read and display ASCII art from HARPOONASCIIART.txt."""
    # 4 rows of space before ASCII art
    print("\n\n\n\n")
    try:
        if ASCII_ART_PATH.exists():
            text = ASCII_ART_PATH.read_text(encoding="utf-8", errors="replace")
            print(text)
        else:
            print("Harpoon - Automated Pentesting Tool")
            print("(HARPOONASCIIART.txt not found)")
    except OSError:
        print("Harpoon - Automated Pentesting Tool")
    # Placeholder text under ASCII art
    print()
    print(f"  by {AUTHOR}")
    print(f'  "{SLOGAN}"')
    print()
