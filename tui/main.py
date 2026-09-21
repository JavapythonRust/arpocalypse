"""
ARPocalypse Gremlin TUI
=======================

Entry point. There should be nothing to edit here.

  - To add a menu, submenu, or option:      tui/menu_tree.py
  - To add new behavior for an option:      tui/actions/*.py
  - To change core engine/drawing behavior: tui/core.py
  - To change shared paths (e.g. macros):   tui/config.py
"""

import sys
from pathlib import Path

# main.py is in arpocalypse/tui/; parent.parent is the repo root.
# This must happen before importing the `tui` or `tools` packages.
BASE_DIR = Path(__file__).resolve().parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from tui.core import run_app
from tui.menu_tree import MAIN_MENU


def main():
    run_app(MAIN_MENU)


if __name__ == "__main__":
    main()
