"""
tui/config.py
=============

Central place for filesystem paths.

If you move the macros folder, or need another shared path, add it
here instead of scattering `Path(...)` calls through the codebase.
"""

from pathlib import Path

# tui/config.py -> tui/ -> repo root
BASE_DIR = Path(__file__).resolve().parent.parent

MACROS_DIR = BASE_DIR / "tools" / "python" / "macros"

# Lives inside tui/, next to this file.
PCAPS_DIR = Path(__file__).resolve().parent / "pcaps"
