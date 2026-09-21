"""
tui/actions/hid_actions.py
===========================

Handler functions for the USB HID menu. Same pattern as
aircrack_actions.py: every public function takes just `stdscr`.
"""

from tools.python.hid_keyboard import HIDKeyboard
from tools.python.macro_parser import MacroParser
from tui.config import MACROS_DIR
from tui.core import message_screen, prompt_text, select_from_list


KEYS = [
    "ENTER", "ESC", "BACKSPACE", "TAB", "SPACE", "CAPSLOCK",
    "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12",
    "HOME", "END", "DELETE", "INSERT",
    "UP", "DOWN", "LEFT", "RIGHT",
    "PAGEUP", "PAGEDOWN",
]


def _connected_keyboard(stdscr):
    """Return a checked HIDKeyboard, or None (after showing the error)."""
    keyboard = HIDKeyboard()
    try:
        keyboard.check_device()
        return keyboard
    except Exception as exc:
        message_screen(stdscr, "HID Error", str(exc))
        return None


def status(stdscr):
    keyboard = HIDKeyboard()
    try:
        keyboard.check_device()
        message_screen(
            stdscr, "HID Status",
            f"HID device: AVAILABLE\n\nDevice: {keyboard.device}",
        )
    except Exception as exc:
        message_screen(
            stdscr, "HID Status",
            f"HID device: NOT AVAILABLE\n\nDevice: {keyboard.device}\n\nError: {exc}",
        )


def type_text(stdscr):
    keyboard = _connected_keyboard(stdscr)
    if keyboard is None:
        return

    text = prompt_text(stdscr, "HID Type Text", "Enter text to type:")
    if not text:
        return

    try:
        keyboard.type_text(text)
        message_screen(stdscr, "HID", "Text sent successfully.")
    except Exception as exc:
        message_screen(stdscr, "HID Error", str(exc))


def press_key(stdscr):
    keyboard = _connected_keyboard(stdscr)
    if keyboard is None:
        return

    key = select_from_list(stdscr, "HID Key", KEYS, lambda k: k)
    if key is None:
        return

    try:
        keyboard.press_key(key)
        message_screen(stdscr, "HID", f"Sent key: {key}")
    except Exception as exc:
        message_screen(stdscr, "HID Error", str(exc))


def hotkey(stdscr):
    keyboard = _connected_keyboard(stdscr)
    if keyboard is None:
        return

    value = prompt_text(stdscr, "HID Hotkey", "Enter hotkey (example: CTRL+ALT+T):")
    if not value:
        return

    keys = [k.strip() for k in value.split("+")]

    try:
        keyboard.hotkey(keys)
        message_screen(stdscr, "HID", f"Sent hotkey: {value}")
    except Exception as exc:
        message_screen(stdscr, "HID Error", str(exc))


def find_macros():
    """Scan MACROS_DIR for .txt files every time it's called."""
    if not MACROS_DIR.exists() or not MACROS_DIR.is_dir():
        return []

    return sorted(
        (p for p in MACROS_DIR.iterdir() if p.is_file() and p.suffix.lower() == ".txt"),
        key=lambda p: p.name.lower(),
    )


def run_macro(stdscr):
    macros = find_macros()

    macro_file = select_from_list(
        stdscr, "HID Macros", macros, lambda m: m.name,
        empty_message=(
            "No macro files found.\n\n"
            f"Macro directory:\n{MACROS_DIR}\n\n"
            "Add .txt files to this directory."
        ),
    )
    if macro_file is None:
        return

    keyboard = _connected_keyboard(stdscr)
    if keyboard is None:
        return

    parser = MacroParser(keyboard)

    try:
        parser.run_file(str(macro_file))
        message_screen(
            stdscr, "Macro Complete",
            f"Macro:\n{macro_file.name}\n\nMacro finished successfully.",
        )
    except Exception as exc:
        message_screen(stdscr, "Macro Error", f"Macro: {macro_file.name}\n\n{exc}")
