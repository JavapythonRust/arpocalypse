#!/usr/bin/env python3

import sys
import time

from hid_keyboard import HIDKeyboard


class MacroParser:

    def __init__(self, keyboard):
        self.keyboard = keyboard

    def run_file(self, filename):

        with open(
            filename,
            "r",
            encoding="utf-8"
        ) as file:

            for line_number, line in enumerate(
                file,
                start=1
            ):

                try:
                    self.execute_line(line)

                except Exception as error:

                    raise RuntimeError(
                        f"Macro error on line "
                        f"{line_number}: {error}"
                    ) from error

    def execute_line(self, line):

        line = line.strip()

        # Ignore blank lines.
        if not line:
            return

        # Ignore comments.
        if line.startswith("#"):
            return

        # ----------------------------------------------------
        # TEXT "hello world"
        # ----------------------------------------------------

        if line.upper().startswith("TEXT "):

            text = line[5:].strip()

            if (
                len(text) >= 2
                and text[0] == '"'
                and text[-1] == '"'
            ):
                text = text[1:-1]

            self.keyboard.type_text(text)
            return

        # ----------------------------------------------------
        # WAIT 500
        # ----------------------------------------------------

        if line.upper().startswith("WAIT "):

            value = line[5:].strip()

            milliseconds = int(value)

            if milliseconds < 0:
                raise ValueError(
                    "WAIT cannot be negative"
                )

            time.sleep(
                milliseconds / 1000
            )

            return

        # ----------------------------------------------------
        # KEY ENTER
        # ----------------------------------------------------

        if line.upper().startswith("KEY "):

            key = line[4:].strip()

            self.keyboard.press_key(key)
            return

        # ----------------------------------------------------
        # CTRL+A
        # CTRL+SHIFT+S
        # ALT+TAB
        # ----------------------------------------------------

        if "+" in line:

            keys = [
                key.strip()
                for key in line.split("+")
            ]

            self.keyboard.hotkey(keys)
            return

        # ----------------------------------------------------
        # Standalone special keys
        # ----------------------------------------------------

        special_keys = {
            "ENTER",
            "ESC",
            "BACKSPACE",
            "TAB",
            "SPACE",
            "CAPSLOCK",

            "F1",
            "F2",
            "F3",
            "F4",
            "F5",
            "F6",
            "F7",
            "F8",
            "F9",
            "F10",
            "F11",
            "F12",

            "HOME",
            "END",
            "DELETE",
            "INSERT",

            "UP",
            "DOWN",
            "LEFT",
            "RIGHT",

            "PAGEUP",
            "PAGEDOWN",
        }

        if line.upper() in special_keys:

            self.keyboard.press_key(
                line.upper()
            )

            return

        # ----------------------------------------------------
        # Single key
        # ----------------------------------------------------

        if len(line) == 1:

            self.keyboard.press_key(
                line.upper()
            )

            return

        raise ValueError(
            f"Unknown command: {line}"
        )


def main():

    if len(sys.argv) != 2:

        print(
            "Usage: sudo python3 "
            "macro_parser.py <macro.txt>"
        )

        sys.exit(1)

    filename = sys.argv[1]

    keyboard = HIDKeyboard()

    keyboard.check_device()

    parser = MacroParser(keyboard)

    print(
        f"[*] Running macro: {filename}"
    )

    parser.run_file(filename)

    print("[+] Macro finished.")


if __name__ == "__main__":
    main()
