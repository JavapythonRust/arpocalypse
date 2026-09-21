#!/usr/bin/env python3

import os
import time


HID_DEVICE = "/dev/hidg0"


# USB HID keyboard scan codes
KEY_CODES = {
    # Letters
    "A": 0x04, "B": 0x05, "C": 0x06, "D": 0x07,
    "E": 0x08, "F": 0x09, "G": 0x0A, "H": 0x0B,
    "I": 0x0C, "J": 0x0D, "K": 0x0E, "L": 0x0F,
    "M": 0x10, "N": 0x11, "O": 0x12, "P": 0x13,
    "Q": 0x14, "R": 0x15, "S": 0x16, "T": 0x17,
    "U": 0x18, "V": 0x19, "W": 0x1A, "X": 0x1B,
    "Y": 0x1C, "Z": 0x1D,

    # Numbers
    "1": 0x1E, "2": 0x1F, "3": 0x20, "4": 0x21,
    "5": 0x22, "6": 0x23, "7": 0x24, "8": 0x25,
    "9": 0x26, "0": 0x27,

    # Special keys
    "ENTER": 0x28,
    "ESC": 0x29,
    "BACKSPACE": 0x2A,
    "TAB": 0x2B,
    "SPACE": 0x2C,

    "MINUS": 0x2D,
    "EQUAL": 0x2E,
    "LEFTBRACE": 0x2F,
    "RIGHTBRACE": 0x30,
    "BACKSLASH": 0x31,

    "SEMICOLON": 0x33,
    "APOSTROPHE": 0x34,
    "GRAVE": 0x35,
    "COMMA": 0x36,
    "DOT": 0x37,
    "SLASH": 0x38,

    "CAPSLOCK": 0x39,

    # Function keys
    "F1": 0x3A,
    "F2": 0x3B,
    "F3": 0x3C,
    "F4": 0x3D,
    "F5": 0x3E,
    "F6": 0x3F,
    "F7": 0x40,
    "F8": 0x41,
    "F9": 0x42,
    "F10": 0x43,
    "F11": 0x44,
    "F12": 0x45,

    # Navigation
    "PRINTSCREEN": 0x46,
    "SCROLLLOCK": 0x47,
    "PAUSE": 0x48,
    "INSERT": 0x49,
    "HOME": 0x4A,
    "PAGEUP": 0x4B,
    "DELETE": 0x4C,
    "END": 0x4D,
    "PAGEDOWN": 0x4E,

    "RIGHT": 0x4F,
    "LEFT": 0x50,
    "DOWN": 0x51,
    "UP": 0x52,
}


# HID modifier bits
MODIFIERS = {
    "CTRL": 0x01,
    "SHIFT": 0x02,
    "ALT": 0x04,
    "GUI": 0x08,
    "WIN": 0x08,
    "CMD": 0x08,
}


class HIDKeyboard:

    def __init__(self, device=HID_DEVICE):
        self.device = device

    def check_device(self):
        if not os.path.exists(self.device):
            raise RuntimeError(
                f"HID device not found: {self.device}"
            )

    def send_report(self, modifier=0, key=0):
        """
        Send an 8-byte keyboard HID report.

        Byte 0: modifier
        Byte 1: reserved
        Byte 2: key
        Bytes 3-7: additional keys
        """

        report = bytes([
            modifier,
            0x00,
            key,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ])

        with open(self.device, "wb") as hid:
            hid.write(report)

            # Release all keys.
            hid.write(bytes(8))

    def press_key(self, key):
        key = key.upper()

        if key not in KEY_CODES:
            raise ValueError(f"Unknown key: {key}")

        self.send_report(
            0,
            KEY_CODES[key]
        )

    def hotkey(self, keys):
        modifier = 0
        normal_key = None

        for key in keys:
            key = key.upper()

            if key in MODIFIERS:
                modifier |= MODIFIERS[key]

            elif key in KEY_CODES:
                normal_key = KEY_CODES[key]

            else:
                raise ValueError(
                    f"Unknown key: {key}"
                )

        if normal_key is None:
            raise ValueError(
                "Hotkey requires a normal key"
            )

        self.send_report(
            modifier,
            normal_key
        )

    def type_text(self, text):
        """
        Type basic text.

        Uppercase letters automatically use SHIFT.
        """

        for char in text:

            if char.isalpha():

                key = char.upper()

                if key not in KEY_CODES:
                    raise ValueError(
                        f"Unsupported character: {char}"
                    )

                modifier = 0x02 if char.isupper() else 0

                self.send_report(
                    modifier,
                    KEY_CODES[key]
                )

            elif char == " ":
                self.press_key("SPACE")

            elif char == "\n":
                self.press_key("ENTER")

            elif char.isdigit():

                if char in KEY_CODES:
                    self.press_key(char)

            else:
                raise ValueError(
                    f"Unsupported character: {char!r}"
                )

            time.sleep(0.01)
