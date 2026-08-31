"""
ARPocalypse Gremlin TUI
=======================

TUI for the Gremlin.
"""

import curses
from pathlib import Path

import aircrack
from hid_keyboard import HIDKeyboard
from macro_parser import MacroParser


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MACROS_DIR = BASE_DIR / "macros"


# ============================================================
# TOOL CATEGORIES
# ============================================================

LINUX_TOOLS = [
    "Nmap",
    "Tcpdump",
    "Aircrack-ng",
]

PYTHON_TOOLS = []
RUST_TOOLS = []

MAIN_MENU = [
    "Linux Tools",
    "Python Tools",
    "Rust Tools",
    "HID",
    "Exit",
]


# ============================================================
# DRAWING
# ============================================================

def draw_title(stdscr, title):
    height, width = stdscr.getmaxyx()

    x = max(0, (width - len(title)) // 2)

    stdscr.addstr(
        1,
        x,
        title,
        curses.A_BOLD,
    )


def draw_menu(stdscr, items, selected):
    height, width = stdscr.getmaxyx()

    start_y = 4

    for index, item in enumerate(items):
        x = max(
            0,
            (width - len(item) - 2) // 2,
        )

        if index == selected:
            stdscr.addstr(
                start_y + index,
                x,
                f"> {item}",
                curses.A_REVERSE,
            )
        else:
            stdscr.addstr(
                start_y + index,
                x,
                f"  {item}",
            )


def draw_help(stdscr):
    height, width = stdscr.getmaxyx()

    message = (
        "↑/↓ Navigate   Enter Select   "
        "Esc Back   Q Quit"
    )

    x = max(
        0,
        (width - len(message)) // 2,
    )

    stdscr.addstr(
        height - 2,
        x,
        message,
    )


# ============================================================
# GENERIC MENU
# ============================================================

def menu_screen(stdscr, title, items):
    menu_items = list(items) + ["Back"]

    selected = 0

    while True:
        stdscr.clear()

        draw_title(
            stdscr,
            title,
        )

        draw_menu(
            stdscr,
            menu_items,
            selected,
        )

        draw_help(stdscr)

        stdscr.refresh()

        key = stdscr.getch()

        if key in (
            curses.KEY_DOWN,
            ord("j"),
        ):
            selected += 1

            if selected >= len(menu_items):
                selected = 0

        elif key in (
            curses.KEY_UP,
            ord("k"),
        ):
            selected -= 1

            if selected < 0:
                selected = len(menu_items) - 1

        elif key in (
            curses.KEY_ENTER,
            10,
            13,
        ):
            if selected == len(menu_items) - 1:
                return None

            return selected

        elif key == 27:
            return None

        elif key in (
            ord("q"),
            ord("Q"),
        ):
            return None


# ============================================================
# MESSAGE SCREEN
# ============================================================

def message_screen(stdscr, title, message):
    while True:
        stdscr.clear()

        draw_title(
            stdscr,
            title,
        )

        height, width = stdscr.getmaxyx()

        lines = message.splitlines()

        start_y = (
            height // 2
            - len(lines) // 2
        )

        for index, line in enumerate(lines):
            y = start_y + index

            if y < 0 or y >= height - 2:
                continue

            x = max(
                0,
                (width - len(line)) // 2,
            )

            stdscr.addstr(
                y,
                x,
                line[: max(1, width - 1)],
            )

        stdscr.addstr(
            height - 2,
            2,
            "Press any key to continue.",
        )

        stdscr.refresh()

        key = stdscr.getch()

        if key != -1:
            return


# ============================================================
# OBJECT SELECTION
# ============================================================

def select_ap(stdscr, aps):
    if not aps:
        message_screen(
            stdscr,
            "Select AP",
            "No access points were discovered.",
        )
        return None

    items = []

    for ap in aps:
        essid = ap.essid or "<hidden>"

        items.append(
            f"{essid} | "
            f"{ap.bssid} | "
            f"CH {ap.channel} | "
            f"{ap.power}"
        )

    selected = menu_screen(
        stdscr,
        "Select Access Point",
        items,
    )

    if selected is None:
        return None

    return aps[selected]


def select_client(stdscr, ap):
    if not ap.clients:
        message_screen(
            stdscr,
            "Select Client",
            (
                f"No clients were discovered for\n"
                f"{ap.essid or '<hidden>'}."
            ),
        )
        return None

    items = [
        f"{client.mac}"
        for client in ap.clients
    ]

    selected = menu_screen(
        stdscr,
        "Select Client",
        items,
    )

    if selected is None:
        return None

    return ap.clients[selected]


# ============================================================
# PASSIVE SCAN
# ============================================================

def run_passive_scan(stdscr):
    try:
        message_screen(
            stdscr,
            "Passive Scan",
            "Starting passive wireless scan...",
        )

        aps = aircrack.scan(
            duration=10,
        )

        return aps

    except Exception as exc:
        message_screen(
            stdscr,
            "Scan Error",
            str(exc),
        )

        return None


def passive_scan_screen(stdscr):
    aps = run_passive_scan(stdscr)

    if aps is None:
        return

    if not aps:
        message_screen(
            stdscr,
            "Passive Scan",
            "No access points detected.",
        )
        return

    lines = [
        "BSSID              CH   POWER   ENCRYPTION   ESSID",
        "-" * 65,
    ]

    for ap in aps:
        lines.append(
            f"{ap.bssid:<18} "
            f"{ap.channel:<4} "
            f"{ap.power:<7} "
            f"{ap.encryption:<12} "
            f"{ap.essid}"
        )

    message_screen(
        stdscr,
        "Passive Wireless Scan",
        "\n".join(lines),
    )


# ============================================================
# HANDSHAKE CAPTURE
# ============================================================

def aircrack_handshake_screen(stdscr):
    aps = run_passive_scan(stdscr)

    if not aps:
        return

    ap = select_ap(
        stdscr,
        aps,
    )

    if ap is None:
        return

    try:
        result = aircrack.capture_handshake(
            bssid=ap.bssid,
            channel=ap.channel,
        )

        lines = [
            f"State: {result.state.value}",
            f"Return code: {result.returncode}",
            f"Verified: {result.verified}",
            f"Handshake observed: "
            f"{result.handshake_captured}",
        ]

        if result.capture_file:
            lines.append(
                f"Capture: {result.capture_file}"
            )

        if result.error:
            lines.extend([
                "",
                f"Error: {result.error}",
            ])

        message_screen(
            stdscr,
            "Handshake Capture",
            "\n".join(lines),
        )

    except Exception as exc:
        message_screen(
            stdscr,
            "Capture Error",
            str(exc),
        )


# ============================================================
# TARGET SELECTION
# ============================================================

def select_target(stdscr):
    aps = run_passive_scan(stdscr)

    if not aps:
        return None

    ap = select_ap(
        stdscr,
        aps,
    )

    if ap is None:
        return None

    return ap


def select_target_client(stdscr):
    ap = select_target(stdscr)

    if ap is None:
        return None, None

    client = select_client(
        stdscr,
        ap,
    )

    if client is None:
        return None, None

    return ap, client


# ============================================================
# OPERATION MENU
# ============================================================

def aircrack_operation_screen(stdscr):
    selected = menu_screen(
        stdscr,
        "Wireless Operations",
        [
            "Listen for Handshakes",
            "Client Operation",
            "Combined Operation",
        ],
    )

    if selected is None:
        return

    if selected == 0:
        aircrack_handshake_screen(
            stdscr,
        )

    elif selected == 1:
        client_operation_screen(
            stdscr,
        )

    elif selected == 2:
        combined_operation_screen(
            stdscr,
        )


# ============================================================
# CLIENT OPERATION
# ============================================================

def client_operation_screen(stdscr):
    ap, client = select_target_client(stdscr)

    if ap is None or client is None:
        return

    bssid = ap.bssid
    client_mac = client.mac
    known_clients = ap.clients

    result = aircrack.deauth_client(
        bssid=bssid,
        client_mac=client_mac,
        known_clients=known_clients,
    )

    message_screen(
        stdscr,
        "Client Operation",
        (
            f"AP: {ap.essid or '<hidden>'}\n"
            f"BSSID: {bssid}\n"
            f"Channel: {ap.channel}\n"
            f"Client: {client_mac}\n"
            f"Known clients: {len(known_clients)}\n\n"
            f"Backend result: {result}"
        ),
    )


# ============================================================
# COMBINED OPERATION
# ============================================================

def combined_operation_screen(stdscr):
    ap, client = select_target_client(
        stdscr,
    )

    if ap is None or client is None:
        return

    message_screen(
        stdscr,
        "Selected Target",
        (
            f"AP: {ap.essid or '<hidden>'}\n"
            f"BSSID: {ap.bssid}\n"
            f"Channel: {ap.channel}\n\n"
            f"Client: {client.mac}\n\n"
            f"Known clients: {len(ap.clients)}\n\n"
            "Parameters collected successfully.\n"
            "The backend remains responsible for authorization."
        ),
    )


# ============================================================
# AIRCRACK MENU
# ============================================================

def aircrack_screen(stdscr):
    while True:
        selected = menu_screen(
            stdscr,
            "Aircrack-ng",
            [
                "Check Tools",
                "Version",
                "Wireless Interfaces",
                "Detect Interface",
                "Monitor Mode",
                "Passive Wireless Scan",
                "Wireless Operations",
            ],
        )

        if selected is None:
            return

        if selected == 0:
            aircrack_tools_screen(stdscr)

        elif selected == 1:
            aircrack_version_screen(stdscr)

        elif selected == 2:
            aircrack_interfaces_screen(stdscr)

        elif selected == 3:
            aircrack_detect_interface_screen(stdscr)

        elif selected == 4:
            aircrack_monitor_screen(stdscr)

        elif selected == 5:
            passive_scan_screen(stdscr)

        elif selected == 6:
            aircrack_operation_screen(stdscr)


# ============================================================
# AIRCRACK INFORMATION SCREENS
# ============================================================

def aircrack_tools_screen(stdscr):
    try:
        tools = aircrack.find_tools()

        lines = [
            "Aircrack-ng dependencies",
            "",
            f"airmon-ng:   {tools.airmon or 'NOT FOUND'}",
            f"airodump-ng: {tools.airodump or 'NOT FOUND'}",
            f"aireplay-ng: {tools.aireplay or 'NOT FOUND'}",
            f"aircrack-ng: {tools.aircrack or 'NOT FOUND'}",
            f"iw:          {tools.iw or 'NOT FOUND'}",
            f"tshark:      {tools.tshark or 'NOT FOUND'}",
            "",
            f"Complete: {'YES' if tools.complete else 'NO'}",
        ]

        message_screen(
            stdscr,
            "Check Tools",
            "\n".join(lines),
        )

    except Exception as exc:
        message_screen(
            stdscr,
            "Aircrack Error",
            str(exc),
        )


def aircrack_version_screen(stdscr):
    try:
        version = aircrack.version()

        message_screen(
            stdscr,
            "Aircrack-ng Version",
            version,
        )

    except Exception as exc:
        message_screen(
            stdscr,
            "Aircrack Error",
            str(exc),
        )


def aircrack_interfaces_screen(stdscr):
    try:
        interfaces = aircrack.list_interfaces()

        if interfaces:
            message = (
                "Wireless Interfaces\n\n"
                + "\n".join(interfaces)
            )
        else:
            message = (
                "No wireless interfaces detected."
            )

        message_screen(
            stdscr,
            "Wireless Interfaces",
            message,
        )

    except Exception as exc:
        message_screen(
            stdscr,
            "Aircrack Error",
            str(exc),
        )


def aircrack_detect_interface_screen(stdscr):
    try:
        interface = aircrack.detect_interface()

        message_screen(
            stdscr,
            "Detect Interface",
            f"Detected interface:\n\n{interface}",
        )

    except Exception as exc:
        message_screen(
            stdscr,
            "Aircrack Error",
            str(exc),
        )


def aircrack_monitor_screen(stdscr):
    try:
        interface = aircrack.detect_interface()

        session = aircrack.start_monitor(
            interface,
        )

        message_screen(
            stdscr,
            "Monitor Mode",
            (
                f"Monitor interface:\n\n"
                f"{session.interface}\n\n"
                "Press a key to stop monitor mode."
            ),
        )

        aircrack.stop_monitor(
            session,
        )

    except Exception as exc:
        message_screen(
            stdscr,
            "Monitor Mode Error",
            str(exc),
        )


# ============================================================
# LINUX TOOLS
# ============================================================

def linux_tools_screen(stdscr):
    while True:
        selected = menu_screen(
            stdscr,
            "Linux Tools",
            LINUX_TOOLS,
        )

        if selected is None:
            return

        if LINUX_TOOLS[selected] == "Aircrack-ng":
            aircrack_screen(stdscr)

        else:
            message_screen(
                stdscr,
                LINUX_TOOLS[selected],
                (
                    f"{LINUX_TOOLS[selected]} interface\n\n"
                    "Not implemented yet."
                ),
            )


# ============================================================
# PYTHON TOOLS
# ============================================================

def python_tools_screen(stdscr):
    selected = menu_screen(
        stdscr,
        "Python Tools",
        PYTHON_TOOLS,
    )

    if selected is None:
        return


# ============================================================
# RUST TOOLS
# ============================================================

def rust_tools_screen(stdscr):
    selected = menu_screen(
        stdscr,
        "Rust Tools",
        RUST_TOOLS,
    )

    if selected is None:
        return


# ============================================================
# HID
# ============================================================

def hid_status_screen(stdscr):
    keyboard = HIDKeyboard()

    try:
        keyboard.check_device()

        message_screen(
            stdscr,
            "HID Status",
            (
                "HID device: AVAILABLE\n\n"
                f"Device: {keyboard.device}"
            ),
        )

    except Exception as exc:
        message_screen(
            stdscr,
            "HID Status",
            (
                "HID device: NOT AVAILABLE\n\n"
                f"Device: {keyboard.device}\n\n"
                f"Error: {exc}"
            ),
        )


def hid_type_screen(stdscr):
    keyboard = HIDKeyboard()

    try:
        keyboard.check_device()

    except Exception as exc:
        message_screen(
            stdscr,
            "HID Error",
            str(exc),
        )
        return

    stdscr.clear()

    draw_title(
        stdscr,
        "HID Type Text",
    )

    height, width = stdscr.getmaxyx()

    stdscr.addstr(
        4,
        2,
        "Enter text to type:",
    )

    curses.echo()

    try:
        text = stdscr.getstr(
            6,
            2,
            max(1, width - 5),
        ).decode(
            "utf-8",
            errors="replace",
        )

    finally:
        curses.noecho()

    if not text:
        return

    try:
        keyboard.type_text(text)

        message_screen(
            stdscr,
            "HID",
            "Text sent successfully.",
        )

    except Exception as exc:
        message_screen(
            stdscr,
            "HID Error",
            str(exc),
        )


def hid_key_screen(stdscr):
    keyboard = HIDKeyboard()

    try:
        keyboard.check_device()

    except Exception as exc:
        message_screen(
            stdscr,
            "HID Error",
            str(exc),
        )
        return

    keys = [
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
    ]

    selected = menu_screen(
        stdscr,
        "HID Key",
        keys,
    )

    if selected is None:
        return

    key = keys[selected]

    try:
        keyboard.press_key(key)

        message_screen(
            stdscr,
            "HID",
            f"Sent key: {key}",
        )

    except Exception as exc:
        message_screen(
            stdscr,
            "HID Error",
            str(exc),
        )


def hid_hotkey_screen(stdscr):
    keyboard = HIDKeyboard()

    try:
        keyboard.check_device()

    except Exception as exc:
        message_screen(
            stdscr,
            "HID Error",
            str(exc),
        )
        return

    stdscr.clear()

    draw_title(
        stdscr,
        "HID Hotkey",
    )

    height, width = stdscr.getmaxyx()

    stdscr.addstr(
        4,
        2,
        "Enter hotkey (example: CTRL+ALT+T):",
    )

    curses.echo()

    try:
        value = stdscr.getstr(
            6,
            2,
            max(1, width - 5),
        ).decode(
            "utf-8",
            errors="replace",
        )

    finally:
        curses.noecho()

    if not value:
        return

    keys = [
        key.strip()
        for key in value.split("+")
    ]

    try:
        keyboard.hotkey(keys)

        message_screen(
            stdscr,
            "HID",
            f"Sent hotkey: {value}",
        )

    except Exception as exc:
        message_screen(
            stdscr,
            "HID Error",
            str(exc),
        )


def find_macros():
    """
    Find all .txt files in the macros directory.

    The directory is scanned every time this function
    is called, so newly added macros appear automatically.
    """

    if not MACROS_DIR.exists():
        return []

    if not MACROS_DIR.is_dir():
        return []

    return sorted(
        (
            path
            for path in MACROS_DIR.iterdir()
            if path.is_file()
            and path.suffix.lower() == ".txt"
        ),
        key=lambda path: path.name.lower(),
    )


def hid_macro_screen(stdscr):
    """
    Display macros found in macros/*.txt and execute
    the selected macro through MacroParser.
    """

    macros = find_macros()

    if not macros:
        message_screen(
            stdscr,
            "HID Macros",
            (
                "No macro files found.\n\n"
                f"Macro directory:\n"
                f"{MACROS_DIR}\n\n"
                "Add .txt files to this directory."
            ),
        )
        return

    items = [
        macro.name
        for macro in macros
    ]

    selected = menu_screen(
        stdscr,
        "HID Macros",
        items,
    )

    if selected is None:
        return

    macro_file = macros[selected]

    keyboard = HIDKeyboard()

    try:
        keyboard.check_device()

    except Exception as exc:
        message_screen(
            stdscr,
            "HID Error",
            str(exc),
        )
        return

    parser = MacroParser(keyboard)

    try:
        parser.run_file(
            str(macro_file)
        )

        message_screen(
            stdscr,
            "Macro Complete",
            (
                f"Macro:\n{macro_file.name}\n\n"
                "Macro finished successfully."
            ),
        )

    except Exception as exc:
        message_screen(
            stdscr,
            "Macro Error",
            (
                f"Macro: {macro_file.name}\n\n"
                f"{exc}"
            ),
        )


def hid_screen(stdscr):
    while True:
        selected = menu_screen(
            stdscr,
            "USB HID",
            [
                "HID Status",
                "Type Text",
                "Press Key",
                "Hotkey",
                "Run Macro",
            ],
        )

        if selected is None:
            return

        if selected == 0:
            hid_status_screen(stdscr)

        elif selected == 1:
            hid_type_screen(stdscr)

        elif selected == 2:
            hid_key_screen(stdscr)

        elif selected == 3:
            hid_hotkey_screen(stdscr)

        elif selected == 4:
            hid_macro_screen(stdscr)


# ============================================================
# MAIN MENU
# ============================================================

def main_menu(stdscr):
    selected = 0

    while True:
        stdscr.clear()

        draw_title(
            stdscr,
            "ARPocalypse Gremlin",
        )

        draw_menu(
            stdscr,
            MAIN_MENU,
            selected,
        )

        draw_help(stdscr)

        stdscr.refresh()

        key = stdscr.getch()

        if key in (
            curses.KEY_DOWN,
            ord("j"),
        ):
            selected += 1

            if selected >= len(MAIN_MENU):
                selected = 0

        elif key in (
            curses.KEY_UP,
            ord("k"),
        ):
            selected -= 1

            if selected < 0:
                selected = len(MAIN_MENU) - 1

        elif key in (
            curses.KEY_ENTER,
            10,
            13,
        ):
            if selected == 0:
                linux_tools_screen(stdscr)

            elif selected == 1:
                python_tools_screen(stdscr)

            elif selected == 2:
                rust_tools_screen(stdscr)

            elif selected == 3:
                hid_screen(stdscr)

            elif selected == 4:
                break

        elif key in (
            ord("q"),
            ord("Q"),
        ):
            break


# ============================================================
# ENTRY POINT
# ============================================================

def main():
    curses.wrapper(main_menu)


if __name__ == "__main__":
    main()
