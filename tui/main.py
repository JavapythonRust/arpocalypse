"""
ARPocalypse Gremlin TUI
=======================

Main terminal interface for the Gremlin.

Current tools:
    Linux Tools
        - Nmap
        - Tcpdump
        - Aircrack-ng

    Python Tools
        - None

    Rust Tools
        - None

Controls:
    ↑ / ↓       Move through a menu
    Enter       Select
    Esc         Go back
    Q           Quit
"""

import curses
import aircrack


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


# ============================================================
# MAIN MENU
# ============================================================

MAIN_MENU = [
    "Linux Tools",
    "Python Tools",
    "Rust Tools",
    "Exit",
]


# ============================================================
# DRAW TITLE
# ============================================================

def draw_title(stdscr, title):
    """Draw a centered title at the top of the screen."""

    height, width = stdscr.getmaxyx()

    x = max(
        0,
        (width - len(title)) // 2
    )

    stdscr.addstr(
        1,
        x,
        title,
        curses.A_BOLD,
    )


# ============================================================
# DRAW MENU
# ============================================================

def draw_menu(stdscr, items, selected):
    """Draw a vertical menu."""

    height, width = stdscr.getmaxyx()

    start_y = 4

    for index, item in enumerate(items):

        x = max(
            0,
            (width - len(item) - 2) // 2
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


# ============================================================
# DRAW HELP
# ============================================================

def draw_help(stdscr):
    """Show the controls at the bottom of the screen."""

    height, width = stdscr.getmaxyx()

    message = (
        "↑/↓ Navigate   Enter Select   "
        "Esc Back   Q Quit"
    )

    x = max(
        0,
        (width - len(message)) // 2
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
    """
    Display a menu and return the selected item index.

    Returns:
        int: Selected item index.

        None: User pressed Esc or selected Back.
    """

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

        # ----------------------------------------------------
        # DOWN
        # ----------------------------------------------------

        if key in (
            curses.KEY_DOWN,
            ord("j"),
        ):

            selected += 1

            if selected >= len(menu_items):
                selected = 0

        # ----------------------------------------------------
        # UP
        # ----------------------------------------------------

        elif key in (
            curses.KEY_UP,
            ord("k"),
        ):

            selected -= 1

            if selected < 0:
                selected = len(menu_items) - 1

        # ----------------------------------------------------
        # ENTER
        # ----------------------------------------------------

        elif key in (
            curses.KEY_ENTER,
            10,
            13,
        ):

            if selected == len(menu_items) - 1:
                return None

            return selected

        # ----------------------------------------------------
        # ESC
        # ----------------------------------------------------

        elif key == 27:
            return None

        # ----------------------------------------------------
        # Q
        # ----------------------------------------------------

        elif key in (
            ord("q"),
            ord("Q"),
        ):
            return None


# ============================================================
# MESSAGE SCREEN
# ============================================================

def message_screen(stdscr, title, message):
    """Display a message until the user presses a key."""

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

            x = max(
                0,
                (width - len(line)) // 2
            )

            stdscr.addstr(
                start_y + index,
                x,
                line,
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
# GENERIC TOOL SCREEN
# ============================================================

def tool_screen(stdscr, tool_name):
    """Temporary screen for tools without a dedicated UI."""

    message_screen(
        stdscr,
        tool_name,
        (
            f"{tool_name} interface\n"
            "\n"
            "Tool interface will be connected here."
        ),
    )


# ============================================================
# AIRCRACK TOOL CHECK
# ============================================================

def aircrack_tools_screen(stdscr):
    """Display discovered Aircrack-ng dependencies."""

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
            f"Unable to check tools:\n\n{exc}",
        )


# ============================================================
# AIRCRACK VERSION
# ============================================================

def aircrack_version_screen(stdscr):
    """Display the installed Aircrack-ng version."""

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


# ============================================================
# WIRELESS INTERFACES
# ============================================================

def aircrack_interfaces_screen(stdscr):
    """Display available wireless interfaces."""

    try:

        interfaces = aircrack.list_interfaces()

        if interfaces:

            message = (
                "Wireless Interfaces\n\n"
                + "\n".join(interfaces)
            )

        else:

            message = "No wireless interfaces detected."

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


# ============================================================
# DETECT INTERFACE
# ============================================================

def aircrack_detect_interface_screen(stdscr):
    """Automatically detect a wireless interface."""

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


# ============================================================
# MONITOR MODE
# ============================================================

def aircrack_monitor_screen(stdscr):
    """
    Monitor-mode interface.

    The backend owns the actual monitor-mode lifecycle.
    """

    try:

        interface = aircrack.detect_interface()

        session = aircrack.start_monitor(
            interface
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
            session
        )

    except Exception as exc:

        message_screen(
            stdscr,
            "Monitor Mode Error",
            str(exc),
        )


# ============================================================
# PASSIVE WIRELESS SCAN
# ============================================================

def aircrack_scan_screen(stdscr):
    """Perform a passive wireless scan."""

    try:

        aps = aircrack.scan(
            duration=10
        )

        if not aps:

            message = "No access points detected."

        else:

            lines = [
                "BSSID              CH  POWER  ENCRYPTION  ESSID",
                "-" * 60,
            ]

            for ap in aps:

                lines.append(
                    f"{ap.bssid:<18} "
                    f"{ap.channel:<3} "
                    f"{ap.power:<6} "
                    f"{ap.encryption:<11} "
                    f"{ap.essid}"
                )

            message = "\n".join(lines)

        message_screen(
            stdscr,
            "Passive Wireless Scan",
            message,
        )

    except Exception as exc:

        message_screen(
            stdscr,
            "Scan Error",
            str(exc),
        )


# ============================================================
# AIRCRACK OPERATION MENU
# ============================================================

def aircrack_operation_screen(stdscr):
    """
    Select an Aircrack-ng wireless operation.

    The backend remains responsible for validating and
    authorizing the requested operation.
    """

    selected = menu_screen(
        stdscr,
        "Wireless Operations",
        [
            "Listen for Handshakes",
            "Send Deauth",
            "Both",
        ],
    )

    if selected is None:
        return

    if selected == 0:

        aircrack_handshake_screen(
            stdscr
        )

    elif selected == 1:

        aircrack_deauth_screen(
            stdscr
        )

    elif selected == 2:

        aircrack_deauth_capture_screen(
            stdscr
        )


# ============================================================
# HANDSHAKE CAPTURE
# ============================================================

def aircrack_handshake_screen(stdscr):
    """
    UI entry point for handshake capture.

    Target parameters should be supplied through the backend's
    validated interface rather than constructed in the TUI.
    """

    message_screen(
        stdscr,
        "Listen for Handshakes",
        (
            "Handshake capture selected.\n\n"
            "Connect this screen to your validated backend\n"
            "target-selection workflow."
        ),
    )


# ============================================================
# DEAUTH
# ============================================================

def aircrack_deauth_screen(stdscr):
    """
    UI entry point for deauthentication.

    Authorization and safety enforcement belong in the backend.
    """

    message_screen(
        stdscr,
        "Send Deauth",
        (
            "Deauthentication selected.\n\n"
            "The backend must perform its authorization and\n"
            "safety checks before executing the operation."
        ),
    )


# ============================================================
# DEAUTH + CAPTURE
# ============================================================

def aircrack_deauth_capture_screen(stdscr):
    """
    UI entry point for the combined operation.

    Authorization and safety enforcement belong in the backend.
    """

    message_screen(
        stdscr,
        "Deauth + Capture",
        (
            "Combined deauthentication + capture selected.\n\n"
            "The backend must perform its authorization and\n"
            "safety checks before executing the operation."
        ),
    )


# ============================================================
# AIRCRACK MENU
# ============================================================

def aircrack_screen(stdscr):
    """Display the Aircrack-ng interface."""

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

            aircrack_tools_screen(
                stdscr
            )

        elif selected == 1:

            aircrack_version_screen(
                stdscr
            )

        elif selected == 2:

            aircrack_interfaces_screen(
                stdscr
            )

        elif selected == 3:

            aircrack_detect_interface_screen(
                stdscr
            )

        elif selected == 4:

            aircrack_monitor_screen(
                stdscr
            )

        elif selected == 5:

            aircrack_scan_screen(
                stdscr
            )

        elif selected == 6:

            aircrack_operation_screen(
                stdscr
            )


# ============================================================
# LINUX TOOLS MENU
# ============================================================

def linux_tools_screen(stdscr):
    """Display Linux tools."""

    while True:

        selected = menu_screen(
            stdscr,
            "Linux Tools",
            LINUX_TOOLS,
        )

        if selected is None:
            return

        if LINUX_TOOLS[selected] == "Aircrack-ng":

            aircrack_screen(
                stdscr
            )

        else:

            tool_screen(
                stdscr,
                LINUX_TOOLS[selected],
            )


# ============================================================
# PYTHON TOOLS MENU
# ============================================================

def python_tools_screen(stdscr):
    """Display Python tools."""

    while True:

        selected = menu_screen(
            stdscr,
            "Python Tools",
            PYTHON_TOOLS,
        )

        if selected is None:
            return

        tool_screen(
            stdscr,
            PYTHON_TOOLS[selected],
        )


# ============================================================
# RUST TOOLS MENU
# ============================================================

def rust_tools_screen(stdscr):
    """Display Rust tools."""

    while True:

        selected = menu_screen(
            stdscr,
            "Rust Tools",
            RUST_TOOLS,
        )

        if selected is None:
            return

        tool_screen(
            stdscr,
            RUST_TOOLS[selected],
        )


# ============================================================
# MAIN MENU
# ============================================================

def main_menu(stdscr):
    """Run the main Gremlin menu."""

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

        # ----------------------------------------------------
        # DOWN
        # ----------------------------------------------------

        if key in (
            curses.KEY_DOWN,
            ord("j"),
        ):

            selected += 1

            if selected >= len(MAIN_MENU):
                selected = 0

        # ----------------------------------------------------
        # UP
        # ----------------------------------------------------

        elif key in (
            curses.KEY_UP,
            ord("k"),
        ):

            selected -= 1

            if selected < 0:
                selected = len(MAIN_MENU) - 1

        # ----------------------------------------------------
        # ENTER
        # ----------------------------------------------------

        elif key in (
            curses.KEY_ENTER,
            10,
            13,
        ):

            if selected == 0:

                linux_tools_screen(
                    stdscr
                )

            elif selected == 1:

                python_tools_screen(
                    stdscr
                )

            elif selected == 2:

                rust_tools_screen(
                    stdscr
                )

            elif selected == 3:

                break

        # ----------------------------------------------------
        # Q = QUIT
        # ----------------------------------------------------

        elif key in (
            ord("q"),
            ord("Q"),
        ):

            break


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

def main():
    """Start the Gremlin TUI."""

    curses.wrapper(
        main_menu
    )


if __name__ == "__main__":
    main()
