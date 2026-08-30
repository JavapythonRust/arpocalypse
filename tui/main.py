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
        - None yet

    Rust Tools
        - None currently working

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
# MESSAGE SCREEN
# ============================================================

def message_screen(stdscr, title, lines):
    """Display information and wait for Esc."""

    while True:

        stdscr.clear()

        draw_title(
            stdscr,
            title,
        )

        height, width = stdscr.getmaxyx()

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

        stdscr.refresh()

        key = stdscr.getch()

        if key == 27:
            return

        if key in (
            ord("q"),
            ord("Q"),
        ):
            return


# ============================================================
# GENERIC MENU
# ============================================================

def menu_screen(stdscr, title, items):
    """Display a menu and return the selected index."""

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


# ============================================================
# GENERIC TOOL SCREEN
# ============================================================

def tool_screen(stdscr, tool_name):
    """Temporary screen for tools without a custom interface."""

    while True:

        stdscr.clear()

        draw_title(
            stdscr,
            tool_name,
        )

        height, width = stdscr.getmaxyx()

        message = [
            f"{tool_name} interface",
            "",
            "Tool interface will be connected here.",
            "",
            "Press Esc to return.",
        ]

        start_y = (
            height // 2
            - len(message) // 2
        )

        for index, line in enumerate(message):

            x = max(
                0,
                (width - len(line)) // 2
            )

            stdscr.addstr(
                start_y + index,
                x,
                line,
            )

        stdscr.refresh()

        key = stdscr.getch()

        if key == 27:
            return


# ============================================================
# AIRCRACK ERROR SCREEN
# ============================================================

def aircrack_error_screen(stdscr, error):
    """Display an Aircrack backend error."""

    message_screen(
        stdscr,
        "Aircrack-ng Error",
        [
            "The operation failed.",
            "",
            str(error),
            "",
            "Press Esc to return.",
        ],
    )


# ============================================================
# AIRCRACK TOOLS
# ============================================================

def aircrack_tools_screen(stdscr):
    """Show available Aircrack-ng dependencies."""

    try:
        tools = aircrack.find_tools()

    except Exception as exc:
        aircrack_error_screen(
            stdscr,
            exc,
        )
        return

    lines = [
        "Aircrack-ng dependencies",
        "",
        f"airmon-ng   : {tools.airmon or 'NOT FOUND'}",
        f"airodump-ng : {tools.airodump or 'NOT FOUND'}",
        f"aireplay-ng : {tools.aireplay or 'NOT FOUND'}",
        f"aircrack-ng : {tools.aircrack or 'NOT FOUND'}",
        f"iw          : {tools.iw or 'NOT FOUND'}",
        f"tshark      : {tools.tshark or 'NOT FOUND'}",
        "",
        f"Complete    : {'YES' if tools.complete else 'NO'}",
        "",
        "Press Esc to return.",
    ]

    message_screen(
        stdscr,
        "Aircrack-ng Tools",
        lines,
    )


# ============================================================
# AIRCRACK VERSION
# ============================================================

def aircrack_version_screen(stdscr):
    """Display the installed Aircrack-ng version."""

    try:
        version = aircrack.version()

    except Exception as exc:
        aircrack_error_screen(
            stdscr,
            exc,
        )
        return

    message_screen(
        stdscr,
        "Aircrack-ng Version",
        [
            version,
            "",
            "Press Esc to return.",
        ],
    )


# ============================================================
# AIRCRACK INTERFACES
# ============================================================

def aircrack_interfaces_screen(stdscr):
    """Display available wireless interfaces."""

    try:
        interfaces = aircrack.list_interfaces()

    except Exception as exc:
        aircrack_error_screen(
            stdscr,
            exc,
        )
        return

    if not interfaces:

        lines = [
            "No wireless interfaces found.",
            "",
            "Press Esc to return.",
        ]

    else:

        lines = [
            "Wireless interfaces:",
            "",
        ]

        lines.extend(
            f"- {interface}"
            for interface in interfaces
        )

        lines.extend(
            [
                "",
                "Press Esc to return.",
            ]
        )

    message_screen(
        stdscr,
        "Wireless Interfaces",
        lines,
    )


# ============================================================
# AIRCRACK DETECT INTERFACE
# ============================================================

def aircrack_detect_interface_screen(stdscr):
    """Automatically detect a usable wireless interface."""

    try:
        interface = aircrack.detect_interface()

    except Exception as exc:
        aircrack_error_screen(
            stdscr,
            exc,
        )
        return

    message_screen(
        stdscr,
        "Detected Interface",
        [
            f"Interface: {interface}",
            "",
            "Press Esc to return.",
        ],
    )


# ============================================================
# MONITOR MODE
# ============================================================

def aircrack_monitor_screen(stdscr):
    """Manage the Gremlin monitor-mode session."""

    session = None

    while True:

        if session is None:

            selected = menu_screen(
                stdscr,
                "Monitor Mode",
                [
                    "Start Monitor",
                ],
            )

            if selected is None:
                return

            if selected == 0:

                stdscr.clear()

                draw_title(
                    stdscr,
                    "Starting Monitor Mode",
                )

                stdscr.refresh()

                try:
                    interface = aircrack.detect_interface()

                    session = aircrack.start_monitor(
                        interface
                    )

                except Exception as exc:

                    aircrack_error_screen(
                        stdscr,
                        exc,
                    )

        else:

            selected = menu_screen(
                stdscr,
                f"Monitor: {session.interface}",
                [
                    "Show Session",
                    "Stop Monitor",
                ],
            )

            if selected is None:
                return

            if selected == 0:

                message_screen(
                    stdscr,
                    "Monitor Session",
                    [
                        f"Interface: {session.interface}",
                        "",
                        (
                            "Created by Gremlin: "
                            f"{session.created_by_gremlin}"
                        ),
                        "",
                        "Press Esc to return.",
                    ],
                )

            elif selected == 1:

                try:
                    aircrack.stop_monitor(
                        session
                    )

                except Exception as exc:

                    aircrack_error_screen(
                        stdscr,
                        exc,
                    )

                session = None


# ============================================================
# PASSIVE WIRELESS SCAN
# ============================================================

def aircrack_scan_screen(stdscr):
    """Run a passive wireless scan."""

    selected = menu_screen(
        stdscr,
        "Wireless Scan",
        [
            "10 Second Scan",
            "30 Second Scan",
            "60 Second Scan",
        ],
    )

    if selected is None:
        return

    durations = [
        10,
        30,
        60,
    ]

    duration = durations[selected]

    stdscr.clear()

    draw_title(
        stdscr,
        "Scanning...",
    )

    height, width = stdscr.getmaxyx()

    lines = [
        f"Running passive scan for {duration} seconds.",
        "",
        "Please wait...",
    ]

    start_y = height // 2

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

    stdscr.refresh()

    try:
        access_points = aircrack.scan(
            duration
        )

    except Exception as exc:
        aircrack_error_screen(
            stdscr,
            exc,
        )
        return

    aircrack_scan_results_screen(
        stdscr,
        access_points,
    )


# ============================================================
# SCAN RESULTS
# ============================================================

def aircrack_scan_results_screen(
    stdscr,
    access_points,
):
    """Display discovered access points."""

    if not access_points:

        message_screen(
            stdscr,
            "Scan Results",
            [
                "No access points discovered.",
                "",
                "Press Esc to return.",
            ],
        )

        return

    selected = 0

    while True:

        stdscr.clear()

        draw_title(
            stdscr,
            "Scan Results",
        )

        height, width = stdscr.getmaxyx()

        visible = max(
            1,
            height - 8,
        )

        start = max(
            0,
            selected - visible + 1,
        )

        displayed = access_points[
            start:start + visible
        ]

        for row, ap in enumerate(displayed):

            index = start + row

            text = (
                f"{ap.bssid:<17} "
                f"CH {ap.channel:<3} "
                f"PWR {ap.power:<4} "
                f"{ap.encryption:<12} "
                f"{ap.essid}"
            )

            if index == selected:

                stdscr.addstr(
                    4 + row,
                    1,
                    text[:width - 2],
                    curses.A_REVERSE,
                )

            else:

                stdscr.addstr(
                    4 + row,
                    1,
                    text[:width - 2],
                )

        footer = (
            "↑/↓ Select   Enter Details   Esc Back"
        )

        x = max(
            0,
            (width - len(footer)) // 2
        )

        stdscr.addstr(
            height - 2,
            x,
            footer,
        )

        stdscr.refresh()

        key = stdscr.getch()

        if key in (
            curses.KEY_DOWN,
            ord("j"),
        ):

            selected += 1

            if selected >= len(access_points):
                selected = 0

        elif key in (
            curses.KEY_UP,
            ord("k"),
        ):

            selected -= 1

            if selected < 0:
                selected = len(access_points) - 1

        elif key in (
            curses.KEY_ENTER,
            10,
            13,
        ):

            aircrack_ap_details_screen(
                stdscr,
                access_points[selected],
            )

        elif key == 27:
            return


# ============================================================
# ACCESS POINT DETAILS
# ============================================================

def aircrack_ap_details_screen(stdscr, ap):
    """Display details about an access point."""

    lines = [
        f"BSSID:      {ap.bssid}",
        f"ESSID:      {ap.essid or '<hidden>'}",
        f"Channel:    {ap.channel}",
        f"Power:      {ap.power}",
        f"Encryption: {ap.encryption}",
        "",
        f"Clients:    {len(ap.clients)}",
    ]

    if ap.clients:

        lines.append("")

        for client in ap.clients:

            lines.append(
                f"{client.mac} -> {client.bssid}"
            )

    lines.extend(
        [
            "",
            "Press Esc to return.",
        ]
    )

    message_screen(
        stdscr,
        "Access Point Details",
        lines,
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
