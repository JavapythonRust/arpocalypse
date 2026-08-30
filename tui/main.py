"""
ARPocalypse Gremlin TUI
=======================

TUI for the Gremlin.

The TUI is responsible for:
    - Navigation
    - Selecting wireless interfaces
    - Running passive scans
    - Selecting discovered APs
    - Selecting discovered clients
    - Collecting parameters
    - Passing parameters to the backend

The backend is responsible for:
    - Validation
    - Authorization
    - Privilege checks
    - Command construction
    - Process execution
    - Cleanup
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

MAIN_MENU = [
    "Linux Tools",
    "Python Tools",
    "Rust Tools",
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
            x = max(
                0,
                (width - len(line)) // 2,
            )

            stdscr.addstr(
                start_y + index,
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
    """
    Let the user select an AccessPoint returned by
    aircrack.scan().
    """

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
    """
    Select one of the clients already associated with
    the selected AP according to the passive scan.
    """

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
    """
    Run the backend's passive scan and return its results.
    """

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


# ============================================================
# DISPLAY SCAN RESULTS
# ============================================================

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
    """
    Perform a passive scan and collect:

        AccessPoint
        BSSID
        channel
        clients
    """

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


# ============================================================
# CLIENT SELECTION
# ============================================================

def select_target_client(stdscr):
    """
    Perform a passive scan, select an AP, then select one
    of the clients discovered for that AP.
    """

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
    """
    Collect the AP and client entirely from passive scan data.

    The actual disruptive backend operation is intentionally
    left behind the backend authorization boundary.
    """

    ap, client = select_target_client(
        stdscr,
    )

    if ap is None or client is None:
        return

    message_screen(
        stdscr,
        "Selected Target",
        (
            f"AP:\n"
            f"{ap.essid or '<hidden>'}\n"
            f"{ap.bssid}\n\n"
            f"Channel: {ap.channel}\n\n"
            f"Client:\n"
            f"{client.mac}\n\n"
            "Parameters collected successfully.\n"
            "The backend authorization layer must approve\n"
            "the requested operation before execution."
        ),
    )


# ============================================================
# COMBINED OPERATION
# ============================================================

def combined_operation_screen(stdscr):
    """
    Collect the parameters required by the combined backend API:

        bssid
        client_mac
        channel
        known_clients
    """

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
