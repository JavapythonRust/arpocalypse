"""
tui/actions/aircrack_actions.py
================================

Handler functions and helpers for the Aircrack-ng workflows.

Every public function below takes a single `stdscr` argument, which
means it can be wired directly onto an `Action(...)` in menu_tree.py,
e.g.:

    Action("Check Tools", aircrack_actions.check_tools)

Shared helpers (select_ap, select_client, ...) are not menu handlers
themselves — they're building blocks the handlers below use.
"""

from tools.python import aircrack
from tui.core import message_screen, select_from_list


# ------------------------------------------------------------
# Shared helpers
# ------------------------------------------------------------

def run_passive_scan(stdscr, duration=10):
    try:
        message_screen(stdscr, "Passive Scan", "Starting passive wireless scan...")
        return aircrack.scan(duration=duration)
    except Exception as exc:
        message_screen(stdscr, "Scan Error", str(exc))
        return None


def select_ap(stdscr, aps):
    def fmt(ap):
        essid = ap.essid or "<hidden>"
        return f"{essid} | {ap.bssid} | CH {ap.channel} | {ap.power}"

    return select_from_list(
        stdscr, "Select Access Point", aps, fmt,
        empty_message="No access points were discovered.",
    )


def select_client(stdscr, ap):
    return select_from_list(
        stdscr, "Select Client", ap.clients, lambda c: c.mac,
        empty_message=f"No clients were discovered for\n{ap.essid or '<hidden>'}.",
    )


def select_target(stdscr):
    aps = run_passive_scan(stdscr)
    if not aps:
        return None
    return select_ap(stdscr, aps)


def select_target_client(stdscr):
    ap = select_target(stdscr)
    if ap is None:
        return None, None

    client = select_client(stdscr, ap)
    if client is None:
        return None, None

    return ap, client


# ------------------------------------------------------------
# Menu handlers
# ------------------------------------------------------------

def check_tools(stdscr):
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
        message_screen(stdscr, "Check Tools", "\n".join(lines))
    except Exception as exc:
        message_screen(stdscr, "Aircrack Error", str(exc))


def version(stdscr):
    try:
        message_screen(stdscr, "Aircrack-ng Version", aircrack.version())
    except Exception as exc:
        message_screen(stdscr, "Aircrack Error", str(exc))


def interfaces(stdscr):
    try:
        ifaces = aircrack.list_interfaces()
        message = (
            "Wireless Interfaces\n\n" + "\n".join(ifaces)
            if ifaces else "No wireless interfaces detected."
        )
        message_screen(stdscr, "Wireless Interfaces", message)
    except Exception as exc:
        message_screen(stdscr, "Aircrack Error", str(exc))


def detect_interface(stdscr):
    try:
        iface = aircrack.detect_interface()
        message_screen(stdscr, "Detect Interface", f"Detected interface:\n\n{iface}")
    except Exception as exc:
        message_screen(stdscr, "Aircrack Error", str(exc))


def monitor_mode(stdscr):
    try:
        iface = aircrack.detect_interface()
        session = aircrack.start_monitor(iface)
        message_screen(
            stdscr, "Monitor Mode",
            (
                f"Monitor interface:\n\n{session.interface}\n\n"
                "Press a key to stop monitor mode."
            ),
        )
        aircrack.stop_monitor(session)
    except Exception as exc:
        message_screen(stdscr, "Monitor Mode Error", str(exc))


def passive_scan(stdscr):
    aps = run_passive_scan(stdscr)
    if aps is None:
        return
    if not aps:
        message_screen(stdscr, "Passive Scan", "No access points detected.")
        return

    lines = [
        "BSSID              CH   POWER   ENCRYPTION   ESSID",
        "-" * 65,
    ]
    for ap in aps:
        lines.append(
            f"{ap.bssid:<18} {ap.channel:<4} {ap.power:<7} "
            f"{ap.encryption:<12} {ap.essid}"
        )
    message_screen(stdscr, "Passive Wireless Scan", "\n".join(lines))


def handshake_capture(stdscr):
    aps = run_passive_scan(stdscr)
    if not aps:
        return

    ap = select_ap(stdscr, aps)
    if ap is None:
        return

    try:
        result = aircrack.capture_handshake(bssid=ap.bssid, channel=ap.channel)
        lines = [
            f"State: {result.state.value}",
            f"Return code: {result.returncode}",
            f"Verified: {result.verified}",
            f"Handshake observed: {result.handshake_captured}",
        ]
        if result.capture_file:
            lines.append(f"Capture: {result.capture_file}")
        if result.error:
            lines.extend(["", f"Error: {result.error}"])
        message_screen(stdscr, "Handshake Capture", "\n".join(lines))
    except Exception as exc:
        message_screen(stdscr, "Capture Error", str(exc))


def client_operation(stdscr):
    ap, client = select_target_client(stdscr)
    if ap is None or client is None:
        return

    result = aircrack.deauth_client(
        bssid=ap.bssid,
        client_mac=client.mac,
        known_clients=ap.clients,
    )

    message_screen(
        stdscr, "Client Operation",
        (
            f"AP: {ap.essid or '<hidden>'}\n"
            f"BSSID: {ap.bssid}\n"
            f"Channel: {ap.channel}\n"
            f"Client: {client.mac}\n"
            f"Known clients: {len(ap.clients)}\n\n"
            f"Backend result: {result}"
        ),
    )


def combined_operation(stdscr):
    ap, client = select_target_client(stdscr)
    if ap is None or client is None:
        return

    message_screen(
        stdscr, "Selected Target",
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
