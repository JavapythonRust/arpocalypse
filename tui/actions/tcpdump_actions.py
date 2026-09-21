"""
tui/actions/tcpdump_actions.py
=================================

Handler functions for the Tcpdump menu.

NOTE: tools/python/tcpdump.py, as currently committed, starts with a
stray ```python line and ends with a stray ``` line (leftover
markdown fences saved into the .py file). That's a SyntaxError on
import — delete those two lines from tcpdump.py before this module
will load.
"""

from pathlib import Path

from tools.python import tcpdump
from tui.config import PCAPS_DIR
from tui.core import message_screen, prompt_text, select_from_list, select_interface


def find_pcaps():
    """
    Scan PCAPS_DIR for .pcap/.pcapng files every time it's called, so
    files saved by Capture Traffic (or dropped in manually) show up
    automatically in Read PCAP File without any extra bookkeeping.
    """
    if not PCAPS_DIR.exists() or not PCAPS_DIR.is_dir():
        return []

    return sorted(
        (
            p for p in PCAPS_DIR.iterdir()
            if p.is_file() and p.suffix.lower() in (".pcap", ".pcapng")
        ),
        key=lambda p: p.name.lower(),
    )


def _format_completed(result) -> str:
    lines = [f"Return code: {result.returncode}", ""]

    if result.stdout:
        lines.append(result.stdout.strip())

    if result.stderr:
        lines.extend(["", "--- stderr ---", result.stderr.strip()])

    return "\n".join(lines)


def _prompt_int(stdscr, title, prompt):
    """Prompt for an optional integer. Returns None if left blank."""
    raw = prompt_text(stdscr, title, prompt).strip()
    if not raw:
        return None, True

    try:
        return int(raw), True
    except ValueError:
        message_screen(stdscr, "Invalid Input", f"'{raw}' is not a whole number.")
        return None, False


# ------------------------------------------------------------
# Menu handlers
# ------------------------------------------------------------

def list_interfaces(stdscr):
    try:
        result = tcpdump.list_interfaces()
        message_screen(stdscr, "Tcpdump Interfaces", _format_completed(result))
    except tcpdump.TcpdumpError as exc:
        message_screen(stdscr, "Tcpdump Error", str(exc))


def monitor_mode(stdscr):
    interface = select_interface(stdscr, "Monitor Mode - Select Interface")
    if not interface:
        return

    try:
        result = tcpdump.set_monitor_mode(interface)
        message_screen(stdscr, "Monitor Mode", _format_completed(result))
    except tcpdump.TcpdumpError as exc:
        message_screen(stdscr, "Tcpdump Error", str(exc))


def managed_mode(stdscr):
    interface = select_interface(stdscr, "Managed Mode - Select Interface")
    if not interface:
        return

    try:
        result = tcpdump.set_managed_mode(interface)
        message_screen(stdscr, "Managed Mode", _format_completed(result))
    except tcpdump.TcpdumpError as exc:
        message_screen(stdscr, "Tcpdump Error", str(exc))


def capture(stdscr):
    interface = select_interface(stdscr, "Capture Traffic - Select Interface")
    if not interface:
        return

    count, ok = _prompt_int(stdscr, "Capture Traffic", "Packet count (blank = unlimited):")
    if not ok:
        return

    filter_expression = prompt_text(
        stdscr, "Capture Traffic",
        "BPF filter (blank = none, e.g. 'tcp', 'arp'):",
    ).strip() or None

    save_name = prompt_text(
        stdscr, "Capture Traffic",
        f"Save as (blank = don't save; files are saved under {PCAPS_DIR}):",
    ).strip()

    output_file = None
    if save_name:
        path = Path(save_name)

        # A bare filename lands in PCAPS_DIR automatically, so it
        # shows up in Read PCAP File right away. An absolute path is
        # respected as-is if you want it saved elsewhere.
        if not path.is_absolute():
            PCAPS_DIR.mkdir(parents=True, exist_ok=True)
            path = PCAPS_DIR / path

        if path.suffix.lower() not in (".pcap", ".pcapng"):
            path = path.with_suffix(".pcap")

        output_file = str(path)

    try:
        result = tcpdump.capture(
            interface=interface,
            count=count,
            filter_expression=filter_expression,
            output_file=output_file,
        )

        message = _format_completed(result)
        if output_file:
            message += f"\n\nSaved to: {output_file}"

        message_screen(stdscr, "Capture Complete", message)
    except tcpdump.TcpdumpError as exc:
        message_screen(stdscr, "Tcpdump Error", str(exc))


def read_pcap(stdscr):
    pcaps = find_pcaps()

    pcap_file = select_from_list(
        stdscr, "Read PCAP", pcaps, lambda p: p.name,
        empty_message=(
            "No .pcap files found.\n\n"
            f"PCAP directory:\n{PCAPS_DIR}\n\n"
            "Drop files there, or use Capture Traffic and save into it."
        ),
    )
    if pcap_file is None:
        return

    filter_expression = prompt_text(
        stdscr, "Read PCAP", "BPF filter (blank = none):",
    ).strip() or None

    try:
        result = tcpdump.read_pcap(
            pcap_file=str(pcap_file),
            filter_expression=filter_expression,
        )
        message_screen(stdscr, "PCAP Contents", _format_completed(result))
    except tcpdump.TcpdumpError as exc:
        message_screen(stdscr, "Tcpdump Error", str(exc))
