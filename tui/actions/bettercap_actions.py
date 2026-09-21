"""
tui/actions/bettercap_actions.py
===================================

Handler for the Bettercap MITM menu.

bettercap.mitm_sslstrip() runs in the foreground, prints its own
status lines with print(), and blocks until Ctrl+C. That doesn't mix
with curses' screen control, so this handler drops out of curses
(curses.endwin()) before calling it and lets curses redraw once it
returns.
"""

import curses

from tools.python import bettercap
from tools.python import network
from tui.core import prompt_text, select_interface, select_target_ip


def mitm_sslstrip(stdscr):
    target_ip = select_target_ip(stdscr, "MITM + SSL Strip - Select Target")
    if not target_ip:
        return

    gateway_ip = network.detect_gateway()
    if not gateway_ip:
        gateway_ip = prompt_text(stdscr, "MITM + SSL Strip", "Gateway IP (auto-detect failed):")
        if not gateway_ip:
            return

    iface = select_interface(stdscr, "MITM + SSL Strip - Select Interface")
    if not iface:
        return

    pcap_output = prompt_text(
        stdscr, "MITM + SSL Strip",
        "PCAP output path (blank = ~/mitm_capture.pcap):",
    ).strip() or "~/mitm_capture.pcap"

    curses.endwin()
    try:
        print(
            f"\nStarting MITM against {target_ip} via gateway {gateway_ip} "
            f"on {iface}. Press Ctrl+C to stop.\n"
        )
        bettercap.mitm_sslstrip(
            target_ip=target_ip,
            gateway_ip=gateway_ip,
            iface=iface,
            pcap_output=pcap_output,
        )
    except Exception as exc:
        print(f"\nBettercap error: {exc}")
    finally:
        input("\nPress Enter to return to the menu...")
        stdscr.clear()
        stdscr.refresh()
