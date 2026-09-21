"""
tui/menu_tree.py
=================

    >>> THIS IS THE FILE YOU EDIT <<<

This is the only file you should need to touch to add a new menu,
submenu, or option. There are two building blocks (from tui.core):

    Action("Label shown in the menu", some_function)
        A leaf item. `some_function` must accept a single argument,
        the curses `stdscr`, and do whatever it needs to do (usually
        by calling a helper in tui/actions/*.py).

    Menu("Title shown at the top of the screen", [ ...children... ])
        A submenu. Its children can be more Menus and/or Actions,
        nested as deep as you like.

Wiring up a brand-new feature usually looks like:

    1. Write a function `my_thing(stdscr)` in tui/actions/<file>.py
       (an existing file, or a new one — new files just need to be
       imported below).
    2. Import it below.
    3. Add `Action("My Thing", my_thing)` wherever you want it to
       show up in the tree.

Want a placeholder before the real handler exists? Use:

    Action("Nmap", placeholder.not_implemented("Nmap"))

Want to reorder, rename, or move something? Just move the Action(...)
/ Menu(...) line around — the engine in tui/core.py doesn't care
about the shape of the tree, only what's in it.
"""

from tui.core import Menu, Action
from tui.actions import aircrack_actions as aircrack
from tui.actions import nmap_actions as nmap
from tui.actions import tcpdump_actions as tcpdump
from tui.actions import bettercap_actions as bettercap
from tui.actions import hid_actions as hid
from tui.actions import placeholder_actions as placeholder


# ------------------------------------------------------------
# Aircrack-ng submenu
# ------------------------------------------------------------

AIRCRACK_MENU = Menu("Aircrack-ng", [
    Action("Check Tools", aircrack.check_tools),
    Action("Version", aircrack.version),
    Action("Wireless Interfaces", aircrack.interfaces),
    Action("Detect Interface", aircrack.detect_interface),
    Action("Monitor Mode", aircrack.monitor_mode),
    Action("Passive Wireless Scan", aircrack.passive_scan),
    Menu("Wireless Operations", [
        Action("Listen for Handshakes", aircrack.handshake_capture),
        Action("Client Operation", aircrack.client_operation),
        Action("Combined Operation", aircrack.combined_operation),
    ]),
])


# ------------------------------------------------------------
# Nmap submenu
# ------------------------------------------------------------

NMAP_MENU = Menu("Nmap", [
    Action("Check / Version", nmap.check_available),
    Action("Host Discovery", nmap.host_discovery),
    Action("Quick Scan", nmap.quick_scan),
    Action("Service Detection", nmap.service_detection),
    Action("OS Detection", nmap.os_detection),
    Action("Default Scripts", nmap.default_scripts),
    Action("Common Ports", nmap.common_ports),
    Action("IPv6 Discovery", nmap.ipv6_discovery),
    Action("Traceroute", nmap.traceroute),
])


# ------------------------------------------------------------
# Tcpdump submenu
# ------------------------------------------------------------

TCPDUMP_MENU = Menu("Tcpdump", [
    Action("List Interfaces", tcpdump.list_interfaces),
    Action("Monitor Mode", tcpdump.monitor_mode),
    Action("Managed Mode", tcpdump.managed_mode),
    Action("Capture Traffic", tcpdump.capture),
    Action("Read PCAP File", tcpdump.read_pcap),
])


# ------------------------------------------------------------
# Bettercap submenu
# ------------------------------------------------------------

BETTERCAP_MENU = Menu("Bettercap", [
    Action("MITM + SSL Strip", bettercap.mitm_sslstrip),
])


# ------------------------------------------------------------
# Linux Tools submenu
#   -> add a new backend the same way: write tui/actions/<x>_actions.py,
#      import it above, and add a Menu(...) or Action(...) below.
# ------------------------------------------------------------

LINUX_TOOLS_MENU = Menu("Linux Tools", [
    NMAP_MENU,
    TCPDUMP_MENU,
    BETTERCAP_MENU,
    AIRCRACK_MENU,
])


# ------------------------------------------------------------
# Python / Rust Tools submenus
#   -> currently empty. Add entries the same way as anywhere else:
#         PYTHON_TOOLS_MENU.children.append(Action("My Script", fn))
#      or just list them inline below.
# ------------------------------------------------------------

PYTHON_TOOLS_MENU = Menu("Python Tools", [])

RUST_TOOLS_MENU = Menu("Rust Tools", [])


# ------------------------------------------------------------
# USB HID submenu
# ------------------------------------------------------------

HID_MENU = Menu("USB HID", [
    Action("HID Status", hid.status),
    Action("Type Text", hid.type_text),
    Action("Press Key", hid.press_key),
    Action("Hotkey", hid.hotkey),
    Action("Run Macro", hid.run_macro),
])


# ------------------------------------------------------------
# Main menu — the root of the tree.
#   -> add a new top-level category by adding a Menu(...) here.
# ------------------------------------------------------------

MAIN_MENU = Menu("ARPocalypse Gremlin", [
    LINUX_TOOLS_MENU,
    PYTHON_TOOLS_MENU,
    RUST_TOOLS_MENU,
    HID_MENU,
])
