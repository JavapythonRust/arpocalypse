"""
tui/core.py
===========

Generic TUI engine + drawing primitives for the ARPocalypse Gremlin TUI.

    >>> You should not need to edit this file to add a menu, submenu,
    >>> option, or new feature. Edit `tui/menu_tree.py` instead, and
    >>> write new behavior as a function in `tui/actions/`.

This file contains only generic, reusable plumbing:
  - low level curses drawing helpers
  - generic list-menu / message / text-prompt screens
  - the Menu / Action tree data structures
  - the recursive engine that walks a Menu tree
"""

from __future__ import annotations

import curses
import os
from dataclasses import dataclass, field
from typing import Callable, List, Union


# ============================================================
# LOW LEVEL DRAWING
# ============================================================

def draw_title(stdscr, title):
    height, width = stdscr.getmaxyx()
    x = max(0, (width - len(title)) // 2)
    stdscr.addstr(1, x, title, curses.A_BOLD)


def draw_menu(stdscr, items, selected):
    start_y = 4

    for index, item in enumerate(items):
        height, width = stdscr.getmaxyx()
        x = max(0, (width - len(item) - 2) // 2)

        if index == selected:
            stdscr.addstr(start_y + index, x, f"> {item}", curses.A_REVERSE)
        else:
            stdscr.addstr(start_y + index, x, f"  {item}")


def draw_help(stdscr, message=None):
    height, width = stdscr.getmaxyx()

    message = message or "Up/Down Navigate   Enter Select   Esc Back   Q Quit"
    x = max(0, (width - len(message)) // 2)

    stdscr.addstr(height - 2, x, message)


# ============================================================
# GENERIC SCREENS
# ============================================================

def menu_screen(stdscr, title, items, exit_label="Back"):
    """
    Show a list of `items` (strings) plus a trailing exit entry.

    Returns the index of the chosen item, or None if the user backed
    out (selected the exit entry, pressed Esc, or pressed Q).
    """
    menu_items = list(items) + [exit_label]
    selected = 0

    while True:
        stdscr.clear()
        draw_title(stdscr, title)
        draw_menu(stdscr, menu_items, selected)
        draw_help(stdscr)
        stdscr.refresh()

        key = stdscr.getch()

        if key in (curses.KEY_DOWN, ord("j")):
            selected = (selected + 1) % len(menu_items)

        elif key in (curses.KEY_UP, ord("k")):
            selected = (selected - 1) % len(menu_items)

        elif key in (curses.KEY_ENTER, 10, 13):
            if selected == len(menu_items) - 1:
                return None
            return selected

        elif key == 27:  # Esc
            return None

        elif key in (ord("q"), ord("Q")):
            return None


def message_screen(stdscr, title, message):
    """Show a block of text and wait for any keypress."""
    while True:
        stdscr.clear()
        draw_title(stdscr, title)

        height, width = stdscr.getmaxyx()
        lines = message.splitlines()
        start_y = height // 2 - len(lines) // 2

        for index, line in enumerate(lines):
            y = start_y + index
            if y < 0 or y >= height - 2:
                continue
            x = max(0, (width - len(line)) // 2)
            stdscr.addstr(y, x, line[: max(1, width - 1)])

        stdscr.addstr(height - 2, 2, "Press any key to continue.")
        stdscr.refresh()

        key = stdscr.getch()
        if key != -1:
            return


def prompt_text(stdscr, title, prompt):
    """Show a title + prompt line, and read one line of text back."""
    stdscr.clear()
    draw_title(stdscr, title)

    height, width = stdscr.getmaxyx()
    stdscr.addstr(4, 2, prompt)

    curses.echo()
    try:
        raw = stdscr.getstr(6, 2, max(1, width - 5))
    finally:
        curses.noecho()

    return raw.decode("utf-8", errors="replace")


def select_from_list(stdscr, title, objects, formatter, empty_message=None):
    """
    Generic "pick one object from a list" screen.

    - objects: any list of python objects
    - formatter: callable(obj) -> str, used to build each menu label
    - empty_message: shown instead of the menu if `objects` is empty

    Returns the chosen object, or None if the list was empty or the
    user backed out.
    """
    if not objects:
        if empty_message:
            message_screen(stdscr, title, empty_message)
        return None

    labels = [formatter(obj) for obj in objects]
    selected = menu_screen(stdscr, title, labels)

    if selected is None:
        return None

    return objects[selected]


def choose_target(stdscr, title, offer_subnet_default=False):
    """
    Let the user provide a scan target without necessarily typing it:

      - "Scan network & pick a host" runs select_target_ip()
      - "Use local subnet (<cidr>)" (only when offer_subnet_default=True
        and detection succeeds) fills in something like 192.168.1.0/24
      - "Enter manually" falls back to prompt_text, for anything
        outside the local network, or a specific CIDR/hostname

    Returns the chosen target string, or None if the user backed out.
    """
    from tools.python import network

    options = ["Scan network & pick a host"]

    subnet = network.local_subnet_cidr() if offer_subnet_default else None
    if subnet:
        options.append(f"Use local subnet ({subnet})")

    options.append("Enter manually")

    choice = menu_screen(stdscr, title, options, exit_label="Cancel")
    if choice is None:
        return None

    picked = options[choice]

    if picked == "Scan network & pick a host":
        return select_target_ip(stdscr, title)

    if subnet and picked == f"Use local subnet ({subnet})":
        return subnet

    return prompt_text(stdscr, title, "Target (IP, hostname, or CIDR):").strip() or None


def select_target_ip(stdscr, title="Select Target", subnet=None):
    """
    Scan the local subnet with Nmap and let the user pick a live host
    from a menu instead of typing an IP address by hand.

    Returns the chosen IP (str), or None if the scan failed, found
    nothing, or the user backed out.
    """
    from tools.python import nmap as nmap_tool
    from tools.python import network

    if subnet is None:
        subnet = network.local_subnet_cidr()

    if not subnet:
        message_screen(
            stdscr, title,
            "Could not determine the local subnet to scan.",
        )
        return None

    stdscr.clear()
    draw_title(stdscr, title)
    height, width = stdscr.getmaxyx()
    msg = f"Scanning {subnet} ..."
    stdscr.addstr(height // 2, max(0, (width - len(msg)) // 2), msg)
    stdscr.refresh()

    try:
        result = nmap_tool.host_discovery(subnet)
    except nmap_tool.NmapError as exc:
        message_screen(stdscr, title, f"Scan failed:\n\n{exc}")
        return None

    hosts = nmap_tool.parse_host_discovery(result)

    def _format(host):
        ip, hostname = host
        return f"{ip} ({hostname})" if hostname else ip

    chosen = select_from_list(
        stdscr, title, hosts, _format,
        empty_message=f"No live hosts found on {subnet}.",
    )

    return chosen[0] if chosen else None


def select_interface(stdscr, title="Select Interface"):
    """
    Auto-detect available network interfaces and let the user pick one
    from a menu instead of typing a name like "wlan0" by hand.

    Returns the chosen interface name (str), or None if none were
    found or the user backed out.
    """
    try:
        ifaces = sorted(os.listdir("/sys/class/net"))
    except OSError:
        ifaces = []

    return select_from_list(
        stdscr,
        title,
        ifaces,
        formatter=lambda name: name,
        empty_message="No network interfaces detected.",
    )


# ============================================================
# MENU TREE DATA STRUCTURES
# ============================================================
# The two building blocks used in tui/menu_tree.py:
#
#   Action("Label", handler)   -> a leaf. handler(stdscr) is called.
#   Menu("Title", [ ... ])     -> a submenu of Actions and/or Menus.
# ============================================================

@dataclass
class Action:
    label: str
    handler: Callable[[object], None]


@dataclass
class Menu:
    title: str
    children: List[Union["Menu", Action]] = field(default_factory=list)


# ============================================================
# ENGINE
# ============================================================

def run_menu(stdscr, menu: Menu, is_root: bool = False):
    """
    Recursively walk a Menu tree.

    Selecting an Action calls its handler. Selecting a Menu recurses
    into it. Backing out of a submenu returns to its parent; backing
    out of the root menu exits the application.
    """
    exit_label = "Exit" if is_root else "Back"

    while True:
        labels = [
            child.title if isinstance(child, Menu) else child.label
            for child in menu.children
        ]

        selected = menu_screen(stdscr, menu.title, labels, exit_label=exit_label)

        if selected is None:
            return

        node = menu.children[selected]

        if isinstance(node, Menu):
            run_menu(stdscr, node)
        else:
            node.handler(stdscr)


def run_app(menu: Menu):
    """Entry point used by main.py."""
    curses.wrapper(lambda stdscr: run_menu(stdscr, menu, is_root=True))
