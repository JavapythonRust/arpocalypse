```python
"""
ARPocalypse Gremlin TUI
=======================

Main terminal interface for the Gremlin.

Current tools:
    Linux Tools
        - Nmap
        - Tcpdump

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


# ============================================================
# TOOL CATEGORIES
# ============================================================

# Keep tools separated by what they are.
#
# When you create another tool later, add it to the
# appropriate list.

LINUX_TOOLS = [
    "Nmap",
    "Tcpdump",
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

        # Highlight the currently selected item.
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
    Display a menu and return the selected item.

    Returns:
        The selected item's index.

    Returns:
        None when the user presses Esc.
    """

    # Always give the user a way to go back.
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

            # "Back" was selected.
            if selected == len(menu_items) - 1:
                return None

            return selected

        # ----------------------------------------------------
        # ESC
        # ----------------------------------------------------

        elif key == 27:
            return None


# ============================================================
# TOOL SCREEN
# ============================================================

def tool_screen(stdscr, tool_name):
    """
    Temporary screen for a tool.

    This will eventually be replaced by the actual interface
    for the selected wrapper.
    """

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
# LINUX TOOLS MENU
# ============================================================

def linux_tools_screen(stdscr):
    """Display the Linux tools."""

    while True:

        selected = menu_screen(
            stdscr,
            "Linux Tools",
            LINUX_TOOLS,
        )

        if selected is None:
            return

        tool_screen(
            stdscr,
            LINUX_TOOLS[selected],
        )


# ============================================================
# PYTHON TOOLS MENU
# ============================================================

def python_tools_screen(stdscr):
    """Display the Python tools."""

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
    """Display the Rust tools."""

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
                linux_tools_screen(stdscr)

            elif selected == 1:
                python_tools_screen(stdscr)

            elif selected == 2:
                rust_tools_screen(stdscr)

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

    curses.wrapper(main_menu)


if __name__ == "__main__":
    main()
```
