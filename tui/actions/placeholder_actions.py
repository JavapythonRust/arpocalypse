"""
tui/actions/placeholder_actions.py
===================================

Factory for "not implemented yet" stub handlers, so you can add an
item into menu_tree.py before its real handler is written.

    Action("Nmap", placeholder_actions.not_implemented("Nmap"))
"""

from tui.core import message_screen


def not_implemented(name):
    def handler(stdscr):
        message_screen(stdscr, name, f"{name} interface\n\nNot implemented yet.")
    return handler
