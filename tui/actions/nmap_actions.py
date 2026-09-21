"""
tui/actions/nmap_actions.py
=============================

Handler functions for the Nmap menu. Every preset (quick_scan,
os_detection, ...) takes a `target` string, so `_run_preset` is a
small shared helper that prompts for the target once and reuses it
for all of them.
"""

from tools.python import nmap
from tui.core import choose_target, message_screen, prompt_text


def _format_result(result: "nmap.NmapResult") -> str:
    lines = [
        "$ " + " ".join(result.command),
        "",
    ]

    if result.stdout:
        lines.append(result.stdout.strip())

    if result.stderr:
        lines.extend(["", "--- stderr ---", result.stderr.strip()])

    lines.extend([
        "",
        f"Return code: {result.returncode}"
        + ("  (timed out)" if result.timed_out else ""),
    ])

    return "\n".join(lines)


def _run_preset(stdscr, title, preset_fn, offer_subnet_default=False):
    """Choose a target, run an Nmap preset against it, show the result."""
    target = choose_target(stdscr, title, offer_subnet_default=offer_subnet_default)
    if not target:
        return

    message_screen(stdscr, title, f"Press a key to scan {target} ...")

    try:
        result = preset_fn(target)
        message_screen(stdscr, title, _format_result(result))
    except nmap.NmapError as exc:
        message_screen(stdscr, "Nmap Error", str(exc))
    except ValueError as exc:
        message_screen(stdscr, "Invalid Target", str(exc))


# ------------------------------------------------------------
# Menu handlers
# ------------------------------------------------------------

def check_available(stdscr):
    if not nmap.available():
        message_screen(stdscr, "Nmap", "Nmap is not installed or not in PATH.")
        return

    try:
        message_screen(stdscr, "Nmap Version", nmap.version())
    except nmap.NmapError as exc:
        message_screen(stdscr, "Nmap Error", str(exc))


def host_discovery(stdscr):
    _run_preset(stdscr, "Host Discovery", nmap.host_discovery, offer_subnet_default=True)


def quick_scan(stdscr):
    _run_preset(stdscr, "Quick Scan", nmap.quick_scan)


def service_detection(stdscr):
    _run_preset(stdscr, "Service Detection", nmap.service_detection)


def os_detection(stdscr):
    _run_preset(stdscr, "OS Detection", nmap.os_detection)


def default_scripts(stdscr):
    _run_preset(stdscr, "Default Scripts", nmap.default_scripts)


def common_ports(stdscr):
    _run_preset(stdscr, "Common Ports", nmap.common_ports)


def ipv6_discovery(stdscr):
    _run_preset(stdscr, "IPv6 Discovery", nmap.ipv6_discovery, offer_subnet_default=True)


def traceroute(stdscr):
    _run_preset(stdscr, "Traceroute", nmap.traceroute)
