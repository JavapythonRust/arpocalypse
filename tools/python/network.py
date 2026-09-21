"""
tools/python/network.py
========================

Small helpers for auto-detecting network info (own IP, subnet,
default gateway) so the TUI doesn't need the user to type things
like "192.168.1.1" on a D-pad.
"""

import socket
import struct


def detect_local_ip() -> str | None:
    """
    Return this machine's LAN IP address (the one used to reach the
    internet), or None if it can't be determined.

    This doesn't actually send any data -- UDP connect() just asks
    the kernel to pick a local address/route for that destination.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def local_subnet_cidr(prefix: int = 24) -> str | None:
    """
    Return a best-guess CIDR for the local subnet, e.g. "192.168.1.0/24".

    Assumes a /24 (the common case for home/small networks) unless a
    different prefix is given. Good enough for a quick host-discovery
    scan; not a substitute for reading the real netmask.
    """
    ip = detect_local_ip()
    if not ip:
        return None

    octets = ip.split(".")
    if prefix == 24:
        network = ".".join(octets[:3]) + ".0"
    elif prefix == 16:
        network = ".".join(octets[:2]) + ".0.0"
    else:
        network = ip  # fall back to a /32-ish single host

    return f"{network}/{prefix}"


def detect_gateway() -> str | None:
    """
    Return the default gateway IP by reading /proc/net/route, or None
    if it can't be found (e.g. non-Linux, no default route).
    """
    try:
        with open("/proc/net/route") as f:
            lines = f.readlines()[1:]  # skip header
    except OSError:
        return None

    for line in lines:
        fields = line.strip().split()
        if len(fields) < 3:
            continue

        iface, destination, gateway = fields[0], fields[1], fields[2]

        if destination != "00000000":  # only the default route
            continue

        try:
            # /proc/net/route stores addresses as little-endian hex
            packed = struct.pack("<L", int(gateway, 16))
            return socket.inet_ntoa(packed)
        except (ValueError, OSError):
            continue

    return None
