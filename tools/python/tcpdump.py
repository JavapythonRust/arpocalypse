```python
import shutil
import subprocess


class TcpdumpError(Exception):
    """Raised when the tcpdump wrapper encounters an error."""
    pass


def available() -> bool:
    """Check whether tcpdump is installed."""
    return shutil.which("tcpdump") is not None


def _require_tcpdump() -> None:
    if not available():
        raise TcpdumpError(
            "tcpdump is not installed or is not in PATH."
        )


def _run(
    command: list[str],
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    """Run a tcpdump command."""

    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )

    except subprocess.TimeoutExpired as exc:
        raise TcpdumpError(
            f"tcpdump timed out after {timeout} seconds."
        ) from exc

    except OSError as exc:
        raise TcpdumpError(
            f"Failed to execute tcpdump: {exc}"
        ) from exc


def list_interfaces() -> subprocess.CompletedProcess[str]:
    """List interfaces available to tcpdump."""

    _require_tcpdump()

    return _run(
        ["tcpdump", "-D"],
        timeout=10,
    )


def set_monitor_mode(
    interface: str,
) -> subprocess.CompletedProcess[str]:
    """Put a Linux Wi-Fi interface into monitor mode."""

    interface = interface.strip()

    if not interface:
        raise TcpdumpError("Interface is required.")

    if shutil.which("iw") is None:
        raise TcpdumpError(
            "iw is not installed or is not in PATH."
        )

    try:
        return subprocess.run(
            [
                "iw",
                "dev",
                interface,
                "set",
                "type",
                "monitor",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    except OSError as exc:
        raise TcpdumpError(
            f"Failed to execute iw: {exc}"
        ) from exc


def set_managed_mode(
    interface: str,
) -> subprocess.CompletedProcess[str]:
    """Return a Linux Wi-Fi interface to managed mode."""

    interface = interface.strip()

    if not interface:
        raise TcpdumpError("Interface is required.")

    if shutil.which("iw") is None:
        raise TcpdumpError(
            "iw is not installed or is not in PATH."
        )

    try:
        return subprocess.run(
            [
                "iw",
                "dev",
                interface,
                "set",
                "type",
                "managed",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    except OSError as exc:
        raise TcpdumpError(
            f"Failed to execute iw: {exc}"
        ) from exc


def capture(
    interface: str,
    count: int | None = None,
    snaplen: int | None = None,
    promiscuous: bool = True,
    timestamp: str | None = None,
    verbosity: int = 0,
    hex_dump: bool = False,
    ascii_dump: bool = False,
    filter_expression: str | None = None,
    output_file: str | None = None,
    monitor_mode: bool = False,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    """
    Capture live traffic with tcpdump.

    timestamp:
        None       -> tcpdump default
        "none"     -> disable timestamps
        "absolute" -> absolute timestamps

    verbosity:
        0 -> normal
        1 -> -v
        2 -> -vv
        3 -> -vvv
    """

    _require_tcpdump()

    interface = interface.strip()

    if not interface:
        raise TcpdumpError("Interface is required.")

    if count is not None and count < 1:
        raise TcpdumpError(
            "Count must be at least 1."
        )

    if snaplen is not None and snaplen < 0:
        raise TcpdumpError(
            "Snap length cannot be negative."
        )

    if verbosity not in range(4):
        raise TcpdumpError(
            "Verbosity must be between 0 and 3."
        )

    if timeout < 1:
        raise TcpdumpError(
            "Timeout must be at least 1 second."
        )

    if monitor_mode:
        result = set_monitor_mode(interface)

        if result.returncode != 0:
            raise TcpdumpError(
                result.stderr.strip()
                or "Failed to enable monitor mode."
            )

    command = [
        "tcpdump",
        "-i",
        interface,
    ]

    if not promiscuous:
        command.append("-p")

    if count is not None:
        command.extend([
            "-c",
            str(count),
        ])

    if snaplen is not None:
        command.extend([
            "-s",
            str(snaplen),
        ])

    if timestamp == "none":
        command.append("-t")

    elif timestamp == "absolute":
        command.append("-tt")

    elif timestamp is not None:
        raise TcpdumpError(
            "Timestamp must be None, 'none', or 'absolute'."
        )

    if verbosity:
        command.append(
            "-" + ("v" * verbosity)
        )

    if hex_dump:
        command.append("-x")

    if ascii_dump:
        command.append("-A")

    if output_file:
        command.extend([
            "-w",
            output_file,
        ])

    if filter_expression:
        command.append(filter_expression)

    return _run(
        command,
        timeout=timeout,
    )


def read_pcap(
    pcap_file: str,
    filter_expression: str | None = None,
    verbosity: int = 0,
    hex_dump: bool = False,
    ascii_dump: bool = False,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    """Read and inspect an existing PCAP file."""

    _require_tcpdump()

    pcap_file = pcap_file.strip()

    if not pcap_file:
        raise TcpdumpError(
            "PCAP file is required."
        )

    if verbosity not in range(4):
        raise TcpdumpError(
            "Verbosity must be between 0 and 3."
        )

    command = [
        "tcpdump",
        "-r",
        pcap_file,
    ]

    if verbosity:
        command.append(
            "-" + ("v" * verbosity)
        )

    if hex_dump:
        command.append("-x")

    if ascii_dump:
        command.append("-A")

    if filter_expression:
        command.append(filter_expression)

    return _run(
        command,
        timeout=timeout,
    )


def ipv4_filter() -> str:
    """Return a BPF filter for IPv4 traffic."""
    return "ip"


def ipv6_filter() -> str:
    """Return a BPF filter for IPv6 traffic."""
    return "ip6"


def tcp_filter() -> str:
    """Return a BPF filter for TCP traffic."""
    return "tcp"


def udp_filter() -> str:
    """Return a BPF filter for UDP traffic."""
    return "udp"


def icmp_filter() -> str:
    """Return a BPF filter for ICMP traffic."""
    return "icmp"


def arp_filter() -> str:
    """Return a BPF filter for ARP traffic."""
    return "arp"


def combine_filters(*filters: str) -> str:
    """Combine multiple BPF filters with AND."""

    valid = [
        value.strip()
        for value in filters
        if value and value.strip()
    ]

    if not valid:
        raise TcpdumpError(
            "At least one filter is required."
        )

    return " and ".join(
        f"({value})"
        for value in valid
    )


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Gremlin tcpdump wrapper"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # Interfaces
    subparsers.add_parser(
        "interfaces",
        help="List capture interfaces",
    )

    # Monitor mode
    monitor_parser = subparsers.add_parser(
        "monitor",
        help="Enable monitor mode",
    )

    monitor_parser.add_argument(
        "interface",
        help="Wireless interface",
    )

    # Managed mode
    managed_parser = subparsers.add_parser(
        "managed",
        help="Return interface to managed mode",
    )

    managed_parser.add_argument(
        "interface",
        help="Wireless interface",
    )

    # Capture
    capture_parser = subparsers.add_parser(
        "capture",
        help="Capture live traffic",
    )

    capture_parser.add_argument(
        "interface",
        help="Interface to capture on",
    )

    capture_parser.add_argument(
        "-c",
        "--count",
        type=int,
        help="Number of packets to capture",
    )

    capture_parser.add_argument(
        "-s",
        "--snaplen",
        type=int,
        help="Maximum bytes captured per packet",
    )

    capture_parser.add_argument(
        "-p",
        "--no-promiscuous",
        action="store_true",
        help="Disable promiscuous mode",
    )

    capture_parser.add_argument(
        "--timestamp",
        choices=["none", "absolute"],
        help="Timestamp mode",
    )

    capture_parser.add_argument(
        "-v",
        "--verbosity",
        type=int,
        choices=range(4),
        default=0,
        help="Verbosity level: 0-3",
    )

    capture_parser.add_argument(
        "-x",
        "--hex",
        action="store_true",
        help="Display packet contents in hex",
    )

    capture_parser.add_argument(
        "-A",
        "--ascii",
        action="store_true",
        help="Display packet contents as ASCII",
    )

    capture_parser.add_argument(
        "-f",
        "--filter",
        dest="filter_expression",
        help="BPF capture filter",
    )

    capture_parser.add_argument(
        "-w",
        "--write",
        dest="output_file",
        help="Write packets to a PCAP file",
    )

    capture_parser.add_argument(
        "--monitor",
        action="store_true",
        help="Enable monitor mode before capture",
    )

    capture_parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=60,
        help="Maximum capture time in seconds",
    )

    # Read PCAP
    pcap_parser = subparsers.add_parser(
        "read-pcap",
        help="Read an existing PCAP file",
    )

    pcap_parser.add_argument(
        "file",
        help="PCAP file",
    )

    pcap_parser.add_argument(
        "-f",
        "--filter",
        dest="filter_expression",
        help="BPF filter",
    )

    pcap_parser.add_argument(
        "-v",
        "--verbosity",
        type=int,
        choices=range(4),
        default=0,
        help="Verbosity level: 0-3",
    )

    pcap_parser.add_argument(
        "-x",
        "--hex",
        action="store_true",
        help="Display packet contents in hex",
    )

    pcap_parser.add_argument(
        "-A",
        "--ascii",
        action="store_true",
        help="Display packet contents as ASCII",
    )

    pcap_parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=60,
        help="Maximum processing time",
    )

    args = parser.parse_args()

    try:
        if args.command == "interfaces":
            result = list_interfaces()

        elif args.command == "monitor":
            result = set_monitor_mode(
                args.interface
            )

        elif args.command == "managed":
            result = set_managed_mode(
                args.interface
            )

        elif args.command == "capture":
            result = capture(
                interface=args.interface,
                count=args.count,
                snaplen=args.snaplen,
                promiscuous=not args.no_promiscuous,
                timestamp=args.timestamp,
                verbosity=args.verbosity,
                hex_dump=args.hex,
                ascii_dump=args.ascii,
                filter_expression=args.filter_expression,
                output_file=args.output_file,
                monitor_mode=args.monitor,
                timeout=args.timeout,
            )

        elif args.command == "read-pcap":
            result = read_pcap(
                pcap_file=args.file,
                filter_expression=args.filter_expression,
                verbosity=args.verbosity,
                hex_dump=args.hex,
                ascii_dump=args.ascii,
                timeout=args.timeout,
            )

        else:
            return 1

    except TcpdumpError as exc:
        print(f"Error: {exc}")
        return 1

    if result.stdout:
        print(result.stdout, end="")

    if result.stderr:
        print(result.stderr, end="")

    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
```
