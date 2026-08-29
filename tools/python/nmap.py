"""
Nmap wrapper for the ARPocalypse Gremlin.

The TUI is responsible for presenting Nmap's functionality to the user.
This module is responsible for validating the request, running Nmap,
and returning the results.

Only use this on systems and networks you are authorized to test.
"""

import shutil
import subprocess
from dataclasses import dataclass


class NmapError(Exception):
    """Raised when Nmap cannot be executed."""


@dataclass
class NmapResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        return self.returncode == 0


def available() -> bool:
    """Check whether Nmap is installed and available in PATH."""
    return shutil.which("nmap") is not None


def version() -> str:
    """Return the installed Nmap version."""
    if not available():
        raise NmapError("Nmap is not installed or not in PATH.")

    result = subprocess.run(
        ["nmap", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise NmapError(
            result.stderr.strip() or "Unable to determine Nmap version."
        )

    return result.stdout.strip()


def run(
    target: str,
    arguments: list[str] | None = None,
) -> NmapResult:
    """
    Run Nmap against a target.

    target:
        IP address, hostname, CIDR range, or another Nmap-supported target.

    arguments:
        List of Nmap command-line arguments.

    Examples:
        run("192.168.1.0/24", ["-sn"])
        run("192.168.1.10", ["-sV", "-p", "22,80,443"])
    """

    if not target or not target.strip():
        raise ValueError("Nmap target is required.")

    if not available():
        raise NmapError("Nmap is not installed or not in PATH.")

    if arguments is None:
        arguments = []

    # Pass arguments directly to Nmap instead of using a shell.
    command = ["nmap", *arguments, target.strip()]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise NmapError(f"Failed to start Nmap: {error}") from error

    return NmapResult(
        command=command,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


# Presets for the Gremlin TUI.


def host_discovery(target: str) -> NmapResult:
    """Discover hosts without performing a port scan."""
    return run(target, ["-sn"])


def quick_scan(target: str) -> NmapResult:
    """Run Nmap's quick scan."""
    return run(target, ["-T4"])


def service_detection(target: str) -> NmapResult:
    """Attempt to identify services and versions."""
    return run(target, ["-sV"])


def os_detection(target: str) -> NmapResult:
    """Attempt OS detection."""
    return run(target, ["-O"])


def default_scripts(target: str) -> NmapResult:
    """Run Nmap's default NSE scripts."""
    return run(target, ["-sC"])


def common_ports(target: str) -> NmapResult:
    """Scan a small set of commonly used ports."""
    return run(target, ["-p", "22,53,80,443"])


def ipv6_discovery(target: str) -> NmapResult:
    """Perform host discovery against an IPv6 target/range."""
    return run(target, ["-6", "-sn"])


def traceroute(target: str) -> NmapResult:
    """Run Nmap with traceroute."""
    return run(target, ["--traceroute"])
