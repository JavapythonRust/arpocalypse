"""
Nmap wrapper for the ARPocalypse Gremlin.

The TUI can build an argument list from its menus and pass it to run().
This wrapper handles executing Nmap and returning structured results.

Only use the Gremlin on systems and networks you are authorized to test.
"""

import logging
import shutil
import subprocess
from dataclasses import dataclass


logger = logging.getLogger(__name__)


class NmapError(Exception):
    """Raised when Nmap cannot be executed."""


@dataclass
class NmapResult:
    """Result returned by an Nmap execution."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def success(self) -> bool:
        """Whether Nmap completed successfully."""
        return self.returncode == 0 and not self.timed_out


def available() -> bool:
    """Check whether Nmap is installed and available in PATH."""
    return shutil.which("nmap") is not None


def version() -> str:
    """Return the installed Nmap version."""

    if not available():
        raise NmapError("Nmap is not installed or not in PATH.")

    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    except subprocess.TimeoutExpired as error:
        raise NmapError(
            "Timed out while checking the Nmap version."
        ) from error

    except OSError as error:
        raise NmapError(
            f"Failed to start Nmap: {error}"
        ) from error

    if result.returncode != 0:
        raise NmapError(
            result.stderr.strip()
            or "Unable to determine Nmap version."
        )

    return result.stdout.strip()


def run(
    target: str,
    arguments: list[str] | None = None,
    timeout: int = 300,
) -> NmapResult:
    """
    Run Nmap against a target.

    target:
        IP address, hostname, CIDR range, or another
        Nmap-supported target specification.

    arguments:
        List of Nmap command-line arguments.

    timeout:
        Maximum time in seconds before the scan is stopped.

    Examples:

        run("192.168.1.1")

        run(
            "192.168.1.0/24",
            ["-sn"]
        )

        run(
            "192.168.1.10",
            ["-sV", "-p", "22,80,443"]
        )
    """

    if not target or not target.strip():
        raise ValueError("Nmap target is required.")

    target = target.strip()

    if target.startswith("-"):
        raise ValueError(
            "Invalid target: targets cannot begin with '-'."
        )

    if timeout <= 0:
        raise ValueError(
            "Timeout must be greater than zero."
        )

    if not available():
        raise NmapError(
            "Nmap is not installed or not in PATH."
        )

    if arguments is None:
        arguments = []

    command = [
        "nmap",
        *arguments,
        target,
    ]

    logger.info(
        "Running Nmap: %s",
        " ".join(command),
    )

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )

    except subprocess.TimeoutExpired as error:
        logger.warning(
            "Nmap timed out for target: %s",
            target,
        )

        stdout = error.stdout or ""
        stderr = error.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode(
                errors="replace"
            )

        if isinstance(stderr, bytes):
            stderr = stderr.decode(
                errors="replace"
            )

        return NmapResult(
            command=command,
            returncode=-1,
            stdout=stdout,
            stderr=stderr or "Nmap scan timed out.",
            timed_out=True,
        )

    except OSError as error:
        raise NmapError(
            f"Failed to start Nmap: {error}"
        ) from error

    logger.info(
        "Nmap exited with return code %d",
        result.returncode,
    )

    return NmapResult(
        command=command,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


# ---------------------------------------------------------
# Convenience presets for the Gremlin TUI
# ---------------------------------------------------------


def host_discovery(target: str) -> NmapResult:
    """Discover hosts without performing a port scan."""
    return run(target, ["-sn"])


def quick_scan(target: str) -> NmapResult:
    """Perform a fast scan of Nmap's common ports."""
    return run(target, ["-F"])


def service_detection(target: str) -> NmapResult:
    """Attempt to identify services and versions."""
    return run(target, ["-sV"])


def os_detection(target: str) -> NmapResult:
    """Attempt operating-system detection."""
    return run(target, ["-O"])


def default_scripts(target: str) -> NmapResult:
    """Run Nmap's default NSE scripts."""
    return run(target, ["-sC"])


def common_ports(target: str) -> NmapResult:
    """Scan a small set of commonly used ports."""
    return run(
        target,
        ["-p", "22,53,80,443"],
    )


def ipv6_discovery(target: str) -> NmapResult:
    """Perform IPv6 host discovery."""
    return run(
        target,
        ["-6", "-sn"],
    )


def traceroute(target: str) -> NmapResult:
    """Run Nmap with traceroute."""
    return run(
        target,
        ["--traceroute"],
    )
