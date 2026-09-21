"""
Aircrack-ng backend wrapper.

Linux-only. Requires aircrack-ng suite and a wireless adapter
with monitor-mode support.

The deauthentication entry points retain their existing API and
command construction. The surrounding infrastructure is hardened
for reliability, cleanup, validation, and TUI integration.

Public API (TUI-facing):
    find_tools()                -> AircrackTools
    version()                   -> str
    list_interfaces()           -> list[str]
    detect_interface()          -> str
    start_monitor(iface)        -> MonitorSession
    stop_monitor(session)       -> None
    scan(duration)              -> list[AccessPoint]
    deauth_client(...)          -> AircrackResult
    deauth_all(...)             -> AircrackResult
    capture_handshake(...)      -> AircrackResult
    deauth_and_capture(...)     -> AircrackResult
"""

from __future__ import annotations

import csv
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Errors
# ------------------------------------------------------------------


class AircrackError(Exception):
    """Base exception for backend failures."""


class ValidationError(AircrackError):
    """Raised when caller-supplied arguments are invalid."""


# ------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------


class Mode(Enum):
    DEAUTH = "deauth"
    CAPTURE = "capture"
    DEAUTH_CAPTURE = "deauth_capture"


class ProcessState(Enum):
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class VerificationState(Enum):
    NOT_REQUESTED = "not_requested"
    NOT_CHECKED = "not_checked"
    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    UNAVAILABLE = "unavailable"


# ------------------------------------------------------------------
# Tool discovery
# ------------------------------------------------------------------


@dataclass(frozen=True)
class AircrackTools:
    airmon: str | None
    airodump: str | None
    aireplay: str | None
    aircrack: str | None
    iw: str | None
    tshark: str | None

    _VALID_NAMES = (
        "airmon",
        "airodump",
        "aireplay",
        "aircrack",
        "iw",
        "tshark",
    )

    @property
    def complete(self) -> bool:
        return all(
            [
                self.airmon,
                self.airodump,
                self.aireplay,
                self.aircrack,
                self.iw,
            ]
        )

    def require(self, *names: str) -> None:
        for name in names:
            if name not in self._VALID_NAMES:
                raise AircrackError(f"Unknown tool name: {name!r}")

        missing = [
            name
            for name in names
            if not getattr(self, name)
        ]

        if missing:
            raise AircrackError(
                f"Missing required tool(s): {', '.join(missing)}"
            )


def find_tools() -> AircrackTools:
    """
    Locate external dependencies.

    Fix:
        Previously only the aircrack-ng binaries were discovered.
        iw and tshark are also dependencies of functionality in this
        backend, so they are now represented explicitly.
    """
    return AircrackTools(
        airmon=shutil.which("airmon-ng"),
        airodump=shutil.which("airodump-ng"),
        aireplay=shutil.which("aireplay-ng"),
        aircrack=shutil.which("aircrack-ng"),
        iw=shutil.which("iw"),
        tshark=shutil.which("tshark"),
    )


def version(tools: AircrackTools | None = None) -> str:
    tools = tools or find_tools()
    tools.require("aircrack")

    try:
        result = subprocess.run(
            [tools.aircrack, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise AircrackError("aircrack-ng --version timed out.") from exc
    except OSError as exc:
        raise AircrackError(
            f"Failed to execute aircrack-ng: {exc}"
        ) from exc

    if result.returncode != 0:
        raise AircrackError(
            result.stderr.strip() or "Unable to determine aircrack-ng version."
        )

    return (result.stdout or "").strip()


# ------------------------------------------------------------------
# Dataclasses
# ------------------------------------------------------------------


@dataclass
class MonitorSession:
    interface: str
    created_by_gremlin: bool
    original_interface: str | None = None
    started_at: float = field(default_factory=time.monotonic)


@dataclass
class AccessPoint:
    bssid: str
    channel: int
    encryption: str
    power: int
    essid: str
    clients: list["Client"] = field(default_factory=list)


@dataclass(frozen=True)
class Client:
    mac: str
    bssid: str
    essid: str


@dataclass
class AircrackResult:
    command: list[str]
    state: ProcessState
    returncode: int
    stdout: str
    stderr: str
    verified: bool = False
    handshake_captured: bool = False
    capture_file: str | None = None
    verification_state: VerificationState = VerificationState.NOT_CHECKED
    error: str | None = None

    @property
    def success(self) -> bool:
        return (
            self.state == ProcessState.COMPLETED
            and self.verified
        )


# ------------------------------------------------------------------
# Interface locking
# ------------------------------------------------------------------

# Fix:
# Previously two TUI actions could manipulate the same wireless
# adapter concurrently. A process-local lock prevents that.
#
# This does not provide inter-process locking. If multiple Gremlin
# processes are expected, replace this with an OS-level file lock.

_INTERFACE_LOCK = threading.RLock()


# ------------------------------------------------------------------
# Validation
# ------------------------------------------------------------------


_MAC_RE = re.compile(
    r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
)


def _validate_mac(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(
            f"{name} must be a string, got {type(value).__name__}"
        )

    normalized = value.strip().upper()

    if not _MAC_RE.fullmatch(normalized):
        raise ValidationError(
            f"Invalid {name}: {value!r}"
        )

    return normalized


def _is_unicast_mac(mac: str) -> bool:
    first_octet = int(mac.split(":")[0], 16)
    return not (first_octet & 0x01)


def _validate_unicast_mac(value: object, name: str) -> str:
    mac = _validate_mac(value, name)

    if not _is_unicast_mac(mac):
        raise ValidationError(
            f"{name} must be a unicast MAC address: {mac}"
        )

    return mac


def _validate_channel(
    channel: object,
    name: str = "channel",
) -> int:
    if (
        not isinstance(channel, int)
        or isinstance(channel, bool)
    ):
        raise ValidationError(
            f"{name} must be an int, "
            f"got {type(channel).__name__}"
        )

    if not 1 <= channel <= 196:
        raise ValidationError(
            f"{name} out of supported range: {channel}"
        )

    return channel


def _validate_duration(
    value: object,
    name: str = "duration",
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
    ):
        raise ValidationError(
            f"{name} must be an int, "
            f"got {type(value).__name__}"
        )

    if not 1 <= value <= 3600:
        raise ValidationError(
            f"{name} must be between 1 and 3600, got {value}"
        )

    return value


def _validate_timeout(
    value: object,
    name: str = "timeout",
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
    ):
        raise ValidationError(
            f"{name} must be an int, "
            f"got {type(value).__name__}"
        )

    if not 1 <= value <= 7200:
        raise ValidationError(
            f"{name} must be between 1 and 7200, got {value}"
        )

    return value


def _validate_count(
    value: object,
    name: str = "count",
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
    ):
        raise ValidationError(
            f"{name} must be an int, "
            f"got {type(value).__name__}"
        )

    if not 1 <= value <= 1000:
        raise ValidationError(
            f"{name} must be between 1 and 1000, got {value}"
        )

    return value


def _validate_output_dir(path: str) -> str:
    """
    Validate and create an output directory.

    Fix:
        Previously callers had to create the directory themselves,
        despite _run() later attempting to create it.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValidationError(
            "output_dir must be a non-empty string path"
        )

    resolved = Path(
        os.path.abspath(
            os.path.expanduser(path.strip())
        )
    )

    try:
        resolved.mkdir(
            parents=True,
            exist_ok=True,
        )
    except OSError as exc:
        raise ValidationError(
            f"Unable to create output_dir {resolved}: {exc}"
        ) from exc

    if not resolved.is_dir():
        raise ValidationError(
            f"output_dir is not a directory: {resolved}"
        )

    # Actually test writability instead of relying only on os.access().
    try:
        fd, test_path = tempfile.mkstemp(
            prefix=".gremlin_write_test_",
            dir=str(resolved),
        )
        os.close(fd)
        os.unlink(test_path)
    except OSError as exc:
        raise ValidationError(
            f"output_dir is not writable: {resolved}: {exc}"
        ) from exc

    return str(resolved)


# ------------------------------------------------------------------
# Linux / privilege checks
# ------------------------------------------------------------------


def _require_linux() -> None:
    if os.name != "posix":
        raise AircrackError(
            "This backend is supported only on Linux."
        )


def _require_privileges() -> None:
    """
    Check for the normal Linux privilege requirement.

    Root is the simple case. Capability-based installations can
    require a more sophisticated check, so failure here is phrased
    as a prerequisite rather than assuming root is the only valid
    configuration.
    """
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise AircrackError(
            "Wireless monitor-mode operations normally require "
            "elevated privileges. Run the Gremlin backend with the "
            "required Linux capabilities or appropriate privileges."
        )


# ------------------------------------------------------------------
# Wireless interface management
# ------------------------------------------------------------------


def _iw_command(
    tools: AircrackTools,
    *args: str,
    timeout: int = 5,
) -> subprocess.CompletedProcess[str]:
    tools.require("iw")

    try:
        return subprocess.run(
            [tools.iw, *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise AircrackError(
            f"iw {' '.join(args)} timed out."
        ) from exc
    except OSError as exc:
        raise AircrackError(
            f"Failed to execute iw: {exc}"
        ) from exc


def _get_iw_interfaces(
    tools: AircrackTools,
) -> dict[str, dict[str, str]]:
    """
    Parse `iw dev`.

    Returns:
        {
            "wlan0": {
                "type": "managed",
                ...
            }
        }

    Fix:
        iw is now the primary interface-information source instead
        of relying exclusively on /sys/class/net.
    """
    result = _iw_command(tools, "dev")

    if result.returncode != 0:
        raise AircrackError(
            result.stderr.strip() or "iw dev failed."
        )

    interfaces: dict[str, dict[str, str]] = {}
    current: str | None = None

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()

        if line.startswith("Interface "):
            current = line.split(maxsplit=1)[1]
            interfaces[current] = {}
            continue

        if current is None:
            continue

        if line.startswith("type "):
            interfaces[current]["type"] = (
                line.split(maxsplit=1)[1]
            )

    return interfaces


def _is_wireless(
    iface: str,
    tools: AircrackTools | None = None,
) -> bool:
    tools = tools or find_tools()

    try:
        interfaces = _get_iw_interfaces(tools)
        if iface in interfaces:
            return True
    except AircrackError:
        pass

    return os.path.isdir(
        f"/sys/class/net/{iface}/wireless"
    )


def _is_monitor_mode(
    iface: str,
    tools: AircrackTools | None = None,
) -> bool:
    """
    Determine monitor mode from iw.

    Fix:
        Removed the old `iface.endswith("mon")` fallback.
        An interface name is not evidence of its actual mode.
    """
    tools = tools or find_tools()

    try:
        interfaces = _get_iw_interfaces(tools)
        return (
            iface in interfaces
            and interfaces[iface].get("type") == "monitor"
        )
    except AircrackError:
        return False


def _get_interface_channel(
    iface: str,
    tools: AircrackTools | None = None,
) -> int | None:
    tools = tools or find_tools()

    try:
        result = _iw_command(
            tools,
            "dev",
            iface,
            "info",
        )
    except AircrackError:
        return None

    if result.returncode != 0:
        return None

    match = re.search(
        r"\bchannel\s+(\d+)",
        result.stdout,
    )

    if not match:
        return None

    return int(match.group(1))


def _set_channel(
    iface: str,
    channel: int,
    tools: AircrackTools | None = None,
) -> bool:
    tools = tools or find_tools()

    try:
        result = _iw_command(
            tools,
            "dev",
            iface,
            "set",
            "channel",
            str(channel),
        )
    except AircrackError:
        return False

    if result.returncode != 0:
        logger.warning(
            "Failed to set %s to channel %d: %s",
            iface,
            channel,
            result.stderr.strip(),
        )
        return False

    actual = _get_interface_channel(iface, tools)

    return actual == channel


def list_interfaces(
    tools: AircrackTools | None = None,
) -> list[str]:
    tools = tools or find_tools()

    _require_linux()

    try:
        interfaces = _get_iw_interfaces(tools)
        return sorted(interfaces)
    except AircrackError:
        # Fallback is only for enumeration. We do not use this
        # fallback to claim that an interface is in monitor mode.
        try:
            entries = sorted(
                os.listdir("/sys/class/net")
            )
        except OSError:
            return []

        return [
            name
            for name in entries
            if os.path.isdir(
                f"/sys/class/net/{name}/wireless"
            )
        ]


def detect_interface(
    tools: AircrackTools | None = None,
) -> str:
    tools = tools or find_tools()
    tools.require("iw")

    interfaces = _get_iw_interfaces(tools)

    candidates = [
        name
        for name, info in interfaces.items()
        if info.get("type") != "monitor"
        and _is_wireless(name, tools)
    ]

    if not candidates:
        raise AircrackError(
            "No usable wireless interface found."
        )

    return sorted(candidates)[0]


def _existing_monitor(
    tools: AircrackTools | None = None,
) -> str | None:
    tools = tools or find_tools()

    interfaces = _get_iw_interfaces(tools)

    monitors = sorted(
        name
        for name, info in interfaces.items()
        if info.get("type") == "monitor"
    )

    return monitors[0] if monitors else None


# ------------------------------------------------------------------
# Monitor lifecycle
# ------------------------------------------------------------------


def start_monitor(
    iface: str,
    tools: AircrackTools | None = None,
) -> MonitorSession:
    tools = tools or find_tools()

    _require_linux()
    _require_privileges()

    tools.require("airmon", "iw")

    if not isinstance(iface, str) or not iface.strip():
        raise ValidationError(
            "Interface name must be a non-empty string."
        )

    iface = iface.strip()

    if not _is_wireless(iface, tools):
        raise AircrackError(
            f"Interface {iface!r} is not a wireless device."
        )

    with _INTERFACE_LOCK:
        existing = _existing_monitor(tools)

        if existing:
            return MonitorSession(
                interface=existing,
                created_by_gremlin=False,
                original_interface=None,
            )

        before = set(
            list_interfaces(tools)
        )

        try:
            result = subprocess.run(
                [tools.airmon, "start", iface],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
        except subprocess.TimeoutExpired as exc:
            raise AircrackError(
                f"airmon-ng start {iface} timed out."
            ) from exc
        except OSError as exc:
            raise AircrackError(
                f"Failed to execute airmon-ng: {exc}"
            ) from exc

        if result.returncode != 0:
            raise AircrackError(
                "airmon-ng start failed "
                f"(rc={result.returncode}):\n"
                f"{result.stdout}\n{result.stderr}"
            )

        # Fix:
        # Don't assume the monitor interface appears immediately.
        deadline = time.monotonic() + 5
        mon_if: str | None = None

        while time.monotonic() < deadline:
            try:
                interfaces = _get_iw_interfaces(tools)
            except AircrackError:
                interfaces = {}

            for candidate, info in interfaces.items():
                if (
                    info.get("type") == "monitor"
                    and (
                        candidate not in before
                        or candidate == iface
                    )
                ):
                    mon_if = candidate
                    break

            if mon_if:
                break

            time.sleep(0.2)

        if not mon_if:
            # Try to find any monitor interface created by the
            # command before declaring failure.
            existing = _existing_monitor(tools)

            if existing:
                mon_if = existing

        if not mon_if:
            logger.warning(
                "airmon-ng reported success but no monitor "
                "interface could be verified."
            )

            try:
                subprocess.run(
                    [tools.airmon, "stop", iface],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass

            raise AircrackError(
                "airmon-ng reported success, but no monitor "
                "interface could be verified."
            )

        if not _is_monitor_mode(mon_if, tools):
            raise AircrackError(
                f"Interface {mon_if!r} was created but "
                "monitor mode could not be verified."
            )

        return MonitorSession(
            interface=mon_if,
            created_by_gremlin=True,
            original_interface=iface,
        )


def stop_monitor(
    session: MonitorSession,
    tools: AircrackTools | None = None,
) -> None:
    if not session.created_by_gremlin:
        return

    tools = tools or find_tools()

    try:
        tools.require("airmon")

        subprocess.run(
            [tools.airmon, "stop", session.interface],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (
        OSError,
        subprocess.TimeoutExpired,
        AircrackError,
    ) as exc:
        logger.error(
            "Failed to stop monitor mode on %s: %s",
            session.interface,
            exc,
        )


def _ensure_monitor(
    tools: AircrackTools,
) -> MonitorSession:
    _require_linux()
    _require_privileges()

    existing = _existing_monitor(tools)

    if existing:
        return MonitorSession(
            interface=existing,
            created_by_gremlin=False,
        )

    iface = detect_interface(tools)

    return start_monitor(
        iface,
        tools,
    )


def _ensure_channel(
    session: MonitorSession,
    channel: int,
    tools: AircrackTools,
    *,
    required: bool = True,
) -> None:
    current = _get_interface_channel(
        session.interface,
        tools,
    )

    if current == channel:
        return

    if _set_channel(
        session.interface,
        channel,
        tools,
    ):
        logger.info(
            "Set %s to channel %d",
            session.interface,
            channel,
        )
        return

    message = (
        f"Could not set {session.interface} to channel "
        f"{channel}; current channel is {current}."
    )

    if required:
        raise AircrackError(message)

    logger.warning(message)


# ------------------------------------------------------------------
# Pre-operation sanity check
# ------------------------------------------------------------------


def _pre_flight_check(
    session: MonitorSession,
    bssid: str,
    channel: int | None,
    client_mac: str | None,
    known_clients: list[Client] | None,
    tools: AircrackTools,
) -> None:
    if not os.path.isdir(
        f"/sys/class/net/{session.interface}"
    ):
        raise ValidationError(
            f"Interface {session.interface} no longer exists."
        )

    if not _is_monitor_mode(
        session.interface,
        tools,
    ):
        raise ValidationError(
            f"Interface {session.interface} is no longer "
            "verified as being in monitor mode."
        )

    if channel is not None:
        current = _get_interface_channel(
            session.interface,
            tools,
        )

        if current is not None and current != channel:
            raise ValidationError(
                f"Interface {session.interface} is on "
                f"channel {current}, expected {channel}."
            )

    if client_mac is not None:
        if known_clients is None:
            raise ValidationError(
                "A known_clients list is required for "
                "client-specific operations."
            )

        if not any(
            client.mac.upper() == client_mac
            and client.bssid.upper() == bssid
            for client in known_clients
        ):
            raise ValidationError(
                f"Client {client_mac} is not currently known "
                f"as associated with {bssid}."
            )


# ------------------------------------------------------------------
# Airodump CSV parsing
# ------------------------------------------------------------------


def _clean_csv_value(value: str | None) -> str:
    if value is None:
        return ""

    return value.strip()


def _parse_power(value: str) -> int:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return 0


def _parse_channel_value(value: str) -> int:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return 0


def _normalize_encryption(
    privacy: str,
    cipher: str,
    auth: str,
) -> str:
    values = [
        privacy.strip(),
        cipher.strip(),
        auth.strip(),
    ]

    return "/".join(
        value
        for value in values
        if value
    ) or "UNKNOWN"


def _parse_airodump_csv(
    csv_path: str,
    clients_csv_path: str | None = None,
) -> list[AccessPoint]:
    """
    Parse airodump-ng's machine-readable CSV output.

    Fix:
        The previous implementation attempted to parse the
        human-readable terminal display. That format is not a
        stable API and frequently differs across versions.

        CSV output is intended for programmatic consumption.
    """
    aps_by_bssid: dict[str, AccessPoint] = {}

    try:
        with open(
            csv_path,
            "r",
            encoding="utf-8",
            errors="replace",
            newline="",
        ) as handle:
            reader = csv.reader(handle)

            for row in reader:
                if not row:
                    continue

                if row[0].strip() != "BSSID":
                    continue

                # Header:
                # BSSID, First time seen, Last time seen,
                # channel, Speed, Privacy, Cipher, Authentication,
                # Power, # beacons, # IV, LAN IP, ID-length, ESSID,
                # Key
                for row in reader:
                    if not row:
                        continue

                    if row[0].strip() == "Station MAC":
                        break

                    if len(row) < 14:
                        continue

                    bssid = _clean_csv_value(row[0]).upper()

                    if not _MAC_RE.fullmatch(bssid):
                        continue

                    channel = _parse_channel_value(row[3])
                    privacy = _clean_csv_value(row[5])
                    cipher = _clean_csv_value(row[6])
                    auth = _clean_csv_value(row[7])
                    power = _parse_power(row[8])
                    essid = _clean_csv_value(row[13])

                    aps_by_bssid[bssid] = AccessPoint(
                        bssid=bssid,
                        channel=channel,
                        encryption=_normalize_encryption(
                            privacy,
                            cipher,
                            auth,
                        ),
                        power=power,
                        essid=essid,
                    )

                break

    except OSError as exc:
        raise AircrackError(
            f"Failed to read airodump CSV: {exc}"
        ) from exc

    # Client parsing is optional because airodump may not always
    # produce a station section.
    if clients_csv_path and os.path.isfile(
        clients_csv_path
    ):
        _parse_clients_csv(
            clients_csv_path,
            aps_by_bssid,
        )

    return list(aps_by_bssid.values())


def _parse_clients_csv(
    csv_path: str,
    aps_by_bssid: dict[str, AccessPoint],
) -> None:
    try:
        with open(
            csv_path,
            "r",
            encoding="utf-8",
            errors="replace",
            newline="",
        ) as handle:
            reader = csv.reader(handle)

            in_clients = False

            for row in reader:
                if not row:
                    continue

                if row[0].strip() == "Station MAC":
                    in_clients = True
                    continue

                if not in_clients:
                    continue

                # Station MAC, First time seen, Last time seen,
                # Power, # packets, BSSID, Probed ESSIDs
                if len(row) < 6:
                    continue

                mac = _clean_csv_value(row[0]).upper()
                bssid = _clean_csv_value(row[5]).upper()

                if not _MAC_RE.fullmatch(mac):
                    continue

                if not _MAC_RE.fullmatch(bssid):
                    continue

                ap = aps_by_bssid.get(bssid)

                if ap is None:
                    continue

                essid = (
                    _clean_csv_value(row[6])
                    if len(row) > 6
                    else ap.essid
                )

                client = Client(
                    mac=mac,
                    bssid=bssid,
                    essid=essid,
                )

                # Fix:
                # Prevent duplicate clients from repeated observations.
                if client not in ap.clients:
                    ap.clients.append(client)

    except OSError as exc:
        logger.warning(
            "Could not parse client CSV %s: %s",
            csv_path,
            exc,
        )


# ------------------------------------------------------------------
# Passive scanning
# ------------------------------------------------------------------


def scan(
    duration: int = 10,
    tools: AircrackTools | None = None,
) -> list[AccessPoint]:
    """
    Perform a passive airodump scan.

    Fixes:
        - Uses CSV instead of terminal-output parsing.
        - Uses an isolated temporary directory.
        - Waits for the requested duration explicitly.
        - Cleans up the process reliably.
        - Does not leave temporary scan files behind.
    """
    tools = tools or find_tools()

    _require_linux()
    _require_privileges()

    tools.require(
        "airodump",
        "airmon",
        "iw",
    )

    duration = _validate_duration(duration)

    with _INTERFACE_LOCK:
        session = _ensure_monitor(tools)

        try:
            with tempfile.TemporaryDirectory(
                prefix="gremlin_scan_"
            ) as temp_dir:
                prefix = os.path.join(
                    temp_dir,
                    "scan",
                )

                command = [
                    tools.airodump,
                    "-w",
                    prefix,
                    "--output-format",
                    "csv",
                    session.interface,
                ]

                logger.info(
                    "Starting passive scan on %s",
                    session.interface,
                )

                try:
                    proc = subprocess.Popen(
                        command,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                except OSError as exc:
                    raise AircrackError(
                        f"Failed to start airodump-ng: {exc}"
                    ) from exc

                stderr = ""

                try:
                    deadline = time.monotonic() + duration

                    while time.monotonic() < deadline:
                        if proc.poll() is not None:
                            stderr = (
                                proc.stderr.read()
                                if proc.stderr
                                else ""
                            )

                            raise AircrackError(
                                "airodump-ng exited early "
                                f"(rc={proc.returncode}): "
                                f"{stderr.strip()}"
                            )

                        time.sleep(0.2)

                finally:
                    _terminate_process(proc)

                    if proc.stderr:
                        try:
                            stderr = (
                                proc.stderr.read() or ""
                            )
                        except OSError:
                            pass

                csv_path = f"{prefix}-01.csv"

                if not os.path.isfile(csv_path):
                    raise AircrackError(
                        "airodump-ng completed, but no CSV "
                        f"capture was produced at {csv_path}"
                    )

                return _parse_airodump_csv(
                    csv_path,
                    csv_path,
                )

        finally:
            stop_monitor(
                session,
                tools,
            )


# ------------------------------------------------------------------
# Process management
# ------------------------------------------------------------------


def _terminate_process(
    process: subprocess.Popen,
    grace_seconds: float = 5.0,
) -> None:
    """
    Terminate a process gracefully, then kill it if necessary.

    Fix:
        Centralizes cleanup instead of duplicating slightly different
        terminate/kill logic throughout the backend.
    """
    if process.poll() is not None:
        return

    try:
        process.terminate()
    except OSError:
        return

    try:
        process.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        process.kill()
    except OSError:
        return

    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        logger.error(
            "Process PID %s did not terminate after SIGKILL.",
            process.pid,
        )


# ------------------------------------------------------------------
# Capture-file discovery
# ------------------------------------------------------------------


def _capture_candidates(
    prefix: str,
    output_dir: str,
) -> list[str]:
    """
    Find capture files belonging to one operation.

    Fix:
        Previously only .cap/.pcap were considered and the largest
        matching file was selected. The operation now knows its exact
        prefix and considers the common capture extensions.
    """
    allowed = {
        ".cap",
        ".pcap",
        ".pcapng",
    }

    try:
        entries = os.listdir(output_dir)
    except OSError:
        return []

    candidates: list[str] = []

    for name in entries:
        path = os.path.join(
            output_dir,
            name,
        )

        if not os.path.isfile(path):
            continue

        if not name.startswith(prefix):
            continue

        if Path(name).suffix.lower() not in allowed:
            continue

        candidates.append(path)

    return candidates


def _find_capture_file(
    prefix: str,
    output_dir: str,
) -> str | None:
    candidates = _capture_candidates(
        prefix,
        output_dir,
    )

    if not candidates:
        return None

    # Prefer the newest file. We know the prefix belongs exclusively
    # to this operation, so newest is a more meaningful criterion than
    # "largest file".
    return max(
        candidates,
        key=lambda path: os.path.getmtime(path),
    )


# ------------------------------------------------------------------
# Capture verification
# ------------------------------------------------------------------


def _has_handshake(
    capture_file: str,
    tools: AircrackTools | None = None,
) -> tuple[bool, VerificationState]:
    """
    Check whether the capture contains EAPOL traffic.

    Fix:
        The old implementation treated key indexes 0..3 as if they
        represented the four EAPOL handshake messages. They do not.

        This implementation intentionally treats the result as
        "EAPOL observed" rather than claiming cryptographic proof
        from those fields alone.
    """
    tools = tools or find_tools()

    if not os.path.isfile(capture_file):
        return (
            False,
            VerificationState.NOT_VERIFIED,
        )

    if not tools.tshark:
        logger.warning(
            "tshark not found; cannot inspect %s",
            capture_file,
        )
        return (
            False,
            VerificationState.UNAVAILABLE,
        )

    try:
        result = subprocess.run(
            [
                tools.tshark,
                "-r",
                capture_file,
                "-Y",
                "eapol",
                "-c",
                "1",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return (
            False,
            VerificationState.UNAVAILABLE,
        )
    except OSError as exc:
        logger.warning(
            "Unable to execute tshark: %s",
            exc,
        )
        return (
            False,
            VerificationState.UNAVAILABLE,
        )

    if result.returncode != 0:
        return (
            False,
            VerificationState.UNAVAILABLE,
        )

    if result.stdout.strip():
        return (
            True,
            VerificationState.VERIFIED,
        )

    return (
        False,
        VerificationState.NOT_VERIFIED,
    )


# ------------------------------------------------------------------
# Public action helpers
# ------------------------------------------------------------------


def deauth_client(
    bssid: str,
    client_mac: str,
    count: int = 5,
    tools: AircrackTools | None = None,
    known_clients: list[Client] | None = None,
) -> AircrackResult:
    """
    Existing client-specific deauthentication API.

    The command construction is intentionally retained.
    """
    bssid = _validate_unicast_mac(
        bssid,
        "BSSID",
    )

    client_mac = _validate_unicast_mac(
        client_mac,
        "client MAC",
    )

    count = _validate_count(count)

    return _run(
        Mode.DEAUTH,
        bssid,
        client_mac=client_mac,
        deauth_count=count,
        tools=tools,
        known_clients=known_clients,
    )


def deauth_all(
    bssid: str,
    count: int = 5,
    tools: AircrackTools | None = None,
) -> AircrackResult:
    """
    Existing AP-wide deauthentication API.

    The command construction is intentionally retained.
    """
    bssid = _validate_unicast_mac(
        bssid,
        "BSSID",
    )

    count = _validate_count(count)

    return _run(
        Mode.DEAUTH,
        bssid,
        deauth_count=count,
        tools=tools,
    )


def capture_handshake(
    bssid: str,
    channel: int,
    duration: int = 60,
    output_dir: str | None = None,
    tools: AircrackTools | None = None,
) -> AircrackResult:
    bssid = _validate_unicast_mac(
        bssid,
        "BSSID",
    )

    channel = _validate_channel(channel)
    duration = _validate_duration(duration)

    output_dir = _validate_output_dir(
        output_dir or tempfile.gettempdir()
    )

    return _run(
        Mode.CAPTURE,
        bssid,
        channel=channel,
        duration=duration,
        output_dir=output_dir,
        tools=tools,
    )


def deauth_and_capture(
    bssid: str,
    client_mac: str,
    channel: int,
    count: int = 3,
    output_dir: str | None = None,
    tools: AircrackTools | None = None,
    known_clients: list[Client] | None = None,
) -> AircrackResult:
    """
    Existing combined API.

    The deauth command construction remains unchanged.
    """
    bssid = _validate_unicast_mac(
        bssid,
        "BSSID",
    )

    client_mac = _validate_unicast_mac(
        client_mac,
        "client MAC",
    )

    channel = _validate_channel(channel)
    count = _validate_count(count)

    output_dir = _validate_output_dir(
        output_dir or tempfile.gettempdir()
    )

    return _run(
        Mode.DEAUTH_CAPTURE,
        bssid,
        client_mac=client_mac,
        channel=channel,
        deauth_count=count,
        output_dir=output_dir,
        tools=tools,
        known_clients=known_clients,
    )


# ------------------------------------------------------------------
# Internal runner
# ------------------------------------------------------------------


def _run(
    mode: Mode,
    bssid: str,
    client_mac: str | None = None,
    channel: int | None = None,
    deauth_count: int = 5,
    duration: int = 30,
    timeout: int = 120,
    output_dir: str | None = None,
    tools: AircrackTools | None = None,
    known_clients: list[Client] | None = None,
) -> AircrackResult:
    tools = tools or find_tools()

    _require_linux()
    _require_privileges()

    timeout = _validate_timeout(timeout)
    deauth_count = _validate_count(
        deauth_count,
        "deauth_count",
    )

    bssid = _validate_unicast_mac(
        bssid,
        "BSSID",
    )

    if client_mac is not None:
        client_mac = _validate_unicast_mac(
            client_mac,
            "client MAC",
        )

    if channel is not None:
        channel = _validate_channel(channel)

    if mode in (
        Mode.CAPTURE,
        Mode.DEAUTH_CAPTURE,
    ):
        duration = _validate_duration(duration)
        tools.require("airodump")

    if mode in (
        Mode.DEAUTH,
        Mode.DEAUTH_CAPTURE,
    ):
        tools.require("aireplay")

    output_dir = _validate_output_dir(
        output_dir or tempfile.gettempdir()
    )

    with _INTERFACE_LOCK:
        session = _ensure_monitor(tools)

        capture_file: str | None = None

        prefix = (
            f"gremlin_{uuid.uuid4().hex[:8]}"
        )

        state = ProcessState.FAILED
        rc = -1
        stdout = ""
        stderr = ""
        verified = False
        verification_state = (
            VerificationState.NOT_CHECKED
        )
        error: str | None = None

        try:
            if channel is not None:
                # Fix:
                # Channel failure is fatal when a specific channel was
                # requested. Continuing on an unknown channel can make
                # a capture appear to succeed while collecting nothing.
                _ensure_channel(
                    session,
                    channel,
                    tools,
                    required=True,
                )

            _pre_flight_check(
                session,
                bssid,
                channel,
                client_mac,
                known_clients,
                tools,
            )

            dump_cmd: list[str] | None = None
            replay_cmd: list[str] | None = None

            commands: list[str] = []

            if mode in (
                Mode.CAPTURE,
                Mode.DEAUTH_CAPTURE,
            ):
                dump_cmd = [
                    tools.airodump,
                    "--bssid",
                    bssid,
                    "-w",
                    os.path.join(
                        output_dir,
                        prefix,
                    ),
                    "--output-format",
                    "csv",
                ]

                if channel is not None:
                    dump_cmd += [
                        "-c",
                        str(channel),
                    ]

                dump_cmd.append(
                    session.interface
                )

                commands.append(
                    " ".join(dump_cmd)
                )

            if mode in (
                Mode.DEAUTH,
                Mode.DEAUTH_CAPTURE,
            ):
                # Existing deauth command construction retained.
                replay_cmd = [
                    tools.aireplay,
                    "-0",
                    str(deauth_count),
                    "-a",
                    bssid,
                ]

                if client_mac:
                    replay_cmd += [
                        "-c",
                        client_mac,
                    ]

                replay_cmd.append(
                    session.interface
                )

                commands.append(
                    " ".join(replay_cmd)
                )

            dump_proc: subprocess.Popen | None = None
            replay_proc: subprocess.Popen | None = None

            try:
                if mode == Mode.DEAUTH:
                    assert replay_cmd is not None

                    try:
                        result = subprocess.run(
                            replay_cmd,
                            capture_output=True,
                            text=True,
                            timeout=timeout,
                            check=False,
                        )
                    except subprocess.TimeoutExpired:
                        state = (
                            ProcessState.TIMED_OUT
                        )
                        error = (
                            "Operation timed out."
                        )
                    except OSError as exc:
                        state = (
                            ProcessState.FAILED
                        )
                        error = (
                            f"Failed to start process: {exc}"
                        )
                    else:
                        rc = result.returncode
                        stdout = (
                            result.stdout or ""
                        )
                        stderr = (
                            result.stderr or ""
                        )

                        state = (
                            ProcessState.COMPLETED
                            if rc == 0
                            else ProcessState.FAILED
                        )

                        verified = rc == 0
                        verification_state = (
                            VerificationState.VERIFIED
                            if verified
                            else VerificationState.NOT_VERIFIED
                        )

                elif mode == Mode.CAPTURE:
                    assert dump_cmd is not None

                    try:
                        dump_proc = subprocess.Popen(
                            dump_cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                    except OSError as exc:
                        state = (
                            ProcessState.FAILED
                        )
                        error = (
                            f"Failed to start airodump-ng: {exc}"
                        )
                    else:
                        start = time.monotonic()

                        try:
                            # Fix:
                            # duration is now an explicit capture timer.
                            while (
                                time.monotonic() - start
                                < duration
                            ):
                                if dump_proc.poll() is not None:
                                    raise AircrackError(
                                        "airodump-ng exited early "
                                        f"(rc={dump_proc.returncode})"
                                    )

                                if (
                                    time.monotonic()
                                    - start
                                    >= timeout
                                ):
                                    raise subprocess.TimeoutExpired(
                                        dump_cmd,
                                        timeout,
                                    )

                                time.sleep(0.2)

                            state = (
                                ProcessState.COMPLETED
                            )
                            rc = 0

                        except subprocess.TimeoutExpired:
                            state = (
                                ProcessState.TIMED_OUT
                            )
                            error = (
                                "Capture operation timed out."
                            )
                        except AircrackError as exc:
                            state = (
                                ProcessState.FAILED
                            )
                            error = str(exc)
                        finally:
                            _terminate_process(
                                dump_proc
                            )

                            if dump_proc.stderr:
                                try:
                                    stderr = (
                                        dump_proc.stderr.read()
                                        or ""
                                    )
                                except OSError:
                                    pass

                elif mode == Mode.DEAUTH_CAPTURE:
                    assert (
                        dump_cmd is not None
                        and replay_cmd is not None
                    )

                    try:
                        dump_proc = subprocess.Popen(
                            dump_cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    except OSError as exc:
                        state = (
                            ProcessState.FAILED
                        )
                        error = (
                            f"Failed to start airodump-ng: {exc}"
                        )
                    else:
                        # Fix:
                        # Poll rather than assuming a fixed one-second
                        # readiness delay.
                        ready_deadline = (
                            time.monotonic() + 5
                        )

                        while (
                            time.monotonic()
                            < ready_deadline
                        ):
                            if dump_proc.poll() is not None:
                                raise AircrackError(
                                    "airodump-ng exited prematurely "
                                    f"(rc={dump_proc.returncode})"
                                )

                            time.sleep(0.2)

                        try:
                            replay_proc = subprocess.Popen(
                                replay_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                            )

                            remaining = max(
                                1,
                                timeout
                                - int(
                                    time.monotonic()
                                    - ready_deadline
                                ),
                            )

                            out_bytes, err_bytes = (
                                replay_proc.communicate(
                                    timeout=remaining
                                )
                            )

                            stdout = (
                                out_bytes or ""
                            )
                            stderr = (
                                err_bytes or ""
                            )

                            rc = (
                                replay_proc.returncode
                                if replay_proc.returncode
                                is not None
                                else -1
                            )

                            state = (
                                ProcessState.COMPLETED
                                if rc == 0
                                else ProcessState.FAILED
                            )

                            verified = (
                                state
                                == ProcessState.COMPLETED
                                and rc == 0
                            )

                        except subprocess.TimeoutExpired:
                            _terminate_process(
                                replay_proc
                            )

                            state = (
                                ProcessState.TIMED_OUT
                            )
                            error = (
                                "Operation timed out."
                            )

                        except OSError as exc:
                            state = (
                                ProcessState.FAILED
                            )
                            error = (
                                f"Failed to start replay process: "
                                f"{exc}"
                            )

            finally:
                if replay_proc is not None:
                    _terminate_process(
                        replay_proc
                    )

                if dump_proc is not None:
                    _terminate_process(
                        dump_proc
                    )

            # Capture files can take a short moment to become visible
            # after the capture process exits.
            if mode in (
                Mode.CAPTURE,
                Mode.DEAUTH_CAPTURE,
            ):
                deadline = time.monotonic() + 5

                while time.monotonic() < deadline:
                    capture_file = (
                        _find_capture_file(
                            prefix,
                            output_dir,
                        )
                    )

                    if capture_file:
                        break

                    time.sleep(0.2)

                if mode == Mode.CAPTURE:
                    if capture_file:
                        verified = (
                            state
                            == ProcessState.COMPLETED
                        )

                        verification_state = (
                            VerificationState.VERIFIED
                            if verified
                            else VerificationState.NOT_VERIFIED
                        )
                    else:
                        verified = False
                        verification_state = (
                            VerificationState.NOT_VERIFIED
                        )

                        if state == ProcessState.COMPLETED:
                            state = ProcessState.FAILED
                            error = (
                                "Capture completed but no "
                                "capture file was produced."
                            )

        except AircrackError as exc:
            state = ProcessState.FAILED
            error = str(exc)

        finally:
            stop_monitor(
                session,
                tools,
            )

        # Handshake inspection is deliberately performed only after
        # the capture process has completely stopped.
        if capture_file:
            handshake, verification = _has_handshake(
                capture_file,
                tools,
            )

            if handshake:
                logger.info(
                    "EAPOL traffic detected in %s",
                    capture_file,
                )

            # Only replace the generic capture verification state
            # when tshark actually performed the check.
            if verification != (
                VerificationState.UNAVAILABLE
            ):
                verification_state = verification

            if mode == Mode.DEAUTH_CAPTURE:
                # Keep the distinction between:
                #   operation succeeded
                #   EAPOL observed
                #
                # Do not claim a complete WPA handshake solely from
                # one packet.
                verified = (
                    state
                    == ProcessState.COMPLETED
                    and handshake
                )

            elif mode == Mode.CAPTURE:
                verified = (
                    state
                    == ProcessState.COMPLETED
                    and capture_file is not None
                )

            handshake_captured = handshake
        else:
            handshake_captured = False

        return AircrackResult(
            command=commands,
            state=state,
            returncode=rc,
            stdout=stdout,
            stderr=stderr,
            verified=verified,
            handshake_captured=handshake_captured,
            capture_file=capture_file,
            verification_state=verification_state,
            error=error,
        )
