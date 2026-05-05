"""WiFi connectivity helpers built on top of NetworkManager (nmcli).

These functions wrap nmcli commands so the orchestrator and Flask portal can
check WiFi state, scan for nearby networks, attempt to connect with provided
credentials, and poll until a connection is confirmed.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)

# Portal-created Wi-Fi profiles use ids ``wifi-portal-<hash>`` so every saved
# SSID gets its own NM connection (travel / multiple sites). The hash is
# derived from the UTF-8 SSID so ids stay stable and safe for ``nmcli``.
# Re-saving the same SSID replaces only that profile (password / settings update).
PORTAL_WIFI_PROFILE_PREFIX = "wifi-portal-"

# Older installs used a single fixed id; remove it opportunistically so users
# are not stuck with only one slot after upgrading.
LEGACY_PORTAL_WIFI_CON_NAME = "wifi-configurator-user"


def portal_wifi_connection_id(ssid: str) -> str:
    """Return the NetworkManager connection id used for this SSID."""
    digest = hashlib.sha256(ssid.encode("utf-8")).hexdigest()[:24]
    return f"{PORTAL_WIFI_PROFILE_PREFIX}{digest}"

# How long to give nmcli for any individual subprocess call.
NMCLI_TIMEOUT_SECONDS = 30

# Polling defaults used when waiting for a freshly issued connection to come up.
DEFAULT_POLL_INTERVAL_SECONDS = 3
DEFAULT_POLL_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class WifiNetwork:
    """A nearby WiFi network as reported by `nmcli device wifi list`."""

    ssid: str
    signal: int  # 0-100, higher is better
    security: str  # e.g. "WPA2", "--" for open networks


def _run_nmcli(args: List[str], timeout: int = NMCLI_TIMEOUT_SECONDS) -> subprocess.CompletedProcess:
    """Run an nmcli command and return the CompletedProcess.

    Raises subprocess.CalledProcessError on non-zero exit so callers can decide
    how to react. Uses `-t` (terse) friendly callers should pass `-t` themselves
    when they need machine-readable output.
    """
    cmd = ["nmcli", *args]
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def wifi_station_connected(interface: str = "wlan0") -> bool:
    """Return True if ``interface`` is associated as a Wi-Fi *client* (STA).

    USB gadget / Ethernet can provide ``CONNECTIVITY=full`` while this
    interface is still disconnected, so we must not infer Wi-Fi from global NM
    connectivity alone.

    Returns False when the interface is down, disconnected, or acting as an
    access point (``802-11-wireless.mode`` ``ap``), e.g. our own captive-portal
    hotspot profile.
    """
    try:
        result = _run_nmcli(["device", "show", interface], timeout=10)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.debug("nmcli device show %s failed: %s", interface, exc)
        return False

    state_val: Optional[str] = None
    conn_val: Optional[str] = None
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if line.startswith("GENERAL.STATE:"):
            state_val = line.split(":", 1)[1].strip()
        elif line.startswith("GENERAL.CONNECTION:"):
            conn_val = line.split(":", 1)[1].strip()

    if not state_val:
        return False
    # NM uses state code 100 for NM_DEVICE_STATE_ACTIVATED ("connected").
    tokens = state_val.split()
    code_ok = bool(tokens) and tokens[0] == "100"
    if "(connected)" not in state_val and not code_ok:
        return False
    if not conn_val or conn_val == "--":
        return False

    try:
        mode_result = _run_nmcli(
            ["-t", "-f", "802-11-wireless.mode", "connection", "show", conn_val],
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.debug("Could not read Wi-Fi mode for %s: %s", conn_val, exc)
        return False

    # With a single `-f` field, nmcli often prints just the value (no key prefix).
    mode = ""
    raw_lines = [ln.strip() for ln in mode_result.stdout.splitlines() if ln.strip()]
    if len(raw_lines) == 1 and ":" not in raw_lines[0]:
        mode = raw_lines[0].lower()
    else:
        for line in raw_lines:
            if line.startswith("802-11-wireless.mode:"):
                mode = line.split(":", 1)[1].strip().lower()
                break
    if mode == "ap":
        return False
    if not mode:
        # Not a wireless connection profile (unexpected on wlan0); play safe.
        return False
    return True


def poll_until_wifi_station(
    interface: str = "wlan0",
    timeout_seconds: int = DEFAULT_POLL_TIMEOUT_SECONDS,
    interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS,
) -> bool:
    """Block until ``wifi_station_connected`` becomes true or timeout elapses."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if wifi_station_connected(interface=interface):
            return True
        time.sleep(interval_seconds)
    return wifi_station_connected(interface=interface)


def scan_networks(interface: str = "wlan0") -> List[WifiNetwork]:
    """Return a list of nearby WiFi networks, sorted by signal strength.

    Duplicate SSIDs (e.g. mesh networks broadcasting on multiple bands) are
    collapsed to the strongest entry so the dropdown stays clean.
    """
    # `--rescan yes` forces NM to refresh its cache; without it the list can be
    # stale right after boot when the captive portal is being shown.
    try:
        _run_nmcli(["device", "wifi", "rescan", "ifname", interface], timeout=15)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        # A failed rescan isn't fatal, the cached list may still be useful.
        logger.warning("WiFi rescan failed: %s", exc)

    try:
        result = _run_nmcli(
            ["-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list", "ifname", interface]
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.error("nmcli wifi list failed: %s", exc)
        return []

    by_ssid: dict[str, WifiNetwork] = {}
    for line in result.stdout.splitlines():
        # Terse output is colon-separated; literal colons in the SSID are
        # escaped as `\:`. Splitting with a negative lookbehind keeps them
        # intact.
        parts = _split_terse(line)
        if len(parts) < 3:
            continue
        ssid_raw, signal_raw, security = parts[0], parts[1], parts[2]
        ssid = ssid_raw.strip()
        if not ssid:
            # Hidden networks come through with an empty SSID; skip them since
            # the user can't pick what they can't see.
            continue
        try:
            signal = int(signal_raw)
        except ValueError:
            signal = 0
        existing = by_ssid.get(ssid)
        if existing is None or signal > existing.signal:
            by_ssid[ssid] = WifiNetwork(ssid=ssid, signal=signal, security=security or "--")

    return sorted(by_ssid.values(), key=lambda n: n.signal, reverse=True)


def _split_terse(line: str) -> List[str]:
    """Split an nmcli `-t` line on unescaped colons.

    nmcli escapes literal colons inside fields as `\\:`; splitting naively on
    `:` mangles SSIDs that contain colons. This is a small state machine that
    respects the escape character.
    """
    parts: List[str] = []
    current: List[str] = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            current.append(line[i + 1])
            i += 2
            continue
        if ch == ":":
            parts.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    parts.append("".join(current))
    return parts


def save_wifi_profile_for_reboot(ssid: str, password: Optional[str]) -> tuple[bool, str]:
    """Persist a Wi-Fi profile for **after reboot** without activating it now.

    On a Raspberry Pi with one Wi-Fi radio, ``nmcli device wifi connect`` would
    immediately switch ``wlan0`` from AP (hotspot) to client mode, which drops
    the captive portal for anyone connected to the hotspot AP. Instead
    we add (or replace) a NetworkManager connection for **this SSID only**,
    with ``autoconnect`` enabled. Other SSIDs saved earlier are left in place so
    traveling between known networks does not wipe previous credentials.

    Returns ``(True, summary_message)`` or ``(False, error_text)``.
    """
    ssid = ssid.strip()
    if not ssid:
        return False, "SSID is required."

    conn_id = portal_wifi_connection_id(ssid)

    # One-time migration away from the legacy single-profile layout.
    subprocess.run(
        ["nmcli", "connection", "delete", LEGACY_PORTAL_WIFI_CON_NAME],
        capture_output=True,
        text=True,
        timeout=NMCLI_TIMEOUT_SECONDS,
    )
    # Replace only this SSID's slot (e.g. password change) without touching others.
    subprocess.run(
        ["nmcli", "connection", "delete", conn_id],
        capture_output=True,
        text=True,
        timeout=NMCLI_TIMEOUT_SECONDS,
    )

    # Do not pin `ifname` here: while the captive-portal hotspot is active,
    # binding `wlan0` on an inactive profile can make `connection add` fail
    # ("device busy"). NM will attach this profile to the default Wi-Fi NIC when
    # it comes up after reboot.
    args = [
        "connection",
        "add",
        "type",
        "wifi",
        "con-name",
        conn_id,
        "ssid",
        ssid,
        "ipv4.method",
        "auto",
        "ipv6.method",
        "auto",
        "connection.autoconnect",
        "yes",
        # Prefer portal-saved profiles over generic autoconnect entries once the
        # Hotspot profile from this session is gone.
        "connection.autoconnect-priority",
        "100",
    ]
    if password:
        args += ["wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", password]
    else:
        args += ["wifi-sec.key-mgmt", "none"]

    try:
        result = _run_nmcli(args, timeout=45)
    except subprocess.CalledProcessError as exc:
        message = (exc.stderr or exc.stdout or str(exc)).strip()
        logger.error("nmcli connection add failed: %s", message)
        return False, message or "Could not save Wi-Fi profile."
    except subprocess.TimeoutExpired:
        logger.error("nmcli connection add timed out for SSID=%s", ssid)
        return False, "Timed out while saving the Wi-Fi profile."

    detail = result.stdout.strip()
    return True, detail or f'Saved profile for "{ssid}" (will connect after reboot).'


def connect_to_wifi(ssid: str, password: Optional[str], interface: str = "wlan0") -> tuple[bool, str]:
    """Attempt to connect to the given SSID immediately (tears down any AP on wlan0).

    Returns `(success, message)`. When `password` is None or empty, the network
    is treated as open. NetworkManager creates a persistent connection profile
    on success, so the credentials survive across reboots.

    Not used from the captive portal UI on single-radio devices; see
    :func:`save_wifi_profile_for_reboot` instead.
    """
    if not ssid:
        return False, "SSID is required."

    args = ["device", "wifi", "connect", ssid, "ifname", interface]
    if password:
        args += ["password", password]

    try:
        result = _run_nmcli(args, timeout=45)
    except subprocess.CalledProcessError as exc:
        # nmcli returns useful error text on stderr (e.g. "Secrets were
        # required, but not provided" for wrong passwords).
        message = (exc.stderr or exc.stdout or str(exc)).strip()
        logger.error("nmcli connect failed: %s", message)
        return False, message or "Failed to connect."
    except subprocess.TimeoutExpired:
        logger.error("nmcli connect timed out for SSID=%s", ssid)
        return False, "Timed out waiting for the network to associate."

    return True, result.stdout.strip() or "Connected."
