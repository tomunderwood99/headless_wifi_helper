#!/usr/bin/env python3
"""Boot-time WiFi configurator orchestrator.

Flow:
  1. Wait briefly for ``wlan0`` to associate as a Wi-Fi *client* (infrastructure
     mode). USB gadget / Ethernet Internet does not count — only a real STA
     link skips the portal.
  2. If a client association is detected, exit cleanly so the rest of the boot
     continues normally and downstream services start.
  3. Otherwise, bring up a captive-portal access point and serve the Flask
     configuration UI on http://192.168.4.1/. The user picks a network,
     submits credentials, and clicks Reboot. The reboot tears everything down
     and on next boot we'll connect to the saved network and exit at step 2.

This script is intended to run as root via systemd (see
deployment/wifi_configurator.service). It assumes NetworkManager is the
active network backend, which is the default on Raspberry Pi OS Trixie.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from typing import Optional

from network import ap_manager, connectivity
from network.env_path import resolve_env_file_path
from portal.server import create_app

# How long we'll wait at boot for wlan0 to join a Wi-Fi network as a client
# before giving up and showing the portal. 30s covers most slow-association
# cases without making a connected boot annoyingly slow.
INITIAL_WIFI_CLIENT_WAIT_SECONDS = 30

# ── AP credentials ──────────────────────────────────────────────────────────
# These are the SSID and WPA2 passphrase of the temporary setup hotspot.
# Change them before deploying (via setup.sh args, env vars, or edit here).
# See the README → Configuration section for full details.
DEFAULT_AP_SSID = "PiWifiSetup"
DEFAULT_AP_PASSWORD = "setupwifi"

# Publicly-known default passwords we refuse to start with — anyone who reads
# this repo would know them. setup.sh enforces the same policy at install
# time; this is a defense-in-depth check for hand-edited unit files.
KNOWN_INSECURE_AP_PASSWORDS = frozenset({DEFAULT_AP_PASSWORD})

# Bind the portal to the AP gateway IP only, not 0.0.0.0. This way the portal
# is never exposed on Ethernet/USB-gadget interfaces if any happen to be up
# while the AP is active.
PORTAL_HOST = ap_manager.AP_GATEWAY_IP
PORTAL_PORT = 80


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _shutdown_event() -> threading.Event:
    """Return an Event that gets set when SIGTERM/SIGINT is received."""
    event = threading.Event()

    def _handle(signum, _frame):
        logging.info("Received signal %s, beginning shutdown.", signum)
        event.set()

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    return event


def _run_portal(ap_state: ap_manager.APState, env_file_path: Optional[str]) -> None:
    """Run Flask in the foreground until the orchestrator decides to stop.

    `on_success` is called by the portal when the reboot button is pressed,
    giving us a hook to tear the AP down before the system actually reboots.
    """
    teardown_done = threading.Event()

    def on_success() -> None:
        # The reboot endpoint already schedules `sleep 2 && reboot`; we use
        # that window to release iptables/dnsmasq/nmcli resources so nothing
        # lingers if the reboot is somehow cancelled.
        if teardown_done.is_set():
            return
        try:
            ap_manager.teardown_ap(ap_state)
        finally:
            teardown_done.set()

    app = create_app(env_file_path=env_file_path, on_success=on_success)

    # Flask's built-in server is fine here: the AP only ever has a few clients
    # (the user's phone or laptop), and we want zero extra dependencies on the
    # Pi at first-boot.
    try:
        app.run(host=PORTAL_HOST, port=PORTAL_PORT, debug=False, use_reloader=False)
    except OSError as exc:
        logging.error("Portal failed to bind to %s:%s: %s", PORTAL_HOST, PORTAL_PORT, exc)
        raise
    finally:
        if not teardown_done.is_set():
            ap_manager.teardown_ap(ap_state)


def main() -> int:
    _configure_logging()
    shutdown = _shutdown_event()

    ap_ssid = os.environ.get("AP_SSID", DEFAULT_AP_SSID)
    ap_password = os.environ.get("AP_PASSWORD", DEFAULT_AP_PASSWORD)

    if ap_password in KNOWN_INSECURE_AP_PASSWORDS:
        logging.error(
            "AP_PASSWORD is set to the publicly-known default %r. Refusing to "
            "start the captive portal — anyone within radio range could join "
            "the AP and reconfigure this device. Edit "
            "/etc/systemd/system/wifi_configurator.service (or re-run "
            "deployment/setup.sh with --ap-password) to set a strong value.",
            ap_password,
        )
        return 1

    logging.info(
        "Waiting up to %ds for wlan0 to join a Wi-Fi network as a client...",
        INITIAL_WIFI_CLIENT_WAIT_SECONDS,
    )
    if connectivity.poll_until_wifi_station(timeout_seconds=INITIAL_WIFI_CLIENT_WAIT_SECONDS):
        logging.info(
            "wlan0 is associated with a Wi-Fi network (client mode); skipping captive portal."
        )
        return 0

    if shutdown.is_set():
        return 0

    logging.warning(
        "wlan0 has no Wi-Fi client connection; starting captive portal AP "
        "(USB/Ethernet Internet alone does not skip this step)."
    )
    env_file_path = resolve_env_file_path()
    logging.info(
        ".env path: %s (set ENV_FILE_PATH in the unit to override)",
        env_file_path,
    )
    try:
        ap_state = ap_manager.setup_ap(ssid=ap_ssid, password=ap_password)
    except (OSError, ValueError, RuntimeError) as exc:
        logging.error("Failed to bring up access point: %s", exc)
        return 1

    try:
        _run_portal(ap_state=ap_state, env_file_path=env_file_path)
    except Exception:
        logging.exception("Portal crashed; tearing down AP.")
        ap_manager.teardown_ap(ap_state)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
