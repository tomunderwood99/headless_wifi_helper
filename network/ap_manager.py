"""Bring up and tear down a WiFi access point with a captive portal redirect.

Strategy:
  1. Use `nmcli device wifi hotspot` to create a WPA2-protected AP. NM brings
     up hostapd internally and manages a small DHCP server that hands out
     192.168.4.x leases on wlan0 (the AP gateway is 192.168.4.1).
  2. Run a *secondary* dnsmasq instance bound to wlan0 that returns
     192.168.4.1 for every DNS query. This makes phones/laptops believe the
     network has no upstream connectivity and triggers the OS-level captive
     portal popup.
  3. Use iptables to redirect any TCP traffic to port 80 toward the Flask
     portal on 192.168.4.1. This catches the HTTP probes (e.g.
     `connectivitycheck.gstatic.com`) that captive portal detection relies on.

All of this is reversible via `teardown_ap()`, which is also called as a
cleanup hook in the orchestrator so the Pi never gets stuck in AP mode.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Subnet handed out by nmcli hotspot mode. This is the documented default.
AP_GATEWAY_IP = "192.168.4.1"
AP_INTERFACE = "wlan0"
HOTSPOT_CONNECTION_NAME = "Hotspot"


@dataclass
class APState:
    """Tracks resources we need to release in teardown_ap()."""

    dnsmasq_pid_file: Optional[str] = None
    iptables_rule_active: bool = False
    hotspot_active: bool = False


def _run(cmd: list[str], check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, check=check, capture_output=True, text=True, timeout=timeout)


def _apply_regdomain_from_env() -> None:
    """Apply ``iw reg set`` when ``WIFI_REGDOMAIN`` is set (e.g. ``US``).

    Raspberry Pi often refuses to start an AP until a Wi-Fi regulatory domain
    is configured; ``raspi-config`` normally sets this, but headless / gadget
    images sometimes omit it. Set ``Environment=WIFI_REGDOMAIN=US`` in the unit
    if hotspot fails with a regulatory / hostapd error.
    """
    reg = os.environ.get("WIFI_REGDOMAIN", "").strip().upper()
    if not reg or not shutil.which("iw"):
        return
    _run(["iw", "reg", "set", reg], check=False, timeout=5)
    logger.info("Applied Wi-Fi regulatory domain via iw: %s", reg)


def _prepare_interface_for_hotspot(interface: str) -> None:
    """Turn the radio on, clear client state, and remove a stale Hotspot profile.

    ``nmcli device wifi hotspot`` frequently returns exit 4 if ``wlan0`` is still
    tied to a client attempt or a half-created ``Hotspot`` connection exists
    from a prior crash — especially common when USB gadget networking is up at
    the same time.
    """
    if shutil.which("rfkill"):
        _run(["rfkill", "unblock", "wifi"], check=False, timeout=5)
        _run(["rfkill", "unblock", "wlan"], check=False, timeout=5)
    _run(["nmcli", "radio", "wifi", "on"], check=False, timeout=10)
    _apply_regdomain_from_env()
    _run(["nmcli", "device", "disconnect", interface], check=False, timeout=20)
    time.sleep(1.5)
    # Remove a broken or half-created profile so `wifi hotspot` can create a fresh one.
    _run(["nmcli", "connection", "delete", HOTSPOT_CONNECTION_NAME], check=False, timeout=15)


def _start_hotspot(ssid: str, password: str, interface: str) -> None:
    """Start the NetworkManager hotspot after freeing ``interface`` for AP mode."""
    _prepare_interface_for_hotspot(interface)
    _run(["nmcli", "connection", "down", HOTSPOT_CONNECTION_NAME], check=False)

    result = subprocess.run(
        [
            "nmcli",
            "device",
            "wifi",
            "hotspot",
            "ifname",
            interface,
            "ssid",
            ssid,
            "password",
            password,
        ],
        capture_output=True,
        text=True,
        timeout=45,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip() or f"exit {result.returncode}"
        logger.error("nmcli device wifi hotspot failed: %s", detail)
        raise RuntimeError(
            "Could not start the Wi-Fi hotspot (nmcli exit "
            f"{result.returncode}). Details: {detail}. "
            "Try: sudo nmcli device status; sudo rfkill list; "
            "and on Raspberry Pi ensure a country is set (raspi-config Localisation, "
            "or set environment WIFI_REGDOMAIN=US on the service and retry)."
        )

    # nmcli's hotspot defaults to "shared" IPv4 method which gives us
    # 10.42.0.1 on some distros but 192.168.4.1 on Trixie's NM. Pin it
    # explicitly so the rest of the module can rely on AP_GATEWAY_IP.
    _run(
        [
            "nmcli",
            "connection",
            "modify",
            HOTSPOT_CONNECTION_NAME,
            "ipv4.method",
            "shared",
            "ipv4.addresses",
            f"{AP_GATEWAY_IP}/24",
        ],
        check=False,
    )
    # Re-apply the modified connection so the address change takes effect.
    _run(["nmcli", "connection", "up", HOTSPOT_CONNECTION_NAME], check=False, timeout=30)


def _start_dns_redirector(state: APState) -> None:
    """Launch a dnsmasq instance that resolves every name to AP_GATEWAY_IP.

    We can't use NM's bundled dnsmasq because that one is configured as a
    standard recursive resolver. Running our own instance with
    `--address=/#/192.168.4.1` is the simplest way to ensure captive-portal
    probes hit our Flask app.
    """
    if not shutil.which("dnsmasq"):
        logger.warning("dnsmasq is not installed; captive portal popup may not auto-trigger.")
        return

    pid_file = os.path.join(tempfile.gettempdir(), "wifi_configurator_dnsmasq.pid")
    state.dnsmasq_pid_file = pid_file

    # Kill any leftover instance from a previous run that may still be holding
    # port 53 on wlan0.
    _kill_pid_file(pid_file)

    cmd = [
        "dnsmasq",
        f"--interface={AP_INTERFACE}",
        # Bind only to wlan0 so we don't conflict with systemd-resolved or
        # NetworkManager's own dnsmasq listening on the loopback.
        "--bind-interfaces",
        f"--listen-address={AP_GATEWAY_IP}",
        # No DHCP from this instance; NM is already handing out leases.
        "--no-dhcp-interface=" + AP_INTERFACE,
        # The captive-portal trick: every A query returns the gateway.
        f"--address=/#/{AP_GATEWAY_IP}",
        # Don't read /etc/resolv.conf or the system hosts file; we want to be
        # fully authoritative.
        "--no-resolv",
        "--no-hosts",
        f"--pid-file={pid_file}",
        # Run in the background; dnsmasq forks by default.
    ]
    try:
        _run(cmd, timeout=10)
    except subprocess.CalledProcessError as exc:
        logger.warning(
            "Failed to start captive-portal dnsmasq (stderr=%s). Continuing without it.",
            (exc.stderr or "").strip(),
        )
        state.dnsmasq_pid_file = None


def _enable_port80_redirect(state: APState) -> None:
    """Redirect incoming TCP/80 on wlan0 to the Flask portal.

    The portal already binds to :80 directly, but some clients probe HTTP on
    other hosts (e.g. captive.apple.com) that resolve via our DNS spoof to
    192.168.4.1. The PREROUTING DNAT rule guarantees they land on the portal
    regardless of the Host header they used.
    """
    if not shutil.which("iptables"):
        logger.warning("iptables is not installed; captive portal redirect skipped.")
        return
    try:
        _run(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-i",
                AP_INTERFACE,
                "-p",
                "tcp",
                "--dport",
                "80",
                "-j",
                "DNAT",
                "--to-destination",
                f"{AP_GATEWAY_IP}:80",
            ]
        )
        state.iptables_rule_active = True
    except subprocess.CalledProcessError as exc:
        logger.warning("iptables redirect failed: %s", (exc.stderr or "").strip())


def _disable_port80_redirect(state: APState) -> None:
    if not state.iptables_rule_active:
        return
    # Mirror the -A above with -D to remove only our rule. Errors are tolerated
    # since the rule may already be gone (e.g. after a reboot of NM).
    _run(
        [
            "iptables",
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-i",
            AP_INTERFACE,
            "-p",
            "tcp",
            "--dport",
            "80",
            "-j",
            "DNAT",
            "--to-destination",
            f"{AP_GATEWAY_IP}:80",
        ],
        check=False,
    )
    state.iptables_rule_active = False


def _kill_pid_file(pid_file: str) -> None:
    if not pid_file or not os.path.exists(pid_file):
        return
    try:
        with open(pid_file, "r", encoding="utf-8") as fh:
            pid = int(fh.read().strip())
        os.kill(pid, signal.SIGTERM)
        # Give the process a moment to exit cleanly before we move on.
        time.sleep(0.5)
    except (OSError, ValueError) as exc:
        logger.debug("Could not kill dnsmasq via pid file %s: %s", pid_file, exc)
    finally:
        try:
            os.remove(pid_file)
        except OSError:
            pass


def setup_ap(ssid: str, password: str, interface: str = AP_INTERFACE) -> APState:
    """Bring the AP up and configure the captive portal redirects.

    Returns an APState that must be passed to teardown_ap() so we can release
    the iptables rule and dnsmasq process during cleanup.
    """
    if len(password) < 8:
        # WPA2 personal requires >= 8 character passphrases; fail fast with a
        # clear message rather than letting nmcli emit a cryptic error.
        raise ValueError("AP password must be at least 8 characters (WPA2 requirement).")

    state = APState()
    logger.info("Starting hotspot SSID=%s on %s", ssid, interface)
    _start_hotspot(ssid=ssid, password=password, interface=interface)
    state.hotspot_active = True

    # Give NM a beat to actually finish bringing the AP online before we try
    # to bind dnsmasq to its IP.
    time.sleep(2)

    _start_dns_redirector(state)
    _enable_port80_redirect(state)
    logger.info("Captive portal AP is up. Gateway=%s", AP_GATEWAY_IP)
    return state


def teardown_ap(state: APState) -> None:
    """Reverse everything setup_ap() did, in reverse order. Best-effort."""
    logger.info("Tearing down captive portal AP")
    _disable_port80_redirect(state)
    if state.dnsmasq_pid_file:
        _kill_pid_file(state.dnsmasq_pid_file)
        state.dnsmasq_pid_file = None
    if state.hotspot_active:
        _run(["nmcli", "connection", "down", HOTSPOT_CONNECTION_NAME], check=False)
        # Removing the connection profile entirely keeps the system clean
        # for the next boot; the configurator will recreate it on demand.
        _run(["nmcli", "connection", "delete", HOTSPOT_CONNECTION_NAME], check=False)
        state.hotspot_active = False
