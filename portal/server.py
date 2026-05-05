"""Flask captive portal application.

The orchestrator imports `create_app()` after the AP is up and runs it bound
to the AP gateway IP (192.168.4.1) on port 80, so the portal is never exposed
on Ethernet/USB-gadget interfaces if any happen to be up while the AP is
active. Because the app is short-lived (it shuts down once WiFi is configured
and the user reboots), we keep things synchronous and lean on a single
in-memory `STATUS` dict to share connection-attempt progress between the form
submission and the polling page.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from dotenv import set_key
from flask import Flask, Response, jsonify, make_response, redirect, render_template, request

from network import connectivity
from network.env_path import resolve_env_file_path

logger = logging.getLogger(__name__)

# Must match AP_GATEWAY_IP in network/ap_manager.py.
PORTAL_URL = "http://192.168.4.1/"

# iOS / macOS CNA probes — these expect exactly the "Success" page from Apple's
# servers. Returning *anything else* with 200 triggers the captive portal popup.
# We return a tiny 200 page with a meta-refresh so if CNA opens a mini-browser
# it will land on our portal.
IOS_PROBE_PATHS = {
    "/hotspot-detect.html",
    "/library/test/success.html",
    "/success.html",
}

# Android / ChromeOS probes — expect HTTP 204 from Google's servers; a
# non-204 response triggers the captive portal popup. We return a 302 to
# force the popup rather than satisfy the probe.
ANDROID_PROBE_PATHS = {
    "/generate_204",
    "/gen_204",
    "/ncsi.txt",          # also used by some Android builds
}

# Windows NCSI / WCM probes — expect specific text bodies; anything else
# triggers connectivity detection. We return a 302 to force the popup.
# Note: /ncsi.txt is intentionally omitted here; it's already in ANDROID_PROBE_PATHS.
WINDOWS_PROBE_PATHS = {
    "/connecttest.txt",
    "/redirect",
}

# Tiny page returned for iOS probes. The meta-refresh sends CNA's mini-browser
# to the portal; the link tag is the RFC 8908 hint.
_IOS_TRIGGER_PAGE = (
    "<!DOCTYPE html><html><head>"
    f'<meta http-equiv="refresh" content="0;url={PORTAL_URL}">'
    f'<link rel="captive-portal" href="{PORTAL_URL}">'
    "</head><body></body></html>"
)

# Cap the API key field to a bounded length. 128 comfortably fits the keys we
# expect in practice (MBTA: 32, AWS: 40, GitHub PAT: ~40-93, Stripe live: ~107),
# and prevents a giant paste from blowing up the .env file or exhausting disk
# on a write retry loop. Bump this if you need to store longer credentials —
# e.g. JWTs are often a few hundred characters, and some OAuth tokens are
# longer still. The same value is mirrored in portal/templates/portal.html as
# the input's `maxlength`; update both together.
MAX_API_KEY_LENGTH = 128


def _initial_status() -> Dict[str, Any]:
    return {
        # One of: idle, connecting, success, error
        "state": "idle",
        "ssid": None,
        "message": None,
    }


def create_app(
    env_file_path: Optional[str] = None,
    on_success: Optional[Callable[[], None]] = None,
) -> Flask:
    """Construct the Flask app.

    Args:
        env_file_path: Path to the `.env` file that an API key value is written
            to if the user fills in the optional API Key field on the portal
            page. When omitted, uses ``ENV_FILE_PATH`` if set, otherwise falls
            back to ``/home/pi/.env``.
        on_success: Optional callback fired when the portal confirms a
            successful WiFi connection. The orchestrator uses this to begin
            tearing down the AP after the user clicks reboot.
    """
    app = Flask(__name__, template_folder="templates")
    app.config["ENV_FILE_PATH"] = resolve_env_file_path(explicit=env_file_path)
    # Variable name written into the .env file when the user supplies a key.
    # Override with Environment=ENV_KEY_NAME=MY_VAR in the systemd unit.
    app.config["ENV_KEY_NAME"] = os.environ.get("ENV_KEY_NAME", "API_KEY")
    app.config["STATUS"] = _initial_status()
    app.config["STATUS_LOCK"] = threading.Lock()
    app.config["ON_SUCCESS"] = on_success

    @app.after_request
    def add_captive_portal_headers(response: Response) -> Response:
        # RFC 8908 / Apple CNA hint: tell clients where the portal lives.
        response.headers["Location-Hint"] = PORTAL_URL
        response.headers["X-Captive-Portal"] = PORTAL_URL
        return response

    @app.route("/", methods=["GET"])
    def index():
        return render_template(
            "portal.html",
            env_file_path=app.config["ENV_FILE_PATH"],
            env_key_name=app.config["ENV_KEY_NAME"],
        )

    @app.route("/scan", methods=["GET"])
    def scan():
        networks = connectivity.scan_networks()
        return jsonify(
            [
                {"ssid": n.ssid, "signal": n.signal, "security": n.security}
                for n in networks
            ]
        )

    @app.route("/connect", methods=["POST"])
    def connect():
        ssid = (request.form.get("ssid") or "").strip()
        password = request.form.get("password") or ""
        api_key = (request.form.get("api_key") or "").strip()

        if not ssid:
            return jsonify({"ok": False, "message": "SSID is required."}), 400

        if len(api_key) > MAX_API_KEY_LENGTH:
            return jsonify({
                "ok": False,
                "message": f"API key is too long (max {MAX_API_KEY_LENGTH} characters).",
            }), 400

        # Reject any ASCII control character (0x00–0x1F). This subsumes the
        # newline check that's needed because we write to the .env file via
        # python-dotenv's `set_key(..., quote_mode="never")` — a value with an
        # embedded newline would inject a second `KEY=value` line. Real API
        # keys are printable, so this is also a useful paste-error filter.
        if any(ord(c) < 0x20 for c in api_key):
            return jsonify({
                "ok": False,
                "message": "API key cannot contain control characters or newlines.",
            }), 400

        with app.config["STATUS_LOCK"]:
            current = app.config["STATUS"]
            if current["state"] == "connecting":
                return jsonify({"ok": False, "message": "A connection attempt is already in progress."}), 409
            app.config["STATUS"] = {
                "state": "connecting",
                "ssid": ssid,
                "message": f"Connecting to {ssid}...",
            }

        # Run the (potentially slow) connect attempt off the request thread so
        # the UI can poll /status and show progress while we wait.
        thread = threading.Thread(
            target=_attempt_connection,
            args=(app, ssid, password, api_key),
            daemon=True,
        )
        thread.start()
        return jsonify({"ok": True, "message": "Saving Wi-Fi profile…"})

    @app.route("/status", methods=["GET"])
    def status():
        with app.config["STATUS_LOCK"]:
            return jsonify(dict(app.config["STATUS"]))

    @app.route("/reboot", methods=["POST"])
    def reboot():
        # Best-effort: notify the orchestrator first so it can tear down the
        # AP and stop the Flask server cleanly, then schedule a reboot.
        callback = app.config.get("ON_SUCCESS")
        if callback:
            try:
                callback()
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("on_success callback raised: %s", exc)

        # Use a short delay so the HTTP response can flush back to the client
        # before the system actually goes down.
        try:
            subprocess.Popen(
                ["sh", "-c", "sleep 2 && /sbin/reboot"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            logger.error("Failed to schedule reboot: %s", exc)
            return jsonify({"ok": False, "message": str(exc)}), 500
        return jsonify({"ok": True, "message": "Rebooting..."})

    @app.route("/<path:probe>", methods=["GET"])
    def captive_probe(probe: str):
        """Handle OS captive-portal detection probes.

        iOS/macOS CNA: expects Apple's "Success" page. We return a tiny 200
        page with a meta-refresh to the portal URL, which triggers the CNA popup.

        All other probes (Android, Windows, unknown): we return a 302 redirect
        to the portal. This causes each OS's connectivity checker to report a
        captive portal and prompt the user to sign in.
        """
        path = "/" + probe
        if path in IOS_PROBE_PATHS:
            resp = make_response(_IOS_TRIGGER_PAGE, 200)
            resp.content_type = "text/html; charset=utf-8"
            return resp
        return redirect(PORTAL_URL, code=302)

    return app


def _attempt_connection(app: Flask, ssid: str, password: str, api_key: str) -> None:
    """Background worker: persist Wi-Fi for after reboot, optionally write API key.

    We do **not** call ``nmcli device wifi connect`` here: on a single Wi-Fi
    radio that would drop the hotspot immediately and the phone would lose this
    page. Credentials go into a NetworkManager profile with autoconnect;
    ``/reboot`` applies them on the next boot.
    """
    success, message = connectivity.save_wifi_profile_for_reboot(ssid=ssid, password=password)
    if not success:
        with app.config["STATUS_LOCK"]:
            app.config["STATUS"] = {
                "state": "error",
                "ssid": ssid,
                "message": message,
            }
        return

    if api_key:
        try:
            _persist_api_key(app.config["ENV_FILE_PATH"], app.config["ENV_KEY_NAME"], api_key)
        except OSError as exc:
            # Don't fail the whole flow over an env write; surface a warning
            # in the success message instead.
            key_name = app.config["ENV_KEY_NAME"]
            logger.error("Failed to write %s to %s: %s", key_name, app.config["ENV_FILE_PATH"], exc)
            with app.config["STATUS_LOCK"]:
                app.config["STATUS"] = {
                    "state": "success",
                    "ssid": ssid,
                    "message": (
                        f"Saved Wi-Fi for “{ssid}”. Reboot to connect. "
                        f"The API key could not be written ({exc}); set {key_name} manually."
                    ),
                }
            return

    with app.config["STATUS_LOCK"]:
        app.config["STATUS"] = {
            "state": "success",
            "ssid": ssid,
            "message": (
                f"Saved Wi-Fi for “{ssid}” (other networks you saved earlier are kept). "
                "This hotspot stays up until you tap Reboot now. After reboot the Pi will "
                "join an in-range saved network (wrong password? you will see this setup screen again)."
            ),
        }


def _persist_api_key(env_file_path: str, key_name: str, api_key: str) -> None:
    """Create/update a key=value entry in the configured .env file."""
    target = Path(env_file_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        # python-dotenv's set_key requires the file to exist first.
        target.touch(mode=0o600)
    set_key(str(target), key_name, api_key, quote_mode="never")
