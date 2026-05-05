#!/usr/bin/env bash
# Installer for headless_wifi_helper.
#
# Run from the project root as root:
#   sudo ./deployment/setup.sh
#
# Optionally pass --env-file to pin the .env path written when a user submits
# an API key through the portal (otherwise falls back to /home/pi/.env):
#   sudo ./deployment/setup.sh --env-file /home/pi/myproject/.env
#
# Optionally pass --env-key-name for the variable name written into that .env
# (otherwise the app defaults to API_KEY unless set in the unit):
#   sudo ./deployment/setup.sh --env-key-name MBTA_API_KEY
#
# Optionally override the AP SSID/password (recommended before deploying):
#   sudo ./deployment/setup.sh --ap-ssid MyPi --ap-password mypassword

set -euo pipefail

# --- Helpers ----------------------------------------------------------------

log()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn ]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "This installer must be run as root (use sudo)."
    exit 1
  fi
}

# Escape `\`, `&`, and the `|` we use as the sed `s` delimiter so an arbitrary
# string can be safely interpolated into the replacement side of `s|...|VAL|`.
sed_replacement_escape() {
  printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}

# Quote a string for use inside a systemd `Environment="KEY=VAL"` directive.
# Per systemd.syntax(7), inside double quotes only `\` and `"` require
# backslash-escaping; the `%` specifier marker (e.g. `%h`) is doubled to
# prevent expansion. Whitespace is permitted because the assignment is quoted.
systemd_quote_value() {
  local v="$1"
  v=${v//\\/\\\\}
  v=${v//\"/\\\"}
  v=${v//%/%%}
  printf '%s' "$v"
}

# Reject newline-bearing values up front. They would otherwise corrupt the
# single-line `Environment=` assignment we splice into the unit file.
reject_newlines() {
  # $1 = human label, $2 = value
  if [[ "$2" == *$'\n'* ]] || [[ "$2" == *$'\r'* ]]; then
    err "$1 cannot contain newline characters."
    exit 1
  fi
}

# --- Argument parsing -------------------------------------------------------

# Empty means: do not inject ENV_FILE_PATH / ENV_KEY_NAME into the unit.
ENV_FILE_PATH="${ENV_FILE_PATH:-}"
ENV_KEY_NAME_VALUE="${ENV_KEY_NAME:-}"
AP_SSID_VALUE="${AP_SSID:-PiWifiSetup}"

# Track whether AP_PASSWORD was supplied (env var or --ap-password flag) so we
# can autogenerate a strong default when it wasn't, while still rejecting weak
# explicit values.
AP_PASSWORD_VALUE="${AP_PASSWORD:-}"
AP_PASSWORD_PROVIDED=0
[[ -n "$AP_PASSWORD_VALUE" ]] && AP_PASSWORD_PROVIDED=1

# Strings that are publicly known to anyone who reads this repo and therefore
# unsafe as the live AP passphrase. Add more here if defaults ever change.
PUBLIC_DEFAULT_AP_PASSWORDS=("setupwifi")

# WPA2 protocol minimum is 8, but offline cracking makes anything under ~12
# trivial. Enforce 12 as the install-time floor.
MIN_AP_PASSWORD_LENGTH=12
# WPA2 PSK passphrase upper bound is 63 ASCII chars (or 64 hex digits for a
# raw key; we don't accept that form).
MAX_AP_PASSWORD_LENGTH=63

# Generate 16 random alphanumeric characters using only coreutils + /dev/urandom.
# Process substitution + head avoids tripping `set -o pipefail` on tr's SIGPIPE
# when head closes the read end early.
generate_ap_password() {
  head -c 16 < <(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null)
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      ENV_FILE_PATH="$2"
      shift 2
      ;;
    --env-key-name)
      ENV_KEY_NAME_VALUE="$2"
      shift 2
      ;;
    --ap-ssid)
      AP_SSID_VALUE="$2"
      shift 2
      ;;
    --ap-password)
      AP_PASSWORD_VALUE="$2"
      AP_PASSWORD_PROVIDED=1
      shift 2
      ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *)
      err "Unknown argument: $1"
      exit 1
      ;;
  esac
done

require_root

# --- AP password policy -----------------------------------------------------

reject_newlines "AP_SSID" "$AP_SSID_VALUE"

if [[ "$AP_PASSWORD_PROVIDED" -eq 1 ]]; then
  reject_newlines "AP_PASSWORD" "$AP_PASSWORD_VALUE"
  for forbidden in "${PUBLIC_DEFAULT_AP_PASSWORDS[@]}"; do
    if [[ "$AP_PASSWORD_VALUE" == "$forbidden" ]]; then
      err "AP_PASSWORD is set to the publicly-known default '$forbidden'."
      err "Anyone who reads this repo knows it. Pass a different value via"
      err "--ap-password (or omit the flag to autogenerate a strong one)."
      exit 1
    fi
  done
  if (( ${#AP_PASSWORD_VALUE} < MIN_AP_PASSWORD_LENGTH )); then
    err "AP_PASSWORD must be at least $MIN_AP_PASSWORD_LENGTH characters (got ${#AP_PASSWORD_VALUE})."
    err "WPA2 only requires 8, but anything shorter than $MIN_AP_PASSWORD_LENGTH is trivial to"
    err "crack offline once the 4-way handshake is captured."
    exit 1
  fi
  if (( ${#AP_PASSWORD_VALUE} > MAX_AP_PASSWORD_LENGTH )); then
    err "AP_PASSWORD must be at most $MAX_AP_PASSWORD_LENGTH characters (WPA2 PSK limit). Got ${#AP_PASSWORD_VALUE}."
    exit 1
  fi
  AP_PASSWORD_GENERATED=0
else
  AP_PASSWORD_VALUE="$(generate_ap_password)"
  if (( ${#AP_PASSWORD_VALUE} < MIN_AP_PASSWORD_LENGTH )); then
    err "Password generation produced only ${#AP_PASSWORD_VALUE} chars; aborting."
    err "Pass --ap-password <your-password> manually."
    exit 1
  fi
  AP_PASSWORD_GENERATED=1
  log "No --ap-password given; generated a random one (printed at the end)."
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$PROJECT_DIR/venv"
SERVICE_SRC="$PROJECT_DIR/deployment/wifi_configurator.service"
SERVICE_DST="/etc/systemd/system/wifi_configurator.service"

log "Project directory: $PROJECT_DIR"
if [[ -n "${ENV_FILE_PATH}" ]]; then
  log "Target .env path : $ENV_FILE_PATH (explicit)"
else
  log "Target .env path : (not set; runtime fallback to /home/pi/.env)"
fi
if [[ -n "${ENV_KEY_NAME_VALUE}" ]]; then
  log "ENV key name     : $ENV_KEY_NAME_VALUE (explicit)"
else
  log "ENV key name     : (not set; app defaults to API_KEY)"
fi
log "AP SSID          : $AP_SSID_VALUE"

# --- System packages --------------------------------------------------------

log "Installing system packages (network-manager, dnsmasq, iptables, python venv)..."
apt-get update
# `dnsmasq` is the binary the AP manager spawns for DNS spoofing; we install
# it but immediately disable the system service so it doesn't bind to :53
# globally. Our orchestrator runs its own bound to wlan0 only.
apt-get install -y \
  network-manager \
  dnsmasq \
  iptables \
  python3 \
  python3-venv \
  python3-pip

if systemctl is-enabled --quiet dnsmasq 2>/dev/null; then
  warn "Disabling system-wide dnsmasq.service (we run our own scoped to wlan0)."
  systemctl disable --now dnsmasq.service || true
fi

# --- Python virtualenv ------------------------------------------------------

if [[ ! -d "$VENV_DIR" ]]; then
  log "Creating virtualenv at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

log "Installing Python dependencies..."
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$PROJECT_DIR/requirements.txt"

# --- systemd unit -----------------------------------------------------------

log "Installing systemd unit to $SERVICE_DST"

# Patch the unit with the actual project directory and overrides. We use sed
# so the source file in the repo stays generic.
#
# AP_SSID and AP_PASSWORD can legally contain shell-special and sed-special
# characters (spaces, `$`, `&`, `\`, `|`, `%`, `"`, …). We do two layers of
# escaping so any printable WPA2 passphrase / SSID survives the trip:
#   1. systemd_quote_value: escape `\`/`"`/`%` for the `Environment="K=V"` form.
#   2. sed_replacement_escape: escape `\`/`&`/`|` for sed's replacement side.
# The resulting line is `Environment="AP_PASSWORD=…"` — the surrounding quotes
# also let the value contain whitespace without splitting into two assignments.
SSID_ESCAPED="$(sed_replacement_escape "$(systemd_quote_value "$AP_SSID_VALUE")")"
PASSWORD_ESCAPED="$(sed_replacement_escape "$(systemd_quote_value "$AP_PASSWORD_VALUE")")"

TMP_UNIT="$(mktemp)"
cp "$SERVICE_SRC" "$TMP_UNIT"

# Inject ENV_FILE_PATH / ENV_KEY_NAME *before* the sed pass below: that pass
# rewrites `Environment=AP_SSID=...` into the quoted `Environment="AP_SSID=..."`
# form, which would break the awk anchor here. Doing this first keeps the
# anchor matching the unquoted line as it appears in the source unit.
if [[ -n "${ENV_FILE_PATH}" ]] || [[ -n "${ENV_KEY_NAME_VALUE}" ]]; then
  awk -v p="$ENV_FILE_PATH" -v k="$ENV_KEY_NAME_VALUE" '
    /^Environment=AP_SSID=/ && !done {
      if (p != "") print "Environment=ENV_FILE_PATH=" p
      if (k != "") print "Environment=ENV_KEY_NAME=" k
      done = 1
    }
    { print }
  ' "$TMP_UNIT" > "${TMP_UNIT}.new" && mv "${TMP_UNIT}.new" "$TMP_UNIT"
  [[ -n "${ENV_FILE_PATH}" ]] && log "Injected Environment=ENV_FILE_PATH into unit file."
  [[ -n "${ENV_KEY_NAME_VALUE}" ]] && log "Injected Environment=ENV_KEY_NAME into unit file."
fi

sed -i \
  -e "s|^WorkingDirectory=.*|WorkingDirectory=$PROJECT_DIR|" \
  -e "s|^ExecStart=.*|ExecStart=$VENV_DIR/bin/python wifi_configurator.py|" \
  -e "s|^Environment=AP_SSID=.*|Environment=\"AP_SSID=$SSID_ESCAPED\"|" \
  -e "s|^Environment=AP_PASSWORD=.*|Environment=\"AP_PASSWORD=$PASSWORD_ESCAPED\"|" \
  "$TMP_UNIT"

install -m 0644 "$TMP_UNIT" "$SERVICE_DST"
rm -f "$TMP_UNIT"

systemctl daemon-reload
systemctl enable wifi_configurator.service

log "Done."
echo
log "AP credentials (use these to join the setup hotspot):"
echo "  SSID    : $AP_SSID_VALUE"
echo "  Password: $AP_PASSWORD_VALUE"
if [[ "$AP_PASSWORD_GENERATED" -eq 1 ]]; then
  warn "This password was autogenerated. Write it down now — it lives in"
  warn "$SERVICE_DST (root-readable) but won't be shown again."
fi
echo
log "Next steps:"
echo "  - Reboot to verify behavior:           sudo reboot"
echo "  - Check service status:                systemctl status wifi_configurator.service"
echo "  - Tail service logs:                   journalctl -u wifi_configurator.service -f"
echo "  - To re-run setup with new AP creds:   sudo ./deployment/setup.sh --ap-password newpw"
