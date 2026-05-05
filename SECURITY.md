# Security

## Scope and threat model

headless_wifi_helper is a **local, first-boot provisioning tool**. It:

- Runs only when no saved Wi-Fi network is reachable
- Serves an HTTP portal over a temporary WPA2 access point
- Shuts down as soon as the Pi reboots into its configured network

The intended threat model is **physical proximity during a brief setup window**,
not persistent internet exposure.

## Known limitations

**HTTP-only portal** — credentials (SSID password and any API key) are
transmitted unencrypted over the local AP link. Anyone within radio range during
setup can theoretically intercept them. For most home/lab deployments this is an
acceptable trade-off; for sensitive environments, provision credentials another
way (e.g. SD card image with `wpa_supplicant.conf` pre-written).

**Runs as root** — the service requires root to bring up the AP, manage
`iptables`, and run `nmcli`. The Flask server therefore also runs as root.

**Default AP credentials** — the repo ships example defaults for the hotspot
SSID and password. You should change these before deployment (see the
Configuration section of the README). Anyone who reads this repo knows the
defaults, so leaving them unchanged means any other device in range during setup
could join the temporary AP.

## Reporting a vulnerability

For actual vulnerabilities, please use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository)
or the email address on the GitHub profile, so the details stay private until
a fix is available.

For general security questions or low-severity issues, open a GitHub issue at
https://github.com/tomunderwood99/headless_wifi_helper/issues and include
**"security"** in the title.
