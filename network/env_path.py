"""Resolve the `.env` file path for the captive portal.

`ENV_FILE_PATH` in the environment wins when set explicitly (e.g. in a
systemd unit or for testing). Falls back to `/home/pi/.env` when not set.

Set `ENV_FILE_PATH` to wherever your project stores its configuration, e.g.:
    /home/pi/myproject/.env
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Fallback used when ENV_FILE_PATH is not configured in the systemd unit.
FALLBACK_ENV_PATH = Path("/home/pi/.env")


def resolve_env_file_path(explicit: Optional[str] = None) -> str:
    """Resolve the `.env` file path.

    Precedence:
      1. Non-empty ``explicit`` argument (caller override).
      2. Non-empty ``ENV_FILE_PATH`` environment variable.
      3. Fallback: ``/home/pi/.env``.
    """
    if explicit and explicit.strip():
        return explicit.strip()
    env = os.environ.get("ENV_FILE_PATH", "").strip()
    if env:
        return env
    logger.warning(
        "ENV_FILE_PATH is not set; falling back to %s. "
        "Pass --env-file to setup.sh or set Environment=ENV_FILE_PATH in the "
        "systemd unit to configure a different path.",
        FALLBACK_ENV_PATH,
    )
    return str(FALLBACK_ENV_PATH)
