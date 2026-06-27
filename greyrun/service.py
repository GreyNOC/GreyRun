"""Autostart -- run the GreyRun monitor automatically at logon.

On Windows this registers a Scheduled Task triggered at user logon and, when
GreyRun is launched from an elevated console, runs it with highest privileges
so the responder can act on processes it does not own. Installation needs an
Administrator shell; if it is not available we say so clearly rather than
failing opaquely.

On other platforms we don't try to guess an init system -- we print a ready-to
-use cron line instead.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Tuple

from .config import Config, Paths

TASK_NAME = "GreyRunMonitor"


def _monitor_command(config: Config, paths: Paths) -> str:
    """The command the scheduled task runs, fully quoted."""
    python = sys.executable or "python"
    # Prefer windowless pythonw so no console pops up at logon.
    if os.name == "nt":
        cand = os.path.join(os.path.dirname(python), "pythonw.exe")
        if os.path.exists(cand):
            python = cand
    home = paths.root
    return f'"{python}" -m greyrun --home "{home}" monitor --mode {config.response_mode}'


def install(config: Config, paths: Paths) -> Tuple[bool, str]:
    if os.name != "nt":
        cmd = f'@reboot {sys.executable} -m greyrun --home "{paths.root}" monitor'
        return False, ("Automatic install is Windows-only. On this platform add a "
                       f"cron entry, e.g.:\n    {cmd}")
    tr = _monitor_command(config, paths)
    args = [
        "schtasks", "/Create", "/F",
        "/SC", "ONLOGON",
        "/TN", TASK_NAME,
        "/RL", "HIGHEST",
        "/TR", tr,
    ]
    try:
        proc = subprocess.run(args, capture_output=True, text=True)
    except FileNotFoundError:
        return False, "schtasks.exe not found (is this Windows?)."
    if proc.returncode == 0:
        return True, (f"Scheduled task '{TASK_NAME}' created. The monitor will start "
                      f"at your next logon.\n    Runs: {tr}")
    err = (proc.stderr or proc.stdout).strip()
    if "Access is denied" in err or proc.returncode == 1:
        return False, ("Access denied creating the scheduled task. Re-run this command "
                       "from an Administrator PowerShell/Command Prompt.")
    return False, f"schtasks failed ({proc.returncode}): {err}"


def uninstall() -> Tuple[bool, str]:
    if os.name != "nt":
        return False, "Nothing to uninstall on this platform (no scheduled task)."
    try:
        proc = subprocess.run(
            ["schtasks", "/Delete", "/F", "/TN", TASK_NAME],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return False, "schtasks.exe not found."
    if proc.returncode == 0:
        return True, f"Scheduled task '{TASK_NAME}' removed."
    err = (proc.stderr or proc.stdout).strip()
    if "cannot find" in err.lower() or "does not exist" in err.lower():
        return True, "No autostart task was installed."
    return False, f"schtasks failed ({proc.returncode}): {err}"


def status() -> str:
    if os.name != "nt":
        return "n/a (Windows-only autostart)"
    try:
        proc = subprocess.run(
            ["schtasks", "/Query", "/TN", TASK_NAME],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return "unknown (schtasks not found)"
    return "installed" if proc.returncode == 0 else "not installed"
