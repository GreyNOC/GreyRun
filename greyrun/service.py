"""Autostart -- run the GreyRun monitor automatically at logon.

Two mechanisms are supported on Windows:

* **Scheduled task** (`task`) -- triggered at logon and, when installed from an
  elevated console, runs with highest privileges so the responder can act on
  processes it does not own. Creating it needs an Administrator shell.
* **Startup folder** (`startup`) -- a tiny launcher dropped in the user's
  Startup folder. Needs no admin rights, but the monitor then runs at normal
  integrity (fine for detection/alerting; weaker for killing other users'
  processes).

``enable`` picks the scheduled task when run elevated and otherwise falls back
to the Startup-folder method, so autostart can always be set up. On non-Windows
platforms we print a ready-to-use cron line instead.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import List, Tuple

from .config import Config, Paths

TASK_NAME = "GreyRunMonitor"
STARTUP_FILENAME = "GreyRunMonitor.vbs"


def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def _python_exe(windowless: bool = False) -> str:
    python = sys.executable or "python"
    if windowless and os.name == "nt":
        cand = os.path.join(os.path.dirname(python), "pythonw.exe")
        if os.path.exists(cand):
            return cand
    return python


def _monitor_command(config: Config, paths: Paths, windowless: bool = False) -> str:
    """The command autostart runs, fully quoted."""
    python = _python_exe(windowless)
    return f'"{python}" -m greyrun --home "{paths.root}" monitor --mode {config.response_mode}'


# --------------------------------------------------------------------------- #
#  Scheduled task (elevated)
# --------------------------------------------------------------------------- #


def install_task(config: Config, paths: Paths) -> Tuple[bool, str]:
    if os.name != "nt":
        cmd = f'@reboot {sys.executable} -m greyrun --home "{paths.root}" monitor'
        return False, (f"Scheduled task is Windows-only. On this platform add cron:\n    {cmd}")
    tr = _monitor_command(config, paths)
    args = ["schtasks", "/Create", "/F", "/SC", "ONLOGON", "/TN", TASK_NAME, "/RL", "HIGHEST", "/TR", tr]
    try:
        proc = subprocess.run(args, capture_output=True, text=True)
    except FileNotFoundError:
        return False, "schtasks.exe not found (is this Windows?)."
    if proc.returncode == 0:
        return True, (f"Scheduled task '{TASK_NAME}' created (runs elevated at logon).\n    {tr}")
    err = (proc.stderr or proc.stdout).strip()
    if "Access is denied" in err or proc.returncode == 1:
        return False, "Access denied — creating an elevated task needs an Administrator shell."
    return False, f"schtasks failed ({proc.returncode}): {err}"


def uninstall_task() -> Tuple[bool, str]:
    if os.name != "nt":
        return True, "No scheduled task on this platform."
    try:
        proc = subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME],
                              capture_output=True, text=True)
    except FileNotFoundError:
        return False, "schtasks.exe not found."
    if proc.returncode == 0:
        return True, f"Removed scheduled task '{TASK_NAME}'."
    err = (proc.stderr or proc.stdout).strip().lower()
    if "cannot find" in err or "does not exist" in err:
        return True, "No scheduled task was installed."
    return False, f"schtasks failed ({proc.returncode})."


def _task_installed() -> bool:
    if os.name != "nt":
        return False
    try:
        proc = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME],
                              capture_output=True, text=True)
        return proc.returncode == 0
    except FileNotFoundError:
        return False


# --------------------------------------------------------------------------- #
#  Startup folder (no admin)
# --------------------------------------------------------------------------- #


def _startup_dir() -> str:
    return os.path.join(os.environ.get("APPDATA", ""),
                        "Microsoft", "Windows", "Start Menu", "Programs", "Startup")


def startup_file() -> str:
    return os.path.join(_startup_dir(), STARTUP_FILENAME)


def install_startup(config: Config, paths: Paths) -> Tuple[bool, str]:
    if os.name != "nt":
        return False, "Startup-folder autostart is Windows-only."
    # The home path is interpolated into a WScript .Run command line; a quote
    # or newline could break out of the quoted argument. Refuse such paths.
    if '"' in paths.root or "\r" in paths.root or "\n" in paths.root:
        return False, "Refusing autostart: state-dir path contains an illegal character (\" or newline)."
    target = startup_file()
    cmd = _monitor_command(config, paths, windowless=True)
    # Inside a VBScript string literal each double-quote must be doubled.
    vbs_cmd = cmd.replace('"', '""')
    body = (
        "' GreyRun autostart launcher (auto-generated). Delete to disable.\r\n"
        'Set sh = CreateObject("WScript.Shell")\r\n'
        f'sh.Run "{vbs_cmd}", 0, False\r\n'  # 0 = hidden window, False = don't wait
    )
    try:
        os.makedirs(_startup_dir(), exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(body)
    except OSError as exc:
        return False, f"Could not write startup launcher: {exc}"
    return True, (f"Startup launcher installed (runs hidden at logon, no admin):\n    {target}")


def uninstall_startup() -> Tuple[bool, str]:
    if os.name != "nt":
        return True, "No startup launcher on this platform."
    target = startup_file()
    if os.path.exists(target):
        try:
            os.remove(target)
            return True, "Removed startup launcher."
        except OSError as exc:
            return False, f"Could not remove startup launcher: {exc}"
    return True, "No startup launcher was installed."


def _startup_installed() -> bool:
    return os.name == "nt" and os.path.exists(startup_file())


# --------------------------------------------------------------------------- #
#  Combined façade
# --------------------------------------------------------------------------- #


def uninstall_all() -> List[Tuple[bool, str]]:
    return [uninstall_task(), uninstall_startup()]


def status() -> str:
    if os.name != "nt":
        return "n/a (Windows-only autostart)"
    task = "installed" if _task_installed() else "not installed"
    startup = "installed" if _startup_installed() else "not installed"
    return f"scheduled task: {task}  ·  startup folder: {startup}"
