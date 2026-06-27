"""Console output: ANSI colour, levelled logging and a structured event log.

All user-facing output in GreyRun flows through this module so that colour
handling (including enabling virtual-terminal processing on Windows) and the
optional JSON-lines audit log live in exactly one place.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional, TextIO

# --- colour support ---------------------------------------------------------

_RESET = "\033[0m"
_COLORS = {
    "grey": "\033[90m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "bg_red": "\033[41m\033[97m",
    "bg_yellow": "\033[43m\033[30m",
}

_LOCK = threading.Lock()
_USE_COLOR = False
_AUDIT_FILE: Optional[str] = None


def _enable_windows_vt() -> bool:
    """Enable ANSI escape handling on legacy Windows consoles."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        for handle_id in (-11, -12):  # STDOUT, STDERR
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                continue
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        return True
    except Exception:
        return False


def _reconfigure_stdio() -> None:
    """Force UTF-8 output so box-drawing/check glyphs never crash the console.

    Windows consoles default to a legacy code page (e.g. cp1252) that cannot
    encode the characters GreyRun prints; we switch the code page to UTF-8 and
    reconfigure the streams with ``errors="replace"`` as a final safety net.
    """
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleOutputCP(65001)  # type: ignore[attr-defined]
            ctypes.windll.kernel32.SetConsoleCP(65001)  # type: ignore[attr-defined]
        except Exception:
            pass
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def init(force_color: Optional[bool] = None) -> None:
    """Initialise console colour handling. Call once at start-up."""
    global _USE_COLOR
    _reconfigure_stdio()
    if force_color is not None:
        _USE_COLOR = force_color
        if force_color:
            _enable_windows_vt()
        return
    if os.environ.get("NO_COLOR") is not None:
        _USE_COLOR = False
        return
    if not sys.stdout.isatty():
        _USE_COLOR = False
        return
    _USE_COLOR = _enable_windows_vt()


def paint(text: str, *colors: str) -> str:
    if not _USE_COLOR or not colors:
        return text
    prefix = "".join(_COLORS.get(c, "") for c in colors)
    return f"{prefix}{text}{_RESET}"


# --- structured audit log ---------------------------------------------------


def set_audit_log(path: Optional[str]) -> None:
    global _AUDIT_FILE
    _AUDIT_FILE = path


def audit(event: str, **fields) -> None:
    """Append one JSON object to the audit log (best effort, never raises)."""
    if not _AUDIT_FILE:
        return
    record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event}
    record.update(fields)
    try:
        with _LOCK:
            with open(_AUDIT_FILE, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
    except Exception:
        pass


# --- levelled console output ------------------------------------------------

_LEVELS = {
    "debug": ("grey", "·"),
    "info": ("cyan", "i"),
    "ok": ("green", "+"),
    "warn": ("yellow", "!"),
    "error": ("red", "x"),
    "alert": ("bg_yellow", "!"),
    "critical": ("bg_red", "*"),
}

_VERBOSE = False


def set_verbose(value: bool) -> None:
    global _VERBOSE
    _VERBOSE = value


def _stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def emit(level: str, message: str, *, stream: TextIO = sys.stdout) -> None:
    if level == "debug" and not _VERBOSE:
        return
    color, glyph = _LEVELS.get(level, ("white", " "))
    tag = paint(f" {glyph} ", color, "bold")
    stamp = paint(_stamp(), "grey")
    with _LOCK:
        print(f"{stamp} {tag} {message}", file=stream, flush=True)


def debug(msg: str) -> None:
    emit("debug", msg)


def info(msg: str) -> None:
    emit("info", msg)


def ok(msg: str) -> None:
    emit("ok", msg)


def warn(msg: str) -> None:
    emit("warn", msg, stream=sys.stderr)


def error(msg: str) -> None:
    emit("error", msg, stream=sys.stderr)


def alert(msg: str) -> None:
    emit("alert", msg, stream=sys.stderr)


def critical(msg: str) -> None:
    emit("critical", msg, stream=sys.stderr)


def plain(msg: str = "") -> None:
    with _LOCK:
        print(msg, flush=True)


def rule(label: str = "") -> None:
    width = 64
    if label:
        label = f" {label} "
        dashes = max(0, width - len(label))
        left = dashes // 2
        line = "─" * left + label + "─" * (dashes - left)
    else:
        line = "─" * width
    plain(paint(line, "grey"))


def banner() -> None:
    from . import __app_name__, __tagline__, __version__

    art = r"""
   ____               ____
  / ___|_ __ ___ _   _|  _ \ _   _ _ __
 | |  _| '__/ _ \ | | | |_) | | | | '_ \
 | |_| | | |  __/ |_| |  _ <| |_| | | | |
  \____|_|  \___|\__, |_| \_\\__,_|_| |_|
                 |___/
"""
    plain(paint(art, "cyan", "bold"))
    plain(paint(f"  {__app_name__} v{__version__} — {__tagline__}", "white"))
    plain(paint("  Defensive use only. Protect what matters.", "grey"))
    plain("")


def confirm(prompt: str, default: bool = False) -> bool:
    """Yes/no prompt. Returns ``default`` if input is not a TTY."""
    if not sys.stdin.isatty():
        return default
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        answer = input(paint("?", "yellow", "bold") + " " + prompt + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        plain("")
        return default
    if not answer:
        return default
    return answer in ("y", "yes")


class Spinner:
    """A tiny background spinner for long operations (no dependencies)."""

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, message: str):
        self.message = message
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._enabled = _USE_COLOR and sys.stdout.isatty()

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            with _LOCK:
                sys.stdout.write("\r" + paint(frame, "cyan") + " " + self.message + " ")
                sys.stdout.flush()
            i += 1
            time.sleep(0.08)

    def __enter__(self) -> "Spinner":
        if self._enabled:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        else:
            info(self.message)
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
            with _LOCK:
                sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r")
                sys.stdout.flush()
