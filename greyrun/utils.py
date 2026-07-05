"""Filesystem and formatting helpers shared across GreyRun."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator, List, Optional, Sequence

# Directories we never descend into: noisy, volatile, or owned by GreyRun.
DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".greyrun",
    "node_modules",
    "__pycache__",
    "$RECYCLE.BIN",
    "System Volume Information",
    ".venv",
    "venv",
    "AppData",
}


def now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


def iso(ts: Optional[float] = None) -> str:
    if ts is None:
        ts = now_ts()
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def stamp_id(ts: Optional[float] = None) -> str:
    """Filesystem-safe UTC timestamp ID (1s resolution), e.g. 20260705T175248Z."""
    return iso(ts).replace(":", "").replace("-", "").replace("+0000", "Z")


def claim_unique_id(base_id: str, claim: Callable[[str], bool]) -> str:
    """Return the first of ``base_id``, ``base_id-02``, ``base_id-03``, … that
    ``claim`` takes ownership of.

    ``claim`` must create the ID's file/directory atomically (O_EXCL open or
    mkdir) and return False on a collision, so two same-second writers -- even
    in separate processes -- can never claim the same ID. Zero-padding keeps
    suffixed IDs in lexical == chronological order (up to 99 per second)."""
    candidate, n = base_id, 1
    while not claim(candidate):
        n += 1
        candidate = f"{base_id}-{n:02d}"
    return candidate


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:.0f}{unit}" if unit == "B" else f"{num:.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}PB"


def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def normpath(path: str) -> str:
    """Absolute, normalised path. Case is preserved but comparisons should
    use :func:`same_path` / :func:`is_within` which fold case on Windows."""
    return os.path.normpath(os.path.abspath(os.path.expanduser(path)))


def _fold(path: str) -> str:
    return os.path.normcase(normpath(path))


def same_path(a: str, b: str) -> bool:
    return _fold(a) == _fold(b)


def is_within(path: str, roots: Sequence[str]) -> bool:
    """True if ``path`` is equal to or inside any of ``roots``.

    The root's trailing separator is stripped before comparison so a drive
    root (``C:\\``) or filesystem root (``/``) -- the one path ``normpath``
    keeps a trailing separator on -- still contains its children. Without this
    a whole-drive watch would match nothing and silently disable detection.
    """
    target = _fold(path)
    for root in roots:
        r = _fold(root).rstrip(os.sep)  # 'c:\\' -> 'c:', '/' -> ''
        if target == r or target == r + os.sep:
            return True
        if target.startswith(r + os.sep):
            return True
    return False


def iter_files(
    roots: Iterable[str],
    exclude_dirs: Optional[Iterable[str]] = None,
    follow_symlinks: bool = False,
    max_files: Optional[int] = None,
) -> Iterator[str]:
    """Yield absolute file paths under ``roots``.

    Symlinks/junctions are skipped by default to avoid escaping the protected
    tree or looping. Excluded directory *names* are pruned at every level.
    """
    excluded = {e.lower() for e in (exclude_dirs or DEFAULT_EXCLUDE_DIRS)}
    seen = 0
    for root in roots:
        root = normpath(root)
        if not os.path.exists(root):
            continue
        if os.path.isfile(root):
            yield root
            seen += 1
            if max_files and seen >= max_files:
                return
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
            dirnames[:] = [
                d
                for d in dirnames
                if d.lower() not in excluded
                and (follow_symlinks or not os.path.islink(os.path.join(dirpath, d)))
            ]
            for name in filenames:
                full = os.path.join(dirpath, name)
                if not follow_symlinks and os.path.islink(full):
                    continue
                yield full
                seen += 1
                if max_files and seen >= max_files:
                    return


def sha256_file(path: str, chunk: int = 1 << 20, max_bytes: Optional[int] = None) -> Optional[str]:
    """SHA-256 of a file. If ``max_bytes`` is set, only that prefix is hashed
    (used for very large files where a prefix digest is sufficient for change
    detection). Returns ``None`` if the file cannot be read."""
    h = hashlib.sha256()
    read = 0
    try:
        with open(path, "rb") as fh:
            while True:
                want = chunk
                if max_bytes is not None:
                    want = min(chunk, max_bytes - read)
                    if want <= 0:
                        break
                block = fh.read(want)
                if not block:
                    break
                h.update(block)
                read += len(block)
    except (OSError, PermissionError):
        return None
    return h.hexdigest()


def read_sample(path: str, size: int = 262_144) -> Optional[bytes]:
    """Read up to ``size`` bytes from the start of a file (for entropy)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except (OSError, PermissionError):
        return None


def safe_stat(path: str):
    try:
        return os.stat(path)
    except (OSError, PermissionError):
        return None


def file_ext(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def short_path(path: str, max_len: int = 60) -> str:
    if len(path) <= max_len:
        return path
    head = path[: max_len // 2 - 2]
    tail = path[-max_len // 2 + 1 :]
    return f"{head}…{tail}"


def count_files(roots: Sequence[str], exclude_dirs: Optional[Iterable[str]] = None) -> int:
    return sum(1 for _ in iter_files(roots, exclude_dirs))
