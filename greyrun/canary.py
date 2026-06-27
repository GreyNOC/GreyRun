"""Canary (honeypot) files.

A canary is a decoy file planted in a protected directory. It is never opened
or modified by any legitimate workflow, so *any* change, rename or deletion of
a canary is a near-certain sign that something is sweeping the directory and
encrypting files -- usually ransomware. Because attackers commonly enumerate a
folder in name order, GreyRun gives canaries names that sort to the very front
and very back of a listing so they are among the first and last things hit.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import utils
from .config import Config, Paths

# Decoy names chosen to (a) look valuable to an attacker and (b) sit at the
# alphabetical extremes of a directory listing.
CANARY_NAMES = [
    "00__account_backup.xlsx",
    "0_master_keyfile.txt",
    "01_password_vault_export.docx",
    "~$financial_statements.xlsx",
    "zzz_payroll_records_2025.csv",
]

# A realistic-looking, low-entropy body so that if it *is* encrypted, the
# entropy jump is also visible. Content is static -> stable hash.
_CANARY_BODY = (
    "CONFIDENTIAL - INTERNAL USE ONLY\r\n"
    "Quarterly reconciliation worksheet\r\n"
    "Account,Holder,Routing,Balance,Updated\r\n"
    + "".join(
        f"{1000+i:06d},Employee_{i:03d},021000021,{(i*137)%99999}.{i%100:02d},2025-01-15\r\n"
        for i in range(240)
    )
)

_HIDDEN = 0x02  # FILE_ATTRIBUTE_HIDDEN


def _set_hidden(path: str) -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.kernel32.SetFileAttributesW(str(path), _HIDDEN)  # type: ignore[attr-defined]
    except Exception:
        pass


def _clear_hidden(path: str) -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x80)  # NORMAL
    except Exception:
        pass


@dataclass
class CanaryStatus:
    path: str
    state: str  # "ok" | "modified" | "missing"


def _registry_load(paths: Paths) -> Dict[str, dict]:
    if not os.path.exists(paths.canaries):
        return {}
    try:
        with open(paths.canaries, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _registry_save(paths: Paths, registry: Dict[str, dict]) -> None:
    paths.ensure()
    tmp = paths.canaries + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(registry, fh, indent=2)
    os.replace(tmp, paths.canaries)


def load_paths(paths: Paths) -> List[str]:
    """Return just the set of canary file paths (for fast membership tests)."""
    return list(_registry_load(paths).keys())


def deploy(config: Config, paths: Paths) -> Tuple[int, int]:
    """Plant canaries in every watched directory.

    Returns ``(created, skipped)``. Existing canaries are preserved.
    """
    registry = _registry_load(paths)
    created = 0
    skipped = 0
    n = max(1, min(config.canaries_per_dir, len(CANARY_NAMES)))
    body = _CANARY_BODY.encode("utf-8")
    import hashlib

    body_digest = hashlib.sha256(body).hexdigest()

    for root in config.watched_paths:
        root = utils.normpath(root)
        if not os.path.isdir(root):
            continue
        for name in CANARY_NAMES[:n]:
            target = os.path.join(root, name)
            if target in registry and os.path.exists(target):
                skipped += 1
                continue
            try:
                with open(target, "wb") as fh:
                    fh.write(body)
                _set_hidden(target)
            except OSError:
                continue
            st = utils.safe_stat(target)
            registry[target] = {
                "sha256": body_digest,
                "size": len(body),
                "mtime": st.st_mtime if st else 0.0,
                "created": utils.iso(),
            }
            created += 1
    _registry_save(paths, registry)
    return created, skipped


def _canary_state(path: str, meta: dict) -> str:
    """Return 'ok' | 'modified' | 'missing' for one canary.

    Size is checked first, so an *append* or *truncate* (which a prefix-only
    hash would miss) is caught without reading the file; only when the size is
    unchanged do we hash the full content to detect in-place edits."""
    if not os.path.exists(path):
        return "missing"
    try:
        size = os.path.getsize(path)
    except OSError:
        return "modified"
    if size != meta.get("size"):
        return "modified"  # appended/truncated -> tampered
    import hashlib

    data = utils.read_sample(path, meta["size"])  # size matches -> whole file
    if data is None:
        return "modified"
    return "ok" if hashlib.sha256(data).hexdigest() == meta.get("sha256") else "modified"


def verify(paths: Paths) -> List[CanaryStatus]:
    """Check every registered canary's integrity."""
    registry = _registry_load(paths)
    return [CanaryStatus(path, _canary_state(path, meta)) for path, meta in registry.items()]


def check_one(path: str, registry: Dict[str, dict]) -> Optional[str]:
    """Fast single-file check used by the live monitor. Returns the bad state
    ("modified"/"missing") or ``None`` if the canary is intact / not a canary."""
    meta = registry.get(path)
    if meta is None:
        return None
    state = _canary_state(path, meta)
    return None if state == "ok" else state


def registry(paths: Paths) -> Dict[str, dict]:
    return _registry_load(paths)


def clear(config: Config, paths: Paths) -> int:
    """Remove all canary files and the registry."""
    reg = _registry_load(paths)
    removed = 0
    for path in list(reg.keys()):
        try:
            if os.path.exists(path):
                _clear_hidden(path)
                os.remove(path)
            removed += 1
        except OSError:
            pass
    try:
        if os.path.exists(paths.canaries):
            os.remove(paths.canaries)
    except OSError:
        pass
    return removed
