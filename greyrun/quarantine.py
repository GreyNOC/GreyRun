"""Quarantine: move ransomware artifacts out of protected folders.

In-place lockdown (marking files read-only) stops further encryption but leaves
the attacker's output (``.locked`` files and ransom notes) scattered through the
user's folders. Quarantine moves those detected artifacts into a holding area
under the GreyRun vault and records where each came from, so the move can be
reversed if it was a false alarm.

Only files that look like attack artifacts are moved:

* files carrying a known ransomware extension,
* files whose name matches a ransom-note pattern, and (optionally)
* document-class files that now read as encrypted.

Ordinary files are not touched.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from typing import List, Optional

from . import utils
from .config import Config, Paths
from .entropy import is_document_class, looks_encrypted
from .signatures import is_ransom_note, is_ransomware_ext


def _set_readonly(path: str, on: bool = True) -> None:
    try:
        if os.name == "nt":
            import ctypes

            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x01 if on else 0x80)
        else:
            os.chmod(path, 0o444 if on else 0o644)
    except Exception:
        pass


def is_artifact(path: str, include_encrypted: bool = True) -> Optional[str]:
    """Return a reason string if ``path`` looks like a ransomware artifact."""
    if is_ransomware_ext(path):
        return "ransomware extension"
    if is_ransom_note(path):
        return "ransom note"
    if include_encrypted and is_document_class(path) and looks_encrypted(path):
        return "document looks encrypted"
    return None


def find_artifacts(config: Config, include_encrypted: bool = True) -> List[tuple]:
    """Scan the watched tree for artifacts. Returns ``(path, reason)`` pairs."""
    found = []
    for path in utils.iter_files(config.watched_paths, config.exclude_dirs):
        reason = is_artifact(path, include_encrypted)
        if reason:
            found.append((path, reason))
    return found


@dataclass
class QuarantineResult:
    batch_id: str
    moved: int
    failed: int
    manifest: Optional[str]


def quarantine_files(paths: Paths, items: List[tuple],
                     roots: Optional[List[str]] = None) -> QuarantineResult:
    """Move ``(path, reason)`` items into a new quarantine batch.

    Files are stored under ``vault/../quarantine/<batch>/files`` with a manifest
    mapping the stored copy back to its original location. Moved files are made
    read-only so a surviving process cannot keep using them. ``roots`` (the
    watched paths) is recorded so restore can refuse to write outside them.
    """
    batch_id = utils.iso().replace(":", "").replace("-", "").replace("+0000", "Z")
    batch_dir = os.path.join(paths.quarantine, batch_id)
    files_dir = utils.ensure_dir(os.path.join(batch_dir, "files"))
    manifest_entries = []
    moved = failed = 0

    for index, (src, reason) in enumerate(items):
        if not os.path.exists(src):
            continue
        stored_name = f"{index:05d}_{os.path.basename(src)}"
        dest = os.path.join(files_dir, stored_name)
        try:
            # Clear attributes so we can move the file, then move + lock.
            _set_readonly(src, on=False)
            shutil.move(src, dest)
            _set_readonly(dest, on=True)
            manifest_entries.append(
                {"original": src, "stored": stored_name, "reason": reason,
                 "quarantined": utils.iso()}
            )
            moved += 1
        except (OSError, shutil.Error):
            failed += 1

    manifest_path = None
    if manifest_entries:
        manifest_path = os.path.join(batch_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "id": batch_id,
                    "created": utils.iso(),
                    "roots": [utils.normpath(r) for r in (roots or [])],
                    "files": manifest_entries,
                },
                fh, indent=2,
            )
    return QuarantineResult(batch_id, moved, failed, manifest_path)


@dataclass
class QuarantineBatch:
    id: str
    created: str
    count: int


def list_batches(paths: Paths) -> List[QuarantineBatch]:
    root = paths.quarantine
    if not os.path.isdir(root):
        return []
    out = []
    for name in sorted(os.listdir(root)):
        manifest = os.path.join(root, name, "manifest.json")
        if not os.path.exists(manifest):
            continue
        try:
            with open(manifest, "r", encoding="utf-8") as fh:
                m = json.load(fh)
        except Exception:
            continue
        out.append(QuarantineBatch(m["id"], m.get("created", "?"), len(m.get("files", []))))
    return out


def _resolve_batch(paths: Paths, batch_id: str) -> Optional[str]:
    root = paths.quarantine
    if not os.path.isdir(root):
        return None
    batches = sorted(
        n for n in os.listdir(root)
        if os.path.exists(os.path.join(root, n, "manifest.json"))
    )
    if not batches:
        return None
    if batch_id in ("latest", "last"):
        return batches[-1]
    if batch_id in batches:
        return batch_id
    match = [b for b in batches if b.startswith(batch_id)]
    return match[0] if match else None


@dataclass
class RestoreQuarantineResult:
    restored: int
    skipped: int
    failed: int


def restore_batch(paths: Paths, batch_id: str, overwrite: bool = False) -> Optional[RestoreQuarantineResult]:
    """Move a quarantined batch back to the original file locations."""
    resolved = _resolve_batch(paths, batch_id)
    if resolved is None:
        return None
    batch_dir = os.path.join(paths.quarantine, resolved)
    with open(os.path.join(batch_dir, "manifest.json"), "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    restored = skipped = failed = 0
    files_root = os.path.join(batch_dir, "files")
    roots = [utils.normpath(r) for r in manifest.get("roots", [])]
    for entry in manifest.get("files", []):
        # Untrusted manifest: keep 'stored' inside the batch, refuse a
        # traversal/relative 'original', and refuse any destination outside the
        # recorded watched roots (write-anywhere guard).
        stored_name = os.path.basename(entry.get("stored", ""))
        stored = os.path.join(files_root, stored_name)
        raw_original = str(entry.get("original", ""))
        target = utils.normpath(raw_original)
        if not os.path.isabs(raw_original) or ".." in raw_original.replace("\\", "/").split("/"):
            failed += 1
            continue
        if roots and not utils.is_within(target, roots):
            failed += 1  # outside the recorded watched roots -> refuse
            continue
        if not os.path.exists(stored):
            failed += 1
            continue
        if os.path.exists(target) and not overwrite:
            skipped += 1
            continue
        try:
            utils.ensure_dir(os.path.dirname(target))
            _set_readonly(stored, on=False)
            shutil.move(stored, target)
            _set_readonly(target, on=False)
            restored += 1
        except (OSError, shutil.Error):
            failed += 1
    return RestoreQuarantineResult(restored, skipped, failed)
