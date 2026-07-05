"""Content-addressed backup vault.

GreyRun keeps a content-addressed vault under ``~/.greyrun/vault``: each unique
file body is stored once under its SHA-256, and every snapshot is a manifest of
references, so repeated snapshots of a mostly-unchanged tree cost little. Stored
blobs are marked read-only.

Point ``GREYRUN_HOME`` at a separate or external volume to keep the vault off
the protected disk. This is a fast local rollback, not a substitute for
offline/immutable backups.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from typing import Callable, List, Optional

from . import utils
from .config import Config, Paths


@dataclass
class SnapshotInfo:
    id: str
    created: str
    file_count: int
    total_size: int
    deduped_size: int


def _objects_dir(paths: Paths) -> str:
    return utils.ensure_dir(os.path.join(paths.vault, "objects"))


def _snapshots_dir(paths: Paths) -> str:
    return utils.ensure_dir(os.path.join(paths.vault, "snapshots"))


def _object_path(paths: Paths, digest: str) -> str:
    sub = os.path.join(_objects_dir(paths), digest[:2])
    utils.ensure_dir(sub)
    return os.path.join(sub, digest)


def _set_readonly(path: str) -> None:
    try:
        if os.name == "nt":
            import ctypes

            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x01)  # READONLY
        else:
            os.chmod(path, 0o444)
    except Exception:
        pass


def create_snapshot(
    config: Config,
    paths: Paths,
    progress: Optional[Callable[[int, str], None]] = None,
) -> SnapshotInfo:
    """Back up every watched file into a new content-addressed snapshot."""
    paths.ensure()
    snap_dir = _snapshots_dir(paths)

    def _claim(candidate: str) -> bool:
        try:
            # O_EXCL create is the atomic claim: two same-second snapshot runs
            # (even in separate processes) cannot take the same manifest name.
            with open(os.path.join(snap_dir, f"{candidate}.json"), "x", encoding="utf-8"):
                return True
        except FileExistsError:
            return False

    snap_id = utils.claim_unique_id(utils.stamp_id(), _claim)
    files_meta: List[dict] = []
    total = 0
    deduped = 0
    count = 0

    # Never back up GreyRun's own state directory.
    own = utils.normpath(paths.root)

    for path in utils.iter_files(config.watched_paths, config.exclude_dirs):
        if utils.is_within(path, [own]):
            continue
        st = utils.safe_stat(path)
        if st is None:
            continue
        digest = utils.sha256_file(path)
        if digest is None:
            continue
        obj = _object_path(paths, digest)
        total += st.st_size
        if not os.path.exists(obj):
            try:
                tmp = obj + ".tmp"
                shutil.copy2(path, tmp)
                os.replace(tmp, obj)
                _set_readonly(obj)
                deduped += st.st_size
            except OSError:
                continue
        # Which watched root does this file belong to?
        root = next(
            (r for r in config.watched_paths if utils.is_within(path, [r])),
            os.path.dirname(path),
        )
        files_meta.append(
            {
                "path": path,
                "root": utils.normpath(root),
                "rel": os.path.relpath(path, utils.normpath(root)),
                "sha256": digest,
                "size": st.st_size,
                "mtime": st.st_mtime,
            }
        )
        count += 1
        if progress and count % 25 == 0:
            progress(count, path)
    if progress:
        progress(count, "")

    manifest = {
        "id": snap_id,
        "created": utils.iso(),
        "roots": list(config.watched_paths),
        "files": files_meta,
    }
    with open(os.path.join(snap_dir, f"{snap_id}.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=0)

    return SnapshotInfo(
        id=snap_id,
        created=manifest["created"],
        file_count=count,
        total_size=total,
        deduped_size=deduped,
    )


def _sorted_manifest_names(snap_dir: str) -> List[str]:
    """Manifest filenames in id (stem) order. Sorting whole filenames would
    put a same-second '<id>-02.json' *before* '<id>.json' ('-' < '.'), making
    'latest' resolve to the older snapshot."""
    return sorted(
        (n for n in os.listdir(snap_dir) if n.endswith(".json")),
        key=lambda n: n[: -len(".json")],
    )


def list_snapshots(paths: Paths) -> List[SnapshotInfo]:
    snap_dir = _snapshots_dir(paths)
    out: List[SnapshotInfo] = []
    for name in _sorted_manifest_names(snap_dir):
        try:
            with open(os.path.join(snap_dir, name), "r", encoding="utf-8") as fh:
                m = json.load(fh)
        except Exception:
            continue
        total = sum(f["size"] for f in m.get("files", []))
        out.append(
            SnapshotInfo(
                id=m["id"],
                created=m.get("created", "?"),
                file_count=len(m.get("files", [])),
                total_size=total,
                deduped_size=0,
            )
        )
    return out


def _read_manifest(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None  # unreadable/partial manifest (e.g. interrupted snapshot)


def _load_manifest(paths: Paths, snapshot_id: str) -> Optional[dict]:
    snap_dir = _snapshots_dir(paths)
    candidate = os.path.join(snap_dir, f"{snapshot_id}.json")
    if os.path.exists(candidate):
        return _read_manifest(candidate)
    # Allow "latest" and prefix matches.
    snaps = _sorted_manifest_names(snap_dir)
    if not snaps:
        return None
    if snapshot_id in ("latest", "last"):
        chosen = snaps[-1]
    else:
        match = [n for n in snaps if n.startswith(snapshot_id)]
        if not match:
            return None
        chosen = match[0]
    return _read_manifest(os.path.join(snap_dir, chosen))


@dataclass
class RestoreResult:
    restored: int
    skipped: int
    failed: int
    dest_root: Optional[str]


def restore(
    paths: Paths,
    snapshot_id: str,
    into: Optional[str] = None,
    overwrite: bool = False,
) -> Optional[RestoreResult]:
    """Restore files from a snapshot.

    By default files go back to their original locations, but only if missing
    (use ``overwrite=True`` to replace). Pass ``into`` to restore into a fresh
    directory instead, the safest option after an active incident.
    """
    manifest = _load_manifest(paths, snapshot_id)
    if manifest is None:
        return None
    restored = skipped = failed = 0
    dest_root = utils.normpath(into) if into else None
    roots = [utils.normpath(r) for r in manifest.get("roots", [])]

    for f in manifest.get("files", []):
        obj = _object_path(paths, f["sha256"])
        if not os.path.exists(obj):
            failed += 1
            continue
        # Treat the manifest as untrusted: never let a crafted path escape the
        # restore root (write-anywhere guard, important under elevated runs).
        if dest_root:
            rel = f.get("rel") or os.path.basename(f["path"])
            if os.path.isabs(rel) or ".." in rel.replace("\\", "/").split("/"):
                failed += 1
                continue
            target = utils.normpath(os.path.join(dest_root, rel))
            if not utils.is_within(target, [dest_root]):
                failed += 1
                continue
        else:
            target = utils.normpath(f["path"])
            if roots and not utils.is_within(target, roots):
                failed += 1  # outside the snapshot's recorded roots -> refuse
                continue
        if os.path.exists(target) and not overwrite:
            skipped += 1
            continue
        try:
            utils.ensure_dir(os.path.dirname(target))
            # Clear read-only on an existing target before overwriting.
            if os.path.exists(target):
                try:
                    if os.name == "nt":
                        import ctypes

                        ctypes.windll.kernel32.SetFileAttributesW(str(target), 0x80)
                    else:
                        os.chmod(target, 0o644)
                except Exception:
                    pass
            shutil.copy2(obj, target)
            try:  # restored copies should be writable
                if os.name == "nt":
                    import ctypes

                    ctypes.windll.kernel32.SetFileAttributesW(str(target), 0x80)
                else:
                    os.chmod(target, 0o644)
            except Exception:
                pass
            restored += 1
        except OSError:
            failed += 1
    return RestoreResult(restored, skipped, failed, dest_root)
