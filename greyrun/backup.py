"""Protected backup vault.

Backups are the ultimate answer to ransomware: if you can restore, you do not
pay. GreyRun keeps a *content-addressed* vault under ``~/.greyrun/vault`` --
each unique file body is stored once under its SHA-256, and every snapshot is
just a manifest of references. Repeated snapshots of a mostly-unchanged tree
therefore cost almost nothing, and stored blobs are marked read-only.

The vault is meant to live on a separate or external volume (point
``GREYRUN_HOME`` at it). It is not a substitute for true offline/immutable
backups, but it gives a fast local rollback after an incident.
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
    snap_id = utils.iso().replace(":", "").replace("-", "").replace("+0000", "Z")
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
    snap_dir = _snapshots_dir(paths)
    with open(os.path.join(snap_dir, f"{snap_id}.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=0)

    return SnapshotInfo(
        id=snap_id,
        created=manifest["created"],
        file_count=count,
        total_size=total,
        deduped_size=deduped,
    )


def list_snapshots(paths: Paths) -> List[SnapshotInfo]:
    snap_dir = _snapshots_dir(paths)
    out: List[SnapshotInfo] = []
    for name in sorted(os.listdir(snap_dir)):
        if not name.endswith(".json"):
            continue
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


def _load_manifest(paths: Paths, snapshot_id: str) -> Optional[dict]:
    snap_dir = _snapshots_dir(paths)
    candidate = os.path.join(snap_dir, f"{snapshot_id}.json")
    if os.path.exists(candidate):
        with open(candidate, "r", encoding="utf-8") as fh:
            return json.load(fh)
    # Allow "latest" and prefix matches.
    snaps = sorted(n for n in os.listdir(snap_dir) if n.endswith(".json"))
    if not snaps:
        return None
    if snapshot_id in ("latest", "last"):
        chosen = snaps[-1]
    else:
        match = [n for n in snaps if n.startswith(snapshot_id)]
        if not match:
            return None
        chosen = match[0]
    with open(os.path.join(snap_dir, chosen), "r", encoding="utf-8") as fh:
        return json.load(fh)


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
    directory instead -- the safest option after an active incident.
    """
    manifest = _load_manifest(paths, snapshot_id)
    if manifest is None:
        return None
    restored = skipped = failed = 0
    dest_root = utils.normpath(into) if into else None

    for f in manifest.get("files", []):
        obj = _object_path(paths, f["sha256"])
        if not os.path.exists(obj):
            failed += 1
            continue
        if dest_root:
            target = os.path.join(dest_root, f.get("rel") or os.path.basename(f["path"]))
        else:
            target = f["path"]
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
