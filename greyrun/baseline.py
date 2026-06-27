"""File-integrity baseline.

A baseline is a manifest of every protected file's size, mtime, SHA-256 and
head-entropy at a known-good point in time. Comparing the live filesystem to
the baseline reveals exactly which files changed, were added, or were deleted
-- the raw material for both on-demand scanning and post-incident triage.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import utils
from .config import Config, Paths
from .entropy import file_entropy


@dataclass
class FileRecord:
    size: int
    mtime: float
    sha256: Optional[str]
    entropy: Optional[float]
    partial: bool = False  # True if sha256 covers only a prefix of a big file

    def to_json(self) -> dict:
        return {
            "size": self.size,
            "mtime": round(self.mtime, 3),
            "sha256": self.sha256,
            "entropy": round(self.entropy, 4) if self.entropy is not None else None,
            "partial": self.partial,
        }

    @classmethod
    def from_json(cls, data: dict) -> "FileRecord":
        return cls(
            size=data["size"],
            mtime=data["mtime"],
            sha256=data.get("sha256"),
            entropy=data.get("entropy"),
            partial=data.get("partial", False),
        )


@dataclass
class Baseline:
    created: str
    roots: List[str]
    files: Dict[str, FileRecord] = field(default_factory=dict)

    # --- construction ---
    @classmethod
    def build(
        cls,
        config: Config,
        progress: Optional[Callable[[int, str], None]] = None,
    ) -> "Baseline":
        roots = list(config.watched_paths)
        files: Dict[str, FileRecord] = {}
        count = 0
        for path in utils.iter_files(roots, config.exclude_dirs):
            st = utils.safe_stat(path)
            if st is None:
                continue
            partial = st.st_size > config.max_hash_bytes
            digest = utils.sha256_file(
                path, max_bytes=config.max_hash_bytes if partial else None
            )
            files[path] = FileRecord(
                size=st.st_size,
                mtime=st.st_mtime,
                sha256=digest,
                entropy=file_entropy(path),
                partial=partial,
            )
            count += 1
            if progress and count % 50 == 0:
                progress(count, path)
        if progress:
            progress(count, "")
        return cls(created=utils.iso(), roots=roots, files=files)

    # --- persistence ---
    def save(self, paths: Paths) -> None:
        paths.ensure()
        payload = {
            "created": self.created,
            "roots": self.roots,
            "files": {p: r.to_json() for p, r in self.files.items()},
        }
        tmp = paths.baseline + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=0)
        os.replace(tmp, paths.baseline)

    @classmethod
    def load(cls, paths: Paths) -> Optional["Baseline"]:
        if not os.path.exists(paths.baseline):
            return None
        try:
            with open(paths.baseline, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None
        files = {p: FileRecord.from_json(r) for p, r in data.get("files", {}).items()}
        return cls(created=data.get("created", "?"), roots=data.get("roots", []), files=files)

    def __len__(self) -> int:
        return len(self.files)


@dataclass
class Diff:
    """Structural difference between a baseline and the current filesystem."""

    added: List[str] = field(default_factory=list)
    deleted: List[str] = field(default_factory=list)
    modified: List[str] = field(default_factory=list)
    unchanged: int = 0

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.deleted) + len(self.modified)


def diff_current(baseline: Baseline, config: Config) -> Diff:
    """Compare ``baseline`` to the live filesystem under the watched roots."""
    result = Diff()
    seen = set()
    for path in utils.iter_files(config.watched_paths, config.exclude_dirs):
        seen.add(path)
        old = baseline.files.get(path)
        st = utils.safe_stat(path)
        if st is None:
            continue
        if old is None:
            result.added.append(path)
            continue
        # Cheap check first: size/mtime. Confirm with hash only when needed.
        if st.st_size == old.size and abs(st.st_mtime - old.mtime) < 0.001:
            result.unchanged += 1
            continue
        partial = st.st_size > config.max_hash_bytes
        digest = utils.sha256_file(
            path, max_bytes=config.max_hash_bytes if partial else None
        )
        if digest is not None and digest == old.sha256:
            result.unchanged += 1
        else:
            result.modified.append(path)
    for path in baseline.files:
        if path not in seen:
            result.deleted.append(path)
    return result
