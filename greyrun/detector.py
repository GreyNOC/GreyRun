"""Detection engine.

Two complementary detectors share one scoring vocabulary:

* :func:`scan`: a stateless, on-demand sweep of the watched tree (optionally
  against a baseline) that produces a risk report.
* :class:`BehaviorEngine`: a stateful machine fed live filesystem events by the
  monitor. It keeps a decaying windowed score, so a burst of individually
  innocent events (the signature of an encryption sweep) escalates into a
  high-confidence threat level.

Both map a numeric risk score onto the same escalating levels, which the
responder acts on.

Scoring is corroboration-based, not a flat sum. Every signal kind belongs to
a class -- canary, content (damaged files), note (extortion artifacts), or
volume (bursts/mass deletes) -- and :func:`corroborated_score` applies the
policy: one noisy detector can warn you but never fight back alone; fighting
back requires a tripped canary or independent detector classes agreeing.
Concretely, every kind except a modified canary is capped below the DEFEND
threshold, and volume evidence only escalates past ALERT when content-, note-
or canary-class evidence corroborates it.
"""

from __future__ import annotations

import os
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple

from . import canary as canary_mod
from . import filetypes, notecontent, utils
from .baseline import Baseline, Diff, diff_current
from .config import Config, Paths
from .entropy import (
    HIGH_ENTROPY_EXTS,
    LOW_ENTROPY_EXTS,
    byte_stats,
    cipher_like,
    inner_document_class,
    is_document_class,
)
from .signatures import (
    BENIGN_TRAILING_EXTS,
    RANSOMWARE_EXTENSIONS,
    USER_CONTENT_EXTS,
    ext_confidence,
    is_double_document_ext,
    is_ransom_note,
    is_stranded_document_ext,
    is_transient,
    ransomware_family,
)

# Risk levels, in ascending severity.
NONE, WATCH, ALERT, DEFEND, CRITICAL = "NONE", "WATCH", "ALERT", "DEFEND", "CRITICAL"

# Per-signal weights (points).
W_CANARY = 100           # decoy content changed in place -- decisive
W_CANARY_MISSING = 60    # decoy gone/unreadable -- needs one corroborator
W_RANSOM_NOTE = 60       # note-like filename
W_NOTE_CONTENT = 60      # note body with a verified payment anchor / 3 topics
W_NOTE_CONTENT_WEAK = 35  # note body, two topics, no anchor
W_EXT = 40               # family-specific ransomware extension (.lockbit)
W_EXT_DOUBLE = 35        # generic crypto suffix over a document ext (.docx.enc)
W_EXT_WEAK = 10          # bare generic suffix (backup.enc): context only
W_HEADER_MISMATCH = 45   # settled file: matches no known format, cipher-like
W_STRANDED = 35          # document ext under unknown suffix + cipher-like head
W_ENCRYPTED = 30         # document-class content reads as ciphertext
W_ENTROPY_JUMP = 35      # scan-only: baselined structured file went random
W_BURST = 40             # many existing files rewritten in the window
W_BURST_CREATE = 15      # many files created (sync/extract/import shaped)
W_MASS_DELETE = 30
W_EXT_CLUSTER = 25       # many files gained the same unknown extension
W_STACKED = 10           # 2+ independent content/note indicators on one file
W_SUSTAINED = 25         # strong evidence trickling across the long memory
W_SUSTAINED_MAX = 45     # ... growing +5 per extra file, always < DEFEND alone

# kind -> (signal class, per-kind score cap). Class None is context: it adds
# points but never uncaps volume or counts as corroboration.
KIND_META: Dict[str, Tuple[Optional[str], Optional[int]]] = {
    "canary": ("canary", None),
    "ext": ("content", 65),
    "encrypted": ("content", 60),
    "hdr": ("content", 65),
    "stranded": ("content", 65),
    "jump": ("content", 65),
    "note": ("note", 60),
    "note_content": ("note", 60),
    "burst": ("volume", None),
    "burst_create": ("volume", None),
    "mass_delete": ("volume", None),
    "ext_weak": (None, 20),
    "ext_cluster": (None, 25),
    "stacked": (None, 30),
    "sustained": (None, W_SUSTAINED_MAX),
}

# Strong per-file evidence kinds that feed the long "sustained" memory.
SUSTAINED_KINDS = frozenset(
    {"ext", "encrypted", "hdr", "stranded", "note", "note_content"}
)

_NOTE_CLASS_CAP = 75           # filename + body on one note: DEFEND, never kill
_VOLUME_CAP_ALONE = 40         # volume alone can never suspend anything
_VOLUME_CAP_CORROBORATED = 65  # with content/note/canary agreement it may


def corroborated_score(pairs: Iterable[Tuple[str, int]]) -> int:
    """Fold (kind, weight) pairs into one risk score under the corroboration
    policy described in the module docstring."""
    per_kind: Dict[str, int] = {}
    for kind, weight in pairs:
        per_kind[kind] = per_kind.get(kind, 0) + weight
    per_class: Dict[Optional[str], int] = {}
    for kind, total in per_kind.items():
        cls, cap = KIND_META.get(kind, (None, None))
        if cap is not None:
            total = min(total, cap)
        per_class[cls] = per_class.get(cls, 0) + total
    if per_class.get("note", 0) > _NOTE_CLASS_CAP:
        per_class["note"] = _NOTE_CLASS_CAP
    if "volume" in per_class:
        strong = any(per_class.get(c) for c in ("canary", "content", "note"))
        cap = _VOLUME_CAP_CORROBORATED if strong else _VOLUME_CAP_ALONE
        per_class["volume"] = min(per_class["volume"], cap)
    return min(sum(per_class.values()), 999)


def level_for(score: int, config: Config) -> str:
    if score >= config.kill_score:
        return CRITICAL
    if score >= config.defend_score:
        return DEFEND
    if score >= config.alert_score:
        return ALERT
    if score > 0:
        return WATCH
    return NONE


# Build/tool outputs that legitimately appear in batches; never treated as an
# "unknown extension" for rename clustering.
_CLUSTER_IGNORED_EXTS = frozenset({
    ".o", ".obj", ".pyc", ".pyo", ".class", ".map", ".d", ".dep", ".tlog",
    ".ilk", ".pdb", ".idb", ".gcda", ".gcno", ".rsp", ".dat", ".db", ".idx",
    ".cache",
})
_CLUSTER_KNOWN_EXTS = (
    LOW_ENTROPY_EXTS | HIGH_ENTROPY_EXTS | BENIGN_TRAILING_EXTS
    | USER_CONTENT_EXTS | frozenset(RANSOMWARE_EXTENSIONS)
    | _CLUSTER_IGNORED_EXTS
)


def _cluster_ext(path: str) -> Optional[str]:
    """The final extension, iff it is the *unknown* kind whose sudden
    convergence across many files marks a novel suffix-appending strain."""
    ext = utils.file_ext(path)
    if not ext or len(ext) > 16 or ext in _CLUSTER_KNOWN_EXTS:
        return None
    body = ext[1:]
    if not body or body.isdigit():
        return None
    return ext


def _head_cipher_like(path: str, config: Config) -> bool:
    """4 KiB head check: matches no known format and reads as ciphertext."""
    head = utils.read_sample(path, filetypes.HEAD_BYTES)
    if not head or filetypes.matches_any_known(head):
        return False
    return cipher_like(byte_stats(head), config.entropy_threshold, config.chi2_max)


# --------------------------------------------------------------------------- #
#  On-demand scan
# --------------------------------------------------------------------------- #


@dataclass
class ScanReport:
    scanned: int = 0
    risk: int = 0
    level: str = NONE
    canaries_bad: List[canary_mod.CanaryStatus] = field(default_factory=list)
    canaries_total: int = 0
    ransomware_ext: List[Tuple[str, str]] = field(default_factory=list)
    ransom_notes: List[str] = field(default_factory=list)
    ransom_note_content: List[Tuple[str, List[str]]] = field(default_factory=list)
    encrypted_like: List[Tuple[str, float, float]] = field(default_factory=list)
    header_mismatch: List[Tuple[str, str]] = field(default_factory=list)
    stranded: List[str] = field(default_factory=list)
    entropy_jumps: List[Tuple[str, float, float]] = field(default_factory=list)
    diff: Optional[Diff] = None
    findings: List[str] = field(default_factory=list)


def scan(config: Config, paths: Paths, baseline: Optional[Baseline] = None) -> ScanReport:
    """Sweep the watched tree and produce a risk report."""
    report = ScanReport()
    pairs: List[Tuple[str, int]] = []

    # 1. Canaries: the highest-weight signal, tiered by verdict.
    statuses = canary_mod.verify(paths)
    report.canaries_total = len(statuses)
    for status in statuses:
        if status.state == "ok":
            continue
        report.canaries_bad.append(status)
        if status.state == "modified":
            pairs.append(("canary", W_CANARY))
            report.findings.append(f"Canary modified: {status.path}")
        elif status.state in ("missing", "unreadable"):
            pairs.append(("canary", W_CANARY_MISSING))
            report.findings.append(f"Canary {status.state}: {status.path}")
        else:  # missing_dir / placeholder: folder move or cloud dehydration
            report.findings.append(f"Canary {status.state} (not scored): {status.path}")

    # 2. Per-file name, content and structure checks.
    cluster: Dict[str, List[str]] = {}
    for path in utils.iter_files(config.watched_paths, config.exclude_dirs):
        report.scanned += 1
        if is_transient(path):
            continue
        conf = ext_confidence(path)
        if conf is not None:
            fam = ransomware_family(path) or "unknown"
            report.ransomware_ext.append((path, fam))
            if conf == "family":
                pairs.append(("ext", W_EXT))
                report.findings.append(f"Ransomware extension ({fam}): {path}")
            elif is_double_document_ext(path):
                pairs.append(("ext", W_EXT_DOUBLE))
                report.findings.append(
                    f"Ransomware extension over document ({fam}): {path}")
            else:
                pairs.append(("ext_weak", W_EXT_WEAK))
                report.findings.append(
                    f"Generic encrypted-file extension ({fam}): {path}")
        if is_ransom_note(path):
            report.ransom_notes.append(path)
            pairs.append(("note", W_RANSOM_NOTE))
            report.findings.append(f"Ransom-note filename: {path}")
        note = notecontent.looks_like_ransom_note_content(
            path, config.note_scan_max_bytes)
        if note is not None:
            report.ransom_note_content.append((path, note.categories))
            pairs.append(("note_content",
                          W_NOTE_CONTENT if note.strong else W_NOTE_CONTENT_WEAK))
            report.findings.append(
                "Ransom-note content ({}): {}".format(
                    ", ".join(note.categories), path))
        # Content where low entropy is expected; structure where the format
        # is verifiable. The two are disjoint by construction.
        if is_document_class(path) or inner_document_class(path):
            stats = byte_stats(utils.read_sample(path))
            if stats is not None and cipher_like(
                stats, config.entropy_threshold, config.chi2_max
            ):
                report.encrypted_like.append((path, stats.entropy, stats.chi2))
                pairs.append(("encrypted", W_ENCRYPTED))
                report.findings.append(
                    f"Document looks encrypted (H={stats.entropy:.2f}): {path}")
        elif config.header_check and filetypes.has_magic_for(path):
            detail = filetypes.header_mismatch(
                path, config.header_min_size,
                config.entropy_threshold, config.chi2_max)
            if detail is not None:
                report.header_mismatch.append((path, detail))
                pairs.append(("hdr", W_HEADER_MISMATCH))
                report.findings.append(f"Header mismatch ({detail}): {path}")
        if is_stranded_document_ext(path) and _head_cipher_like(path, config):
            report.stranded.append(path)
            pairs.append(("stranded", W_STRANDED))
            report.findings.append(
                f"Document stranded under unknown extension: {path}")
        cext = _cluster_ext(path)
        if cext is not None:
            cluster.setdefault(cext, []).append(path)

    # 3. Rename cluster: many files sharing one unknown extension, confirmed
    # by at least one sampled member reading as ciphertext.
    for cext, members in sorted(cluster.items(), key=lambda kv: -len(kv[1])):
        if len(members) < config.ext_cluster_count:
            break
        if any(_head_cipher_like(p, config) for p in members[:3]):
            pairs.append(("ext_cluster", W_EXT_CLUSTER))
            report.findings.append(
                f"{len(members)} files share unknown extension {cext}")
            break

    # 4. Baseline drift, if available -- including the extension-agnostic
    # entropy-jump check on files the baseline knew as structured data.
    if baseline is not None:
        report.diff = diff_current(baseline, config)
        for path in report.diff.modified:
            old = baseline.files.get(path)
            if old is None or old.entropy is None or old.entropy > 6.0:
                continue  # was compressed-ish already; a jump proves nothing
            stats = byte_stats(utils.read_sample(path))
            if (
                stats is not None
                and stats.entropy >= config.entropy_threshold
                and stats.entropy - old.entropy >= config.entropy_jump_min
                and cipher_like(stats, config.entropy_threshold, config.chi2_max)
            ):
                report.entropy_jumps.append((path, old.entropy, stats.entropy))
                pairs.append(("jump", W_ENTROPY_JUMP))
                report.findings.append(
                    f"Entropy jump {old.entropy:.2f} -> {stats.entropy:.2f}: {path}")

    report.risk = corroborated_score(pairs)
    report.level = level_for(report.risk, config)
    return report


# --------------------------------------------------------------------------- #
#  Live behavioural engine
# --------------------------------------------------------------------------- #


@dataclass
class Signal:
    ts: float
    weight: int
    kind: str
    path: str
    detail: str


@dataclass
class Assessment:
    score: int
    level: str
    reasons: List[str]
    suspect_paths: List[str]
    families: List[str]
    changed_count: int


class BehaviorEngine:
    """Accumulates weighted signals over a sliding window and reports threat
    level. Thread-safe: the monitor may call :meth:`observe` from an observer
    thread while the main thread reads state."""

    def __init__(self, config: Config, paths: Paths):
        self.config = config
        self.paths = paths
        self._lock = threading.Lock()
        self._signals: Deque[Signal] = deque()
        self._credited: set = set()          # (kind, path) already scored
        self._changed: Deque[Tuple[float, str, bool]] = deque()  # ts, path, overwrite
        self._deleted: Deque[Tuple[float, str]] = deque()
        self._burst_credited_at: float = 0.0
        self._burst_create_credited_at: float = 0.0
        self._families: Dict[str, int] = {}
        self._canary_registry = canary_mod.registry(paths)
        # A canary renamed with its content intact keeps being watched under
        # its new name, so encrypting it later is still the decisive signal.
        self._displaced_canaries: Dict[str, dict] = {}
        self._pending_canary: Dict[str, float] = {}   # path -> first-seen ts
        self._pending_hdr: Dict[str, float] = {}      # path -> last event ts
        self._ext_events: Deque[Tuple[float, str, str]] = deque()  # ts, ext, stem
        self._ext_stems: Dict[str, Dict[str, int]] = {}
        self._path_kinds: Dict[str, Set[str]] = {}    # content/note kinds per path
        self._content_hits: Deque[Tuple[float, str]] = deque()  # sustained memory

    # internal helpers (call with lock held)
    def _prune(self, now: float) -> None:
        cutoff = now - self.config.burst_window_sec
        while self._signals and self._signals[0].ts < cutoff:
            old = self._signals.popleft()
            self._credited.discard((old.kind, old.path))
            kinds = self._path_kinds.get(old.path)
            if kinds is not None:
                kinds.discard(old.kind)
                if not kinds:
                    del self._path_kinds[old.path]
        while self._changed and self._changed[0][0] < cutoff:
            self._changed.popleft()
        while self._deleted and self._deleted[0][0] < cutoff:
            self._deleted.popleft()
        while self._ext_events and self._ext_events[0][0] < cutoff:
            _, ext, stem = self._ext_events.popleft()
            stems = self._ext_stems.get(ext)
            if stems is not None:
                left = stems.get(stem, 1) - 1
                if left <= 0:
                    stems.pop(stem, None)
                    if not stems:
                        del self._ext_stems[ext]
                else:
                    stems[stem] = left
        self._recheck_canaries(now)
        self._flush_headers(now)
        self._maintain_sustained(now)

    def _add(self, now: float, weight: int, kind: str, path: str, detail: str) -> None:
        key = (kind, path)
        if key in self._credited:
            return
        self._credited.add(key)
        self._signals.append(Signal(now, weight, kind, path, detail))
        if kind in SUSTAINED_KINDS and self.config.memory_window_sec > 0:
            self._content_hits.append((now, path))
        cls = KIND_META.get(kind, (None, None))[0]
        if cls in ("content", "note") and path != "*":
            kinds = self._path_kinds.setdefault(path, set())
            kinds.add(kind)
            if len(kinds) == 2:
                self._add(now, W_STACKED, "stacked", path,
                          "independent indicators stacking on one file")

    def _score(self) -> int:
        return corroborated_score((s.kind, s.weight) for s in self._signals)

    def _canary_state_any(self, path: str) -> Optional[str]:
        """Check ``path`` against the deployed registry and, failing that,
        the displaced-canary map. ``None`` means intact or not a canary."""
        state = canary_mod.check_one(path, self._canary_registry)
        if state is None and path in self._displaced_canaries:
            state = canary_mod.check_one(path, self._displaced_canaries)
        return state

    def _recheck_canaries(self, now: float) -> None:
        """A missing/unreadable canary is scored only if it is still bad a
        beat later, so a sync or backup race that briefly displaces it never
        counts. A real deletion is durable and survives the recheck."""
        if not self._pending_canary:
            return
        for path, seen in list(self._pending_canary.items()):
            if now - seen < self.config.canary_recheck_sec:
                continue
            del self._pending_canary[path]
            state = self._canary_state_any(path)
            if state == "modified":
                self._add(now, W_CANARY, "canary", path, "canary modified")
            elif state in ("missing", "unreadable"):
                self._add(now, W_CANARY_MISSING, "canary", path, f"canary {state}")
            # recovered / placeholder / missing_dir: not a tamper

    def _flush_headers(self, now: float) -> None:
        """Run the header check on files whose events went quiet. The settle
        delay guarantees a legitimate save mid-write is never read torn."""
        if not self._pending_hdr:
            return
        for path, last in list(self._pending_hdr.items()):
            if now - last < self.config.header_settle_sec:
                continue
            del self._pending_hdr[path]
            detail = filetypes.header_mismatch(
                path, self.config.header_min_size,
                self.config.entropy_threshold, self.config.chi2_max)
            if detail is not None:
                self._add(now, W_HEADER_MISMATCH, "hdr", path, detail)

    def _maintain_sustained(self, now: float) -> None:
        """Keep the long content-evidence memory current. While enough
        *distinct* files carry strong hits inside the memory window, a
        'sustained' signal is held live so a slow encryptor can't reset the
        score by pausing longer than the short burst window. Its weight grows
        with the file count (capped below DEFEND), so victim #5 of a paced
        sweep escalates even when each per-file signal has long decayed --
        while one repeatedly re-saved file counts only once."""
        mem = self.config.memory_window_sec
        if mem <= 0:
            self._content_hits.clear()
            return
        mcut = now - mem
        while self._content_hits and self._content_hits[0][0] < mcut:
            self._content_hits.popleft()
        minimum = max(1, self.config.sustained_content_min)
        distinct = len({p for _, p in self._content_hits})
        if distinct < minimum:
            return  # below the bar: any live sustained signal decays normally
        weight = min(W_SUSTAINED + 5 * (distinct - minimum), W_SUSTAINED_MAX)
        detail = f"{distinct} files with strong indicators in {int(mem // 60)}m"
        if ("sustained", "*") in self._credited:
            live = next((s for s in self._signals if s.kind == "sustained"), None)
            if live is not None:
                self._signals.remove(live)
                self._signals.append(Signal(now, weight, "sustained", "*", detail))
        else:
            self._add(now, weight, "sustained", "*", detail)

    def _observe_canary(self, now: float, candidate: str) -> None:
        state = self._canary_state_any(candidate)
        if state is None:
            return
        if state == "modified":
            self._pending_canary.pop(candidate, None)
            self._add(now, W_CANARY, "canary", candidate, "canary modified")
        elif state in ("missing", "unreadable"):
            if ("canary", candidate) not in self._credited:
                self._pending_canary.setdefault(candidate, now)
        # missing_dir / placeholder: folder move or cloud dehydration -- the
        # audit log keeps the event; no score.

    def _observe_canary_move(self, now: float, src: str, dest: str) -> bool:
        """Handle a rename whose *source* is a canary. Rename-first strains
        hit the decoy before touching its content; merely losing the file
        would score only 60, so keep watching the new name: encrypting the
        displaced decoy later is still the decisive 100. Returns True if
        ``src`` was a canary."""
        meta = self._canary_registry.get(src) or self._displaced_canaries.pop(src, None)
        if meta is None:
            return False
        state = canary_mod.check_one(dest, {dest: meta})
        if state is None:
            # Content survived the rename intact: suspicious (nothing
            # legitimate renames a decoy) but not decisive. Follow it.
            self._displaced_canaries[dest] = meta
            while len(self._displaced_canaries) > 256:
                self._displaced_canaries.pop(next(iter(self._displaced_canaries)))
            self._add(now, W_CANARY_MISSING, "canary", src, "canary renamed")
        elif state == "modified":
            self._add(now, W_CANARY, "canary", dest,
                      "canary rewritten under rename")
        else:  # dest unreadable/gone -- fall back to the recheck path
            if ("canary", src) not in self._credited:
                self._pending_canary.setdefault(src, now)
        return True

    def _reads_cipher_like(self, target: str) -> bool:
        """One bounded read with a torn-write guard: if the file changed while
        being read, it is mid-write -- skip rather than score a torn state."""
        before = utils.safe_stat(target)
        if before is None or before.st_size == 0:
            return False
        stats = byte_stats(utils.read_sample(target))
        if not cipher_like(stats, self.config.entropy_threshold, self.config.chi2_max):
            return False
        after = utils.safe_stat(target)
        return (
            after is not None
            and after.st_size == before.st_size
            and after.st_mtime == before.st_mtime
        )

    def _check_file(self, now: float, event_type: str, path: str, target: str) -> None:
        """Per-file checks for a created/modified/moved-to path (lock held)."""
        conf = ext_confidence(target)
        if conf is not None:
            fam = ransomware_family(target) or "unknown"
            if conf == "family":
                self._families[fam] = self._families.get(fam, 0) + 1
                self._add(now, W_EXT, "ext", target,
                          f"ransomware extension ({fam})")
            elif is_double_document_ext(target):
                self._families[fam] = self._families.get(fam, 0) + 1
                self._add(now, W_EXT_DOUBLE, "ext", target,
                          f"ransomware extension over document ({fam})")
            else:
                self._add(now, W_EXT_WEAK, "ext_weak", target,
                          f"generic encrypted-file extension ({fam})")
        if is_ransom_note(target):
            self._add(now, W_RANSOM_NOTE, "note", target, "ransom note")
        if ("note_content", target) not in self._credited:
            note = notecontent.looks_like_ransom_note_content(
                target, self.config.note_scan_max_bytes)
            if note is not None:
                self._add(
                    now,
                    W_NOTE_CONTENT if note.strong else W_NOTE_CONTENT_WEAK,
                    "note_content", target,
                    "ransom-note content ({})".format(", ".join(note.categories)),
                )
        # Entropy: check the credited set first (the read is up to 256 KB and
        # a file being rewritten fires many events). Eligible when the name --
        # or, for a rename, the *source* name -- promises low-entropy content.
        if (
            ("encrypted", target) not in self._credited
            and (
                is_document_class(target)
                or (event_type == "moved" and is_document_class(path))
                or inner_document_class(target)
            )
            and self._reads_cipher_like(target)
        ):
            self._add(now, W_ENCRYPTED, "encrypted", target,
                      "document looks encrypted")
        if (
            ("stranded", target) not in self._credited
            and is_stranded_document_ext(target)
            and _head_cipher_like(target, self.config)
        ):
            self._add(now, W_STRANDED, "stranded", target,
                      "document stranded under unknown extension")
        if (
            self.config.header_check
            and ("hdr", target) not in self._credited
            and filetypes.has_magic_for(target)
        ):
            # Every event on the file re-arms its settle timer; _prune() runs
            # the check once it has gone quiet.
            self._pending_hdr.pop(target, None)
            self._pending_hdr[target] = now
            while len(self._pending_hdr) > 4096:
                self._pending_hdr.pop(next(iter(self._pending_hdr)))
        cext = _cluster_ext(target)
        if cext is not None:
            stem = os.path.normcase(os.path.splitext(target)[0])
            self._ext_events.append((now, cext, stem))
            stems = self._ext_stems.setdefault(cext, {})
            stems[stem] = stems.get(stem, 0) + 1
            # Same cipher confirmation as the scan path: a data pipeline
            # emitting healthy .parquet-style batches must not fire on the
            # name pattern alone. A real sweep's members are all ciphertext,
            # so the member that crosses the threshold confirms it.
            if (
                len(stems) >= self.config.ext_cluster_count
                and ("ext_cluster", "*") not in self._credited
                and _head_cipher_like(target, self.config)
            ):
                self._add(now, W_EXT_CLUSTER, "ext_cluster", "*",
                          f"{len(stems)} files gained unknown extension {cext}")

    def _check_burst(self, now: float) -> None:
        # Each burst kind has its own re-credit throttle: a benign create
        # storm must never pin the timer and mute the *stronger* rewrite
        # burst that an in-place sweep earns moments later.
        half = self.config.burst_window_sec / 2
        if now - self._burst_credited_at > half:
            rewritten = {p for _, p, overwrite in self._changed if overwrite}
            if len(rewritten) >= self.config.burst_count:
                self._burst_credited_at = now
                self._add(now, W_BURST, "burst", "*",
                          f"{len(rewritten)} files rewritten in "
                          f"{int(self.config.burst_window_sec)}s")
                return
        # A creates-only storm is archive-extraction/sync/import shaped;
        # encryption sweeps rewrite or rename *existing* files. It is only a
        # distinct observation while the rewrite burst is NOT live -- an
        # overwrite burst always implies the distinct count too.
        if ("burst", "*") in self._credited:
            return
        if now - self._burst_create_credited_at > half:
            distinct = {p for _, p, _overwrite in self._changed}
            if len(distinct) >= self.config.burst_count:
                self._burst_create_credited_at = now
                self._add(now, W_BURST_CREATE, "burst_create", "*",
                          f"{len(distinct)} files created in "
                          f"{int(self.config.burst_window_sec)}s")

    # public API
    def observe(self, event_type: str, path: str, dest: Optional[str] = None) -> Assessment:
        """Feed one filesystem event. ``event_type`` is one of
        ``created|modified|deleted|moved``. Returns the current assessment."""
        now = utils.now_ts()
        with self._lock:
            self._prune(now)
            target = dest or path

            # Canaries first: they must see every event, transient or not.
            # A rename is handled as a pair (source canary -> followed dest);
            # anything else checks each touched path independently.
            canary_move = (event_type == "moved" and dest is not None
                           and self._observe_canary_move(now, path, dest))
            if not canary_move:
                for candidate in filter(None, (path, dest)):
                    self._observe_canary(now, candidate)

            if event_type == "deleted":
                # Transient deletions count too: a wiper stays visible.
                self._deleted.append((now, path))
                self._pending_hdr.pop(path, None)
                distinct_deleted = {p for _, p in self._deleted}
                if len(distinct_deleted) >= self.config.burst_count:
                    self._add(now, W_MASS_DELETE, "mass_delete", "*",
                              f"{len(distinct_deleted)} files deleted in window")
            elif is_transient(target):
                # Office save dances, download shards, lock files: no per-file
                # checks, and by default no burst credit either.
                if self.config.count_transient_in_burst:
                    self._changed.append(
                        (now, target, event_type in ("modified", "moved")))
            else:
                self._changed.append(
                    (now, target, event_type in ("modified", "moved")))
                if event_type == "moved":
                    self._pending_hdr.pop(path, None)  # source name is gone
                self._check_file(now, event_type, path, target)

            self._check_burst(now)
            # Signals added by this event may complete the sustained-memory
            # bar; re-evaluate so this assessment already reflects it.
            self._maintain_sustained(now)

            score = self._score()
            reasons = [f"{s.detail} [{s.kind}]" for s in self._signals]
            suspects = list(
                dict.fromkeys(
                    s.path for s in self._signals if s.path != "*"
                )
            )[-12:]
            families = [f for f, _ in sorted(self._families.items(),
                                             key=lambda kv: -kv[1])]
            return Assessment(
                score=score,
                level=level_for(score, self.config),
                reasons=reasons,
                suspect_paths=suspects,
                families=families,
                changed_count=len({p for _, p, _overwrite in self._changed}),
            )

    def snapshot(self) -> Assessment:
        now = utils.now_ts()
        with self._lock:
            self._prune(now)
            score = self._score()
            return Assessment(
                score=score,
                level=level_for(score, self.config),
                reasons=[f"{s.detail} [{s.kind}]" for s in self._signals],
                suspect_paths=[s.path for s in self._signals if s.path != "*"][-12:],
                families=[f for f, _ in sorted(self._families.items(),
                                               key=lambda kv: -kv[1])],
                changed_count=len({p for _, p, _overwrite in self._changed}),
            )

    def reset(self) -> None:
        with self._lock:
            self._signals.clear()
            self._credited.clear()
            self._changed.clear()
            self._deleted.clear()
            self._families.clear()
            self._burst_credited_at = 0.0
            self._burst_create_credited_at = 0.0
            self._displaced_canaries.clear()
            self._pending_canary.clear()
            self._pending_hdr.clear()
            self._ext_events.clear()
            self._ext_stems.clear()
            self._path_kinds.clear()
            self._content_hits.clear()
