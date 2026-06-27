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
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

from . import canary as canary_mod
from . import utils
from .baseline import Baseline, Diff, diff_current
from .config import Config, Paths
from .entropy import file_entropy, is_document_class, looks_encrypted
from .signatures import is_ransom_note, is_ransomware_ext, ransomware_family

# Risk levels, in ascending severity.
NONE, WATCH, ALERT, DEFEND, CRITICAL = "NONE", "WATCH", "ALERT", "DEFEND", "CRITICAL"

# Per-signal weights (points).
W_CANARY = 100
W_RANSOM_NOTE = 60
W_RANSOMWARE_EXT = 35
W_ENCRYPTED = 20
W_BURST = 40
W_MASS_DELETE = 30


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
    encrypted_like: List[Tuple[str, float]] = field(default_factory=list)
    diff: Optional[Diff] = None
    findings: List[str] = field(default_factory=list)


def scan(config: Config, paths: Paths, baseline: Optional[Baseline] = None) -> ScanReport:
    """Sweep the watched tree and produce a risk report."""
    report = ScanReport()

    # 1. Canaries: the highest-weight signal.
    statuses = canary_mod.verify(paths)
    report.canaries_total = len(statuses)
    for status in statuses:
        if status.state != "ok":
            report.canaries_bad.append(status)
            report.risk += W_CANARY
            report.findings.append(f"Canary {status.state}: {status.path}")

    # 2. Per-file static + entropy checks.
    for path in utils.iter_files(config.watched_paths, config.exclude_dirs):
        report.scanned += 1
        if is_ransomware_ext(path):
            fam = ransomware_family(path) or "unknown"
            report.ransomware_ext.append((path, fam))
            report.risk += W_RANSOMWARE_EXT
            report.findings.append(f"Ransomware extension ({fam}): {path}")
        if is_ransom_note(path):
            report.ransom_notes.append(path)
            report.risk += W_RANSOM_NOTE
            report.findings.append(f"Ransom-note filename: {path}")
        # Entropy only where a high reading is actually suspicious.
        if is_document_class(path):
            ent = file_entropy(path)
            if ent is not None and looks_encrypted(path, ent, config.entropy_threshold):
                report.encrypted_like.append((path, ent))
                report.risk += W_ENCRYPTED
                report.findings.append(f"Document looks encrypted (H={ent:.2f}): {path}")

    # 3. Baseline drift, if available.
    if baseline is not None:
        report.diff = diff_current(baseline, config)

    report.risk = min(report.risk, 999)
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
        self._changed: Deque[Tuple[float, str]] = deque()  # for burst detection
        self._deleted: Deque[Tuple[float, str]] = deque()
        self._burst_credited_at: float = 0.0
        self._families: Dict[str, int] = {}
        self._canary_registry = canary_mod.registry(paths)

    # internal helpers (call with lock held)
    def _prune(self, now: float) -> None:
        window = self.config.burst_window_sec
        cutoff = now - window
        while self._signals and self._signals[0].ts < cutoff:
            old = self._signals.popleft()
            self._credited.discard((old.kind, old.path))
        while self._changed and self._changed[0][0] < cutoff:
            self._changed.popleft()
        while self._deleted and self._deleted[0][0] < cutoff:
            self._deleted.popleft()

    def _add(self, now: float, weight: int, kind: str, path: str, detail: str) -> None:
        key = (kind, path)
        if key in self._credited:
            return
        self._credited.add(key)
        self._signals.append(Signal(now, weight, kind, path, detail))

    def _score(self) -> int:
        return min(sum(s.weight for s in self._signals), 999)

    # public API
    def observe(self, event_type: str, path: str, dest: Optional[str] = None) -> Assessment:
        """Feed one filesystem event. ``event_type`` is one of
        ``created|modified|deleted|moved``. Returns the current assessment."""
        now = utils.now_ts()
        with self._lock:
            self._prune(now)
            target = dest or path

            # Canary tamper: check both the event path and any move source.
            for candidate in filter(None, (path, dest)):
                state = canary_mod.check_one(candidate, self._canary_registry)
                if state:
                    self._add(now, W_CANARY, "canary", candidate,
                              f"canary {state}")

            if event_type == "deleted":
                self._deleted.append((now, path))
                if len(self._deleted) >= self.config.burst_count:
                    self._add(now, W_MASS_DELETE, "mass_delete", "*",
                              f"{len(self._deleted)} deletions in window")
            else:
                # created / modified / moved-to
                self._changed.append((now, target))
                if is_ransomware_ext(target):
                    fam = ransomware_family(target) or "unknown"
                    self._families[fam] = self._families.get(fam, 0) + 1
                    self._add(now, W_RANSOMWARE_EXT, "ext", target,
                              f"ransomware extension ({fam})")
                if is_ransom_note(target):
                    self._add(now, W_RANSOM_NOTE, "note", target, "ransom note")
                elif is_document_class(target) and looks_encrypted(
                    target, threshold=self.config.entropy_threshold
                ):
                    self._add(now, W_ENCRYPTED, "encrypted", target,
                              "document looks encrypted")

            # Burst of distinct changed files.
            distinct = {p for _, p in self._changed}
            if (
                len(distinct) >= self.config.burst_count
                and now - self._burst_credited_at > self.config.burst_window_sec / 2
            ):
                self._burst_credited_at = now
                self._add(now, W_BURST, "burst", "*",
                          f"{len(distinct)} files changed in "
                          f"{int(self.config.burst_window_sec)}s")

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
                changed_count=len(distinct),
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
                changed_count=len({p for _, p in self._changed}),
            )

    def reset(self) -> None:
        with self._lock:
            self._signals.clear()
            self._credited.clear()
            self._changed.clear()
            self._deleted.clear()
            self._families.clear()
            self._burst_credited_at = 0.0
