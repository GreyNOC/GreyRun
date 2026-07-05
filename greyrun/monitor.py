"""Real-time monitor.

Wires live filesystem events into the :class:`BehaviorEngine` and, when the
threat level rises, into the :class:`Responder`. It prefers ``watchdog`` for
efficient OS-level notifications and falls back to a stdlib polling scanner when
watchdog is not installed, so the monitor always runs.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Dict, List, Optional, Tuple

from . import console, utils
from .config import Config, Paths
from .detector import ALERT, CRITICAL, DEFEND, NONE, WATCH, BehaviorEngine
from .responder import Responder, available as responder_available

try:
    from watchdog.events import FileSystemEventHandler  # type: ignore
    from watchdog.observers import Observer  # type: ignore

    WATCHDOG = True
except Exception:  # pragma: no cover
    WATCHDOG = False

_LEVEL_RANK = {NONE: 0, WATCH: 1, ALERT: 2, DEFEND: 3, CRITICAL: 4}
_LEVEL_COLOR = {
    NONE: "grey", WATCH: "cyan", ALERT: "yellow",
    DEFEND: "magenta", CRITICAL: "red",
}


class Monitor:
    def __init__(self, config: Config, paths: Paths, heartbeat: float = 30.0):
        self.config = config
        self.paths = paths
        self.engine = BehaviorEngine(config, paths)
        self.responder = Responder(config, paths)
        self.heartbeat = heartbeat
        self._excluded = {e.lower() for e in config.exclude_dirs}
        self._stop = threading.Event()
        self._last_score = 0
        self._last_acted_rank = 0
        self._last_action_ts = 0.0
        self._events = 0
        self._lock = threading.Lock()
        self._inflight_ranks: List[int] = []  # ranks of responses currently running

    # event sink shared by both backends
    def _ignore(self, path: str) -> bool:
        """Drop events for our own state dir and for excluded *sub*directories.

        Exclusions apply only to path components *below* a watched root, so a
        watched root that itself lives under an excluded-named directory (e.g.
        a sandbox under ``AppData\\Local\\Temp``) is still monitored.
        """
        if not path:
            return True
        if utils.is_within(path, [self.paths.root]):
            return True
        for root in self.config.watched_paths:
            if utils.is_within(path, [root]):
                rel = os.path.relpath(path, utils.normpath(root))
                parts = [p.lower() for p in rel.split(os.sep)[:-1]]  # dirs only
                return any(p in self._excluded for p in parts)
        return True  # not under any watched root

    def on_event(self, event_type: str, path: str, dest: Optional[str] = None) -> None:
        if self._ignore(path) and (dest is None or self._ignore(dest)):
            return
        with self._lock:
            self._events += 1
        assessment = self.engine.observe(event_type, path, dest)
        console.audit(
            "fs_event", type=event_type, path=path, dest=dest,
            score=assessment.score, level=assessment.level,
        )

        # Report rising risk.
        if assessment.score > self._last_score:
            new_reasons = assessment.reasons[-2:]
            color = _LEVEL_COLOR.get(assessment.level, "white")
            console.emit(
                "warn" if assessment.level in (ALERT, WATCH) else "alert",
                console.paint(
                    f"[{assessment.level} {assessment.score}] ", color, "bold"
                )
                + "; ".join(new_reasons),
            )
        self._last_score = assessment.score

        # Escalate to the responder on a rising or sustained high level. The
        # guards are read/written under the lock: the heartbeat thread's rearm
        # check touches the same fields.
        rank = _LEVEL_RANK.get(assessment.level, 0)
        now = utils.now_ts()
        with self._lock:
            should_act = rank >= _LEVEL_RANK[ALERT] and (
                rank > self._last_acted_rank
                or (rank >= _LEVEL_RANK[DEFEND] and now - self._last_action_ts > 2.0)
            )
            if should_act:
                self._last_acted_rank = max(self._last_acted_rank, rank)
                self._last_action_ts = now
        if should_act:
            self._dispatch_response(assessment, rank)
        else:
            self._maybe_rearm(assessment.score)

    def _maybe_rearm(self, score: int) -> None:
        """Once a raised threat has fully decayed (score back to 0), re-arm the
        one-shot alert and escalation guards so the next incident in this
        monitor run alerts, escalates and captures forensics again."""
        if score != 0 or self._last_acted_rank == 0:
            return  # unlocked fast path: benign steady state pays no lock
        now = utils.now_ts()
        with self._lock:
            if self._last_acted_rank == 0:
                return
            if self._inflight_ranks:
                return  # a response is still running; the incident isn't over
            # A genuinely decayed score implies a full quiet window since the
            # last signal, which is never sooner than the last response. If the
            # last response is more recent, the score we were handed is stale
            # (it raced a fresh escalation) -- stay armed.
            if now - self._last_action_ts < self.config.burst_window_sec:
                return
            self._last_acted_rank = 0
            self._last_action_ts = 0.0
        self.responder.rearm()
        console.audit("rearm")
        console.info("Threat window cleared — alerts re-armed.")

    def _dispatch_response(self, assessment, rank: int) -> None:
        """Run the (potentially slow) responder off the event thread so file
        events keep flowing. Coalesce: skip if an equal/higher-severity
        response is already running."""
        with self._lock:
            # Each in-flight response holds its own slot, so a fast-finishing
            # CRITICAL can't drop the guard while a slower DEFEND still runs.
            if self._inflight_ranks and max(self._inflight_ranks) >= rank:
                return
            self._inflight_ranks.append(rank)

        def _work():
            try:
                actions = self.responder.handle(assessment)
                for action in actions:
                    console.emit(
                        "critical" if assessment.level == CRITICAL else "alert",
                        "RESPONSE: " + action,
                    )
            finally:
                with self._lock:
                    self._inflight_ranks.remove(rank)

        threading.Thread(target=_work, daemon=True).start()

    # heartbeat
    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.heartbeat):
            snap = self.engine.snapshot()
            # Events stop flowing once an attacker is contained, so the decay
            # check must also run here, not only in the event path.
            self._maybe_rearm(snap.score)
            color = _LEVEL_COLOR.get(snap.level, "grey")
            console.info(
                f"watching {len(self.config.watched_paths)} path(s) · "
                f"events={self._events} · changed={snap.changed_count} · "
                + console.paint(f"{snap.level} ({snap.score})", color)
            )

    def stop(self) -> None:
        """Signal the monitor to shut down (used by tests/embedders)."""
        self._stop.set()

    # run loops
    def run(self) -> None:
        console.rule("LIVE MONITOR")
        backend = "watchdog (OS events)" if WATCHDOG else "polling (stdlib)"
        console.ok(f"Monitoring {len(self.config.watched_paths)} path(s) via {backend}")
        console.info(f"Response mode: {self.config.response_mode}  ·  "
                     f"process control: {'on' if responder_available() else 'OFF (install psutil)'}")
        for p in self.config.watched_paths:
            console.plain("    " + console.paint("▸ " + utils.short_path(p, 70), "grey"))
        console.info("Press Ctrl+C to stop.")
        console.audit("monitor_start", paths=self.config.watched_paths,
                      backend=backend, mode=self.config.response_mode)

        hb = threading.Thread(target=self._heartbeat_loop, daemon=True)
        hb.start()
        try:
            if WATCHDOG:
                self._run_watchdog()
            else:
                self._run_polling()
        except KeyboardInterrupt:
            pass
        finally:
            self._stop.set()
            console.plain("")
            console.ok(f"Monitor stopped after {self._events} event(s).")
            console.audit("monitor_stop", events=self._events)

    def _run_watchdog(self) -> None:
        monitor = self

        class _Handler(FileSystemEventHandler):  # type: ignore[misc]
            def on_created(self, event):
                if not event.is_directory:
                    monitor.on_event("created", event.src_path)

            def on_modified(self, event):
                if not event.is_directory:
                    monitor.on_event("modified", event.src_path)

            def on_deleted(self, event):
                monitor.on_event("deleted", event.src_path)

            def on_moved(self, event):
                if not event.is_directory:
                    monitor.on_event("moved", event.src_path, event.dest_path)

        observer = Observer()
        handler = _Handler()
        watched = 0
        for path in self.config.watched_paths:
            if os.path.isdir(path):
                observer.schedule(handler, path, recursive=True)
                watched += 1
            else:
                console.warn(f"Not a directory, skipping: {path}")
        if watched == 0:
            console.error("No valid directories to watch. Add paths with: greyrun protect <dir>")
            return
        observer.start()
        try:
            while not self._stop.is_set():
                time.sleep(0.5)
        finally:
            observer.stop()
            observer.join(timeout=3)

    def _run_polling(self, interval: float = 2.0) -> None:
        index: Dict[str, Tuple[float, int]] = {}
        # Prime the index without firing events.
        for path in utils.iter_files(self.config.watched_paths, self.config.exclude_dirs):
            st = utils.safe_stat(path)
            if st:
                index[path] = (st.st_mtime, st.st_size)

        while not self._stop.is_set():
            time.sleep(interval)
            current: Dict[str, Tuple[float, int]] = {}
            for path in utils.iter_files(self.config.watched_paths, self.config.exclude_dirs):
                st = utils.safe_stat(path)
                if not st:
                    continue
                current[path] = (st.st_mtime, st.st_size)
                old = index.get(path)
                if old is None:
                    self.on_event("created", path)
                elif old != current[path]:
                    self.on_event("modified", path)
            for path in index:
                if path not in current:
                    self.on_event("deleted", path)
            index = current
