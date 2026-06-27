"""Active response -- the "fight back" half of GreyRun.

When the detector raises the threat level, the responder:

1. **Identifies** the offending process by looking for processes holding open
   handles inside the protected tree and doing heavy write I/O (needs psutil).
2. **Contains** it -- first *suspending* it (reversible), then *terminating*
   it if policy allows and the threat is critical.
3. **Locks down** the affected directories by marking files read-only so a
   process that survives can't keep encrypting.
4. **Captures forensics** -- a JSON snapshot of the suspect process tree.

Every step is best-effort and guarded: GreyRun must never crash the box it is
protecting, and it refuses to suspend or kill a small set of critical OS
processes.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional

from . import console, utils
from .config import Config, Paths
from .detector import ALERT, CRITICAL, DEFEND, Assessment

try:  # process control is optional; without it we degrade to alert-only
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

# Processes we will never suspend or terminate, regardless of score.
CRITICAL_PROCS = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsm.exe",
    "svchost.exe", "dwm.exe", "fontdrvhost.exe", "memcompression",
    "explorer.exe",  # killing the shell would lock the user out mid-incident
    "python.exe", "py.exe", "pythonw.exe",  # don't shoot ourselves
}

_READONLY = 0x01
_NORMAL = 0x80


@dataclass
class Suspect:
    pid: int
    name: str
    score: int
    evidence: List[str] = field(default_factory=list)
    cmdline: str = ""
    username: str = ""
    exe: str = ""
    # Only processes proven to hold an open handle inside a protected path are
    # "actionable" -- i.e. eligible for automatic suspend/terminate. Processes
    # that merely look busy (high write I/O elsewhere) are reported but never
    # auto-contained, so GreyRun won't suspend an innocent browser or backup job.
    actionable: bool = False


def available() -> bool:
    return psutil is not None


# --------------------------------------------------------------------------- #
#  Suspect identification
# --------------------------------------------------------------------------- #


def identify_suspects(config: Config, limit: int = 5, confirm_top: int = 12) -> List[Suspect]:
    """Rank running processes by how much they look like the encrypter.

    Two passes for speed: a *cheap* pass scores every process on write I/O and
    age (no handle enumeration), then we confirm only the top candidates with
    ``open_files()`` -- which is expensive on Windows (~100ms/process) -- and
    add the strong "open handle inside a protected path" signal. An active
    encrypter writes constantly, so it ranks at the top of the cheap pass and
    is confirmed first; bounding ``confirm_top`` keeps total latency to ~1-2s
    so the response lands while the attack is still in progress.
    """
    if psutil is None:
        return []
    self_pid = os.getpid()
    parent_pid = os.getppid()
    roots = config.watched_paths
    now = utils.now_ts()

    # -- cheap pass: write I/O + recency, no handle enumeration --
    prelim: List[tuple] = []
    for proc in psutil.process_iter(["pid", "name"]):
        pid = proc.info.get("pid")
        name = (proc.info.get("name") or "").lower()
        if pid in (self_pid, parent_pid, 0) or name in CRITICAL_PROCS:
            continue
        score = 0
        evidence: List[str] = []
        try:
            io = proc.io_counters()
            if io.write_bytes > 1_000_000:
                score += min(int(io.write_bytes / 1_000_000), 40)
                evidence.append(f"{utils.human_size(io.write_bytes)} written")
        except Exception:
            pass
        try:
            age = now - proc.create_time()
            if age < 180:
                score += 15
                evidence.append(f"started {int(age)}s ago")
        except Exception:
            pass
        prelim.append((score, proc, evidence))

    prelim.sort(key=lambda t: t[0], reverse=True)

    # -- confirm pass: handle enumeration only for the top candidates --
    suspects: List[Suspect] = []
    for score, proc, evidence in prelim[:confirm_top]:
        try:
            open_files = proc.open_files()
        except Exception:
            open_files = []
        hits = [f.path for f in open_files if utils.is_within(f.path, roots)]
        actionable = bool(hits)
        if hits:
            score += 60 + min(len(hits), 20) * 5
            evidence = evidence + [f"{len(hits)} open handle(s) in protected paths"]
        if score <= 0:
            continue
        try:
            cmdline = " ".join(proc.cmdline())
        except Exception:
            cmdline = ""
        try:
            info = proc.as_dict(["name", "username", "exe"])
        except Exception:
            info = {}
        suspects.append(
            Suspect(
                pid=proc.pid,
                name=info.get("name") or "?",
                score=score,
                evidence=evidence,
                cmdline=cmdline[:300],
                username=info.get("username") or "",
                exe=info.get("exe") or "",
                actionable=actionable,
            )
        )

    suspects.sort(key=lambda s: s.score, reverse=True)
    return suspects[:limit]


# --------------------------------------------------------------------------- #
#  Desktop alert
# --------------------------------------------------------------------------- #


def _popup(title: str, message: str) -> None:
    """Non-blocking desktop alert (Windows MessageBox), best effort."""
    if os.name != "nt":
        return

    def _show():
        try:
            import ctypes

            # MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x10 | 0x1000 | 0x10000)
        except Exception:
            pass

    threading.Thread(target=_show, daemon=True).start()


# --------------------------------------------------------------------------- #
#  Lockdown (read-only) of affected directories
# --------------------------------------------------------------------------- #


def _set_readonly(path: str, on: bool) -> bool:
    try:
        if os.name == "nt":
            import ctypes

            attr = _READONLY if on else _NORMAL
            return bool(ctypes.windll.kernel32.SetFileAttributesW(str(path), attr))
        mode = 0o444 if on else 0o644
        os.chmod(path, mode)
        return True
    except Exception:
        return False


def lockdown(paths: Paths, target_dirs: List[str]) -> int:
    """Mark every file under ``target_dirs`` read-only. Returns file count.
    The set of locked files is recorded so :func:`unlock` can revert it."""
    locked: List[str] = []
    for d in target_dirs:
        d = utils.normpath(d)
        base = d if os.path.isdir(d) else os.path.dirname(d)
        for f in utils.iter_files([base]):
            if _set_readonly(f, True):
                locked.append(f)
    if locked:
        paths.ensure()
        state_file = os.path.join(paths.root, "lock_state.json")
        existing = []
        if os.path.exists(state_file):
            try:
                with open(state_file, "r", encoding="utf-8") as fh:
                    existing = json.load(fh)
            except Exception:
                existing = []
        merged = sorted(set(existing) | set(locked))
        with open(state_file, "w", encoding="utf-8") as fh:
            json.dump(merged, fh)
    return len(locked)


def _suspended_state_file(paths: Paths) -> str:
    return os.path.join(paths.root, "suspended.json")


def _record_suspended(paths: Paths, pid: int) -> None:
    """Persist a suspended PID so it can be resumed after GreyRun exits."""
    f = _suspended_state_file(paths)
    pids = []
    if os.path.exists(f):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                pids = json.load(fh)
        except Exception:
            pids = []
    if pid not in pids:
        pids.append(pid)
        try:
            with open(f, "w", encoding="utf-8") as fh:
                json.dump(pids, fh)
        except OSError:
            pass


def resume_suspended(paths: Paths) -> int:
    """Resume every process GreyRun previously suspended."""
    f = _suspended_state_file(paths)
    if not os.path.exists(f) or psutil is None:
        return 0
    try:
        with open(f, "r", encoding="utf-8") as fh:
            pids = json.load(fh)
    except Exception:
        pids = []
    resumed = 0
    for pid in pids:
        try:
            psutil.Process(pid).resume()
            resumed += 1
        except Exception:
            pass
    try:
        os.remove(f)
    except OSError:
        pass
    return resumed


def unlock(paths: Paths) -> int:
    """Revert a previous lockdown."""
    state_file = os.path.join(paths.root, "lock_state.json")
    if not os.path.exists(state_file):
        return 0
    try:
        with open(state_file, "r", encoding="utf-8") as fh:
            locked = json.load(fh)
    except Exception:
        return 0
    count = 0
    for f in locked:
        if _set_readonly(f, False):
            count += 1
    try:
        os.remove(state_file)
    except OSError:
        pass
    return count


# --------------------------------------------------------------------------- #
#  Forensics capture
# --------------------------------------------------------------------------- #


def capture_forensics(paths: Paths, suspects: List[Suspect], assessment: Assessment) -> Optional[str]:
    utils.ensure_dir(paths.forensics)
    stamp = utils.iso().replace(":", "").replace("-", "")
    out = os.path.join(paths.forensics, f"incident_{stamp}.json")
    record = {
        "captured": utils.iso(),
        "assessment": {
            "score": assessment.score,
            "level": assessment.level,
            "reasons": assessment.reasons,
            "suspect_paths": assessment.suspect_paths,
            "families": assessment.families,
            "changed_count": assessment.changed_count,
        },
        "suspects": [],
    }
    for s in suspects:
        entry = {
            "pid": s.pid, "name": s.name, "score": s.score,
            "evidence": s.evidence, "cmdline": s.cmdline,
            "username": s.username, "exe": s.exe,
        }
        if psutil is not None:
            try:
                p = psutil.Process(s.pid)
                entry["parent"] = p.ppid()
                entry["open_files"] = [f.path for f in p.open_files()][:50]
                # net_connections() on modern psutil; connections() on older.
                get_conns = getattr(p, "net_connections", None) or p.connections
                entry["connections"] = [
                    f"{c.laddr}->{c.raddr}" for c in get_conns() if c.raddr
                ][:20]
            except Exception:
                pass
        record["suspects"].append(entry)
    try:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, default=str)
        return out
    except OSError:
        return None


# --------------------------------------------------------------------------- #
#  The responder
# --------------------------------------------------------------------------- #


class Responder:
    """Turns an :class:`Assessment` into containment actions, honouring policy
    (``config.response_mode``) and never acting twice on the same PID."""

    def __init__(self, config: Config, paths: Paths):
        self.config = config
        self.paths = paths
        self._suspended: set = set()
        self._killed: set = set()
        self._alerted_level: str = ""
        self._lock = threading.Lock()
        self.incident_file: Optional[str] = None

    def _suspend(self, suspects: List[Suspect]) -> List[str]:
        actions = []
        if psutil is None:
            return actions
        for s in suspects:
            if not s.actionable:  # never suspend on weak (I/O-only) evidence
                continue
            if s.pid in self._suspended or s.name.lower() in CRITICAL_PROCS:
                continue
            try:
                psutil.Process(s.pid).suspend()
                self._suspended.add(s.pid)
                _record_suspended(self.paths, s.pid)
                actions.append(f"suspended {s.name} (pid {s.pid})")
                console.audit("suspend", pid=s.pid, name=s.name, score=s.score)
            except Exception as exc:
                actions.append(f"failed to suspend pid {s.pid}: {exc}")
        return actions

    def _terminate(self, suspects: List[Suspect]) -> List[str]:
        actions = []
        if psutil is None:
            return actions
        grace = self.config.kill_grace_seconds
        for s in suspects:
            if not s.actionable:  # never terminate on weak (I/O-only) evidence
                continue
            if s.pid in self._killed or s.name.lower() in CRITICAL_PROCS:
                continue
            try:
                p = psutil.Process(s.pid)
                p.terminate()
                try:
                    p.wait(timeout=grace)
                except Exception:
                    p.kill()
                self._killed.add(s.pid)
                actions.append(f"terminated {s.name} (pid {s.pid})")
                console.audit("terminate", pid=s.pid, name=s.name, score=s.score)
            except Exception as exc:
                actions.append(f"failed to terminate pid {s.pid}: {exc}")
        return actions

    def handle(self, assessment: Assessment) -> List[str]:
        """React to an assessment. Returns a list of human-readable actions."""
        actions: List[str] = []
        mode = self.config.response_mode
        level = assessment.level

        with self._lock:
            if level == ALERT and self._alerted_level != ALERT:
                self._alerted_level = ALERT
                self._fire_alert(assessment, actions)

            if level in (DEFEND, CRITICAL):
                if self._alerted_level not in (DEFEND, CRITICAL):
                    self._fire_alert(assessment, actions)
                    self._alerted_level = level

                # "monitor" mode is strictly observe-and-alert: no process
                # control, no file changes. All containment requires defend/kill.
                if mode == "monitor":
                    return actions

                suspects = identify_suspects(self.config)
                if self.incident_file is None:
                    self.incident_file = capture_forensics(
                        self.paths, suspects, assessment
                    )
                    if self.incident_file:
                        actions.append(f"forensics captured -> {self.incident_file}")

                # If nothing is caught red-handed (encrypters often hold each
                # file open only briefly), report busy processes for review but
                # do NOT auto-contain on that weak evidence.
                if suspects and not any(s.actionable for s in suspects):
                    review = ", ".join(f"{s.name}(pid {s.pid})" for s in suspects[:3])
                    actions.append(f"no process caught with open protected-file "
                                   f"handles; for review: {review}")

                actions += self._suspend(suspects)  # defend and kill both suspend

                if level == CRITICAL:
                    if mode == "kill":
                        actions += self._terminate(suspects)
                    if self.config.auto_lockdown:
                        actions += self._contain(assessment)

            for a in actions:
                console.audit("response", action=a, level=level, score=assessment.score)
        return actions

    def _contain(self, assessment: Assessment) -> List[str]:
        """Contain the affected directories per the configured method:
        read-only lockdown, quarantine of artifacts, or both."""
        actions: List[str] = []
        method = self.config.containment
        dirs = list({os.path.dirname(p) for p in assessment.suspect_paths if p != "*"})
        dirs = dirs or list(self.config.watched_paths)

        if method in ("lockdown", "both"):
            n = lockdown(self.paths, dirs)
            if n:
                actions.append(f"locked down {n} files (read-only)")

        if method in ("quarantine", "both"):
            from . import quarantine as quarantine_mod

            scope = Config(watched_paths=dirs, exclude_dirs=self.config.exclude_dirs)
            items = quarantine_mod.find_artifacts(scope)
            if items:
                res = quarantine_mod.quarantine_files(self.paths, items)
                actions.append(f"quarantined {res.moved} artifact(s) -> batch {res.batch_id}")
                console.audit("quarantine", batch=res.batch_id, moved=res.moved)
        return actions

    def _fire_alert(self, assessment: Assessment, actions: List[str]) -> None:
        title = f"GreyRun: {assessment.level} threat (score {assessment.score})"
        body = "Possible ransomware activity detected.\n\n" + "\n".join(
            assessment.reasons[:6]
        )
        if assessment.families:
            body += "\n\nLikely family: " + ", ".join(assessment.families)
        console.plain("\a")  # terminal bell
        if self.config.desktop_notifications:
            _popup(title, body)
        actions.append("raised desktop + console alert")

        # Off-box notifications for real incidents only (DEFEND/CRITICAL).
        if assessment.level in (DEFEND, CRITICAL):
            from . import notify

            for result in notify.dispatch(self.config, assessment, actions):
                actions.append(result)
