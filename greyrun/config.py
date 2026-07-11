"""Configuration and on-disk state locations for GreyRun.

State lives under ``~/.greyrun`` by default (override with the ``GREYRUN_HOME``
environment variable, which is handy for tests and for keeping the protection
state on a separate, ideally read-only or external, volume).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import List, Optional

from .utils import DEFAULT_EXCLUDE_DIRS, ensure_dir, normpath


def home_dir() -> str:
    override = os.environ.get("GREYRUN_HOME")
    if override:
        return normpath(override)
    return normpath(os.path.join(os.path.expanduser("~"), ".greyrun"))


class Paths:
    """Resolved locations of every file GreyRun persists."""

    def __init__(self, root: Optional[str] = None):
        self.root = normpath(root) if root else home_dir()
        self.config = os.path.join(self.root, "config.json")
        self.baseline = os.path.join(self.root, "baseline.json")
        self.canaries = os.path.join(self.root, "canaries.json")
        self.audit_log = os.path.join(self.root, "events.jsonl")
        self.vault = os.path.join(self.root, "vault")
        self.quarantine = os.path.join(self.root, "quarantine")
        self.forensics = os.path.join(self.root, "forensics")

    def ensure(self) -> "Paths":
        ensure_dir(self.root)
        return self


@dataclass
class Config:
    """User-tunable policy. Conservative, low-false-positive defaults."""

    watched_paths: List[str] = field(default_factory=list)
    exclude_dirs: List[str] = field(default_factory=lambda: sorted(DEFAULT_EXCLUDE_DIRS))

    # --- detection tuning ---
    entropy_threshold: float = 7.8
    burst_count: int = 25          # files changed ...
    burst_window_sec: float = 60.0  # ... within this many seconds = a burst
    canaries_per_dir: int = 3
    max_hash_bytes: int = 64 * 1024 * 1024  # prefix-hash files larger than this
    # Chi-square-vs-uniform ceiling for "reads as ciphertext" (ciphertext ~255,
    # compressed data lands well above; see entropy.py).
    chi2_max: float = 320.0
    # Scan-only: flag a baselined low-entropy file whose entropy rose at least
    # this much and now reads as ciphertext.
    entropy_jump_min: float = 2.0
    # Header (magic-byte) validation of formats the entropy check must skip.
    header_check: bool = True
    header_settle_sec: float = 2.0   # quiet time before reading (skip mid-writes)
    header_min_size: int = 512       # smaller heads prove nothing
    # A missing canary is re-verified after this long before scoring, so a
    # sync/backup race that briefly removes it never counts.
    canary_recheck_sec: float = 0.3
    # Distinct files gaining the same unknown extension within the burst
    # window before the rename-cluster signal fires.
    ext_cluster_count: int = 12
    # Transient working files (~$x, *.tmp, *.part) never feed per-file
    # detectors; count them toward the change burst only if enabled here.
    count_transient_in_burst: bool = False
    # Long memory for strong per-file evidence: N hits within this window add
    # a "sustained" signal so a slow encryptor can't hide between bursts.
    # 0 disables.
    memory_window_sec: float = 1800.0
    sustained_content_min: int = 3
    # Ransom-note content scoring reads text-like files up to this size.
    note_scan_max_bytes: int = 32768

    # --- risk scoring -> response escalation (points) ---
    alert_score: int = 40    # surface a warning
    defend_score: int = 70   # suspend the suspected process
    kill_score: int = 100    # terminate + lock down

    # --- response policy ---
    # monitor: alert only | defend: suspend | kill: terminate offender
    response_mode: str = "defend"
    auto_lockdown: bool = True       # strip write perms on hit directories
    desktop_notifications: bool = True
    kill_grace_seconds: float = 3.0  # suspend -> wait -> terminate
    # How to contain hit directories: lockdown (read-only), quarantine (move
    # ransomware artifacts to the vault), or both.
    containment: str = "lockdown"

    # --- external alerting (optional) ---
    # A webhook URL (Slack/Discord/Teams/generic) receives a JSON POST on a
    # high-confidence incident. SMTP settings enable email alerts. Secrets may
    # be supplied via env vars GREYRUN_WEBHOOK_URL / GREYRUN_SMTP_PASSWORD.
    webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    smtp_tls: bool = True

    # --- bookkeeping ---
    version: int = 1

    def add_path(self, path: str) -> bool:
        p = normpath(path)
        if p in self.watched_paths:
            return False
        self.watched_paths.append(p)
        return True

    def remove_path(self, path: str) -> bool:
        p = normpath(path)
        if p in self.watched_paths:
            self.watched_paths.remove(p)
            return True
        return False

    # --- persistence ---
    @classmethod
    def load(cls, paths: Paths) -> "Config":
        if not os.path.exists(paths.config):
            return cls()
        try:
            with open(paths.config, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return cls()
        defaults = cls()
        known = defaults.__dataclass_fields__  # type: ignore[attr-defined]
        clean = {}
        for key, value in data.items():
            if key not in known:
                continue
            # Type-check against the field's default so a hand-edited config
            # (e.g. watched_paths as a string) degrades to the default value
            # instead of silently breaking scans and monitoring later.
            default = getattr(defaults, key)
            if isinstance(default, bool):
                if isinstance(value, int) and value in (0, 1):
                    value = bool(value)  # accept hand-edited JSON 0/1
                elif not isinstance(value, bool):
                    continue
            elif isinstance(default, (int, float)):
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    continue
                value = type(default)(value)
            elif isinstance(default, str):
                if not isinstance(value, str):
                    continue
            elif isinstance(default, list):
                if not (isinstance(value, list)
                        and all(isinstance(item, str) for item in value)):
                    continue
            clean[key] = value
        cfg = cls(**clean)
        # Validate enums on load so a hand-edited config can't smuggle an
        # invalid policy past the `set` command's checks.
        if cfg.response_mode not in ("monitor", "defend", "kill"):
            cfg.response_mode = "defend"
        if cfg.containment not in ("lockdown", "quarantine", "both"):
            cfg.containment = "lockdown"
        return cfg

    def save(self, paths: Paths) -> None:
        paths.ensure()
        tmp = paths.config + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, indent=2, sort_keys=True)
        os.replace(tmp, paths.config)

    def as_dict(self) -> dict:
        return asdict(self)
