# Changelog

All notable changes to GreyRun are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [1.1.3] — 2026-07-05

### Security
- **Webhook redirects are refused.** The SSRF guard checked the configured
  URL's host but the HTTP client then followed redirects, so a malicious
  endpoint could 302-bounce the alert payload (hostname, file paths) to a
  blocked address such as the cloud-metadata service.

### Fixed
- **Alerts re-arm after a threat decays.** Previously the desktop popup,
  off-box alert and forensics capture fired at most once per monitor run; a
  second, separate incident hours later would escalate silently. Once the risk
  score returns to zero the one-shot guards reset (checked from both the event
  path and the heartbeat, since a contained attacker stops generating events).
- Response coalescing now tracks every in-flight response (a finishing
  response — of any severity, in either order — can no longer drop the guard
  while another is still running), and re-arming is refused while a response
  is in flight or the last response is younger than the burst window.
- `quarantine run` and auto-quarantine containment now honour the configured
  `entropy_threshold`; the auto-containment scope is a full policy copy
  (`dataclasses.replace`) so future config fields can't be silently dropped.
- Backup snapshots, quarantine batches **and forensics captures** created
  within the same second get distinct IDs instead of overwriting/merging
  (timestamp IDs have 1s resolution). The ID is claimed atomically (O_EXCL
  create / mkdir), so concurrent runs — even separate processes — can't
  collide, and `restore latest` resolves suffixed IDs in true chronological
  order.

### Changed / Hardened
- `Config.load` type-checks every field against its default (a hand-edited
  `watched_paths` string no longer silently breaks protection); numeric fields
  coerce int/float, boolean fields accept hand-edited `0`/`1`.
- The live engine skips the entropy read (up to 256 KB from disk) for files
  that already scored in the current window.
- The monitor's escalation guards are updated under its lock (the heartbeat
  thread now also reads them), and a corrupt/partial snapshot manifest is
  reported as not-found instead of crashing restore.
- Tests: +11 (rearm ×2, webhook redirect, quarantine threshold, config
  validation ×3, ID uniqueness ×3, latest-resolution order). 48 passing.

## [1.1.2] — 2026-06-27

A second review pass found and fixed real bugs the earlier reviews missed.

### Security
- **Quarantine restore** now refuses to write outside the recorded watched
  roots, closing a write-anywhere primitive driven by a tampered manifest
  (matches the existing `backup` restore guard).
- Webhook **SSRF guard** broadened to block reserved/multicast/unspecified
  addresses as well as the link-local cloud-metadata address.
- Process response **fails closed**: it will not suspend/terminate a PID whose
  start time or owner can't be verified at action time.

### Fixed
- `is_within` now correctly contains the children of a drive/filesystem root
  (`C:\` or `/`). Previously, protecting a whole drive silently disabled
  detection, auto-containment, and restore for that drive.
- Removed `important.txt`/`attention.txt` from the ransom-note name list — too
  common as benign filenames.

### Changed
- The responder runs its slow work (suspect scan, suspend, lockdown/quarantine)
  outside its lock, so a CRITICAL response is never serialized behind a slower
  in-flight DEFEND pass.
- Tests: +4 (quarantine out-of-root restore, filesystem-root containment,
  fail-closed response, ransom-note false positive). 37 passing.

## [1.1.1] — 2026-06-27

### Fixed
- CI: byte-compile step uses `compileall` (a directory argument) instead of a
  `*.py` glob, which the Windows PowerShell shell did not expand — the full
  Windows × Python matrix is now green.

### Changed
- Tone pass over docstrings, comments, and docs: flattened editorial prose to
  terse technical descriptions and collapsed em-dash asides. No functional
  change; the test suite is unchanged.

## [1.1.0] — 2026-06-27

### Added
- **CI/CD** — GitHub Actions test matrix (Windows + Linux, Python 3.9–3.12) and
  a release pipeline that builds artifacts and can publish to PyPI via Trusted
  Publishing.
- Webhook **SSRF guard** — alerts to link-local/cloud-metadata addresses
  (e.g. `169.254.169.254`) are refused.
- `MIT` LICENSE, `SECURITY.md`, `CHANGELOG.md`, and project URLs in metadata.

### Changed / Hardened
- Responder now **re-validates a suspect immediately before acting** — defeats
  PID reuse (start-time check) and refuses to suspend/terminate processes owned
  by another user or SYSTEM.
- Off-box alerts are sent on a **background thread** so a slow webhook/SMTP can
  never stall the containment response.
- **Lockdown is capped** (default 20k files) and `recover` now reports a corrupt
  lock-state file instead of silently doing nothing.
- `Config.load` validates `response_mode`/`containment` so a hand-edited config
  can't smuggle an invalid policy past the `set` command.
- Simulator per-iteration guard resolves symlinks (`realpath`) before its
  in-sandbox check.

## [1.0.0] — 2026-06-27

Initial release.

### Detection
- Canary honeypots (planted to be hit first by an encryption sweep).
- Shannon-entropy analysis (documents that read as random).
- Behavioural burst detection over a sliding window.
- Known ransomware extension + ransom-note signatures.

### Response & recovery
- Identify and suspend → terminate the encrypter — only processes proven to
  hold an open handle inside a protected path (no false kills).
- Read-only lockdown and/or quarantine of artifacts; forensic incident capture.
- Content-addressed, deduplicated backup/restore vault.
- Off-box alerting via webhook (Slack/Discord/Teams) and email.
- Logon autostart (scheduled task when elevated, else Startup-folder launcher).
- Safe, sandboxed attack simulator for drills.
- `gr` short CLI alias and `exclude` command for skipping noisy folders.

[1.1.3]: https://github.com/GreyNOC/GreyRun/releases/tag/v1.1.3
[1.1.2]: https://github.com/GreyNOC/GreyRun/releases/tag/v1.1.2
[1.1.1]: https://github.com/GreyNOC/GreyRun/releases/tag/v1.1.1
[1.1.0]: https://github.com/GreyNOC/GreyRun/releases/tag/v1.1.0
[1.0.0]: https://github.com/GreyNOC/GreyRun/releases/tag/v1.0.0
