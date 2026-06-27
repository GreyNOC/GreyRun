# Changelog

All notable changes to GreyRun are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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

[1.1.1]: https://github.com/GreyNOC/GreyRun/releases/tag/v1.1.1
[1.1.0]: https://github.com/GreyNOC/GreyRun/releases/tag/v1.1.0
[1.0.0]: https://github.com/GreyNOC/GreyRun/releases/tag/v1.0.0
