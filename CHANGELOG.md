# Changelog

All notable changes to GreyRun are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [1.2.0] — 2026-07-10

Detection-engine overhaul: four new detectors close the engine's biggest
blind spots, and risk scoring is now corroboration-based, which removes three
paths where benign workloads could reach kill-level responses.

### Added
- **Header (magic-byte) validation** (`greyrun/filetypes.py`). A file whose
  extension promises a verifiable format (docx/xlsx/zip/jpg/png/pdf/mp4, ~30
  more) but whose head matches *no* known format and reads as ciphertext is
  flagged — this covers exactly the high-entropy formats the entropy detector
  must skip, i.e. ransomware that encrypts in place and keeps filenames.
  Guards: a write-settle debounce (never reads a file mid-save), a
  known-format sweep (a PNG saved as `.jpg` is misnamed, never a victim), and
  a cipher-likeness gate (zero-filled preallocations don't count).
- **Chi-square byte statistics** fused into the entropy pass. Shannon entropy
  cannot tell encrypted from compressed; the chi-square test against the
  uniform distribution can (ciphertext ~255 on 255 degrees of freedom,
  compressed data lands far above). The `encrypted` signal now requires both,
  raising its precision and its weight (20 → 30).
- **Ransom-note content scoring** (`greyrun/notecontent.py`). Small text-like
  files are scored across independent topics (payment, contact channel,
  threat phrases, instructions) plus checksum-validated payment anchors
  (base58check Bitcoin addresses, v3 onion hosts). A note named `README.txt`
  is now caught by its body; a crypto-news article (one topic) or a wallet
  backup (address, no prose) never fires. Handles UTF-16 notes and HTML/RTF
  markup.
- **Stranded double-extension detector**: a document extension buried under
  an unknown suffix (`invoice.docx.k8s3x`) whose content reads as ciphertext
  fires on the *first* victim file — no signature needed for novel strains.
- **Rename clustering**: many files gaining the *same* unknown extension in
  one window is the novel-family tell; scores as context that accelerates
  real sweeps but can never escalate a bulk-rename script past ALERT.
- **Sustained memory**: strong per-file evidence is remembered for 30 minutes
  (configurable), so a slow encryptor that rewrites one file every couple of
  minutes — previously invisible, since each hit decayed out of the 60s
  window — now accumulates to DEFEND by its third file.
- **Scan-side entropy jump**: a baselined low-entropy file that now reads as
  ciphertext is flagged regardless of extension (catches `.dat`/no-ext
  victims at scan time).
- **Burst split**: rewriting existing files (the sweep shape) scores the full
  burst weight; creates-only storms (archive extraction, initial sync, photo
  import) score a fraction of it.
- New tunables: `chi2_max`, `entropy_jump_min`, `header_check`,
  `header_settle_sec`, `header_min_size`, `canary_recheck_sec`,
  `ext_cluster_count`, `count_transient_in_burst`, `memory_window_sec`,
  `sustained_content_min`, `note_scan_max_bytes`. Existing `config.json`
  files load unchanged.

### Changed
- **Scoring is corroboration-based, not a flat sum.** Signals belong to
  classes (canary / content / note / volume); every kind except a modified
  canary is capped below the DEFEND threshold, the note class is capped so
  one file of prose can never kill a process, and volume evidence (bursts,
  mass deletes) escalates past ALERT only when content-, note- or
  canary-class evidence agrees. One noisy detector can warn you but never
  fight back alone.
- **Tiered canary verdicts.** Only an in-place *modification* of a decoy is
  decisive (100). A missing/unreadable canary (60) needs one corroborator and
  is re-verified after a beat so sync/backup races never count; a moved
  folder or a OneDrive Files-On-Demand dehydration scores zero.
- **Generic extensions demoted.** `.enc`/`.locked`-style suffixes that
  everyday tools also produce are weak context alone (three `backup.enc`
  files used to score 105 = kill; now 20 = WATCH), but stacked over a real
  document extension (`report.docx.enc`) they score as content evidence.
  Family-specific suffixes (`.lockbit`, `.wncry`) score higher than before.
- **Transient files suppressed.** Office save dances (`~$x`, `*.tmp`),
  browser download shards and lock files no longer feed any per-file detector
  or (by default) the burst counter; their deletions still count, so a wiper
  stays visible.
- Renamed victims are now content-checked (the old `elif` chain skipped
  entropy on any note-named or renamed file), and `moved` events use the
  *source* name's entropy class.

### Fixed
- **Removed the `~$financial_statements.xlsx` canary name.** Office claims
  `~$<name>` for owner-lock files: opening a similarly named workbook next to
  the canary silently replaced it — an instant decisive-signal false
  positive. Existing deployments migrate on the next `init`/`canary deploy`
  (the old file is deleted only if its content still hashes to the canary
  body).
- A git checkout / branch switch (volume evidence only) could reach DEFEND
  and suspend `git.exe`; it now tops out at ALERT.
- Same-file signals dedupe per kind but corroborate: two *independent*
  indicators on one file earn a small capped bonus instead of unbounded
  stacking.

### Hardened (post-review)
An adversarial multi-agent review of the new engine confirmed and fixed a
further round of issues before release:

- A Bitcoin donation footer in a project README (valid address + "contact us
  via …") scored as a *strong* ransom note; the note scorer now treats a
  payment anchor as payment-topic evidence (not its own topic) and only
  counts extortion-framed prose — "files are encrypted **at rest**", "the
  price doubled in 24 hours" and generic support phrases no longer match.
- Displaced-canary tracking: a canary *renamed* with content intact scores 60
  and its new name stays watched, so rename-first strains that encrypt the
  decoy a moment later still trip the decisive 100; a canary rewritten under
  a rename is decisive immediately.
- The sustained-memory signal counts *distinct files* (one repeatedly
  re-saved file no longer accumulates) and its weight grows with the file
  count (25 → 45), so a paced sweep of plain documents now reaches DEFEND by
  its fifth victim instead of plateauing at ALERT.
- A creates-only storm no longer pins the burst throttle and mutes the
  stronger rewrite-burst that a real sweep earns moments later.
- `mass_delete` counts distinct paths, so one churning journal file (or
  duplicated OS delete events) can't read as a mass deletion.
- `cipher_like` rejects samples too small for the chi-square test instead of
  accepting them on entropy alone (a 3.5 KB compressed fragment cleared the
  entropy bar and read as ciphertext).
- Live rename-clustering now requires the same cipher confirmation as the
  scan path — a data pipeline emitting healthy batches under a novel
  extension no longer alerts.
- User-run encryption suffixes `.age`, `.aes`, `.axx`, `.cpt`, `.kdbx` are
  recognized as benign wrappers (age/rage output previously scored DEFEND).
- The bare MPEG frame-sync heuristic validated only 11 bits and waved ~1 in
  2048 ciphertext heads through header validation; it now validates the full
  frame header.
- `.sqlite` removed from header validation: SQLCipher databases are
  legitimately ciphertext from byte 0.
- Note decoding handles BOM-less UTF-16-BE and no longer misdecodes
  zero-padded UTF-8 as UTF-16.

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
