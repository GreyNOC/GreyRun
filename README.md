# GreyRun — behaviour-based ransomware shield

[![CI](https://github.com/GreyNOC/GreyRun/actions/workflows/ci.yml/badge.svg)](https://github.com/GreyNOC/GreyRun/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GreyNOC/GreyRun)](https://github.com/GreyNOC/GreyRun/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

GreyRun is a defensive command-line tool that **detects, contains and helps you
recover from ransomware** by watching your important folders for the *behaviour*
of an encryption attack rather than relying on a virus signature for a specific
strain. When it sees that behaviour it can alert you, freeze the offending
process, lock the affected folders and — because the real cure for ransomware is
a good backup — restore your files from its own protected vault.

> **Defensive use only.** GreyRun protects *your own* machine and data. It
> contains a *safe, sandboxed* attack simulator for testing — it never produces,
> deploys, or spreads real malware.

---

## Why behaviour, not signatures?

New ransomware strains appear daily, so a signature for "WannaCry" or "LockBit"
always lags the latest variant. Almost all ransomware behaves the same way:

* it sweeps through a folder opening and rewriting many files quickly,
* the rewritten files become **high-entropy** (encrypted data looks random),
* it **appends a new extension** (`.locked`, `.wncry`, …) and
* it **drops a ransom note** (`HOW_TO_DECRYPT.txt`).

GreyRun watches for exactly those tells. Five independent detectors feed one
risk score:

| Detector | Signal | Strength |
|---|---|---|
| **Canary honeypots** | A decoy file is modified/renamed/deleted | Decisive |
| **Entropy analysis** | A document suddenly reads as random bytes | High |
| **Behavioural burst** | Many files changed in a short window | High |
| **Extension signatures** | Known ransomware suffix appears | Medium |
| **Ransom-note detection** | A note-like filename appears | Medium |

No single weak signal trips a response; they accumulate, and the strongest
(a touched canary) is on its own enough to act.

---

## Install

GreyRun works on the standard library alone, but two packages make it much
stronger — `psutil` (process containment) and `watchdog` (efficient file
events):

```bash
pip install -r requirements.txt        # recommended
# or, to install GreyRun as a `greyrun` command:
pip install -e ".[full]"
```

After installing, two commands are registered — the full `greyrun` and the
short **`gr`**:

```bash
gr status
gr monitor
gr scan
```

You can also run it without installing, from this folder:

```bash
python -m greyrun <command>
# Windows: greyrun.bat <command>
```

---

## 60-second demo (completely safe)

See every detector and the response fire end-to-end inside a throwaway sandbox.
Nothing outside the sandbox is ever touched:

```bash
python -m greyrun simulate demo
```

You'll watch GreyRun create decoy documents, scan them clean, run a *simulated*
encryption sweep, and then catch it at **CRITICAL** with the canary, extension,
entropy and ransom-note detectors all lighting up.

---

## Quickstart (protect for real)

```bash
# 1. Protect your important folders (auto-adds Desktop & Documents),
#    plant canaries and record an integrity baseline:
python -m greyrun init

#    …or choose folders explicitly:
python -m greyrun protect "C:\Users\me\Documents" "D:\Projects"

# 2. Take a protected backup snapshot (do this regularly!):
python -m greyrun backup

# 3. Run the real-time shield (leave it running):
python -m greyrun monitor

# 4. Any time, run a one-shot check:
python -m greyrun scan
```

> **Tip — protect document stores, not giant code trees.** GreyRun is built for
> folders of documents/photos. If a protected folder contains a large, busy dev
> project (tens of thousands of files), `baseline`/`backup` get slow and normal
> file churn can raise harmless "burst" ALERTs. Either protect a more targeted
> folder, or skip the heavy subtree by name:
> ```
> greyrun exclude add "my-big-project" node_modules
> ```
> Canaries planted in the protected folder's root still trip on any sweep, so
> excluding a noisy subfolder doesn't remove your tripwire.

If GreyRun ever contains an incident, recover with:

```bash
python -m greyrun recover           # resume frozen processes + lift folder lockdown
python -m greyrun restore latest    # roll files back from the vault
```

---

## How the response works

When the risk score crosses a threshold, GreyRun escalates through levels
(`WATCH → ALERT → DEFEND → CRITICAL`) and acts according to the configured
**response mode**:

| Mode | What it does on a high-confidence attack |
|---|---|
| `monitor` | Observe and **alert only** — no changes to processes or files |
| `defend` *(default)* | Alert, capture forensics, **suspend** the attacker, contain the hit folders |
| `kill` | Everything in `defend`, and **terminate** the attacker after a grace period |

```bash
python -m greyrun monitor --mode kill        # most aggressive
python -m greyrun set response_mode defend   # persist a default
```

**Containment method** — what happens to the affected folders in `defend`/`kill`:

| `containment` | Effect |
|---|---|
| `lockdown` *(default)* | Mark the hit folders **read-only** so encryption can't continue |
| `quarantine` | **Move** the attack's artifacts (`.locked` files, ransom notes) into the vault |
| `both` | Lock down *and* quarantine |

```bash
python -m greyrun set containment quarantine
# Clean up artifacts manually any time (with restore safety net):
python -m greyrun quarantine run          # find & move artifacts
python -m greyrun quarantine list
python -m greyrun quarantine restore latest
```

**Safety guard against false positives:** GreyRun only ever suspends or kills a
process that is **proven to hold an open file handle inside a protected folder**.
A process that merely looks busy (a browser writing its cache, a backup job) is
listed for your review but is *never* auto-contained. A short list of critical
OS processes (and GreyRun itself) is never touched.

Because containment can occasionally freeze a legitimate app that had a
protected file open, every suspension is reversible with `greyrun recover`.

---

## Off-box alerting

Get notified even when you're not at the console. On a real incident
(`DEFEND`/`CRITICAL`) GreyRun can POST to a **webhook** and/or send **email**:

```bash
# Slack / Discord / Teams / generic webhook (payload includes a Slack-style "text"):
python -m greyrun set webhook_url "https://hooks.slack.com/services/XXX/YYY/ZZZ"

# Email over SMTP (keep the password in an env var, not the config file):
python -m greyrun set smtp_host smtp.gmail.com
python -m greyrun set smtp_from you@example.com
python -m greyrun set smtp_to   you@example.com
$env:GREYRUN_SMTP_PASSWORD = "app-password"        # PowerShell

python -m greyrun test-alert                        # verify your channels
```

The webhook URL and SMTP password can also be supplied via `GREYRUN_WEBHOOK_URL`
and `GREYRUN_SMTP_PASSWORD` so no secrets touch `config.json`.

> **What gets sent:** the alert payload contains this machine's **hostname** and
> **absolute paths** of the affected files (plus threat level, score, and the
> likely family). Point it only at endpoints you trust, and prefer an `https://`
> webhook — a plain `http://` URL sends that data in cleartext and GreyRun will
> warn you.

## Run automatically at logon (Windows)

```bash
python -m greyrun autostart enable     # from an Administrator shell
python -m greyrun autostart status
python -m greyrun autostart disable
```

`enable` registers a logon-triggered Scheduled Task that launches the monitor
with highest privileges (so it can act on processes it doesn't own). It needs an
Administrator console; on other platforms GreyRun prints a ready-to-use cron
line instead.

---

## Command reference

| Command | Purpose |
|---|---|
| `init [paths…]` | Set up protection: add folders, plant canaries, build baseline |
| `protect <dirs…>` / `unprotect <dirs…>` | Add / remove protected folders |
| `exclude add\|remove\|list <name>` | Skip subfolders by name (e.g. big dev trees) |
| `status` | Show configuration, canaries, baseline, backups, capabilities |
| `scan` | One-shot risk scan (exit code reflects threat level) |
| `monitor [--mode] [--no-notify]` | Real-time protection |
| `baseline [--update]` | Build/refresh the file-integrity baseline |
| `canary deploy\|check\|clear` | Manage honeypot files |
| `backup` / `snapshots` / `restore [id] [--into dir]` | Protected backup vault |
| `quarantine run\|list\|restore` | Move ransomware artifacts to a safe holding area |
| `recover` | Resume suspended processes and lift folder lockdown |
| `test-alert` | Send a test alert through configured channels |
| `autostart enable\|disable\|status` | Run the monitor at logon (Windows) |
| `set <key> <value>` | Tune any policy value (thresholds, mode, channels, …) |
| `simulate setup\|attack\|demo\|cleanup` | Safe sandboxed drill |

Scan exit codes: `0` clean/low, `2` ALERT, `3` DEFEND, `4` CRITICAL — handy for
scripting and scheduled checks.

---

## State & where things live

Everything GreyRun stores lives under `~/.greyrun` (override with the
`GREYRUN_HOME` environment variable — point it at an external/separate drive to
keep the backup vault out of an attacker's reach):

```
~/.greyrun/
  config.json        policy & protected paths
  baseline.json      known-good file hashes/entropy
  canaries.json      canary registry
  events.jsonl       structured audit log (every event & response)
  forensics/         per-incident process snapshots
  quarantine/        moved ransomware artifacts (restorable)
  vault/             content-addressed backup snapshots (deduped, read-only)
```

---

## Architecture

```
cli ──► config
        ├─ canary      honeypot deploy / verify / tamper-check
        ├─ baseline    integrity manifest + drift diff
        ├─ entropy     Shannon-entropy / "looks encrypted?"
        ├─ signatures  ransomware extensions & ransom-note names
        ├─ detector    scan() + BehaviorEngine (windowed risk scoring)
        ├─ monitor     watchdog/polling → detector → responder
        ├─ responder   identify → suspend → terminate → contain → forensics
        ├─ quarantine  move/restore ransomware artifacts
        ├─ notify      webhook + email alerting
        ├─ service     logon autostart (scheduled task)
        ├─ backup      content-addressed vault + restore
        └─ simulator   SAFE sandboxed attack drill
```

Run the tests with:

```bash
python -m unittest discover -s tests
```

---

## Honest limitations

GreyRun is an additional layer, not a complete defense:

* It reduces damage by catching an attack mid-sweep, but some files may be lost
  before detection. Keep **offline/immutable backups** as well; the built-in
  vault is a fast local rollback, not a replacement for 3-2-1 backups.
* Read-only **lockdown** stops naive encrypters, but one running as your user
  can clear the attribute. The process **suspend/kill** is the hard stop, and
  that needs `psutil`.
* Detecting an attacker by its open handles can miss strains that hold each file
  open only briefly. The other layers (canaries, entropy, lockdown, backups)
  cover that gap.
* For automatic process termination, run GreyRun elevated (Administrator) so it
  can act on processes it doesn't own.

Keep your OS patched, keep offline backups, and run GreyRun as one more layer.
