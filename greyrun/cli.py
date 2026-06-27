"""Command-line interface for GreyRun."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from typing import List, Optional

from . import __version__, backup as backup_mod, canary as canary_mod
from . import console, detector, simulator, utils
from . import quarantine as quarantine_mod
from . import responder as responder_mod
from .baseline import Baseline
from .config import Config, Paths
from .detector import ALERT, CRITICAL, DEFEND, NONE, WATCH
from .monitor import WATCHDOG, Monitor

_EXIT_BY_LEVEL = {NONE: 0, WATCH: 0, ALERT: 2, DEFEND: 3, CRITICAL: 4}
_LEVEL_COLOR = {NONE: "green", WATCH: "cyan", ALERT: "yellow",
                DEFEND: "magenta", CRITICAL: "red"}


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #


def _require_paths(config: Config) -> bool:
    if not config.watched_paths:
        console.error("No protected paths configured.")
        console.info("Add one with:  greyrun protect <directory>")
        return False
    return True


def _level_badge(level: str) -> str:
    color = _LEVEL_COLOR.get(level, "white")
    return console.paint(f" {level} ", "bg_red" if level == CRITICAL else color, "bold")


def _print_status(config: Config, paths: Paths) -> None:
    console.banner()
    console.rule("STATUS")
    console.plain(f"  State dir       : {paths.root}")
    console.plain(f"  Protected paths : {len(config.watched_paths)}")
    for p in config.watched_paths:
        exists = "✓" if os.path.isdir(p) else "✗ (missing)"
        console.plain("      " + console.paint(f"{exists} {p}", "grey"))
    # Canaries
    reg = canary_mod.registry(paths)
    console.plain(f"  Canaries        : {len(reg)} planted")
    # Baseline
    base = Baseline.load(paths)
    if base:
        console.plain(f"  Baseline        : {len(base)} files (built {base.created})")
    else:
        console.plain("  Baseline        : " + console.paint("none — run `greyrun baseline`", "yellow"))
    # Backups
    snaps = backup_mod.list_snapshots(paths)
    console.plain(f"  Backup snapshots: {len(snaps)}")
    # Policy / capabilities
    console.plain(f"  Response mode   : {config.response_mode}  "
                  f"(alert@{config.alert_score} defend@{config.defend_score} kill@{config.kill_score})")
    console.plain(f"  Containment     : {config.containment}"
                  f"  (auto: {'on' if config.auto_lockdown else 'off'})")
    from . import notify
    channels = notify.channels_configured(config)
    console.plain(f"  Alert channels  : {', '.join(channels) if channels else 'desktop/console only'}")
    proc = "available" if responder_mod.available() else console.paint("UNAVAILABLE (pip install psutil)", "yellow")
    watch = "watchdog" if WATCHDOG else console.paint("polling fallback (pip install watchdog)", "yellow")
    console.plain(f"  Process control : {proc}")
    console.plain(f"  FS events       : {watch}")
    console.plain("")
    console.info("Next:  greyrun scan   ·   greyrun monitor   ·   greyrun simulate demo")


# --------------------------------------------------------------------------- #
#  Commands
# --------------------------------------------------------------------------- #


def cmd_init(args, config: Config, paths: Paths) -> int:
    paths.ensure()
    added = 0
    for p in args.paths or []:
        if config.add_path(p):
            added += 1
    if not config.watched_paths and not args.no_defaults:
        for candidate in ("Desktop", "Documents"):
            full = os.path.join(os.path.expanduser("~"), candidate)
            if os.path.isdir(full) and config.add_path(full):
                added += 1
                console.ok(f"Protecting {full}")
    config.save(paths)
    console.ok(f"Initialised GreyRun state at {paths.root}  (+{added} path(s))")

    if not config.watched_paths:
        console.warn("No paths protected yet. Add one:  greyrun protect <dir>")
        return 0

    if not args.no_canary:
        created, skipped = canary_mod.deploy(config, paths)
        console.ok(f"Canaries: {created} planted, {skipped} already present")
    if not args.no_baseline:
        with console.Spinner("Building integrity baseline"):
            base = Baseline.build(config)
            base.save(paths)
        console.ok(f"Baseline: {len(base)} files recorded")
    console.plain("")
    console.info("Start protection with:  greyrun monitor")
    return 0


def cmd_protect(args, config: Config, paths: Paths) -> int:
    added = 0
    for p in args.paths:
        if not os.path.exists(p):
            console.warn(f"Path does not exist (added anyway): {p}")
        if config.add_path(p):
            console.ok(f"Now protecting: {utils.normpath(p)}")
            added += 1
        else:
            console.info(f"Already protected: {utils.normpath(p)}")
    config.save(paths)
    if added and not args.no_canary:
        created, _ = canary_mod.deploy(config, paths)
        console.ok(f"Planted {created} new canaries")
    return 0


def cmd_unprotect(args, config: Config, paths: Paths) -> int:
    for p in args.paths:
        if config.remove_path(p):
            console.ok(f"Stopped protecting: {utils.normpath(p)}")
        else:
            console.warn(f"Not in protected list: {utils.normpath(p)}")
    config.save(paths)
    return 0


def cmd_status(args, config: Config, paths: Paths) -> int:
    _print_status(config, paths)
    return 0


def cmd_baseline(args, config: Config, paths: Paths) -> int:
    if not _require_paths(config):
        return 1
    existing = Baseline.load(paths)
    if existing and not args.update:
        console.warn(f"Baseline already exists ({len(existing)} files, {existing.created}).")
        if not console.confirm("Rebuild it?", default=False):
            console.info("Keeping existing baseline. Use --update to force.")
            return 0
    total = utils.count_files(config.watched_paths, config.exclude_dirs)
    console.info(f"Hashing {total} files under {len(config.watched_paths)} path(s)…")
    with console.Spinner("Building baseline"):
        base = Baseline.build(config)
        base.save(paths)
    console.ok(f"Baseline saved: {len(base)} files  ->  {paths.baseline}")
    return 0


def cmd_canary(args, config: Config, paths: Paths) -> int:
    sub = args.canary_cmd or "check"
    if sub == "deploy":
        if not _require_paths(config):
            return 1
        created, skipped = canary_mod.deploy(config, paths)
        console.ok(f"Canaries deployed: {created} new, {skipped} existing")
        return 0
    if sub == "clear":
        removed = canary_mod.clear(config, paths)
        console.ok(f"Removed {removed} canary file(s)")
        return 0
    # check
    statuses = canary_mod.verify(paths)
    if not statuses:
        console.warn("No canaries planted. Run:  greyrun canary deploy")
        return 0
    bad = [s for s in statuses if s.state != "ok"]
    for s in statuses:
        if s.state == "ok":
            console.emit("ok", f"intact   {utils.short_path(s.path)}")
        else:
            console.emit("critical", f"{s.state.upper():8} {s.path}")
    if bad:
        console.critical(f"{len(bad)} canary file(s) compromised — possible active attack!")
        return 4
    console.ok(f"All {len(statuses)} canaries intact.")
    return 0


def cmd_scan(args, config: Config, paths: Paths) -> int:
    if not _require_paths(config):
        return 1
    base = Baseline.load(paths)
    console.rule("SCAN")
    with console.Spinner("Scanning protected paths"):
        report = detector.scan(config, paths, base)

    console.plain(f"  Files scanned     : {report.scanned}")
    console.plain(f"  Canaries checked  : {report.canaries_total}"
                  + (f"  ({len(report.canaries_bad)} COMPROMISED)" if report.canaries_bad else "  (all intact)"))
    console.plain(f"  Ransomware exts   : {len(report.ransomware_ext)}")
    console.plain(f"  Ransom notes      : {len(report.ransom_notes)}")
    console.plain(f"  Encrypted-looking : {len(report.encrypted_like)}")
    if report.diff is not None:
        d = report.diff
        console.plain(f"  Baseline drift    : {len(d.modified)} modified, "
                      f"{len(d.added)} added, {len(d.deleted)} deleted")

    if report.findings:
        console.plain("")
        console.rule("FINDINGS")
        for line in report.findings[:40]:
            console.emit("warn", line)
        if len(report.findings) > 40:
            console.plain(f"      … and {len(report.findings) - 40} more")

    console.plain("")
    console.plain(f"  Risk score: {report.risk}    Threat level: {_level_badge(report.level)}")
    if report.level in (DEFEND, CRITICAL):
        console.critical("High-risk indicators present. If unexpected, disconnect from the "
                         "network and run `greyrun monitor` / restore from backup.")
    elif report.level == NONE:
        console.ok("No ransomware indicators found.")
    return _EXIT_BY_LEVEL.get(report.level, 0)


def cmd_monitor(args, config: Config, paths: Paths) -> int:
    if not _require_paths(config):
        return 1
    if args.mode:
        config.response_mode = args.mode
    if args.no_notify:
        config.desktop_notifications = False
    if not canary_mod.registry(paths):
        console.info("No canaries planted yet — deploying for stronger detection.")
        canary_mod.deploy(config, paths)
    mon = Monitor(config, paths, heartbeat=args.heartbeat)
    mon.run()
    return 0


def cmd_backup(args, config: Config, paths: Paths) -> int:
    if not _require_paths(config):
        return 1
    console.info("Creating content-addressed backup snapshot…")
    with console.Spinner("Backing up protected files"):
        info = backup_mod.create_snapshot(config, paths)
    console.ok(f"Snapshot {info.id}: {info.file_count} files, "
              f"{utils.human_size(info.total_size)} "
              f"({utils.human_size(info.deduped_size)} new in vault)")
    console.info(f"Vault: {paths.vault}")
    return 0


def cmd_snapshots(args, config: Config, paths: Paths) -> int:
    snaps = backup_mod.list_snapshots(paths)
    if not snaps:
        console.warn("No snapshots yet. Create one with:  greyrun backup")
        return 0
    console.rule("SNAPSHOTS")
    for s in snaps:
        console.plain(f"  {s.id}   {s.file_count:>6} files   "
                      f"{utils.human_size(s.total_size):>9}   {s.created}")
    return 0


def cmd_restore(args, config: Config, paths: Paths) -> int:
    snap_id = args.snapshot or "latest"
    result = backup_mod.restore(paths, snap_id, into=args.into, overwrite=args.overwrite)
    if result is None:
        console.error(f"Snapshot not found: {snap_id}")
        return 1
    where = result.dest_root or "original locations"
    console.ok(f"Restore complete -> {where}")
    console.plain(f"  restored={result.restored}  skipped={result.skipped}  failed={result.failed}")
    if result.skipped and not args.overwrite and not args.into:
        console.info("Existing files were skipped. Use --overwrite or --into <dir>.")
    return 0


def cmd_exclude(args, config: Config, paths: Paths) -> int:
    """Manage excluded subfolder names. Matching is by folder *name* at any
    depth, so excluding 'GreyNOC CORE' skips it wherever it appears under a
    protected path; handy for keeping huge dev trees out of monitoring."""
    sub = args.exclude_cmd or "list"
    if sub == "list":
        console.rule("EXCLUDED FOLDER NAMES")
        for name in sorted(config.exclude_dirs):
            console.plain("  " + name)
        console.info("Add with:  greyrun exclude add \"<folder name>\"")
        return 0
    if sub == "add":
        added = 0
        for name in args.names:
            if name not in config.exclude_dirs:
                config.exclude_dirs.append(name)
                added += 1
        config.save(paths)
        console.ok(f"Excluded {added} folder name(s). Now {len(config.exclude_dirs)} total.")
        return 0
    if sub == "remove":
        removed = 0
        for name in args.names:
            if name in config.exclude_dirs:
                config.exclude_dirs.remove(name)
                removed += 1
        config.save(paths)
        console.ok(f"Removed {removed} exclude(s).")
        return 0
    return 0


def cmd_quarantine(args, config: Config, paths: Paths) -> int:
    sub = args.q_cmd or "run"

    if sub == "list":
        batches = quarantine_mod.list_batches(paths)
        if not batches:
            console.info("Quarantine is empty.")
            return 0
        console.rule("QUARANTINE")
        for b in batches:
            console.plain(f"  {b.id}   {b.count:>5} file(s)   {b.created}")
        console.info("Restore a batch with:  greyrun quarantine restore <id>")
        return 0

    if sub == "restore":
        result = quarantine_mod.restore_batch(paths, args.batch, overwrite=args.overwrite)
        if result is None:
            console.error(f"Quarantine batch not found: {args.batch}")
            return 1
        console.ok(f"Restored from quarantine: restored={result.restored} "
                   f"skipped={result.skipped} failed={result.failed}")
        if result.skipped and not args.overwrite:
            console.info("Some targets already exist. Use --overwrite to replace them.")
        return 0

    # run: find and move artifacts
    if not _require_paths(config):
        return 1
    with console.Spinner("Scanning for ransomware artifacts"):
        items = quarantine_mod.find_artifacts(config)
    if not items:
        console.ok("No ransomware artifacts found in protected paths.")
        return 0
    console.warn(f"Found {len(items)} artifact(s):")
    for path, reason in items[:25]:
        console.emit("warn", f"{reason:24} {utils.short_path(path)}")
    if len(items) > 25:
        console.plain(f"      … and {len(items) - 25} more")
    if not getattr(args, "yes", False) and not console.confirm(
        f"Move these {len(items)} file(s) to quarantine?", default=False
    ):
        console.info("Aborted. Nothing moved.")
        return 0
    result = quarantine_mod.quarantine_files(paths, items)
    console.ok(f"Quarantined {result.moved} file(s) into batch {result.batch_id} "
               f"({result.failed} failed)")
    console.info("Undo with:  greyrun quarantine restore latest")
    return 0


def cmd_autostart(args, config: Config, paths: Paths) -> int:
    from . import service

    sub = args.autostart_cmd or "status"
    if sub == "status":
        console.info(f"Autostart: {service.status()}")
        return 0
    if sub == "disable":
        for ok, msg in service.uninstall_all():
            (console.ok if ok else console.warn)(msg)
        return 0
    if sub == "enable":
        if not _require_paths(config):
            return 1
        method = args.method or ("task" if service.is_admin() else "startup")
        if method == "task":
            ok, msg = service.install_task(config, paths)
            if not ok and not service.is_admin() and not args.method:
                console.warn(msg)
                console.info("Falling back to no-admin Startup-folder autostart…")
                ok, msg = service.install_startup(config, paths)
        else:
            ok, msg = service.install_startup(config, paths)
        (console.ok if ok else console.warn)(msg)
        if ok and method == "startup":
            console.info("Tip: for elevated autostart (can stop attacker processes it "
                         "doesn't own), run from an Admin shell: greyrun autostart enable --method task")
        return 0 if ok else 1
    return 0


def cmd_test_alert(args, config: Config, paths: Paths) -> int:
    from . import notify

    channels = notify.channels_configured(config)
    if not channels:
        console.warn("No alert channels configured.")
        console.info("Set one, e.g.:  greyrun set webhook_url https://hooks.slack.com/…")
        console.info("Email:  greyrun set smtp_host …  smtp_from …  smtp_to …  (and GREYRUN_SMTP_PASSWORD)")
        return 1
    console.info(f"Sending a test alert via: {', '.join(channels)}")
    sample = detector.Assessment(
        score=120, level="CRITICAL",
        reasons=["canary modified [canary]", "ransomware extension (LockBit) [ext]",
                 "25 files changed in 60s [burst]"],
        suspect_paths=[os.path.join(p, "example.docx.locked") for p in config.watched_paths[:1]] or ["C:/example.docx.locked"],
        families=["LockBit"], changed_count=42,
    )
    results = notify.dispatch(config, sample, ["[TEST] this is a GreyRun test alert"])
    for r in results:
        console.emit("ok" if "sent" in r else "error", r)
    return 0 if all("sent" in r for r in results) else 1


def cmd_recover(args, config: Config, paths: Paths) -> int:
    """Post-incident recovery: resume suspended processes and lift the lockdown."""
    resumed = responder_mod.resume_suspended(paths)
    unlocked = responder_mod.unlock(paths)
    if unlocked < 0:
        console.warn("Lockdown state file is corrupt — could not auto-revert read-only flags.")
        console.info('Clear them manually, e.g.:  attrib -r /s "C:\\path\\to\\protected\\*"')
        unlocked = 0
    console.ok(f"Recovery complete: resumed {resumed} process(es), "
               f"unlocked {unlocked} file(s).")
    if resumed == 0 and unlocked == 0:
        console.info("Nothing to recover (no suspended processes or locked files).")
    return 0


def cmd_set(args, config: Config, paths: Paths) -> int:
    key = args.key
    fields = config.__dataclass_fields__  # type: ignore[attr-defined]
    if key not in fields:
        console.error(f"Unknown setting: {key}")
        console.info("Settable: " + ", ".join(k for k in fields if k not in ("watched_paths", "exclude_dirs", "version")))
        return 1
    current = getattr(config, key)
    raw = args.value
    try:
        if isinstance(current, bool):
            value = raw.lower() in ("1", "true", "yes", "on")
        elif isinstance(current, int):
            value = int(raw)
        elif isinstance(current, float):
            value = float(raw)
        else:
            value = raw
    except ValueError:
        console.error(f"Invalid value for {key}: {raw}")
        return 1
    if key == "response_mode" and value not in ("monitor", "defend", "kill"):
        console.error("response_mode must be one of: monitor, defend, kill")
        return 1
    if key == "containment" and value not in ("lockdown", "quarantine", "both"):
        console.error("containment must be one of: lockdown, quarantine, both")
        return 1
    setattr(config, key, value)
    config.save(paths)
    console.ok(f"{key} = {value}")
    return 0


def cmd_simulate(args, config: Config, paths: Paths) -> int:
    sub = args.sim_cmd or "demo"
    default_dir = os.path.join(tempfile.gettempdir(), "greyrun_sandbox")

    if sub == "setup":
        info = simulator.make_sandbox(args.dir, num_files=args.files)
        console.ok(f"Sandbox ready: {info.path}  ({len(info.files)} sample files)")
        if args.protect:
            config.add_path(info.path)
            config.save(paths)
            canary_mod.deploy(config, paths)
            console.ok("Sandbox added to protected paths + canaries planted.")
            console.info("Now run `greyrun monitor` in one terminal, then "
                         "`greyrun simulate attack` in another.")
        else:
            console.info(f"Tip: greyrun simulate attack --dir \"{info.path}\"")
        return 0

    if sub == "attack":
        target = args.dir or default_dir
        try:
            simulator.simulate_attack(target, extension=args.ext, delay=args.delay)
        except RuntimeError as exc:
            console.error(str(exc))
            return 1
        return 0

    if sub == "cleanup":
        target = args.dir or default_dir
        try:
            if config.remove_path(utils.normpath(target)):
                config.save(paths)
            n = simulator.cleanup(target)
            console.ok("Sandbox removed." if n else "Nothing to remove.")
        except RuntimeError as exc:
            console.error(str(exc))
            return 1
        return 0

    # demo: self-contained end-to-end demonstration in an isolated sandbox.
    return _run_demo(args)


def _run_demo(args) -> int:
    console.banner()
    console.rule("DRILL / DEMO")
    console.info("Creating an isolated sandbox and running a full detection drill.")
    info = simulator.make_sandbox(args.dir, num_files=40)
    sandbox = info.path

    # Isolated state so the demo never touches the user's real config/baseline.
    # Use a ".greyrun" subdir: it is in the default exclude set, so the
    # simulated sweep skips it and the canary registry survives to be checked.
    demo_paths = Paths(os.path.join(sandbox, ".greyrun")).ensure()
    demo_cfg = Config(watched_paths=[sandbox])

    canary_mod.deploy(demo_cfg, demo_paths)
    console.ok(f"Sandbox + canaries ready ({len(info.files)} docs): {sandbox}")

    console.plain("")
    console.info("Scan BEFORE attack:")
    pre = detector.scan(demo_cfg, demo_paths)
    console.plain(f"    risk={pre.risk}  level={_level_badge(pre.level)}")

    console.plain("")
    simulator.simulate_attack(sandbox, extension=".locked", delay=0.0)

    console.plain("")
    console.info("Scan AFTER attack:")
    post = detector.scan(demo_cfg, demo_paths)
    console.plain(f"    files flagged: ext={len(post.ransomware_ext)} "
                  f"notes={len(post.ransom_notes)} encrypted={len(post.encrypted_like)} "
                  f"canaries_hit={len(post.canaries_bad)}")
    console.plain(f"    risk={post.risk}  level={_level_badge(post.level)}")
    for line in post.findings[:8]:
        console.emit("warn", line)
    if len(post.findings) > 8:
        console.plain(f"      … and {len(post.findings) - 8} more findings")

    console.plain("")
    if post.level in (DEFEND, CRITICAL):
        console.ok("Detection works: the simulated attack was caught at "
                   f"{post.level} level.")
    else:
        console.warn("Drill did not reach high threat — check configuration.")
    console.info(f"Clean up the sandbox with:  greyrun simulate cleanup --dir \"{sandbox}\"")
    return 0


# --------------------------------------------------------------------------- #
#  Parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="greyrun",
        description="GreyRun — behaviour-based ransomware shield (defensive).",
        epilog="Run `greyrun simulate demo` for a safe, self-contained demonstration.",
    )
    p.add_argument("--version", action="version", version=f"GreyRun {__version__}")
    p.add_argument("--home", help="Override state directory (default ~/.greyrun)")
    p.add_argument("--no-color", action="store_true", help="Disable coloured output")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose / debug output")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("init", help="Initialise protection (paths, canaries, baseline)")
    sp.add_argument("paths", nargs="*", help="Directories to protect")
    sp.add_argument("--no-defaults", action="store_true", help="Do not auto-add Desktop/Documents")
    sp.add_argument("--no-canary", action="store_true")
    sp.add_argument("--no-baseline", action="store_true")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("protect", help="Add directories to the protected set")
    sp.add_argument("paths", nargs="+")
    sp.add_argument("--no-canary", action="store_true")
    sp.set_defaults(func=cmd_protect)

    sp = sub.add_parser("unprotect", help="Remove directories from the protected set")
    sp.add_argument("paths", nargs="+")
    sp.set_defaults(func=cmd_unprotect)

    sp = sub.add_parser("status", help="Show configuration and protection status")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("baseline", help="Build/refresh the file-integrity baseline")
    sp.add_argument("--update", action="store_true", help="Rebuild without prompting")
    sp.set_defaults(func=cmd_baseline)

    sp = sub.add_parser("canary", help="Manage canary honeypot files")
    csub = sp.add_subparsers(dest="canary_cmd")
    csub.add_parser("deploy", help="Plant canaries in protected directories")
    csub.add_parser("check", help="Verify canary integrity")
    csub.add_parser("clear", help="Remove all canaries")
    sp.set_defaults(func=cmd_canary)

    sp = sub.add_parser("scan", help="One-shot scan for ransomware indicators")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("monitor", help="Run the real-time protection monitor")
    sp.add_argument("--mode", choices=("monitor", "defend", "kill"),
                    help="Response policy override")
    sp.add_argument("--heartbeat", type=float, default=30.0, help="Status interval (s)")
    sp.add_argument("--no-notify", action="store_true", help="Disable desktop pop-ups")
    sp.set_defaults(func=cmd_monitor)

    sp = sub.add_parser("backup", help="Create a protected backup snapshot")
    sp.set_defaults(func=cmd_backup)

    sp = sub.add_parser("snapshots", help="List backup snapshots")
    sp.set_defaults(func=cmd_snapshots)

    sp = sub.add_parser("restore", help="Restore files from a snapshot")
    sp.add_argument("snapshot", nargs="?", default="latest", help="Snapshot id / prefix / 'latest'")
    sp.add_argument("--into", help="Restore into this directory instead of original locations")
    sp.add_argument("--overwrite", action="store_true", help="Overwrite existing files")
    sp.set_defaults(func=cmd_restore)

    sp = sub.add_parser("exclude", help="Manage excluded subfolder names (skip dev trees, etc.)")
    esub = sp.add_subparsers(dest="exclude_cmd")
    e_add = esub.add_parser("add", help="Exclude folder name(s)")
    e_add.add_argument("names", nargs="+")
    e_rm = esub.add_parser("remove", help="Stop excluding folder name(s)")
    e_rm.add_argument("names", nargs="+")
    esub.add_parser("list", help="List excluded folder names")
    sp.set_defaults(func=cmd_exclude)

    sp = sub.add_parser("quarantine", help="Move ransomware artifacts to a safe holding area")
    qsub = sp.add_subparsers(dest="q_cmd")
    q_run = qsub.add_parser("run", help="Find and quarantine artifacts (default)")
    q_run.add_argument("--yes", "-y", action="store_true", help="Do not prompt")
    qsub.add_parser("list", help="List quarantine batches")
    q_rest = qsub.add_parser("restore", help="Restore a quarantined batch")
    q_rest.add_argument("batch", nargs="?", default="latest")
    q_rest.add_argument("--overwrite", action="store_true")
    sp.set_defaults(func=cmd_quarantine)

    sp = sub.add_parser("autostart", help="Run the monitor automatically at logon (Windows)")
    asub = sp.add_subparsers(dest="autostart_cmd")
    a_en = asub.add_parser("enable", help="Install logon autostart (task if admin, else startup folder)")
    a_en.add_argument("--method", choices=("task", "startup"), help="Force a specific method")
    asub.add_parser("disable", help="Remove all autostart entries")
    asub.add_parser("status", help="Show autostart status")
    sp.set_defaults(func=cmd_autostart)

    sp = sub.add_parser("test-alert", help="Send a test alert through configured channels")
    sp.set_defaults(func=cmd_test_alert)

    sp = sub.add_parser("recover", help="Post-incident: resume suspended procs + lift lockdown")
    sp.set_defaults(func=cmd_recover)

    sp = sub.add_parser("set", help="Change a configuration value")
    sp.add_argument("key")
    sp.add_argument("value")
    sp.set_defaults(func=cmd_set)

    sp = sub.add_parser("simulate", help="Safe ransomware drill (sandboxed)")
    ssub = sp.add_subparsers(dest="sim_cmd")
    s_setup = ssub.add_parser("setup", help="Create a sandbox with sample files")
    s_setup.add_argument("--dir", help="Sandbox directory (default: temp)")
    s_setup.add_argument("--files", type=int, default=40)
    s_setup.add_argument("--protect", action="store_true", help="Add sandbox to protected set")
    s_attack = ssub.add_parser("attack", help="Run the simulated encryption sweep")
    s_attack.add_argument("--dir", help="Sandbox directory")
    s_attack.add_argument("--ext", default=".locked", help="Extension to append")
    s_attack.add_argument("--delay", type=float, default=0.05, help="Per-file delay (s)")
    s_demo = ssub.add_parser("demo", help="End-to-end self-contained demonstration")
    s_demo.add_argument("--dir", help="Sandbox directory")
    s_clean = ssub.add_parser("cleanup", help="Delete the sandbox")
    s_clean.add_argument("--dir", help="Sandbox directory")
    sp.set_defaults(func=cmd_simulate)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    # Initialise UTF-8/colour before argparse can print --help/--version,
    # which it does (and exits) during parse_args().
    console.init()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        console.init(force_color=False)
    console.set_verbose(args.verbose)

    paths = Paths(args.home).ensure()
    console.set_audit_log(paths.audit_log)
    config = Config.load(paths)

    if not getattr(args, "command", None):
        _print_status(config, paths)
        return 0

    try:
        return args.func(args, config, paths)
    except KeyboardInterrupt:
        console.plain("")
        console.warn("Interrupted.")
        return 130
    except Exception as exc:  # pragma: no cover - top-level safety net
        console.error(f"Unexpected error: {exc}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
