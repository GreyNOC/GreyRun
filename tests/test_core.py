"""GreyRun test suite.

Covers the detection math, signatures, canaries, scan, behavioural engine,
baseline, backup/restore, the safety guards on the simulator, and -- when
psutil is available -- the real process suspend/terminate path against a
controlled external writer process.

Run with:  python -m pytest tests/  (or)  python -m unittest discover -s tests
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from greyrun import backup as backup_mod
from greyrun import canary as canary_mod
from greyrun import detector, notify, quarantine, simulator, utils
from greyrun.baseline import Baseline, diff_current
from greyrun.config import Config, Paths
from greyrun.detector import Assessment
from greyrun.entropy import looks_encrypted, shannon_entropy
from greyrun.signatures import is_ransom_note, is_ransomware_ext, ransomware_family

try:
    import psutil
except Exception:
    psutil = None


def _tmp_paths():
    root = tempfile.mkdtemp(prefix="grtest_")
    return Paths(os.path.join(root, ".greyrun")).ensure(), root


class TestEntropy(unittest.TestCase):
    def test_low_vs_high(self):
        self.assertLess(shannon_entropy(b"aaaaaaaaaaaaaaaa"), 1.0)
        self.assertEqual(round(shannon_entropy(bytes(range(256)) * 4)), 8)

    def test_random_is_high(self):
        self.assertGreater(shannon_entropy(os.urandom(8192)), 7.8)

    def test_looks_encrypted_only_for_documents(self):
        d = tempfile.mkdtemp(prefix="grent_")
        doc = os.path.join(d, "report.txt")
        with open(doc, "wb") as fh:
            fh.write(os.urandom(20000))
        jpg = os.path.join(d, "photo.jpg")
        with open(jpg, "wb") as fh:
            fh.write(os.urandom(20000))
        # A .txt full of random bytes looks encrypted...
        self.assertTrue(looks_encrypted(doc))
        # ...but a .jpg (normally high entropy) does not raise suspicion.
        self.assertFalse(looks_encrypted(jpg))


class TestSignatures(unittest.TestCase):
    def test_extensions(self):
        self.assertTrue(is_ransomware_ext("x.locky"))
        self.assertEqual(ransomware_family("data.wncry"), "WannaCry")
        self.assertFalse(is_ransomware_ext("report.docx"))

    def test_ransom_notes(self):
        self.assertTrue(is_ransom_note("HOW_TO_DECRYPT.txt"))
        self.assertTrue(is_ransom_note("YOUR_FILES_ARE_ENCRYPTED.html"))
        self.assertTrue(is_ransom_note("_readme.txt"))
        self.assertFalse(is_ransom_note("budget.xlsx"))
        self.assertFalse(is_ransom_note("readme.md"))  # ordinary project readme

    def test_no_false_positive_extensions(self):
        # Common extensions reused by some strains must NOT be flagged, or
        # every music/Java file would trip the detector.
        self.assertFalse(is_ransomware_ext("song.mp3"))
        self.assertFalse(is_ransomware_ext("Main.java"))
        self.assertFalse(is_ransomware_ext("wallet.dat"))


class TestCanary(unittest.TestCase):
    def test_deploy_verify_and_tamper(self):
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        cfg = Config(watched_paths=[watched], canaries_per_dir=2)
        created, _ = canary_mod.deploy(cfg, paths)
        self.assertEqual(created, 2)
        self.assertTrue(all(s.state == "ok" for s in canary_mod.verify(paths)))

        # Tamper with one canary -> detected as modified.
        victim = list(canary_mod.registry(paths))[0]
        try:
            if os.name == "nt":
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(victim), 0x80)
            with open(victim, "wb") as fh:
                fh.write(os.urandom(500))
        except OSError:
            self.skipTest("could not modify canary")
        states = {s.state for s in canary_mod.verify(paths)}
        self.assertIn("modified", states)

    def test_append_tamper_is_detected(self):
        # A prefix-only hash would miss an append; size-check must catch it.
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        cfg = Config(watched_paths=[watched], canaries_per_dir=1)
        canary_mod.deploy(cfg, paths)
        victim = list(canary_mod.registry(paths))[0]
        if os.name == "nt":
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(victim), 0x80)
        with open(victim, "ab") as fh:  # append, keep original prefix intact
            fh.write(b"extra ransomware bytes")
        self.assertEqual(
            canary_mod.check_one(victim, canary_mod.registry(paths)), "modified"
        )


class TestScan(unittest.TestCase):
    def test_scan_flags_attack(self):
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        # Healthy file
        with open(os.path.join(watched, "ok.txt"), "w") as fh:
            fh.write("perfectly normal text " * 50)
        # Ransomware-extension file
        with open(os.path.join(watched, "report.docx.locked"), "wb") as fh:
            fh.write(os.urandom(4000))
        # Ransom note
        with open(os.path.join(watched, "HOW_TO_DECRYPT.txt"), "w") as fh:
            fh.write("pay us")
        # Encrypted-looking document
        with open(os.path.join(watched, "secret.txt"), "wb") as fh:
            fh.write(os.urandom(20000))

        cfg = Config(watched_paths=[watched])
        report = detector.scan(cfg, paths)
        self.assertGreaterEqual(len(report.ransomware_ext), 1)
        self.assertGreaterEqual(len(report.ransom_notes), 1)
        self.assertGreaterEqual(len(report.encrypted_like), 1)
        self.assertEqual(report.level, "CRITICAL")


class TestBehaviorEngine(unittest.TestCase):
    def test_canary_event_is_critical(self):
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        cfg = Config(watched_paths=[watched], canaries_per_dir=1)
        canary_mod.deploy(cfg, paths)
        canary = list(canary_mod.registry(paths))[0]
        # Modify the canary then notify the engine.
        if os.name == "nt":
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(canary), 0x80)
        with open(canary, "wb") as fh:
            fh.write(os.urandom(500))
        engine = detector.BehaviorEngine(cfg, paths)
        assessment = engine.observe("modified", canary)
        self.assertEqual(assessment.level, "CRITICAL")

    def test_burst_detection(self):
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        cfg = Config(watched_paths=[watched], burst_count=5, burst_window_sec=60)
        engine = detector.BehaviorEngine(cfg, paths)
        last = None
        for i in range(6):
            p = os.path.join(watched, f"f{i}.dat")
            last = engine.observe("modified", p)
        self.assertGreaterEqual(last.changed_count, 5)
        self.assertTrue(any("burst" in r for r in last.reasons))


class TestBaseline(unittest.TestCase):
    def test_build_and_diff(self):
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        a = os.path.join(watched, "a.txt")
        b = os.path.join(watched, "b.txt")
        with open(a, "w") as fh:
            fh.write("alpha")
        with open(b, "w") as fh:
            fh.write("bravo")
        cfg = Config(watched_paths=[watched])
        base = Baseline.build(cfg)
        base.save(paths)
        self.assertEqual(len(base), 2)

        # Modify a, delete b, add c.
        time.sleep(0.01)
        with open(a, "w") as fh:
            fh.write("ALPHA CHANGED")
        os.remove(b)
        with open(os.path.join(watched, "c.txt"), "w") as fh:
            fh.write("charlie")
        d = diff_current(Baseline.load(paths), cfg)
        self.assertIn(a, d.modified)
        self.assertIn(b, d.deleted)
        self.assertEqual(len(d.added), 1)


class TestBackup(unittest.TestCase):
    def test_snapshot_and_restore_roundtrip(self):
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        original = os.path.join(watched, "important.txt")
        content = "irreplaceable data " * 100
        with open(original, "w") as fh:
            fh.write(content)
        cfg = Config(watched_paths=[watched])
        info = backup_mod.create_snapshot(cfg, paths)
        self.assertEqual(info.file_count, 1)

        # Simulate destruction, then restore into a fresh dir.
        os.remove(original)
        dest = os.path.join(root, "restored")
        result = backup_mod.restore(paths, "latest", into=dest)
        self.assertEqual(result.restored, 1)
        restored_file = os.path.join(dest, "important.txt")
        self.assertTrue(os.path.exists(restored_file))
        with open(restored_file) as fh:
            self.assertEqual(fh.read(), content)


class TestSimulatorSafety(unittest.TestCase):
    def test_refuses_non_sandbox(self):
        d = tempfile.mkdtemp(prefix="grsafe_")
        # No marker file -> must refuse.
        with self.assertRaises(RuntimeError):
            simulator.simulate_attack(d)

    def test_sandbox_lifecycle(self):
        d = tempfile.mkdtemp(prefix="grsbx_")
        info = simulator.make_sandbox(d, num_files=5)
        self.assertEqual(len(info.files), 5)
        result = simulator.simulate_attack(d, delay=0.0)
        self.assertGreaterEqual(result.encrypted, 5)
        self.assertEqual(simulator.cleanup(d), 1)
        self.assertFalse(os.path.exists(d))


@unittest.skipIf(psutil is None, "psutil not installed")
class TestActiveResponse(unittest.TestCase):
    # Lives long enough to survive a (deliberately bounded) suspect scan.
    WRITER = (
        "import sys,time,os\n"
        "p=sys.argv[1]\n"
        "f=open(p,'wb')\n"
        "data=os.urandom(1048576)\n"
        "end=time.time()+30\n"
        "while time.time()<end:\n"
        "    f.write(data); f.flush()\n"
        "    time.sleep(0.02)\n"
    )

    def test_suspend_and_terminate_real_writer(self):
        import greyrun.responder as R

        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        target = os.path.join(watched, "victim.bin")
        cfg = Config(watched_paths=[watched])

        proc = subprocess.Popen([sys.executable, "-c", self.WRITER, target])
        # Allow python to be a suspect for the whole identify->suspend->kill
        # sequence (the responder also refuses to act on CRITICAL_PROCS).
        saved = set(R.CRITICAL_PROCS)
        R.CRITICAL_PROCS.difference_update({"python.exe", "py.exe", "pythonw.exe"})
        try:
            time.sleep(1.2)  # accumulate write I/O + hold the handle open

            suspects = R.identify_suspects(cfg, limit=10, confirm_top=15)
            mine = [s for s in suspects if s.pid == proc.pid]
            self.assertTrue(mine, "writer process was not identified as a suspect")
            self.assertTrue(mine[0].actionable, "writer should be actionable (open handle)")

            responder = R.Responder(cfg, paths)
            self.assertIsNone(proc.poll(), "writer died before suspend (scan too slow)")
            actions = responder._suspend(mine)
            if not any("suspended" in a for a in actions):
                # Restricted environments (some CI containers) disallow process
                # control; skip rather than fail. Verified on Windows locally.
                self.skipTest(f"process control not permitted here: {actions}")
            time.sleep(0.2)
            status = psutil.Process(proc.pid).status()
            self.assertEqual(status, psutil.STATUS_STOPPED)

            responder._terminate(mine)
            proc.wait(timeout=6)
            self.assertIsNotNone(proc.returncode)
        finally:
            R.CRITICAL_PROCS.clear()
            R.CRITICAL_PROCS.update(saved)
            if proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass

    def test_non_actionable_not_suspended(self):
        # A suspect with no open handle in protected paths must not be acted on.
        import greyrun.responder as R

        paths, root = _tmp_paths()
        cfg = Config(watched_paths=[os.path.join(root, "docs")])
        fake = R.Suspect(pid=999999, name="busy.exe", score=40,
                         evidence=["lots of I/O"], actionable=False)
        responder = R.Responder(cfg, paths)
        self.assertEqual(responder._suspend([fake]), [])
        self.assertEqual(responder._terminate([fake]), [])


class TestLockdown(unittest.TestCase):
    def test_lockdown_and_unlock(self):
        import greyrun.responder as R

        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        f = os.path.join(watched, "doc.txt")
        with open(f, "w") as fh:
            fh.write("data")
        n = R.lockdown(paths, [watched])
        self.assertGreaterEqual(n, 1)
        if os.name == "nt":
            with self.assertRaises(OSError):
                open(f, "w").close()  # read-only blocks truncating write
        R.unlock(paths)
        open(f, "w").close()  # now writable again


class TestSecurityHardening(unittest.TestCase):
    def test_entropy_threshold_is_honoured(self):
        d = tempfile.mkdtemp(prefix="grthr_")
        doc = os.path.join(d, "report.txt")
        with open(doc, "wb") as fh:
            fh.write(os.urandom(20000))  # ~8.0 bits/byte
        self.assertTrue(looks_encrypted(doc, threshold=7.8))
        self.assertFalse(looks_encrypted(doc, threshold=9.0))  # unreachable -> off

    def test_restore_rejects_path_traversal(self):
        import json as _json

        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        with open(os.path.join(watched, "a.txt"), "w") as fh:
            fh.write("data")
        cfg = Config(watched_paths=[watched])
        backup_mod.create_snapshot(cfg, paths)

        # Tamper the snapshot manifest with a traversal 'rel'.
        snap = sorted(os.listdir(os.path.join(paths.vault, "snapshots")))[-1]
        mpath = os.path.join(paths.vault, "snapshots", snap)
        with open(mpath) as fh:
            m = _json.load(fh)
        m["files"][0]["rel"] = os.path.join("..", "..", "escape.txt")
        with open(mpath, "w") as fh:
            _json.dump(m, fh)

        dest = os.path.join(root, "restore_dest")
        result = backup_mod.restore(paths, "latest", into=dest, overwrite=True)
        self.assertEqual(result.restored, 0)   # traversal entry refused
        self.assertEqual(result.failed, 1)
        self.assertFalse(os.path.exists(os.path.join(root, "escape.txt")))

    def test_quarantine_restore_refuses_out_of_root(self):
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        locked = os.path.join(watched, "report.docx.locked")
        with open(locked, "wb") as fh:
            fh.write(b"encrypted")
        res = quarantine.quarantine_files(paths, [(locked, "ext")], roots=[watched])
        self.assertEqual(res.moved, 1)

        # Tamper the manifest to point at an absolute path outside the roots.
        batch_dir = os.path.join(paths.quarantine, res.batch_id)
        mpath = os.path.join(batch_dir, "manifest.json")
        with open(mpath) as fh:
            m = json.load(fh)
        evil = os.path.join(root, "ESCAPE", "pwned.txt")
        m["files"][0]["original"] = evil
        with open(mpath, "w") as fh:
            json.dump(m, fh)

        result = quarantine.restore_batch(paths, "latest", overwrite=True)
        self.assertEqual(result.restored, 0)     # out-of-root write refused
        self.assertFalse(os.path.exists(evil))

    def test_is_within_filesystem_root(self):
        # A whole-drive / filesystem-root watch must still contain its children.
        if os.name == "nt":
            self.assertTrue(utils.is_within(r"C:\Users\x\f.txt", ["C:\\"]))
            self.assertFalse(utils.is_within(r"D:\x\f.txt", ["C:\\"]))
        else:
            self.assertTrue(utils.is_within("/home/x/f.txt", ["/"]))
        base = tempfile.mkdtemp(prefix="grwin_")
        self.assertTrue(utils.is_within(os.path.join(base, "a", "b.txt"), [base]))
        self.assertFalse(utils.is_within(base + "_sibling", [base]))

    def test_block_reason_fails_closed_without_start_time(self):
        import greyrun.responder as R

        if R.psutil is None:
            self.skipTest("psutil not installed")
        # A live PID we can't verify (create_time=0) must be refused, not acted on.
        s = R.Suspect(pid=os.getpid(), name="probe.exe", score=1,
                      actionable=True, create_time=0.0)
        self.assertIsNotNone(R._block_reason(s, None))

    def test_important_txt_not_flagged_as_note(self):
        self.assertFalse(is_ransom_note("important.txt"))


class TestMonitorRouting(unittest.TestCase):
    def test_ignore_logic(self):
        from greyrun.monitor import Monitor

        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        cfg = Config(watched_paths=[watched],
                     exclude_dirs=list(utils.DEFAULT_EXCLUDE_DIRS) + ["BigDev"])
        mon = Monitor(cfg, paths)
        self.assertFalse(mon._ignore(os.path.join(watched, "a.txt")))            # normal
        self.assertTrue(mon._ignore(os.path.join(watched, "BigDev", "x.txt")))   # excluded subdir
        self.assertTrue(mon._ignore(os.path.join(paths.root, "config.json")))    # our state
        self.assertTrue(mon._ignore(os.path.join(root, "elsewhere", "y.txt")))   # outside roots

    def test_event_routing_and_burst(self):
        from greyrun.monitor import Monitor

        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        cfg = Config(watched_paths=[watched], burst_count=5,
                     response_mode="monitor", desktop_notifications=False)
        mon = Monitor(cfg, paths)
        for i in range(6):
            mon.on_event("modified", os.path.join(watched, f"f{i}.dat"))
        # Ignored events must not be counted.
        mon.on_event("modified", os.path.join(paths.root, "events.jsonl"))
        snap = mon.engine.snapshot()
        self.assertEqual(mon._events, 6)
        self.assertGreaterEqual(snap.changed_count, 5)


class TestResponderHandle(unittest.TestCase):
    def test_monitor_mode_is_alert_only(self):
        import greyrun.responder as R

        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        cfg = Config(watched_paths=[watched], response_mode="monitor",
                     desktop_notifications=False, auto_lockdown=True)
        resp = R.Responder(cfg, paths)
        a = Assessment(score=120, level="CRITICAL", reasons=["x [canary]"],
                       suspect_paths=[os.path.join(watched, "f.locked")],
                       families=[], changed_count=30)
        actions = resp.handle(a)
        self.assertFalse(any("locked down" in x for x in actions))
        self.assertFalse(any("suspended" in x for x in actions))
        self.assertFalse(os.path.exists(os.path.join(paths.root, "lock_state.json")))

    def test_block_reason_rejects_dead_pid(self):
        import greyrun.responder as R

        if R.psutil is None:
            self.skipTest("psutil not installed")
        s = R.Suspect(pid=999_999, name="x.exe", score=99, actionable=True, create_time=123.0)
        self.assertIsNotNone(R._block_reason(s, None))


class TestConfigValidation(unittest.TestCase):
    def test_invalid_enums_reset_on_load(self):
        paths, _ = _tmp_paths()
        with open(paths.config, "w", encoding="utf-8") as fh:
            json.dump({"response_mode": "bogus", "containment": "nope",
                       "watched_paths": ["x"]}, fh)
        cfg = Config.load(paths)
        self.assertEqual(cfg.response_mode, "defend")
        self.assertEqual(cfg.containment, "lockdown")
        self.assertEqual(cfg.watched_paths, ["x"])  # valid fields preserved


class TestNotifySSRF(unittest.TestCase):
    def test_link_local_webhook_refused(self):
        a = Assessment(score=1, level="CRITICAL", reasons=[], suspect_paths=[],
                       families=[], changed_count=0)
        # 169.254.169.254 is the cloud-metadata address; must be refused offline.
        self.assertFalse(
            notify.send_webhook("http://169.254.169.254/latest/meta-data", a, [])
        )


class TestLockdownCap(unittest.TestCase):
    def test_respects_max_files(self):
        import greyrun.responder as R

        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        for i in range(10):
            open(os.path.join(watched, f"f{i}.txt"), "w").close()
        self.assertEqual(R.lockdown(paths, [watched], max_files=3), 3)
        R.unlock(paths)


class TestExcludeScoping(unittest.TestCase):
    def test_excluded_subfolder_is_skipped(self):
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        devtree = os.path.join(watched, "BigDevProject")
        utils.ensure_dir(devtree)
        with open(os.path.join(watched, "real_doc.txt"), "w") as fh:
            fh.write("keep me")
        for i in range(5):
            with open(os.path.join(devtree, f"src{i}.txt"), "w") as fh:
                fh.write("noise")
        cfg = Config(watched_paths=[watched],
                     exclude_dirs=list(utils.DEFAULT_EXCLUDE_DIRS) + ["BigDevProject"])
        files = list(utils.iter_files(cfg.watched_paths, cfg.exclude_dirs))
        names = {os.path.basename(f) for f in files}
        self.assertIn("real_doc.txt", names)
        self.assertNotIn("src0.txt", names)  # excluded dev tree skipped


class TestQuarantine(unittest.TestCase):
    def test_find_move_and_restore(self):
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        normal = os.path.join(watched, "keepme.txt")
        with open(normal, "w") as fh:
            fh.write("a perfectly normal document")
        locked = os.path.join(watched, "report.docx.locked")
        with open(locked, "wb") as fh:
            fh.write(os.urandom(2000))
        note = os.path.join(watched, "HOW_TO_DECRYPT.txt")
        with open(note, "w") as fh:
            fh.write("pay us")
        cfg = Config(watched_paths=[watched])

        items = quarantine.find_artifacts(cfg)
        found = {p for p, _ in items}
        self.assertIn(locked, found)
        self.assertIn(note, found)
        self.assertNotIn(normal, found)  # healthy file untouched

        result = quarantine.quarantine_files(paths, items)
        self.assertEqual(result.moved, 2)
        self.assertFalse(os.path.exists(locked))     # moved out
        self.assertTrue(os.path.exists(normal))      # left in place

        restored = quarantine.restore_batch(paths, "latest", overwrite=True)
        self.assertEqual(restored.restored, 2)
        self.assertTrue(os.path.exists(locked))      # back again
        self.assertTrue(os.path.exists(note))


class TestNotify(unittest.TestCase):
    def _sample(self):
        return Assessment(
            score=120, level="CRITICAL",
            reasons=["canary modified [canary]", "ransomware extension (LockBit) [ext]"],
            suspect_paths=["C:/docs/report.docx.locked"], families=["LockBit"],
            changed_count=42,
        )

    def test_summary_contains_key_facts(self):
        text = notify.build_summary(self._sample(), ["suspended evil.exe (pid 1)"])
        self.assertIn("CRITICAL", text)
        self.assertIn("LockBit", text)
        self.assertIn("evil.exe", text)

    def test_channels_configured(self):
        self.assertEqual(notify.channels_configured(Config()), [])
        self.assertIn("webhook", notify.channels_configured(Config(webhook_url="http://x")))
        email = Config(smtp_host="h", smtp_from="a@b", smtp_to="c@d")
        self.assertIn("email", notify.channels_configured(email))

    def test_webhook_delivery(self):
        import http.server
        import threading

        received = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                received["body"] = json.loads(self.rfile.read(n))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        threading.Thread(target=srv.handle_request, daemon=True).start()
        try:
            cfg = Config(webhook_url=f"http://127.0.0.1:{port}/hook")
            results = notify.dispatch(cfg, self._sample(), ["locked down 10 files"])
            self.assertTrue(any("sent" in r for r in results))
            # http:// must be flagged as cleartext
            self.assertTrue(any("not HTTPS" in r for r in results))
            time.sleep(0.2)
            body = received.get("body", {})
            self.assertEqual(body.get("level"), "CRITICAL")
            self.assertEqual(body.get("score"), 120)
            self.assertIn("GreyRun ransomware alert", body.get("text", ""))
        finally:
            srv.server_close()


class TestAlertRearm(unittest.TestCase):
    def test_monitor_rearms_after_decay(self):
        from greyrun.monitor import Monitor

        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        cfg = Config(watched_paths=[watched], response_mode="monitor",
                     desktop_notifications=False)
        mon = Monitor(cfg, paths)
        # Pretend a CRITICAL incident already fired its one-shot guards.
        mon._last_acted_rank = 4
        mon.responder._alerted_level = "CRITICAL"
        mon.responder.incident_file = "incident.json"

        mon._maybe_rearm(50)  # still elevated -> no rearm
        self.assertEqual(mon._last_acted_rank, 4)

        mon._inflight_ranks.append(3)
        mon._maybe_rearm(0)   # response still running -> no rearm
        self.assertEqual(mon._last_acted_rank, 4)
        mon._inflight_ranks.clear()

        mon._last_action_ts = utils.now_ts()
        mon._maybe_rearm(0)   # last response too recent (stale score) -> no rearm
        self.assertEqual(mon._last_acted_rank, 4)
        mon._last_action_ts = 0.0

        mon._maybe_rearm(0)   # fully decayed -> guards reset
        self.assertEqual(mon._last_acted_rank, 0)
        self.assertEqual(mon.responder._alerted_level, "")
        self.assertIsNone(mon.responder.incident_file)

    def test_responder_alerts_again_after_rearm(self):
        import greyrun.responder as R

        paths, root = _tmp_paths()
        cfg = Config(watched_paths=[os.path.join(root, "docs")],
                     response_mode="monitor", desktop_notifications=False)
        resp = R.Responder(cfg, paths)
        a = Assessment(score=80, level="DEFEND", reasons=["x [burst]"],
                       suspect_paths=[], families=[], changed_count=30)
        first = resp.handle(a)
        self.assertTrue(any("alert" in x for x in first))
        second = resp.handle(a)  # same incident -> one-shot guard holds
        self.assertFalse(any("raised desktop" in x for x in second))
        resp.rearm()
        third = resp.handle(a)   # new incident after decay -> alerts again
        self.assertTrue(any("raised desktop" in x for x in third))


class TestWebhookRedirect(unittest.TestCase):
    def test_redirect_is_refused(self):
        import http.server
        import threading

        hits = {"target": 0}

        class Target(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits["target"] += 1
                self.send_response(200)
                self.end_headers()

            do_GET = do_POST  # urllib downgrades a followed 302 POST to GET

            def log_message(self, *a):
                pass

        tgt = http.server.HTTPServer(("127.0.0.1", 0), Target)
        tport = tgt.server_address[1]

        class Redirector(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{tport}/steal")
                self.end_headers()

            def log_message(self, *a):
                pass

        red = http.server.HTTPServer(("127.0.0.1", 0), Redirector)
        rport = red.server_address[1]
        threading.Thread(target=red.handle_request, daemon=True).start()
        threading.Thread(target=tgt.handle_request, daemon=True).start()
        try:
            a = Assessment(score=1, level="CRITICAL", reasons=[],
                           suspect_paths=[], families=[], changed_count=0)
            ok = notify.send_webhook(f"http://127.0.0.1:{rport}/hook", a, [])
            self.assertFalse(ok)          # redirect refused -> send fails
            # The refusal is synchronous, so the count is already final here.
            self.assertEqual(hits["target"], 0)  # payload never followed it
        finally:
            red.server_close()
            tgt.server_close()


class TestQuarantineThreshold(unittest.TestCase):
    def test_is_artifact_honours_threshold(self):
        d = tempfile.mkdtemp(prefix="grqt_")
        doc = os.path.join(d, "notes.txt")
        with open(doc, "wb") as fh:
            fh.write(os.urandom(20000))  # ~8.0 bits/byte
        self.assertEqual(quarantine.is_artifact(doc), "document looks encrypted")
        # An unreachable configured threshold disables the entropy signal.
        self.assertIsNone(quarantine.is_artifact(doc, entropy_threshold=9.0))


class TestConfigTypeValidation(unittest.TestCase):
    def test_wrong_types_fall_back_to_defaults(self):
        paths, _ = _tmp_paths()
        with open(paths.config, "w", encoding="utf-8") as fh:
            json.dump({"watched_paths": "C:\\not-a-list",
                       "burst_count": "lots",
                       "entropy_threshold": "high",
                       "auto_lockdown": "yes",
                       "webhook_url": 42,
                       "exclude_dirs": ["keep-me"]}, fh)
        cfg = Config.load(paths)
        defaults = Config()
        self.assertEqual(cfg.watched_paths, [])            # str is not a list
        self.assertEqual(cfg.burst_count, defaults.burst_count)
        self.assertEqual(cfg.entropy_threshold, defaults.entropy_threshold)
        self.assertEqual(cfg.auto_lockdown, defaults.auto_lockdown)
        self.assertEqual(cfg.webhook_url, "")
        self.assertEqual(cfg.exclude_dirs, ["keep-me"])    # valid field kept

    def test_numeric_coercion(self):
        paths, _ = _tmp_paths()
        with open(paths.config, "w", encoding="utf-8") as fh:
            json.dump({"burst_count": 30.0, "burst_window_sec": 45}, fh)
        cfg = Config.load(paths)
        self.assertEqual(cfg.burst_count, 30)              # float -> int field
        self.assertEqual(cfg.burst_window_sec, 45.0)       # int -> float field

    def test_bool_fields_accept_zero_one(self):
        # Hand-edited JSON commonly uses 0/1 for booleans; a dropped 0 would
        # silently flip a user-disabled setting back to its True default.
        paths, _ = _tmp_paths()
        with open(paths.config, "w", encoding="utf-8") as fh:
            json.dump({"desktop_notifications": 0, "auto_lockdown": 1,
                       "smtp_tls": "no"}, fh)
        cfg = Config.load(paths)
        self.assertIs(cfg.desktop_notifications, False)
        self.assertIs(cfg.auto_lockdown, True)
        self.assertIs(cfg.smtp_tls, True)                  # invalid -> default


class TestIdUniqueness(unittest.TestCase):
    def test_same_second_quarantine_batches_stay_distinct(self):
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        ids = set()
        for i in range(2):
            f = os.path.join(watched, f"r{i}.docx.locked")
            with open(f, "wb") as fh:
                fh.write(b"x")
            res = quarantine.quarantine_files(paths, [(f, "ext")], roots=[watched])
            self.assertEqual(res.moved, 1)
            ids.add(res.batch_id)
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(quarantine.list_batches(paths)), 2)

    def test_same_second_snapshots_stay_distinct(self):
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        with open(os.path.join(watched, "a.txt"), "w") as fh:
            fh.write("data")
        cfg = Config(watched_paths=[watched])
        s1 = backup_mod.create_snapshot(cfg, paths)
        s2 = backup_mod.create_snapshot(cfg, paths)
        self.assertNotEqual(s1.id, s2.id)
        self.assertEqual(len(backup_mod.list_snapshots(paths)), 2)

    def test_latest_resolves_newest_same_second_snapshot(self):
        # A same-second collision suffix must not invert 'latest' resolution
        # ('-02.json' sorts before '.json' when whole filenames are compared).
        paths, root = _tmp_paths()
        watched = os.path.join(root, "docs")
        utils.ensure_dir(watched)
        f = os.path.join(watched, "doc.txt")
        cfg = Config(watched_paths=[watched])
        with open(f, "w") as fh:
            fh.write("old contents")
        backup_mod.create_snapshot(cfg, paths)
        with open(f, "w") as fh:
            fh.write("new contents")
        backup_mod.create_snapshot(cfg, paths)

        os.remove(f)
        dest = os.path.join(root, "restored")
        result = backup_mod.restore(paths, "latest", into=dest)
        self.assertEqual(result.restored, 1)
        with open(os.path.join(dest, "doc.txt")) as fh:
            self.assertEqual(fh.read(), "new contents")

    def test_same_second_forensics_stay_distinct(self):
        import greyrun.responder as R

        paths, _ = _tmp_paths()
        a = Assessment(score=120, level="CRITICAL", reasons=["x [canary]"],
                       suspect_paths=[], families=[], changed_count=1)
        f1 = R.capture_forensics(paths, [], a)
        f2 = R.capture_forensics(paths, [], a)
        self.assertIsNotNone(f1)
        self.assertIsNotNone(f2)
        self.assertNotEqual(f1, f2)  # second incident must not overwrite the first


class TestServiceAutostart(unittest.TestCase):
    def test_command_is_quoted(self):
        from greyrun import service

        paths, _ = _tmp_paths()
        cfg = Config(watched_paths=["x"], response_mode="kill")
        cmd = service._monitor_command(cfg, paths)
        self.assertIn("-m greyrun", cmd)
        self.assertIn("--mode kill", cmd)
        self.assertTrue(cmd.startswith('"'))  # python path is quoted


if __name__ == "__main__":
    unittest.main(verbosity=2)
