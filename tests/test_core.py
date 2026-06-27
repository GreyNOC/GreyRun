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
            self.assertTrue(any("suspended" in a for a in actions), actions)
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

        cfg = Config(webhook_url=f"http://127.0.0.1:{port}/hook")
        results = notify.dispatch(cfg, self._sample(), ["locked down 10 files"])
        self.assertTrue(any("sent" in r for r in results))
        time.sleep(0.2)
        body = received.get("body", {})
        self.assertEqual(body.get("level"), "CRITICAL")
        self.assertEqual(body.get("score"), 120)
        self.assertIn("GreyRun ransomware alert", body.get("text", ""))


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
