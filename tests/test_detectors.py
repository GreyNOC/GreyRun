"""Tests for the corroboration-based detection engine.

Covers the tiered canary verdicts, transient-file suppression, chi-square
gating, header (magic-byte) validation, stranded double extensions, rename
clustering, the sustained long-memory signal, ransom-note content scoring,
and the class/cap scoring arithmetic -- both the attack shapes each detector
must catch and the benign workflows it must stay quiet on.

Run with:  python -m pytest tests/  (or)  python -m unittest discover -s tests
"""

import os
import random
import shutil
import sys
import tempfile
import time
import unittest
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from greyrun import canary as canary_mod
from greyrun import detector, filetypes, notecontent, utils
from greyrun.baseline import Baseline
from greyrun.config import Config, Paths
from greyrun.entropy import byte_stats, cipher_like, looks_encrypted
from greyrun.signatures import (
    is_stranded_document_ext,
    is_transient,
)

_RNG = random.Random(1234)  # deterministic "ciphertext"


def _tmp_paths():
    root = tempfile.mkdtemp(prefix="grtest2_")
    return Paths(os.path.join(root, ".greyrun")).ensure(), root


def _watched(root):
    d = os.path.join(root, "docs")
    utils.ensure_dir(d)
    return d


def _write(path, data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _random_bytes(n):
    return _RNG.randbytes(n)


def _kinds(assessment):
    return {r.rsplit("[", 1)[1].rstrip("]") for r in assessment.reasons}


# --------------------------------------------------------------------------- #
#  Canary hygiene
# --------------------------------------------------------------------------- #


class TestCanaryHygiene(unittest.TestCase):
    def test_no_tilde_canary_names(self):
        # `~$<name>` is Office's owner-lock namespace; a canary there is a
        # guaranteed decisive-signal false positive.
        self.assertFalse(any(n.startswith("~$") for n in canary_mod.CANARY_NAMES))
        self.assertFalse(any(is_transient(n) for n in canary_mod.CANARY_NAMES))

    def test_deploy_migrates_tilde_entries(self):
        import hashlib

        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], canaries_per_dir=1)
        body = canary_mod._CANARY_BODY.encode("utf-8")

        # Old-style ~$ canary whose content still matches -> file removed.
        stale = _write(os.path.join(watched, "~$financial_statements.xlsx"), body)
        # Same name shape but *real* Office lock content -> file preserved.
        lock = _write(os.path.join(watched, "~$budget.xlsx"), b"\x00" * 162)
        registry = {
            stale: {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body)},
            lock: {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body)},
        }
        canary_mod._registry_save(paths, registry)

        canary_mod.deploy(cfg, paths)
        reg = canary_mod.registry(paths)
        self.assertFalse(any(os.path.basename(p).startswith("~$") for p in reg))
        self.assertFalse(os.path.exists(stale))   # our body -> deleted
        self.assertTrue(os.path.exists(lock))     # foreign content -> untouched

    def test_missing_canary_is_alert_not_critical(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], canaries_per_dir=1,
                     canary_recheck_sec=0.0)
        canary_mod.deploy(cfg, paths)
        victim = list(canary_mod.registry(paths))[0]
        os.remove(victim)

        engine = detector.BehaviorEngine(cfg, paths)
        engine.observe("deleted", victim)          # queues the recheck
        a = engine.observe("modified", os.path.join(watched, "other.dat"))
        self.assertEqual(a.score, detector.W_CANARY_MISSING)
        self.assertEqual(a.level, detector.ALERT)

    def test_missing_canary_plus_burst_is_critical(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], canaries_per_dir=1,
                     canary_recheck_sec=0.0, burst_count=5)
        canary_mod.deploy(cfg, paths)
        victim = list(canary_mod.registry(paths))[0]
        os.remove(victim)
        engine = detector.BehaviorEngine(cfg, paths)
        engine.observe("deleted", victim)
        last = None
        for i in range(6):
            last = engine.observe("modified", os.path.join(watched, f"f{i}.dat"))
        self.assertEqual(last.score, 100)  # 60 canary + 40 burst
        self.assertEqual(last.level, detector.CRITICAL)

    def test_folder_move_scores_zero(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], canaries_per_dir=1)
        canary_mod.deploy(cfg, paths)
        shutil.rmtree(watched)

        states = {s.state for s in canary_mod.verify(paths)}
        self.assertEqual(states, {"missing_dir"})
        report = detector.scan(cfg, paths)
        self.assertEqual(report.risk, 0)
        self.assertEqual(report.level, detector.NONE)

    def test_transient_recovery_never_scores(self):
        # A canary that is "missing" for one event but back before the recheck
        # (sync/backup race) must not score.
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], canaries_per_dir=1,
                     canary_recheck_sec=0.0)
        canary_mod.deploy(cfg, paths)
        victim = list(canary_mod.registry(paths))[0]
        with open(victim, "rb") as fh:
            body = fh.read()
        engine = detector.BehaviorEngine(cfg, paths)
        os.remove(victim)
        engine.observe("deleted", victim)
        _write(victim, body)                       # restored before recheck
        a = engine.observe("modified", os.path.join(watched, "other.dat"))
        self.assertEqual(a.score, 0)


# --------------------------------------------------------------------------- #
#  Transient suppression + moved-event handling
# --------------------------------------------------------------------------- #


class TestTransients(unittest.TestCase):
    def test_office_save_dance_no_signals(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        doc = _write(os.path.join(watched, "doc.docx"),
                     b"PK\x03\x04" + b"docx-ish content " * 64)
        cfg = Config(watched_paths=[watched], header_settle_sec=0.0)
        engine = detector.BehaviorEngine(cfg, paths)
        engine.observe("created", os.path.join(watched, "~$doc.docx"))
        engine.observe("created", os.path.join(watched, "AB12CD34.tmp"))
        engine.observe("modified", os.path.join(watched, "AB12CD34.tmp"))
        engine.observe("modified", doc)
        a = engine.observe("modified", doc)        # flushes the header check
        self.assertEqual(a.score, 0)
        self.assertEqual(a.level, detector.NONE)

    def test_transient_deletes_still_count(self):
        # A wiper that shreds temp files must stay visible.
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], burst_count=3)
        engine = detector.BehaviorEngine(cfg, paths)
        last = None
        for i in range(3):
            last = engine.observe("deleted", os.path.join(watched, f"x{i}.tmp"))
        self.assertIn("mass_delete", _kinds(last))

    def test_renamed_victim_gets_entropy_checked(self):
        # Encrypt-in-place then rename: the *source* name promises low-entropy
        # content, so the destination must still be content-checked.
        paths, root = _tmp_paths()
        watched = _watched(root)
        dest = _write(os.path.join(watched, "report.txt.k8s3x"),
                      _random_bytes(20000))
        cfg = Config(watched_paths=[watched])
        engine = detector.BehaviorEngine(cfg, paths)
        a = engine.observe("moved", os.path.join(watched, "report.txt"), dest)
        kinds = _kinds(a)
        self.assertIn("encrypted", kinds)
        self.assertIn("stranded", kinds)   # unknown suffix over .txt, random body
        self.assertIn("stacked", kinds)    # two independent hits on one file

    def test_note_named_file_still_entropy_checked(self):
        # The old elif chain skipped the entropy check on note-named files.
        paths, root = _tmp_paths()
        watched = _watched(root)
        p = _write(os.path.join(watched, "recover_files.txt"), _random_bytes(20000))
        cfg = Config(watched_paths=[watched])
        engine = detector.BehaviorEngine(cfg, paths)
        kinds = _kinds(engine.observe("modified", p))
        self.assertIn("note", kinds)
        self.assertIn("encrypted", kinds)


# --------------------------------------------------------------------------- #
#  Chi-square gating + entropy jump
# --------------------------------------------------------------------------- #


class TestChiSquare(unittest.TestCase):
    def test_chi_separates_cipher_from_deflate(self):
        s = byte_stats(_random_bytes(65536))
        self.assertGreater(s.entropy, 7.9)
        self.assertLess(s.chi2, 320.0)
        self.assertTrue(cipher_like(s))

        text = b"".join(
            (f"line {i}: the quick brown fox jumps over the lazy dog {i*i}\n").encode()
            for i in range(5000)
        )
        comp = byte_stats(zlib.compress(text, 9)[:4096])
        # The head of real compressed data clears the entropy bar (this is
        # exactly the sample the entropy-only detector would flag)...
        self.assertGreaterEqual(comp.entropy, 7.8)
        # ...but its byte distribution is nowhere near uniform.
        self.assertGreater(comp.chi2, 320.0)
        self.assertFalse(cipher_like(comp))

    def test_compressed_document_no_longer_flags(self):
        d = tempfile.mkdtemp(prefix="grchi_")
        text = b"".join(
            (f"row {i},{i*i},{i*7919}\n").encode() for i in range(20000)
        )
        doc = _write(os.path.join(d, "export.txt"), zlib.compress(text, 9))
        # Entropy-only: false positive. Chi-gated: clean.
        self.assertTrue(looks_encrypted(doc, threshold=7.8))
        self.assertFalse(looks_encrypted(doc, threshold=7.8, chi2_max=320.0))

    def test_scan_entropy_jump(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        victim = _write(os.path.join(watched, "ledger.dat"),
                        b"".join(f"rec {i},ok\n".encode() for i in range(2000)))
        already_high = _write(os.path.join(watched, "blob.bin"),
                              zlib.compress(_random_bytes(20000)))
        cfg = Config(watched_paths=[watched])
        base = Baseline.build(cfg)
        base.save(paths)

        time.sleep(0.01)
        _write(victim, _random_bytes(20000))        # encrypted in place
        _write(already_high, _random_bytes(20000))  # high before, high after

        report = detector.scan(cfg, paths, Baseline.load(paths))
        jumped = {p for p, _old, _new in report.entropy_jumps}
        self.assertIn(victim, jumped)      # .dat: no entropy class, still caught
        self.assertNotIn(already_high, jumped)  # was never structured
        self.assertGreaterEqual(report.risk, detector.W_ENTROPY_JUMP)


# --------------------------------------------------------------------------- #
#  Scoring: classes, caps, corroboration
# --------------------------------------------------------------------------- #


class TestScoring(unittest.TestCase):
    def _engine(self, root, **kw):
        paths = Paths(os.path.join(root, ".greyrun")).ensure()
        cfg = Config(watched_paths=[_watched(root)], **kw)
        return detector.BehaviorEngine(cfg, paths), cfg

    def test_gpg_trio_is_watch(self):
        # Three bare .enc files: openssl/licensing context, never an incident.
        root = tempfile.mkdtemp(prefix="grsc_")
        engine, _ = self._engine(root)
        last = None
        for i in range(3):
            last = engine.observe("created", os.path.join(root, f"backup{i}.enc"))
        self.assertEqual(last.score, 20)   # 3x10 capped at 20
        self.assertEqual(last.level, detector.WATCH)

    def test_git_checkout_is_alert_not_defend(self):
        # Volume evidence alone (burst + mass delete) must never reach DEFEND.
        root = tempfile.mkdtemp(prefix="grsc_")
        engine, _ = self._engine(root)
        last = None
        for i in range(30):
            engine.observe("modified", os.path.join(root, f"src{i}.py"))
        for i in range(30):
            last = engine.observe("deleted", os.path.join(root, f"old{i}.py"))
        self.assertEqual(last.score, 40)   # burst 40 + mass_delete 30, capped
        self.assertEqual(last.level, detector.ALERT)

    def test_creates_only_burst_is_watch(self):
        # Archive extraction / initial sync / photo import: creates, no rewrites.
        root = tempfile.mkdtemp(prefix="grsc_")
        engine, _ = self._engine(root)
        last = None
        for i in range(30):
            last = engine.observe("created", os.path.join(root, f"new{i}.html"))
        self.assertIn("burst_create", _kinds(last))
        self.assertEqual(last.score, detector.W_BURST_CREATE)
        self.assertEqual(last.level, detector.WATCH)

    def test_volume_uncaps_with_content(self):
        # The same churn plus one family-extension file is a different story.
        root = tempfile.mkdtemp(prefix="grsc_")
        engine, _ = self._engine(root)
        for i in range(30):
            engine.observe("modified", os.path.join(root, f"src{i}.py"))
        for i in range(30):
            engine.observe("deleted", os.path.join(root, f"old{i}.py"))
        a = engine.observe("created", os.path.join(root, "report.lockbit"))
        self.assertGreaterEqual(a.score, 100)  # ext 40 + volume 65 -> CRITICAL
        self.assertEqual(a.level, detector.CRITICAL)

    def test_stacked_bonus_fires_once_per_file(self):
        root = tempfile.mkdtemp(prefix="grsc_")
        engine, _ = self._engine(root)
        victim = _write(os.path.join(root, "doc.txt.lockbit"), _random_bytes(20000))
        a = engine.observe("modified", victim)
        kinds = _kinds(a)
        self.assertIn("ext", kinds)
        self.assertIn("encrypted", kinds)
        self.assertIn("stacked", kinds)
        stacked = [r for r in a.reasons if "[stacked]" in r]
        self.assertEqual(len(stacked), 1)
        # ext 40 + encrypted 30 + stacked 10
        self.assertEqual(a.score, 80)
        self.assertEqual(a.level, detector.DEFEND)

    def test_note_class_is_capped(self):
        root = tempfile.mkdtemp(prefix="grsc_")
        engine, _ = self._engine(root)
        engine.observe("created", os.path.join(root, "HOW_TO_DECRYPT.txt"))
        a = engine.observe("created", os.path.join(root, "RESTORE_FILES.txt"))
        self.assertEqual(a.score, 60)      # note kind capped, not 120
        self.assertEqual(a.level, detector.ALERT)

    def test_corroborated_score_arithmetic(self):
        f = detector.corroborated_score
        self.assertEqual(f([("canary", 100)]), 100)
        self.assertEqual(f([("burst", 40), ("mass_delete", 30)]), 40)
        self.assertEqual(f([("burst", 40), ("mass_delete", 30), ("ext", 40)]), 105)
        self.assertEqual(f([("ext_weak", 10)] * 5), 20)
        # Class-None context can never uncap volume.
        self.assertEqual(f([("burst", 40), ("ext_cluster", 25)]), 65)
        self.assertEqual(f([("note", 60), ("note_content", 60)]), 75)


# --------------------------------------------------------------------------- #
#  Header (magic-byte) validation
# --------------------------------------------------------------------------- #


def _make_docx(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("word/document.xml", "<w:document>hello</w:document>")
    return path


class TestHeaderMismatch(unittest.TestCase):
    def test_encrypted_docx_fires_after_settle(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        doc = _make_docx(os.path.join(watched, "report.docx"))
        _write(doc, _random_bytes(8192))           # encrypted in place
        cfg = Config(watched_paths=[watched], header_settle_sec=0.0)
        engine = detector.BehaviorEngine(cfg, paths)
        engine.observe("modified", doc)             # arms the settle timer
        a = engine.observe("modified", doc)         # prune flushes the check
        self.assertIn("hdr", _kinds(a))
        self.assertEqual(a.score, detector.W_HEADER_MISMATCH)
        self.assertEqual(a.level, detector.ALERT)   # one file alerts, never kills

    def test_healthy_and_misnamed_files_never_fire(self):
        d = tempfile.mkdtemp(prefix="grhdr_")
        healthy = _make_docx(os.path.join(d, "real.docx"))
        png_as_jpg = _write(os.path.join(d, "photo.jpg"),
                            b"\x89PNG\r\n\x1a\n" + _random_bytes(4000))
        rtf_as_doc = _write(os.path.join(d, "memo.doc"),
                            b"{\\rtf1\\ansi " + b"words and words " * 64 + b"}")
        for p in (healthy, png_as_jpg, rtf_as_doc):
            self.assertIsNone(
                filetypes.header_mismatch(p, 512, 7.8, 320.0), p)

    def test_preallocated_zeros_do_not_fire(self):
        d = tempfile.mkdtemp(prefix="grhdr_")
        p = _write(os.path.join(d, "big.zip"), b"\x00" * (1 << 20))
        self.assertIsNone(filetypes.header_mismatch(p, 512, 7.8, 320.0))

    def test_partial_write_stays_debounced(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        doc = _write(os.path.join(watched, "report.docx"), _random_bytes(8192))
        cfg = Config(watched_paths=[watched], header_settle_sec=30.0)
        engine = detector.BehaviorEngine(cfg, paths)
        engine.observe("modified", doc)
        a = engine.observe("modified", doc)         # still inside the settle
        self.assertNotIn("hdr", _kinds(a))
        self.assertEqual(a.score, 0)

    def test_scan_reports_header_mismatch(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        doc = _make_docx(os.path.join(watched, "report.docx"))
        _write(doc, _random_bytes(8192))
        cfg = Config(watched_paths=[watched])
        report = detector.scan(cfg, paths)
        self.assertEqual([p for p, _ in report.header_mismatch], [doc])
        self.assertEqual(report.risk, detector.W_HEADER_MISMATCH)


# --------------------------------------------------------------------------- #
#  Stranded double extensions + rename clustering
# --------------------------------------------------------------------------- #


class TestStrandedAndCluster(unittest.TestCase):
    def test_stranded_fires_on_encrypted_double_ext(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        p = _write(os.path.join(watched, "invoice.docx.k8s3x"), _random_bytes(8192))
        cfg = Config(watched_paths=[watched])
        engine = detector.BehaviorEngine(cfg, paths)
        a = engine.observe("created", p)
        self.assertIn("stranded", _kinds(a))

    def test_stranded_ignores_benign_workflows(self):
        # Name-level exclusions.
        self.assertFalse(is_stranded_document_ext("report.docx.gpg"))
        self.assertFalse(is_stranded_document_ext("archive.docx.zip"))
        self.assertFalse(is_stranded_document_ext("data.csv.001"))
        self.assertFalse(is_stranded_document_ext("report.docx.bak"))
        # Content gate: a batch-renamed file keeping readable content is clean.
        paths, root = _tmp_paths()
        watched = _watched(root)
        p = _write(os.path.join(watched, "report.xlsx.processed"),
                   b"perfectly readable plaintext " * 100)
        cfg = Config(watched_paths=[watched])
        engine = detector.BehaviorEngine(cfg, paths)
        self.assertNotIn("stranded", _kinds(engine.observe("created", p)))

    def test_ext_cluster_fires_at_threshold(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], ext_cluster_count=5)
        engine = detector.BehaviorEngine(cfg, paths)
        last = None
        for i in range(5):
            p = _write(os.path.join(watched, f"f{i}.qq7zx"), _random_bytes(6000))
            last = engine.observe("created", p)
        self.assertIn("ext_cluster", _kinds(last))
        self.assertEqual(last.score, detector.W_EXT_CLUSTER)
        self.assertEqual(last.level, detector.WATCH)

    def test_live_cluster_needs_cipher_content(self):
        # A data pipeline emitting healthy batches under a novel extension:
        # the name pattern alone must not fire (parity with the scan path).
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], ext_cluster_count=5)
        engine = detector.BehaviorEngine(cfg, paths)
        last = None
        for i in range(8):
            p = _write(os.path.join(watched, f"batch{i}.qq7zx"),
                       b"col1,col2,col3\n" + b"1,2,3\n" * 400)
            last = engine.observe("created", p)
        self.assertNotIn("ext_cluster", _kinds(last))

    def test_bulk_rename_of_plaintext_stays_alert(self):
        # A homegrown bulk-rename script: readable content, so neither the
        # cluster nor any content detector fires -- volume alone, ALERT max.
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], ext_cluster_count=12, burst_count=25)
        engine = detector.BehaviorEngine(cfg, paths)
        last = None
        for i in range(25):
            src = os.path.join(watched, f"f{i}.txt")
            dest = _write(src + ".qq7zx", b"perfectly readable text " * 40)
            last = engine.observe("moved", src, dest)
        self.assertIn("burst", _kinds(last))
        self.assertNotIn("ext_cluster", _kinds(last))
        self.assertEqual(last.score, 40)   # volume-capped burst only
        self.assertEqual(last.level, detector.ALERT)

    def test_cluster_ignores_known_and_build_exts(self):
        self.assertIsNone(detector._cluster_ext("a.txt"))
        self.assertIsNone(detector._cluster_ext("a.o"))
        self.assertIsNone(detector._cluster_ext("a.pyc"))
        self.assertIsNone(detector._cluster_ext("a.001"))
        self.assertIsNone(detector._cluster_ext("a.locked"))  # scored as ext
        self.assertIsNone(detector._cluster_ext("a"))
        self.assertEqual(detector._cluster_ext("a.qq7zx"), ".qq7zx")

    def test_scan_cluster_requires_cipher_confirmation(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], ext_cluster_count=4)
        # Renamed but still-readable files: no confirmation, no signal.
        for i in range(4):
            _write(os.path.join(watched, f"a{i}.txt.qq7zx"), b"plain text " * 50)
        self.assertEqual(detector.scan(cfg, paths).risk, 0)
        # Same cluster with encrypted members: fires.
        for i in range(4):
            _write(os.path.join(watched, f"a{i}.txt.qq7zx"), _random_bytes(6000))
        report = detector.scan(cfg, paths)
        self.assertTrue(any("qq7zx" in f for f in report.findings))


# --------------------------------------------------------------------------- #
#  Sustained long memory
# --------------------------------------------------------------------------- #


class TestSustainedMemory(unittest.TestCase):
    def _engine(self, watched, paths, **kw):
        cfg = Config(watched_paths=[watched], **kw)
        return detector.BehaviorEngine(cfg, paths)

    def test_fires_on_third_content_credit_across_windows(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        engine = self._engine(watched, paths, burst_window_sec=0.3,
                              memory_window_sec=60.0, sustained_content_min=3)
        last = None
        for i in range(3):
            p = _write(os.path.join(watched, f"doc{i}.txt"), _random_bytes(9000))
            last = engine.observe("modified", p)
            if i < 2:
                time.sleep(0.4)  # let the short window fully drain
        self.assertIn("sustained", _kinds(last))
        # encrypted (this window) + sustained
        self.assertEqual(last.score, detector.W_ENCRYPTED + detector.W_SUSTAINED)

    def test_survives_short_window_while_memory_warm(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        engine = self._engine(watched, paths, burst_window_sec=0.3,
                              memory_window_sec=60.0, sustained_content_min=2)
        for i in range(2):
            p = _write(os.path.join(watched, f"doc{i}.txt"), _random_bytes(9000))
            engine.observe("modified", p)
        time.sleep(0.4)
        snap = engine.snapshot()   # per-file signals decayed; memory holds
        self.assertEqual(_kinds(snap), {"sustained"})
        self.assertEqual(snap.score, detector.W_SUSTAINED)

    def test_ignores_volume_and_weak_kinds(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        engine = self._engine(watched, paths, burst_window_sec=0.2,
                              burst_count=2, memory_window_sec=60.0,
                              sustained_content_min=3)
        for rnd in range(3):
            engine.observe("modified", os.path.join(watched, f"a{rnd}.dat"))
            engine.observe("modified", os.path.join(watched, f"b{rnd}.dat"))
            engine.observe("created", os.path.join(watched, f"c{rnd}.enc"))
            time.sleep(0.25)
        self.assertNotIn("sustained", _kinds(engine.snapshot()))

    def test_decays_after_memory_window(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        engine = self._engine(watched, paths, burst_window_sec=0.2,
                              memory_window_sec=0.5, sustained_content_min=3)
        for i in range(3):
            p = _write(os.path.join(watched, f"doc{i}.txt"), _random_bytes(9000))
            engine.observe("modified", p)
        time.sleep(0.75)
        snap = engine.snapshot()
        self.assertEqual(snap.score, 0)
        self.assertNotIn("sustained", _kinds(snap))

    def test_disabled_by_zero_window(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        engine = self._engine(watched, paths, memory_window_sec=0.0,
                              sustained_content_min=1)
        for i in range(3):
            p = _write(os.path.join(watched, f"doc{i}.txt"), _random_bytes(9000))
            engine.observe("modified", p)
        self.assertNotIn("sustained", _kinds(engine.snapshot()))


# --------------------------------------------------------------------------- #
#  Ransom-note content scoring
# --------------------------------------------------------------------------- #

_GENESIS_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"   # valid base58check
_ONION = "x" * 56 + ".onion"

_STRONG_NOTE = (
    "ALL YOUR FILES HAVE BEEN ENCRYPTED!\r\n"
    "To restore your files, buy bitcoin and send 0.5 BTC to the wallet\r\n"
    f"{_GENESIS_BTC}\r\n"
    f"Then contact us via http://{_ONION} using tor browser.\r\n"
    "You have 72 hours or the price will be doubled.\r\n"
)


class TestNoteContent(unittest.TestCase):
    def test_strong_note_all_encodings(self):
        d = tempfile.mkdtemp(prefix="grnote_")
        fixtures = [
            _write(os.path.join(d, "utf8.txt"), _STRONG_NOTE.encode("utf-8")),
            # PowerShell Out-File default: UTF-16-LE without a BOM.
            _write(os.path.join(d, "utf16.txt"), _STRONG_NOTE.encode("utf-16-le")),
            _write(os.path.join(d, "note.hta"),
                   ("<html><body><p>"
                    + _STRONG_NOTE.replace("\r\n", "</p><p>")
                    + "</p></body></html>").encode("utf-8")),
        ]
        for p in fixtures:
            match = notecontent.looks_like_ransom_note_content(p)
            self.assertIsNotNone(match, p)
            self.assertTrue(match.strong, p)
            self.assertTrue(any(c.startswith("anchor:") for c in match.categories), p)

    def test_single_topic_never_fires(self):
        article = ("Bitcoin rallied again this week as investors bought bitcoin "
                   "and monero; analysts expect wallet adoption to grow.")
        backup_readme = ("This tool can restore your files from a snapshot. "
                         "See the recovery instructions in the manual.")
        self.assertIsNone(notecontent.analyze_note_text(article))
        self.assertIsNone(notecontent.analyze_note_text(backup_readme))

    def test_invalid_base58_downgrades_to_weak(self):
        base = ("Your files have been encrypted. Do not rename your files.\r\n"
                "Pay 0.5 btc to {addr} within 48 hours.\r\n")
        strong = notecontent.analyze_note_text(base.format(addr=_GENESIS_BTC))
        self.assertIsNotNone(strong)
        self.assertTrue(strong.strong)
        # One flipped character breaks the checksum: same prose, weak tier.
        flipped = _GENESIS_BTC[:-1] + ("b" if _GENESIS_BTC[-1] != "b" else "c")
        weak = notecontent.analyze_note_text(base.format(addr=flipped))
        self.assertIsNotNone(weak)
        self.assertFalse(weak.strong)

    def test_lone_address_is_not_a_note(self):
        # A wallet backup: an address with no extortion prose.
        self.assertIsNone(notecontent.analyze_note_text(
            f"my cold wallet: {_GENESIS_BTC}"))

    def test_binary_renamed_txt_scores_zero(self):
        d = tempfile.mkdtemp(prefix="grnote_")
        p = _write(os.path.join(d, "note.txt"),
                   b"\x89PNG\r\n\x1a\n" + _random_bytes(4000))
        self.assertIsNone(notecontent.looks_like_ransom_note_content(p))

    def test_size_gate_blocks_large_files(self):
        d = tempfile.mkdtemp(prefix="grnote_")
        p = _write(os.path.join(d, "thesis.txt"),
                   (_STRONG_NOTE * 400).encode("utf-8"))  # way over 32 KB
        self.assertIsNone(notecontent.looks_like_ransom_note_content(p))

    def test_scan_finds_content_note_by_body(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        note = _write(os.path.join(watched, "README.txt"), _STRONG_NOTE)
        _write(os.path.join(watched, "bitcoin_news.txt"),
               "bitcoin price analysis: investors bought bitcoin this week")
        cfg = Config(watched_paths=[watched])
        report = detector.scan(cfg, paths)
        flagged = {p for p, _cats in report.ransom_note_content}
        self.assertEqual(flagged, {note})
        self.assertNotIn(note, report.ransom_notes)  # filename alone is clean

    def test_engine_scores_note_content(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        note = _write(os.path.join(watched, "README.txt"), _STRONG_NOTE)
        cfg = Config(watched_paths=[watched])
        engine = detector.BehaviorEngine(cfg, paths)
        a = engine.observe("created", note)
        self.assertIn("note_content", _kinds(a))
        self.assertEqual(a.score, detector.W_NOTE_CONTENT)


class TestReviewRegressions(unittest.TestCase):
    """Regression tests for defects found by the adversarial review of the
    v1.2.0 detection engine."""

    def test_donation_footer_is_not_a_note(self):
        # A real BTC address plus everyday support prose is a project README,
        # not extortion. The anchor is payment-topic evidence; it needs
        # threat/contact/decrypt prose around it to fire.
        self.assertIsNone(notecontent.analyze_note_text(
            f"Support our project! Donate Bitcoin to {_GENESIS_BTC}. "
            "Questions? contact us via email."))
        self.assertIsNone(notecontent.analyze_note_text(
            f"Donations: {_GENESIS_BTC}. See the recovery instructions "
            "in our manual to restore your files from a snapshot."))

    def test_vendor_security_prose_is_not_a_note(self):
        self.assertIsNone(notecontent.analyze_note_text(
            "Your files are encrypted at rest and in transit. To restore "
            "your files, contact us via support@vendor.example."))
        self.assertIsNone(notecontent.analyze_note_text(
            "Bitcoin analysis: the price doubled in just 24 hours as "
            "wallet adoption grew."))

    def test_burst_not_muted_by_preceding_create_storm(self):
        # A creates-only storm must not pin the throttle and demote the
        # stronger rewrite burst that a real sweep earns moments later.
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], burst_count=5)
        engine = detector.BehaviorEngine(cfg, paths)
        for i in range(5):
            engine.observe("created", os.path.join(watched, f"new{i}.html"))
        last = None
        for i in range(5):
            last = engine.observe("modified", os.path.join(watched, f"doc{i}.dat"))
        kinds = _kinds(last)
        self.assertIn("burst_create", kinds)
        self.assertIn("burst", kinds)   # full weight, not muted

    def test_mass_delete_needs_distinct_paths(self):
        # One churning path (SQLite journal, duplicate OS events) must not
        # read as a mass deletion.
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], burst_count=5)
        engine = detector.BehaviorEngine(cfg, paths)
        last = None
        for _ in range(10):
            last = engine.observe("deleted", os.path.join(watched, "app.db-journal"))
        self.assertNotIn("mass_delete", _kinds(last))

    def test_small_compressed_fragment_not_cipher_like(self):
        # cipher_like must reject sub-chi-sample data, never accept it on
        # entropy alone: a 3.5KB deflate fragment clears 7.8 bits/byte.
        text = b"".join(
            (f"line {i}: assorted words {i*i}\n").encode() for i in range(3000))
        frag = zlib.compress(text, 9)[:3500]
        self.assertFalse(cipher_like(byte_stats(frag)))
        d = tempfile.mkdtemp(prefix="grrev_")
        p = _write(os.path.join(d, "part.zip"), frag)
        self.assertIsNone(filetypes.header_mismatch(p, 512, 7.8, 320.0))

    def test_user_encryption_tools_not_stranded(self):
        # age/AES Crypt/AxCrypt output wraps the user's own document.
        for name in ("report.txt.age", "report.txt.aes", "report.docx.axx",
                     "passwords.kdbx"):
            self.assertFalse(is_stranded_document_ext(name), name)

    def test_sustained_counts_distinct_files_not_saves(self):
        # One repeatedly re-saved cipher-like file must not satisfy the
        # sustained bar by itself.
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], burst_window_sec=0.2,
                     memory_window_sec=60.0, sustained_content_min=3)
        engine = detector.BehaviorEngine(cfg, paths)
        p = _write(os.path.join(watched, "blob.txt"), _random_bytes(9000))
        for _ in range(3):
            engine.observe("modified", p)
            time.sleep(0.25)   # short window drains; 'encrypted' re-credits
        self.assertNotIn("sustained", _kinds(engine.snapshot()))

    def test_sustained_weight_scales_with_file_count(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], burst_window_sec=0.2,
                     memory_window_sec=60.0, sustained_content_min=3)
        engine = detector.BehaviorEngine(cfg, paths)
        for i in range(5):
            p = _write(os.path.join(watched, f"doc{i}.txt"), _random_bytes(9000))
            engine.observe("modified", p)
        time.sleep(0.3)        # per-file signals decay; memory holds
        snap = engine.snapshot()
        self.assertEqual(_kinds(snap), {"sustained"})
        self.assertEqual(snap.score, detector.W_SUSTAINED + 5 * 2)  # 5 files

    def test_canary_renamed_then_encrypted_is_critical(self):
        # Rename-first strains: the displaced decoy stays watched under its
        # new name, so encrypting it is still the decisive signal.
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], canaries_per_dir=1)
        canary_mod.deploy(cfg, paths)
        src = list(canary_mod.registry(paths))[0]
        dest = src + ".qq7zx"
        if os.name == "nt":
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(src), 0x80)
        os.rename(src, dest)

        engine = detector.BehaviorEngine(cfg, paths)
        a = engine.observe("moved", src, dest)
        self.assertEqual(a.score, detector.W_CANARY_MISSING)  # renamed intact

        _write(dest, _random_bytes(4000))       # now encrypted in place
        a = engine.observe("modified", dest)
        self.assertGreaterEqual(a.score, detector.W_CANARY)
        self.assertEqual(a.level, detector.CRITICAL)

    def test_canary_rewritten_under_rename_is_critical(self):
        paths, root = _tmp_paths()
        watched = _watched(root)
        cfg = Config(watched_paths=[watched], canaries_per_dir=1)
        canary_mod.deploy(cfg, paths)
        src = list(canary_mod.registry(paths))[0]
        dest = src + ".locked"
        if os.name == "nt":
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(src), 0x80)
        os.rename(src, dest)
        _write(dest, _random_bytes(4000))       # rewritten before we observe

        engine = detector.BehaviorEngine(cfg, paths)
        a = engine.observe("moved", src, dest)
        self.assertGreaterEqual(a.score, detector.W_CANARY)
        self.assertEqual(a.level, detector.CRITICAL)

    def test_mp3_sync_no_longer_excuses_ciphertext(self):
        # An 11-bit frame sync matches ~1/2048 random heads; the full frame
        # validation must reject e.g. FF F1 (reserved layer).
        self.assertFalse(filetypes.matches_any_known(
            b"\xff\xf1" + _random_bytes(4094)))
        # A genuine MPEG1 Layer III header still passes.
        self.assertTrue(filetypes.matches_any_known(
            b"\xff\xfb\x90\x44" + b"\x00" * 100))
        d = tempfile.mkdtemp(prefix="grrev_")
        doc = _write(os.path.join(d, "report.docx"),
                     b"\xff\xf1" + _random_bytes(8190))
        self.assertIsNotNone(filetypes.header_mismatch(doc, 512, 7.8, 320.0))

    def test_utf16be_and_zero_padded_notes_decode(self):
        d = tempfile.mkdtemp(prefix="grrev_")
        be = _write(os.path.join(d, "be.txt"), _STRONG_NOTE.encode("utf-16-be"))
        padded = _write(os.path.join(d, "padded.txt"),
                        _STRONG_NOTE.encode("utf-8") + b"\x00" * 2048)
        for p in (be, padded):
            match = notecontent.looks_like_ransom_note_content(p)
            self.assertIsNotNone(match, p)
            self.assertTrue(match.strong, p)

    def test_sqlcipher_style_db_not_flagged(self):
        # A database encrypted at rest (SQLCipher) is ciphertext from byte 0
        # by design; the header detector must not treat it as a victim.
        d = tempfile.mkdtemp(prefix="grrev_")
        p = _write(os.path.join(d, "db.sqlite"), _random_bytes(16384))
        self.assertFalse(filetypes.has_magic_for(p))


if __name__ == "__main__":
    unittest.main(verbosity=2)
