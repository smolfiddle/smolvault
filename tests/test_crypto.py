"""Encryption regression net.

Focus: the data-loss path. `disable_encryption` used to drop the key
material while leaving every envelope in place, after which every read
failed with "authentication failed — tampered or wrong key" while the
message board stayed perfectly readable.

Run: python -m unittest tests.test_crypto -v
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import smolvault as sv


def have_crypto():
    try:
        sv._Crypto.lib()
        return True
    except sv.CryptoUnavailable:
        return False


@unittest.skipUnless(have_crypto(), "libcrypto unavailable")
class TestCryptoRoundTrip(unittest.TestCase):
    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="svcrypto_")
        self.vault = os.path.join(self.W, "e.vault")
        self.pw = "correct horse battery staple"
        self.store = sv.Store(self.vault)
        self.store.set_password(self.pw)
        self.store.enable_encryption(self.pw)
        self.data = b"payload " * 50_000
        self.store.put("/a.bin", io.BytesIO(self.data))
        self.store.put("/b.bin", io.BytesIO(self.data))   # dedup + duplicate path

    def tearDown(self):
        shutil.rmtree(self.W, ignore_errors=True)

    def env_count(self, store):
        return store.conn().execute(
            "SELECT COUNT(*) FROM chunks WHERE hex(substr(data,1,5))=?",
            (sv.Store.ENC_MAGIC.hex().upper(),)).fetchone()[0]

    def test_legacy_chunk_was_migrated(self):
        self.assertEqual(self.env_count(self.store), 1)

    def test_fresh_store_can_unlock_and_read(self):
        fresh = sv.Store(self.vault)
        self.assertTrue(fresh.enc_enabled())
        self.assertFalse(fresh.is_unlocked())
        fresh.unlock(self.pw)
        row = fresh.lookup("/a.bin")
        self.assertEqual(b"".join(fresh.read_full(row)), self.data)

    def test_wrong_password_raises(self):
        fresh = sv.Store(self.vault)
        with self.assertRaises(ValueError):
            fresh.unlock("wrong password")

    def test_reads_before_unlock_raise_locked(self):
        fresh = sv.Store(self.vault)
        row = fresh.lookup("/a.bin")
        with self.assertRaises(sv.LockedVault):
            b"".join(fresh.read_full(row))

    def test_matching_password_check(self):
        self.assertTrue(self.store.check_password(self.pw))
        self.assertFalse(self.store.check_password(self.pw + "x"))

    def test_board_encrypted_and_readable_after_unlock(self):
        self.store.post_msg("alice", "user", "top secret note")
        row = self.store.conn().execute(
            "SELECT body FROM messages ORDER BY id DESC LIMIT 1").fetchone()
        self.assertTrue(row["body"].startswith("SVMSG:"))
        self.assertNotIn("top secret note", row["body"])
        self.assertIn("top secret note",
                      [m["body"] for m in self.store.msgs_since(0)])

    # ---- the data-loss regression ----

    def test_disable_encryption_refuses_while_enveloped(self):
        with self.assertRaises(ValueError) as cm:
            self.store.disable_encryption(self.pw)
        self.assertIn("still encrypted", str(cm.exception))
        # nothing destroyed: the vault still reads
        row = self.store.lookup("/a.bin")
        self.assertEqual(b"".join(self.store.read_full(row)), self.data)
        self.assertEqual(self.env_count(self.store), 1)

    def test_disable_after_migration_works_and_keeps_data(self):
        stripped = 0
        c = self.store.conn()
        for h, blob in c.execute("SELECT hash, data FROM chunks").fetchall():
            c.execute("UPDATE chunks SET data=? WHERE hash=?",
                      (self.store._open(blob, h), h))
            stripped += 1
        c.commit()
        self.assertEqual(stripped, 1)
        self.assertEqual(self.env_count(self.store), 0)

        self.store.disable_encryption(self.pw)
        self.assertFalse(self.store.enc_enabled())
        self.assertTrue(self.store.is_unlocked())
        row = self.store.lookup("/a.bin")
        self.assertEqual(b"".join(self.store.read_full(row)), self.data)

    def test_disable_clears_all_key_material(self):
        stripped = 0
        c = self.store.conn()
        for h, blob in c.execute("SELECT hash, data FROM chunks").fetchall():
            c.execute("UPDATE chunks SET data=? WHERE hash=?",
                      (self.store._open(blob, h), h))
            stripped += 1
        c.commit()
        self.store.disable_encryption(self.pw)
        for attr in ("_mk", "_ek", "_nk", "_msg_k"):
            self.assertIsNone(getattr(self.store, attr, None),
                              f"{attr} survived disable_encryption")

    def test_migrate_is_idempotent_and_resumable(self):
        # a second pass must find nothing left to do
        again = self.store.migrate_encryption()
        self.assertEqual(again, 0)
        row = self.store.lookup("/a.bin")
        self.assertEqual(b"".join(self.store.read_full(row)), self.data)

    def test_check_passes_on_encrypted_vault(self):
        self.assertTrue(self.store.check())

    def test_tampered_envelope_detected(self):
        c = self.store.conn()
        h, blob = c.execute("SELECT hash, data FROM chunks").fetchone()
        bad = bytearray(blob)
        bad[-1] ^= 0xFF                      # flip a tag bit
        c.execute("UPDATE chunks SET data=? WHERE hash=?", (bytes(bad), h))
        c.commit()
        with self.assertRaises(ValueError):
            self.store._open(bytes(bad), h)
        self.assertFalse(self.store.check(), "check must FAIL on a bad tag")


@unittest.skipUnless(have_crypto(), "libcrypto unavailable")
class TestCryptoPrimitives(unittest.TestCase):
    def test_seal_open_roundtrip_and_aad(self):
        key, nonce = b"k" * 32, b"n" * 12
        ct, tag = sv._Crypto.seal(key, nonce, b"hello", aad=b"ctx")
        self.assertEqual(sv._Crypto.open(key, nonce, ct + tag, aad=b"ctx"),
                         b"hello")
        # AAD is authenticated: a mismatch must not decrypt
        for bad_aad in (b"other", b""):
            with self.assertRaises(ValueError):
                sv._Crypto.open(key, nonce, ct + tag, aad=bad_aad)
        with self.assertRaises(ValueError):
            sv._Crypto.open(b"j" * 32, nonce, ct + tag, aad=b"ctx")
        with self.assertRaises(ValueError):
            sv._Crypto.open(key, b"m" * 12, ct + tag, aad=b"ctx")
        with self.assertRaises(ValueError):
            sv._Crypto.open(key, nonce, ct + bytes(16), aad=b"ctx")
        with self.assertRaises(ValueError):
            sv._Crypto.open(key, nonce, b"short", aad=b"ctx")

    def test_convergent_nonce_is_deterministic(self):
        """same key+plaintext => same envelope, which is what preserves dedup"""
        key, nonce = b"k" * 32, b"n" * 12
        a = sv._Crypto.seal(key, nonce, b"same", aad=b"x")
        b = sv._Crypto.seal(key, nonce, b"same", aad=b"x")
        self.assertEqual(a, b)

    def test_plaintext_passes_through_when_not_encrypted(self):
        s = sv.Store(":memory:")
        self.assertFalse(s.enc_enabled())
        self.assertTrue(s.is_unlocked())
        self.assertEqual(s._open(b"plain blob", "aa" * 32), b"plain blob")
        self.assertEqual(s._seal(b"plain blob", "aa" * 32), b"plain blob")


class TestInMemoryStore(unittest.TestCase):
    """:memory: used to hand every thread a private, schema-less DB."""

    def test_same_connection_across_threads(self):
        s = sv.Store(":memory:")
        s.put("/a.txt", io.BytesIO(b"x"))
        out = {}

        def other():
            try:
                out["n"] = s.conn().execute(
                    "SELECT COUNT(*) FROM files").fetchone()[0]
            except Exception as e:
                out["err"] = str(e)

        import threading
        t = threading.Thread(target=other)
        t.start()
        t.join()
        self.assertNotIn("err", out, out.get("err"))
        self.assertEqual(out["n"], 1)


@unittest.skipUnless(have_crypto(), "libcrypto unavailable")
class TestMaintenanceUnlocks(unittest.TestCase):
    """--check/--gc used to run straight against a locked Store, so an
    encrypted vault died with a raw LockedVault traceback."""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="svmaint_")
        self.vault = os.path.join(self.W, "e.vault")
        s = sv.Store(self.vault)
        s.set_password("pw")
        s.enable_encryption("pw")
        s.put("/a.bin", io.BytesIO(b"payload" * 1000))
        s.set_auth_required(False)
        subprocess.run([sys.executable, sv.__file__, self.vault,
                        "--decrypt", "-p", "pw"],
                       capture_output=True)     # leave it encrypted
        subprocess.run([sys.executable, sv.__file__, self.vault,
                        "--encrypt", "-p", "pw"], capture_output=True)

    def tearDown(self):
        shutil.rmtree(self.W, ignore_errors=True)

    def _run(self, *args):
        return subprocess.run([sys.executable, sv.__file__, self.vault]
                              + list(args), capture_output=True, text=True)

    def test_check_with_password(self):
        r = self._run("--check", "-p", "pw")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PASS", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    def test_check_with_wrong_password(self):
        r = self._run("--check", "-p", "nope")
        self.assertEqual(r.returncode, sv.EXIT_NOMATCH)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("incorrect password", r.stdout)

    def test_check_without_password_piped(self):
        r = self._run("--check")
        self.assertEqual(r.returncode, sv.EXIT_NOMATCH)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("provide -p/--password", r.stdout)

    def test_gc_with_password(self):
        r = self._run("--gc", "-p", "pw")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_unlock_helper_contract(self):
        st = sv.Store(self.vault)
        self.assertTrue(st.enc_enabled())
        self.assertFalse(st.is_unlocked())
        self.assertFalse(sv._unlock_for_maintenance(st, "wrong", self.vault))
        self.assertTrue(sv._unlock_for_maintenance(st, "pw", self.vault))
        self.assertTrue(st.is_unlocked())


if __name__ == "__main__":
    unittest.main()
