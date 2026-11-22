"""Regression net for the Stage-4 audit swarm fixes.

Covers: the ENC_MAGIC prefix collision, board encryption symmetry, the
two-Store WORM race, lease heartbeats, strict Content-Length parsing,
share-root desync/NUL handling, weak If-Range, target parsing, auth
caching, redacted Termux URLs, empty-file info and multi-file export.

Run: python -m unittest tests.test_fixes -v
"""
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import http.client
import contextlib
from unittest import mock

import smolvault as sv


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def serve(store):
    srv = sv.make_server(store, "127.0.0.1", free_port())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    for _ in range(50):
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1],
                                           timeout=1)
            c.request("OPTIONS", "/")
            c.getresponse().read()
            c.close()
            break
        except OSError:
            time.sleep(0.05)
    return srv, srv.server_address[1]


def have_crypto():
    try:
        sv._Crypto.lib()
        return True
    except sv.CryptoUnavailable:
        return False


class ChunkerBoundaryTests(unittest.TestCase):
    """The two-phase hot loop must produce byte-identical chunks to the
    original single-loop scanner. Any drift silently breaks dedup with
    every vault sealed before the change (and --check would still pass).
    """

    @staticmethod
    def reference(chunker, fobj):
        """Original pre-optimisation scanner, kept as an oracle."""
        gear, stride = chunker.gear, chunker.stride
        min_s, max_s = chunker.min_s, chunker.max_s
        mask_s, mask_l = chunker.mask_s, chunker.mask_l
        buf, pos = bytearray(), 0
        while True:
            if len(buf) - pos < max_s + stride:
                if pos > 0:
                    buf = buf[pos:]
                    pos = 0
                data = fobj.read(4 * 1024 * 1024)
                if not data:
                    break
                buf.extend(data)
            n = len(buf)
            if n - pos < min_s:
                continue
            cut, h, cur = -1, 0, pos + min_s
            while cur < n:
                h = ((h << 1) + gear[buf[cur]]) & 0xFFFFFFFFFFFFFFFF
                off = cur - pos
                if off < 262144:
                    if (h & mask_s) == 0:
                        cut = cur
                        break
                elif (h & mask_l) == 0:
                    cut = cur
                    break
                cur += stride
            if cut != -1:
                yield bytes(buf[pos:cut + 1])
                pos = cut + 1
            elif n - pos >= max_s:
                yield bytes(buf[pos:pos + max_s])
                pos += max_s
        if pos < len(buf):
            yield bytes(buf[pos:])

    def test_boundaries_match_reference(self):
        payloads = [
            os.urandom(3 * 1024 * 1024),
            (b"the quick brown fox " * 160_000)[:3 * 1024 * 1024],
        ]
        for stride in (32, 64, 128, 256, 512):
            ch = sv.Chunker(stride=stride)
            for payload in payloads:
                want = list(self.reference(ch, io.BytesIO(payload)))
                got = list(ch.chunk(io.BytesIO(payload)))
                self.assertEqual(got, want,
                                 f"stride {stride}: chunk boundaries changed")


class PrefixCollisionTests(unittest.TestCase):
    """A valid plaintext chunk beginning with SVEN\\x01 used to be treated
    as an AES envelope on read — silent, permanent data loss."""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="svfix_magic_")
        self.data = sv.Store.ENC_MAGIC + bytes(
            (i * 37 + 11) & 0xFF for i in range(200_000))

    def tearDown(self):
        shutil.rmtree(self.W, ignore_errors=True)

    def test_plain_vault_reads_magic_prefixed_chunk(self):
        s = sv.Store(os.path.join(self.W, "p.vault"))
        s.put("/p.bin", io.BytesIO(self.data))
        row = s.lookup("/p.bin")
        self.assertEqual(b"".join(s.read_full(row)), self.data)
        self.assertTrue(s.check())

    @unittest.skipUnless(have_crypto(), "libcrypto unavailable")
    def test_encrypted_vault_seals_and_reads_magic_prefixed_chunk(self):
        v = os.path.join(self.W, "e.vault")
        s = sv.Store(v)
        s.set_password("pw")
        s.enable_encryption("pw")
        s.put("/p.bin", io.BytesIO(self.data))
        stored = s.conn().execute("SELECT data FROM chunks").fetchone()[0]
        self.assertTrue(stored.startswith(sv.Store.ENC_MAGIC))
        self.assertNotEqual(stored, self.data, "chunk must really be sealed")
        self.assertEqual(b"".join(s.read_full(s.lookup("/p.bin"))), self.data)

    @unittest.skipUnless(have_crypto(), "libcrypto unavailable")
    def test_legacy_plaintext_collision_self_heals(self):
        """A chunk stored by the old code (raw, with the magic prefix) is
        recognised by its hash and read back as plaintext."""
        v = os.path.join(self.W, "legacy.vault")
        s = sv.Store(v)
        s.set_password("pw")
        s.enable_encryption("pw")
        s.put("/p.bin", io.BytesIO(self.data))
        h = s.conn().execute("SELECT hash FROM chunks").fetchone()[0]
        s.conn().execute("UPDATE chunks SET data=? WHERE hash=?",
                         (self.data, h))
        s.conn().commit()
        self.assertEqual(b"".join(s.read_full(s.lookup("/p.bin"))), self.data)


class BoardMigrationTests(unittest.TestCase):
    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="svfix_board_")
        self.vault = os.path.join(self.W, "b.vault")

    def tearDown(self):
        shutil.rmtree(self.W, ignore_errors=True)

    def test_plain_note_starting_svmsg_is_readable(self):
        s = sv.Store(self.vault)
        s.post_msg("alice", "user", "SVMSG:just a normal note")
        self.assertEqual(s.msgs_since(0)[0]["body"], "SVMSG:just a normal note")

    @unittest.skipUnless(have_crypto(), "libcrypto unavailable")
    def test_decrypt_preserves_board_history(self):
        s = sv.Store(self.vault)
        s.set_password("pw")
        s.enable_encryption("pw")
        s.post_msg("alice", "user", "IMPORTANT BOARD NOTE")
        r = subprocess.run([sys.executable, sv.__file__, self.vault,
                            "--decrypt", "-p", "pw"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        fresh = sv.Store(self.vault)
        self.assertFalse(fresh.enc_enabled())
        self.assertIn("IMPORTANT BOARD NOTE",
                      [m["body"] for m in fresh.msgs_since(0)])

    @unittest.skipUnless(have_crypto(), "libcrypto unavailable")
    def test_decrypt_with_piped_password_does_not_crash(self):
        s = sv.Store(self.vault)
        s.set_password("pw")
        s.enable_encryption("pw")
        s.post_msg("alice", "user", "note")
        r = subprocess.run([sys.executable, sv.__file__, self.vault,
                            "--decrypt"], input="pw\n",
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertFalse(sv.Store(self.vault).enc_enabled())

    @unittest.skipUnless(have_crypto(), "libcrypto unavailable")
    def test_encrypt_seals_existing_messages(self):
        s = sv.Store(self.vault)
        s.set_password("pw")
        s.post_msg("alice", "user", "OLD BOARD NOTE")
        r = subprocess.run([sys.executable, sv.__file__, self.vault,
                            "--encrypt", "-p", "pw"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        fresh = sv.Store(self.vault)
        fresh.unlock("pw")
        stored = fresh.conn().execute("SELECT body FROM messages").fetchone()[0]
        self.assertTrue(stored.startswith("SVMSG:"), stored)
        self.assertEqual(fresh.msgs_since(0)[0]["body"], "OLD BOARD NOTE")

    @unittest.skipUnless(have_crypto(), "libcrypto unavailable")
    def test_migrate_encryption_returns_a_count(self):
        s = sv.Store(self.vault)
        s.set_password("pw")
        s.enable_encryption("pw")
        for i in range(3):
            s.put(f"/f{i}.bin", io.BytesIO(bytes([65 + i]) * 100))
        # manually revert one chunk to plaintext
        c = s.conn()
        h, data = c.execute("SELECT hash, data FROM chunks LIMIT 1").fetchone()
        c.execute("UPDATE chunks SET data=? WHERE hash=?", (b"B" * 100, h))
        c.commit()
        n = s.migrate_encryption()
        self.assertEqual(n, 1)
        self.assertEqual(s.migrate_encryption(), 0)


class ConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="svfix_race_")
        self.vault = os.path.join(self.W, "r.vault")

    def tearDown(self):
        shutil.rmtree(self.W, ignore_errors=True)

    def test_losing_put_does_not_delete_the_winners_row(self):
        s1 = sv.Store(self.vault)
        s2 = sv.Store(self.vault)      # separate _wlock, like another process

        class Racer:
            def __init__(self):
                self.did = False

            def read(self, n=-1):
                if not self.did:
                    self.did = True
                    c = s1.conn()
                    c.execute(
                        "INSERT INTO files (path,size,root_hash,mime,manifest) "
                        "VALUES (?,?,?,?,?)",
                        ("/dup.bin", 5, "winner", "x",
                         json.dumps({"chunks": [], "sizes": [], "offsets": []})))
                    c.commit()
                return b""

        with self.assertRaises(sv.ExistsError):
            s2.put("/dup.bin", Racer())
        self.assertIsNotNone(s1.lookup("/dup.bin"))

    def test_each_batch_refreshes_the_lease(self):
        s = sv.Store(self.vault)
        c = s.conn()
        before = c.execute("SELECT started FROM ingest_lease WHERE path='/x'").fetchone()
        s._flush_chunks(c, {"h" + "0" * 63: (b"abc", 0)}, [0], lease="/x")
        first = c.execute("SELECT started FROM ingest_lease WHERE path='/x'").fetchone()[0]
        time.sleep(0.01)
        s._flush_chunks(c, {"h" + "1" * 63: (b"def", 0)}, [0], lease="/x")
        second = c.execute("SELECT started FROM ingest_lease WHERE path='/x'").fetchone()[0]
        self.assertGreater(second, first, "later batches must heartbeat")


class ConfigTests(unittest.TestCase):
    def test_wal_checkpoint_override(self):
        W = tempfile.mkdtemp(prefix="svfix_wal_")
        try:
            with mock.patch.dict(os.environ,
                                 {"SMOLVAULT_WAL_CHECKPOINT": "100000"}):
                s = sv.Store(os.path.join(W, "a.vault"))
                self.assertEqual(
                    s.conn().execute("PRAGMA wal_autocheckpoint").fetchone()[0],
                    100000)
            old = os.environ.pop("SMOLVAULT_WAL_CHECKPOINT", None)
            try:
                s2 = sv.Store(os.path.join(W, "b.vault"))
                self.assertEqual(
                    s2.conn().execute("PRAGMA wal_autocheckpoint").fetchone()[0],
                    1000)          # SQLite default, unchanged
            finally:
                if old is not None:
                    os.environ["SMOLVAULT_WAL_CHECKPOINT"] = old
        finally:
            shutil.rmtree(W, ignore_errors=True)


class InputParsingTests(unittest.TestCase):
    def test_unicode_digit_content_length_is_400(self):
        self.assertEqual(sv._parse_content_length(
            {"Content-Length": "²"})[1], 400)

    def test_ascii_digit_flood_content_length_is_400(self):
        self.assertEqual(sv._parse_content_length(
            {"Content-Length": "9" * 5000})[1], 400)

    def test_target_parse_validation(self):
        self.assertEqual(sv.parse_target("host"), ("host", 8100))
        self.assertEqual(sv.parse_target("host:9000"), ("host", 9000))
        self.assertEqual(sv.parse_target("[::1]:8100"), ("::1", 8100))
        for bad in ("h:abc", "h:70000", "h:-1", "h:1:2", "[::1"):
            with self.assertRaises(ValueError, msg=bad):
                sv.parse_target(bad)

    def test_auth_cache_skips_repeated_pbkdf2(self):
        s = sv.Store(":memory:")
        s.set_password("pw")
        calls = []
        real = sv.hashlib.pbkdf2_hmac

        def spy(*a, **k):
            calls.append(1)
            return real(*a, **k)

        with mock.patch.object(sv.hashlib, "pbkdf2_hmac", spy):
            self.assertTrue(s.verify_password("pw"))
            self.assertTrue(s.verify_password("pw"))
            self.assertEqual(len(calls), 1)
            self.assertFalse(s.verify_password("wrong"))
            self.assertEqual(len(calls), 2)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="svfix_http_")
        self.store = sv.Store(os.path.join(self.W, "h.vault"))
        self.srv, self.port = serve(self.store)

    def tearDown(self):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        except Exception:
            pass
        shutil.rmtree(self.W, ignore_errors=True)

    def test_weak_if_range_is_ignored(self):
        self.store.put("/f.bin", io.BytesIO(b"0123456789"))
        etag = self.store.lookup("/f.bin")["root_hash"]
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/f.bin", headers={
            "Range": "bytes=0-1", "If-Range": 'W/"' + etag + '"'})
        r = c.getresponse()
        data = r.read()
        c.close()
        self.assertEqual(r.status, 200)
        self.assertEqual(data, b"0123456789")

    def test_ingest_without_share_root_closes_the_connection(self):
        body = b'{"paths":["x"],"into":"/"}'
        req = (b"POST /__api/ingest HTTP/1.1\r\nHost: x\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body
               + b"GET /__api/list HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        k = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        k.sendall(req)
        k.settimeout(5)
        buf = b""
        try:
            while True:
                d = k.recv(65536)
                if not d:
                    break
                buf += d
        except OSError:
            pass
        k.close()
        self.assertEqual(buf.count(b"HTTP/1.1 "), 1, repr(buf[:300]))
        self.assertIn(b"Connection: close", buf)

    def test_nul_byte_in_browse_is_400(self):
        share = os.path.join(self.W, "share")
        os.makedirs(share)
        self.store.cfg_set("share_root", share)
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/__api/browse?dir=%00")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 400)
        c.close()

    def test_browse_hides_symlinks_outside_share_root(self):
        share = os.path.join(self.W, "share2")
        os.makedirs(share)
        with open(os.path.join(share, "real.txt"), "wb") as f:
            f.write(b"ok")
        os.symlink("/etc/passwd", os.path.join(share, "escape"))
        self.store.cfg_set("share_root", share)
        for query in ("/__api/browse?dir=/",
                      "/__api/browse?dir=/&recursive=1"):
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            c.request("GET", query)
            r = c.getresponse()
            body = r.read()
            c.close()
            self.assertEqual(r.status, 200, query)
            self.assertNotIn(b"escape", body, query)
            self.assertIn(b"real.txt", body, query)

    def test_sync_survives_incomplete_read(self):
        W = tempfile.mkdtemp(prefix="svfix_sync_")
        try:
            peer = sv.Store(os.path.join(W, "peer.vault"))
            mine = sv.Store(os.path.join(W, "mine.vault"))
            peer.put("/f.bin", io.BytesIO(b"payload" * 100))
            srv, port = serve(peer)
            try:
                with mock.patch.object(sv.Store, "put",
                                       side_effect=http.client.IncompleteRead(b"x")):
                    rc = sv.sync_vault(mine, "from", "127.0.0.1", port,
                                       assume_yes=True)
                self.assertEqual(rc, sv.EXIT_NOMATCH)
            finally:
                srv.shutdown()
                srv.server_close()
        finally:
            shutil.rmtree(W, ignore_errors=True)

    def test_show_info_on_empty_file(self):
        self.store.put("/empty.bin", io.BytesIO(b""))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sv.show_info(self.store, "/empty.bin")
        self.assertEqual(rc, sv.EXIT_OK)
        self.assertIn("0", buf.getvalue())


class DuplicateFileTests(unittest.TestCase):
    """Malformed UDP replies must not crash discovery."""

    def test_malformed_discovery_reply_is_ignored(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            srv.bind(("127.0.0.1", sv.DISCOVERY_PORT))
        except OSError:
            self.skipTest("discovery port busy")

        def answer():
            srv.settimeout(2.0)
            try:
                data, addr = srv.recvfrom(1024)
                if data.strip() == sv.DISCOVERY_MAGIC:
                    srv.sendto(b'{"proto":"smolvault","name":"broken"}', addr)
                    data, addr = srv.recvfrom(1024)
                    srv.sendto(b'1234', addr)
            except OSError:
                pass

        threading.Thread(target=answer, daemon=True).start()
        try:
            hits = sv.discover_vaults(timeout=1.0)
            self.assertEqual(hits, [])
        finally:
            srv.close()


class UITests(unittest.TestCase):
    def test_termux_url_is_redacted_in_output(self):
        W = tempfile.mkdtemp(prefix="svfix_termux_")
        try:
            fake = os.path.join(W, "termux-am")
            with open(fake, "w") as f:
                f.write("#!/bin/sh\necho fail >&2\nexit 1\n")
            os.chmod(fake, 0o755)
            display = os.environ.get("DISPLAY")
            try:
                os.environ["TERMUX_VERSION"] = "1"
                os.environ["PATH"] = W + ":" + os.environ.get("PATH", "")
                os.environ.pop("DISPLAY", None)
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    sv.play_url("http://smolvault:Sup3rSecret@h:9/f.mkv",
                                mime="video/mp4")
                self.assertNotIn("Sup3rSecret", buf.getvalue())
                self.assertIn("***", buf.getvalue())
            finally:
                if display is not None:
                    os.environ["DISPLAY"] = display
                os.environ.pop("TERMUX_VERSION", None)
                os.environ["PATH"] = os.environ["PATH"].replace(W + ":", "", 1)
        finally:
            shutil.rmtree(W, ignore_errors=True)

    def test_multi_export_uses_each_basename(self):
        W = tempfile.mkdtemp(prefix="svfix_export_")
        try:
            store = sv.Store(os.path.join(W, "t.vault"))
            for p in ("/a.mkv", "/b.mkv"):
                store.put(p, io.BytesIO(b"x"))
            picked = [("/a.mkv", None), ("/b.mkv", None)]
            captured = []
            answers = iter(["b", "out.bin"])

            def fake_export(_store, path, out=None):
                captured.append(out)

            with mock.patch.object(sv, "vault_browse_picker",
                                   return_value=picked), \
                 mock.patch.object(sv, "export_file", fake_export), \
                 mock.patch("builtins.input", lambda p="": next(answers)):
                w = sv.Wizard(store, "t.vault", no_discover=True)
                with contextlib.redirect_stdout(io.StringIO()):
                    w.do_get()
            self.assertEqual(captured, ["a.mkv", "b.mkv"])
        finally:
            shutil.rmtree(W, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
