"""Vault sync regression net — push, pull, no-op, and the rollback path.

The pull path used to delete only the `files` row on a hash mismatch,
permanently orphaning every chunk the partial ingest had already
committed (nothing in the sync path called gc()).

Run: python -m unittest tests.test_sync -v
"""
import io
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
import http.client

import smolvault as sv


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    _, p = s.getsockname()
    s.close()
    return p


def serve(store, port):
    srv = sv.make_server(store, "127.0.0.1", port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    for _ in range(50):
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            c.request("OPTIONS", "/")
            c.getresponse().read()
            c.close()
            break
        except OSError:
            time.sleep(0.05)
    return srv


class SyncBase(unittest.TestCase):
    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="svsync_")
        self.mine_p = os.path.join(self.W, "mine.vault")
        self.peer_p = os.path.join(self.W, "peer.vault")
        self.mine = sv.Store(self.mine_p)
        self.peer = sv.Store(self.peer_p)
        self.port = free_port()
        self.srv = serve(self.peer, self.port)
        self.payload = bytes(range(256)) * 400

    def tearDown(self):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        except Exception:
            pass
        shutil.rmtree(self.W, ignore_errors=True)

    def paths(self, store):
        return {r["path"] for r in store.all_files()}

    def orphans(self, store):
        c = store.conn()
        ref = set()
        for (m,) in c.execute("SELECT manifest FROM files"):
            import json
            ref.update(json.loads(m)["chunks"])
        live = {r[0] for r in c.execute("SELECT hash FROM chunks")}
        return live - ref


class TestSyncPush(SyncBase):
    def setUp(self):
        super().setUp()
        self.mine.put("/movie.mkv", io.BytesIO(self.payload))
        self.mine.put("/notes.txt", io.BytesIO(b"hello notes"))

    def test_push_fills_the_gap(self):
        rc = sv.sync_vault(self.mine, "to", "127.0.0.1", self.port,
                           assume_yes=True)
        self.assertEqual(rc, sv.EXIT_OK)
        self.assertEqual(self.paths(self.peer), {"/movie.mkv", "/notes.txt"})
        row = self.peer.lookup("/movie.mkv")
        self.assertEqual(b"".join(self.peer.read_full(row)), self.payload)
        self.assertEqual(self.peer.lookup("/movie.mkv")["root_hash"],
                         self.mine.lookup("/movie.mkv")["root_hash"])

    def test_push_twice_is_a_noop(self):
        sv.sync_vault(self.mine, "to", "127.0.0.1", self.port,
                      assume_yes=True)
        before = self.peer.stats()["stored"]
        rc = sv.sync_vault(self.mine, "to", "127.0.0.1", self.port,
                           assume_yes=True)
        self.assertEqual(rc, sv.EXIT_OK)
        self.assertEqual(self.peer.stats()["stored"], before)

    def test_push_alias_push(self):
        rc = sv.sync_vault(self.mine, "push", "127.0.0.1", self.port,
                           assume_yes=True)
        self.assertEqual(rc, sv.EXIT_OK)
        self.assertIn("/movie.mkv", self.paths(self.peer))

    def test_rejects_unknown_direction_without_network_io(self):
        seen = []
        real = sv.RemoteVault

        def spy(*a, **k):
            seen.append(a)
            return real(*a, **k)

        sv.RemoteVault = spy
        try:
            rc = sv.sync_vault(self.mine, "sideways", "127.0.0.1", self.port,
                               assume_yes=True)
        finally:
            sv.RemoteVault = real
        self.assertEqual(rc, sv.EXIT_USAGE)
        self.assertEqual(seen, [], "must validate before authenticating")


class TestSyncPull(SyncBase):
    def setUp(self):
        super().setUp()
        self.peer.put("/movie.mkv", io.BytesIO(self.payload))
        self.peer.put("/art/poster.jpg", io.BytesIO(b"\xff\xd8jpegdata"))

    def test_pull_fills_the_gap(self):
        rc = sv.sync_vault(self.mine, "from", "127.0.0.1", self.port,
                           assume_yes=True)
        self.assertEqual(rc, sv.EXIT_OK)
        self.assertEqual(self.paths(self.mine),
                         {"/movie.mkv", "/art/poster.jpg"})
        row = self.mine.lookup("/movie.mkv")
        self.assertEqual(b"".join(self.mine.read_full(row)), self.payload)

    def test_pull_alias_pull(self):
        rc = sv.sync_vault(self.mine, "pull", "127.0.0.1", self.port,
                           assume_yes=True)
        self.assertEqual(rc, sv.EXIT_OK)
        self.assertIn("/movie.mkv", self.paths(self.mine))

    def test_pull_leaves_no_orphans(self):
        sv.sync_vault(self.mine, "from", "127.0.0.1", self.port,
                      assume_yes=True)
        self.assertEqual(self.orphans(self.mine), set())
        self.assertTrue(self.mine.check())

    def test_pull_twice_is_a_noop(self):
        sv.sync_vault(self.mine, "from", "127.0.0.1", self.port,
                      assume_yes=True)
        before = self.mine.stats()["stored"]
        rc = sv.sync_vault(self.mine, "from", "127.0.0.1", self.port,
                           assume_yes=True)
        self.assertEqual(rc, sv.EXIT_OK)
        self.assertEqual(self.mine.stats()["stored"], before)

    def test_both_directions_converge(self):
        self.mine.put("/mine.mkv", io.BytesIO(b"local only"))
        sv.sync_vault(self.mine, "to", "127.0.0.1", self.port, assume_yes=True)
        sv.sync_vault(self.mine, "from", "127.0.0.1", self.port,
                      assume_yes=True)
        self.assertEqual(self.paths(self.mine), self.paths(self.peer))
        self.assertEqual(self.orphans(self.mine), set())
        self.assertEqual(self.orphans(self.peer), set())


class TestRollbackCleansUp(SyncBase):
    def test_drop_file_removes_row_and_its_chunks(self):
        self.mine.put("/doomed.bin", io.BytesIO(b"z" * 300_000))
        before = self.mine.stats()
        self.assertGreater(before["chunks"], 0)
        self.mine.drop_file("/doomed.bin")
        self.assertIsNone(self.mine.lookup("/doomed.bin"))
        after = self.mine.stats()
        self.assertEqual(after["chunks"], 0)
        self.assertEqual(after["stored"], 0)
        self.assertEqual(self.orphans(self.mine), set())

    def test_drop_file_keeps_shared_chunks(self):
        data = b"shared payload " * 30_000
        self.mine.put("/one.bin", io.BytesIO(data))
        self.mine.put("/two.bin", io.BytesIO(data))
        chunks = self.mine.stats()["chunks"]
        self.mine.drop_file("/one.bin")
        self.assertIsNone(self.mine.lookup("/one.bin"))
        self.assertIsNotNone(self.mine.lookup("/two.bin"))
        self.assertEqual(self.mine.stats()["chunks"], chunks,
                         "a chunk still referenced by /two.bin must survive")
        row = self.mine.lookup("/two.bin")
        self.assertEqual(b"".join(self.mine.read_full(row)), data)
        self.assertEqual(self.orphans(self.mine), set())

    def test_drop_missing_path_is_a_noop(self):
        self.mine.put("/keep.bin", io.BytesIO(b"k"))
        self.mine.drop_file("/never-existed")
        self.assertIsNotNone(self.mine.lookup("/keep.bin"))


class TestIngestLease(SyncBase):
    """gc() must never delete chunks belonging to an in-flight ingest —
    including from a *different process*, which is what --gc is."""

    def _simulate_inflight(self, path, data, stale=False, dead_pid=False):
        """Mimic the window _put opens: chunks committed, files row not yet
        written, ingest_lease row live."""
        self.mine.put(path, io.BytesIO(data))
        c = self.mine.conn()
        c.execute("DELETE FROM files WHERE path=?", (path,))
        started = time.time() - (sv.Store.LEASE_GRACE * 4 if stale else 0)
        pid = 999_999 if dead_pid else os.getpid()      # a pid that can't be live
        c.execute("INSERT OR REPLACE INTO ingest_lease (path, started, pid) "
                  "VALUES (?,?,?)", (path, started, pid))
        c.commit()
        return self.mine.stats()["chunks"]

    def test_lease_protects_chunks_from_gc(self):
        before = self._simulate_inflight("/incoming.bin", b"y" * 300_000)
        self.assertGreater(before, 0)

        self.mine.gc()
        self.assertEqual(self.mine.stats()["chunks"], before,
                         "gc() deleted chunks a live ingest still owns")
        self.assertEqual(self.mine.conn().execute(
            "SELECT COUNT(*) FROM ingest_lease").fetchone()[0], 1,
            "the lease must survive so the writer can release it")

    def test_live_lease_defers_collection_entirely(self):
        # real orphans must also be left alone while an ingest is running
        c = self.mine.conn()
        c.execute("INSERT OR IGNORE INTO chunks VALUES (?,?,?)",
                  ("aa" * 32, b"orphan", 0))
        c.commit()
        self._simulate_inflight("/busy.bin", b"z" * 200_000)
        self.mine.gc()
        self.assertIsNotNone(c.execute(
            "SELECT 1 FROM chunks WHERE hash=?", ("aa" * 32,)).fetchone(),
            "collection must be deferred, not partial")

    def test_lease_is_released_after_a_successful_put(self):
        self.mine.put("/normal.bin", io.BytesIO(b"n" * 200_000))
        n = self.mine.conn().execute(
            "SELECT COUNT(*) FROM ingest_lease").fetchone()[0]
        self.assertEqual(n, 0, "a completed put must not leave a lease behind")

    def test_lease_is_released_after_a_failed_put(self):
        class Boom(io.RawIOBase):
            def readable(self):
                return True

            def read(self, n=-1):
                raise OSError("disk went away")

        with self.assertRaises(OSError):
            self.mine.put("/fails.bin", Boom())
        n = self.mine.conn().execute(
            "SELECT COUNT(*) FROM ingest_lease").fetchone()[0]
        self.assertEqual(n, 0, "a failed put must not leave a lease behind")

    def test_stale_lease_is_reclaimed(self):
        self._simulate_inflight("/crashed.bin", b"z" * 200_000, stale=True)
        self.mine.gc()
        self.assertEqual(self.mine.conn().execute(
            "SELECT COUNT(*) FROM ingest_lease").fetchone()[0], 0)
        self.assertEqual(self.mine.stats()["chunks"], 0,
                         "a kill -9 mid-ingest must self-heal on the next gc")

    def test_dead_pid_reclaims_immediately(self):
        """the usual crash case: the owner is gone, so no waiting for the
        grace period -- otherwise `--gc` right after a kill -9 would defer"""
        self._simulate_inflight("/crashed.bin", b"z" * 200_000, dead_pid=True)
        self.mine.gc()
        self.assertEqual(self.mine.conn().execute(
            "SELECT COUNT(*) FROM ingest_lease").fetchone()[0], 0)
        self.assertEqual(self.mine.stats()["chunks"], 0)

    def test_our_own_live_lease_is_respected(self):
        before = self._simulate_inflight("/mine.bin", b"z" * 200_000)
        self.mine.gc()
        self.assertEqual(self.mine.stats()["chunks"], before,
                         "a lease held by a live pid must protect its chunks")

    def test_pid_alive_probe(self):
        self.assertTrue(sv.Store._pid_alive(os.getpid()))
        self.assertFalse(sv.Store._pid_alive(0))
        self.assertFalse(sv.Store._pid_alive(999_999))

    def test_lease_survives_a_put_that_dies_midway(self):
        """a reader that dies after a batch has flushed must not leave a
        lease behind in a long-lived server: that would block its own --gc
        until the process exited"""
        class HalfDead(io.RawIOBase):
            def __init__(s, n):
                s.left = n
                s.calls = 0

            def readable(self):
                return True

            def read(s, n=-1):
                s.calls += 1
                if s.left <= 0:
                    raise OSError("cable pulled")
                take = min(262144, s.left)
                s.left -= take
                return b"H" * take

        s = self.mine
        s.DB_BATCH = 2                     # force several batch flushes
        r = HalfDead(4 * 1024 * 1024)
        with self.assertRaises(OSError):
            s.put("/halfdead.bin", r)
        s.DB_BATCH = 100
        n = s.conn().execute("SELECT COUNT(*) FROM ingest_lease").fetchone()[0]
        self.assertEqual(n, 0, "a failed put must not leave a lease behind")
        # and gc must not be blocked by it
        s.gc()
        self.assertEqual(s.conn().execute(
            "SELECT COUNT(*) FROM ingest_lease").fetchone()[0], 0)

    def test_lease_is_not_a_separate_commit(self):
        """The lease rides in the first batch's transaction. Committing it
        separately cost 7% (media) to 16% (small files) of ingest."""
        s = self.mine
        s.DB_BATCH = 100
        c = s.conn()
        before = len(c.execute("PRAGMA database_list").fetchall())
        s.put("/commits.bin", io.BytesIO(b"Z" * (2 * 1024 * 1024)))
        n = s.conn().execute(
            "SELECT COUNT(*) FROM ingest_lease").fetchone()[0]
        self.assertEqual(n, 0, "lease cleared with the files row")
        self.assertIsNotNone(s.lookup("/commits.bin"))
        self.assertTrue(s.check())

    def test_worm_race_does_not_leak_chunks_or_lease(self):
        """the IntegrityError path must roll back cleanly, not deadlock on
        _wlock (drop_file takes it, and put() already holds it)"""
        s = self.mine
        s.put("/dup.bin", io.BytesIO(b"first"))
        with self.assertRaises(sv.ExistsError):
            s.put("/dup.bin", io.BytesIO(b"second"))
        self.assertEqual(
            s.conn().execute(
                "SELECT COUNT(*) FROM ingest_lease").fetchone()[0], 0)
        self.assertEqual(self.orphans(s), set())
        self.assertTrue(s.check())

    def test_gc_still_works_when_idle(self):
        self.mine.put("/a.bin", io.BytesIO(b"a" * 200_000))
        c = self.mine.conn()
        c.execute("INSERT OR IGNORE INTO chunks VALUES (?,?,?)",
                  ("bb" * 32, b"orphan", 0))
        c.commit()
        self.assertEqual(self.orphans(self.mine), {"bb" * 32})
        self.mine.gc()
        self.assertEqual(self.orphans(self.mine), set())
        self.assertIsNotNone(self.mine.lookup("/a.bin"))
        self.assertTrue(self.mine.check())


if __name__ == "__main__":
    unittest.main()
