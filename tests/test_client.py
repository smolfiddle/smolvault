"""Remote client + board regression net.

Covers the crash that ended every client session after a successful remote
ingest (a 3-arg call into a 2-arg function), the export partial-file
leak, the unchecked ingest status, the stale auth probe, and the board's
documented-but-absent `q` exit.

Run: python -m unittest tests.test_client -v
"""
import http.client
import io
import itertools
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

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


class TestStoreNoteRemote(unittest.TestCase):
    """#2: `store_note_remote(rv, sealed, into)` raised TypeError on every
    remote ingest, killing the client with exit 1 *after* the work landed."""

    def test_signature_is_two_args(self):
        import inspect
        self.assertEqual(
            list(inspect.signature(sv.store_note_remote).parameters),
            ["rv", "text"])

    def test_posts_a_message(self):
        posted = []

        class FakeConn:
            def request(self, method, path, body=None, headers=None):
                posted.append((method, path, body))

            def getresponse(self):
                class R:
                    def read(self):
                        return b"{}"
                return R()

            def close(self):
                pass

        rv = mock.Mock()
        rv.host, rv.port = "h", 1
        rv._headers.return_value = {}
        with mock.patch.object(http.client, "HTTPConnection",
                               return_value=FakeConn()):
            sv.store_note_remote(rv, "sealed 3 file(s) into /movies")
        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0][0], "POST")
        self.assertEqual(posted[0][1], "/__api/msg")
        self.assertEqual(json.loads(posted[0][2])["body"],
                         "sealed 3 file(s) into /movies")

    def test_never_raises(self):
        rv = mock.Mock()
        rv.host, rv.port = "h", 1
        with mock.patch.object(http.client, "HTTPConnection",
                               side_effect=OSError("refused")):
            sv.store_note_remote(rv, "anything")   # must not propagate


class TestExportCleanup(unittest.TestCase):
    """#14: a transfer that dies mid-stream left a truncated file on disk
    and raised an http.client error _fetch does not catch."""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="svexp_")

    def tearDown(self):
        shutil.rmtree(self.W, ignore_errors=True)

    def test_incomplete_read_removes_the_partial(self):
        rv = sv.RemoteVault("127.0.0.1", 1)
        out = os.path.join(self.W, "movie.mkv")

        class Resp:
            status = 200

            def __init__(self):
                self.n = 0

            def getheader(self, k):
                return "1000"

            def read(self, n):
                self.n += 1
                if self.n == 1:
                    return b"x" * 100
                # IncompleteRead is an HTTPException, *not* an OSError, so
                # it used to escape _fetch and leave the partial on disk
                raise http.client.IncompleteRead(b"short")

        class C:
            def request(self, *a, **k):
                pass

            def getresponse(self):
                return Resp()

            def close(self):
                pass

        with mock.patch.object(http.client, "HTTPConnection",
                               return_value=C()):
            with self.assertRaises(sv.RemoteError):
                rv._fetch("/x.mkv", out=out)
        self.assertFalse(os.path.exists(out),
                         "a failed export must not leave a partial file")

    def test_rows_none_is_safe(self):
        rv = sv.RemoteVault("127.0.0.1", 1)
        rv.rows = None
        with redirect_stdout(io.StringIO()):
            rc = rv.export("/x.mkv", out=os.path.join(self.W, "nope.bin"))
        self.assertEqual(rc, sv.EXIT_NOMATCH)
        self.assertFalse(os.path.exists(os.path.join(self.W, "nope.bin")))

    def test_refuses_to_overwrite(self):
        rv = sv.RemoteVault("127.0.0.1", 1)
        rv.rows = []
        dest = os.path.join(self.W, "exists.bin")
        with open(dest, "wb") as f:
            f.write(b"keep me")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = rv.export("/x.mkv", out=dest)
        self.assertEqual(rc, sv.EXIT_NOMATCH)
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), b"keep me")


class TestIngestStatus(unittest.TestCase):
    """#27: a 400 rejection from /__api/ingest was parsed and printed as
    nothing at all -- the user believed 900 files had been sealed."""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="sving_")
        self.vault = os.path.join(self.W, "p.vault")
        self.store = sv.Store(self.vault)
        self.port = free_port()
        self.srv = serve(self.store, self.port)

    def tearDown(self):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        except Exception:
            pass
        shutil.rmtree(self.W, ignore_errors=True)

    def test_error_body_is_reported(self):
        rv = sv.RemoteVault("127.0.0.1", self.port)
        rv.password = "pw"
        self.store.set_password("pw")
        rv.password = "pw"
        buf = io.StringIO()
        with redirect_stdout(buf):
            results = sv.run_client_ingest(rv, ["a"] * 500, "/backup")
        self.assertIsInstance(results, dict)
        self.assertIn("error", results)
        self.assertNotIn("results", results)

    def test_ok_body_is_reported(self):
        self.share = os.path.join(self.W, "share")
        os.makedirs(self.share)
        with open(os.path.join(self.share, "a.txt"), "wb") as f:
            f.write(b"hello")
        self.store.cfg_set("share_root", self.share)
        rv = sv.RemoteVault("127.0.0.1", self.port)
        with redirect_stdout(io.StringIO()):
            results = sv.run_client_ingest(rv, ["/a.txt"], "/backup")
        self.assertIn("results", results)
        self.assertEqual(results["results"][0]["status"], 201)
        self.assertIsNotNone(self.store.lookup("/backup/a.txt"))


class TestAuthProbe(unittest.TestCase):
    """#29: `_auth_probe` was never initialised nor reset on reconnect, so
    after switching to an un-gated vault the client still embedded a
    password into the URL it handed the player."""

    def test_initialised(self):
        rv = sv.RemoteVault("h", 1)
        self.assertIn("_auth_probe", vars(rv))
        self.assertIsNone(rv._auth_probe)

    def test_reset_on_reconnect(self):
        W = tempfile.mkdtemp(prefix="svprobe_")
        try:
            vault = os.path.join(W, "a.vault")
            s = sv.Store(vault)
            s.set_password("pw")
            s.put("/f.bin", io.BytesIO(b"x"))
            s.set_auth_required(False)
            port = free_port()
            srv = serve(s, port)
            try:
                rv = sv.RemoteVault("127.0.0.1", port)
                rv.authenticate()
                self.assertFalse(rv.store_requires_auth(),
                                 "open vault -> not gated")
                # simulate the reconnect bug
                rv._auth_probe = True
                sv.reset_auth_probe(rv)
                self.assertIsNone(rv._auth_probe)
                self.assertNotIn("@", rv.cred_url("/f.bin"))
            finally:
                srv.shutdown()
                srv.server_close()
        finally:
            shutil.rmtree(W, ignore_errors=True)

    def test_cred_url_embeds_only_when_gated(self):
        rv = sv.RemoteVault("h", 9)
        rv.password = "pw"
        rv._auth_probe = False
        self.assertEqual(rv.cred_url("/a.mkv"), "http://h:9/a.mkv")
        rv._auth_probe = True
        self.assertIn("smolvault:pw@", rv.cred_url("/a.mkv"))


class TestBoardQ(unittest.TestCase):
    """#33: the docstring promised 'Esc/q exits'; on a TTY `q` was typed
    into the buffer and posted to the permanent board instead."""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="svboardq_")
        self.store = sv.Store(os.path.join(self.W, "b.vault"))
        self.store.post_msg("alice", "user", "existing")

    def tearDown(self):
        shutil.rmtree(self.W, ignore_errors=True)

    def test_q_exits_without_posting(self):
        keys = itertools.chain(["q"], itertools.repeat("\x1b"))
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = sv.board_live(store=self.store, poll=60,
                               read_key=lambda: next(keys), assume_tty=True)
        self.assertEqual(rc, sv.EXIT_OK)
        bodies = [m["body"] for m in self.store.msgs_since(0)]
        self.assertEqual(bodies, ["existing"],
                         "'q' must exit, not post")

    def test_poll_failure_is_surfaced(self):
        calls = {"n": 0}

        def flaky(after, limit):
            calls["n"] += 1
            if calls["n"] > 1:
                raise sv.RemoteError("peer went away")
            return [dict(r) for r in self.store.msgs_since(after, limit)]

        keys = itertools.chain(["t"], itertools.repeat("\x1b"))
        buf = io.StringIO()
        with redirect_stdout(buf):
            sv.board_live(store=self.store, poll=0, fetch=None,
                          read_key=lambda: next(keys), assume_tty=True)
        # the render helper takes an explicit error slot
        frame = sv._board_render([{"ts": "", "sender": "a", "kind": "user",
                                   "body": "hi"}], "", "board", "peer went away")
        self.assertIn("offline", frame.lower())

    def test_injected_readkey_does_not_busyloop(self):
        # a read_key that always says "tick" must not spin a core forever
        n = {"i": 0}

        def keys():
            n["i"] += 1
            if n["i"] > 50:
                raise KeyboardInterrupt
            return "tick"

        t0 = time.perf_counter()
        with redirect_stdout(io.StringIO()):
            try:
                sv.board_live(store=self.store, poll=0, read_key=keys,
                              assume_tty=True)
            except KeyboardInterrupt:
                pass
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 5.0,
                        f"50 iterations took {elapsed:.1f}s -- busy loop")


class TestWizardEOF(unittest.TestCase):
    """#17: `except EOFError` swallowed the unlock prompt and the wizard
    went on to serve a still-locked vault on 0.0.0.0."""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="svweof_")
        try:
            sv._Crypto.lib()
        except sv.CryptoUnavailable:
            self.skipTest("libcrypto unavailable")
        self.vault = os.path.join(self.W, "e.vault")
        s = sv.Store(self.vault)
        s.set_password("pw")
        s.enable_encryption("pw")
        s.put("/f.bin", io.BytesIO(b"x"))
        self.store = sv.Store(self.vault)
        self.w = sv.Wizard(self.store, "e.vault", no_discover=True)

    def tearDown(self):
        shutil.rmtree(self.W, ignore_errors=True)

    def test_eof_while_locked_exits(self):
        with mock.patch("getpass.getpass", side_effect=EOFError):
            with redirect_stdout(io.StringIO()):
                rc = self.w.run()
        self.assertEqual(rc, sv.EXIT_NOMATCH)
        self.assertIsNone(self.w.srv, "must not serve a locked vault")

    def test_eof_while_locked_prints_a_reason(self):
        buf = io.StringIO()
        with mock.patch("getpass.getpass", side_effect=EOFError):
            with redirect_stdout(buf):
                self.w.run()
        self.assertIn("locked", buf.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
