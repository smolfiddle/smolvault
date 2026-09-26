"""Locked-vault matrix — an encrypted vault must refuse *everything*
over HTTP until it is unlocked, and must never leak metadata, crash the
connection, or answer with a bare reset.

This is the regression net for the gate that used to sit *after* the
/__api/* dispatch, which let GET /__api/list answer 200 with the full
listing while file bodies correctly 423'd.

Run: python -m unittest tests.test_locked -v
"""
import io
import json
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


class TestLockedVault(unittest.TestCase):
    """Every endpoint, on a vault that was never unlocked in this process."""

    @classmethod
    def setUpClass(cls):
        try:
            sv._Crypto.lib()
        except sv.CryptoUnavailable as e:
            raise unittest.SkipTest(f"libcrypto unavailable: {e}")
        cls.W = tempfile.mkdtemp(prefix="svlock_")
        cls.vault = os.path.join(cls.W, "e.vault")
        seed = sv.Store(cls.vault)
        seed.set_password("pw")
        seed.enable_encryption("pw")
        seed.put("/secret.mkv", io.BytesIO(b"top secret payload" * 100))
        seed.post_msg("alice", "user", "pre-existing board note")
        seed.set_auth_required(False)      # isolate the 423 from the 401
        # a brand-new Store on the same file: has keys in config, none in RAM
        cls.locked = sv.Store(cls.vault)
        cls.port = free_port()
        cls.srv = serve(cls.locked, cls.port)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.srv.shutdown()
            cls.srv.server_close()
        except Exception:
            pass
        shutil.rmtree(cls.W, ignore_errors=True)

    def setUp(self):
        self.assertTrue(self.locked.enc_enabled())
        self.assertFalse(self.locked.is_unlocked())

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        st = r.status
        c.close()
        return st, data

    # ---- the gate must cover reads ------------------------------------

    def test_file_body_423(self):
        st, _ = self.req("GET", "/secret.mkv")
        self.assertEqual(st, 423)

    def test_range_read_423(self):
        st, _ = self.req("GET", "/secret.mkv", headers={"Range": "bytes=0-9"})
        self.assertEqual(st, 423)

    def test_head_423_no_body(self):
        st, data = self.req("HEAD", "/secret.mkv")
        self.assertEqual(st, 423)
        self.assertEqual(data, b"")

    # ---- the gate must cover the API surface too (the actual bug) ----

    def test_api_list_423_and_no_metadata(self):
        st, data = self.req("GET", "/__api/list")
        self.assertEqual(st, 423, "listing must not survive a locked vault")
        self.assertNotIn(b"secret.mkv", data)
        self.assertNotIn(b"root_hash", data)

    def test_dir_page_423(self):
        st, data = self.req("GET", "/")
        self.assertEqual(st, 423)
        self.assertNotIn(b"secret.mkv", data)

    def test_api_msg_get_423(self):
        st, data = self.req("GET", "/__api/msg")
        self.assertEqual(st, 423)
        self.assertNotIn(b"pre-existing board note", data)

    def test_api_browse_423(self):
        st, data = self.req("GET", "/__api/browse?dir=/")
        self.assertEqual(st, 423)
        self.assertNotIn(b"entries", data)

    def test_api_auth_state_423(self):
        st, _ = self.req("GET", "/__api/auth")
        self.assertEqual(st, 423)

    # ---- POST paths used to die with an uncaught AttributeError ----

    def test_post_msg_423_not_crash(self):
        body = json.dumps({"body": "hello"}).encode()
        st, _ = self.req("POST", "/__api/msg", body=body,
                         headers={"Content-Length": str(len(body))})
        self.assertEqual(st, 423)

    def test_post_ingest_423_not_crash(self):
        body = json.dumps({"paths": [], "into": "/"}).encode()
        st, _ = self.req("POST", "/__api/ingest", body=body,
                         headers={"Content-Length": str(len(body))})
        self.assertEqual(st, 423)

    def test_put_423(self):
        st, _ = self.req("PUT", "/new.bin", body=b"x",
                         headers={"Content-Length": "1"})
        self.assertEqual(st, 423)
        self.assertIsNone(self.locked.lookup("/new.bin"))

    # ---- the server must survive all of the above ----

    def test_connection_still_usable_after_locked_endpoints(self):
        for method, path in [("GET", "/__api/list"),
                             ("GET", "/__api/msg"),
                             ("GET", "/")]:
            self.req(method, path)
        # an unlocked-path request must still work on a fresh connection
        st, _ = self.req("OPTIONS", "/")
        self.assertEqual(st, 200)

    def test_unlock_then_reads_work(self):
        """sanity: the 423 is the lock, not a broken vault"""
        fresh = sv.Store(self.vault)
        fresh.unlock("pw")
        row = fresh.lookup("/secret.mkv")
        self.assertIsNotNone(row)
        self.assertEqual(b"".join(fresh.read_full(row)),
                         b"top secret payload" * 100)
        self.assertIn("pre-existing board note",
                      [m["body"] for m in fresh.msgs_since(0)])


class TestLockedVaultAuthOn(unittest.TestCase):
    """With --auth on, a locked vault answers 401 before it ever reaches
    the 423 check — and the body is still not drained."""

    @classmethod
    def setUpClass(cls):
        try:
            sv._Crypto.lib()
        except sv.CryptoUnavailable as e:
            raise unittest.SkipTest(f"libcrypto unavailable: {e}")
        cls.W = tempfile.mkdtemp(prefix="svlock2_")
        cls.vault = os.path.join(cls.W, "e.vault")
        seed = sv.Store(cls.vault)
        seed.set_password("pw")
        seed.enable_encryption("pw")
        seed.put("/f.bin", io.BytesIO(b"data"))
        seed.set_auth_required(True)
        cls.store = sv.Store(cls.vault)
        cls.port = free_port()
        cls.srv = serve(cls.store, cls.port)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.srv.shutdown()
            cls.srv.server_close()
        except Exception:
            pass
        shutil.rmtree(cls.W, ignore_errors=True)

    def test_unauthenticated_listing_is_401(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/__api/list")
        r = c.getresponse()
        data = r.read()
        c.close()
        self.assertEqual(r.status, 401)
        self.assertNotIn(b"f.bin", data)
        self.assertIn("www-authenticate", {k.lower(): v for k, v in r.getheaders()})

    def test_authed_listing_is_423(self):
        import base64
        tok = base64.b64encode(b":pw").decode()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/__api/list", headers={"Authorization": f"Basic {tok}"})
        r = c.getresponse()
        data = r.read()
        c.close()
        self.assertEqual(r.status, 423)
        self.assertNotIn(b"f.bin", data)


if __name__ == "__main__":
    unittest.main()
