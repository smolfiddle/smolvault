#!/usr/bin/env python3
# MIT License — Copyright (c) 2026 smolfiddle / SmolVault project
"""
smolvault — an immutable vault for everything, with a front-row seat
for your media.
====================================================================

One command opens an interactive hub where you can add files by dragging
them into your terminal window, search your vault, and watch anything
in mpv without ever leaving the CLI. Any file type is welcome — video,
music, images, documents, archives, disk images — everything is sealed
write-once and deduplicated:

    python3 smolvault.py

Media is the flagship experience: files stream over HTTP/1.1 with full
byte-range support so players seek as if the file were local. But the
vault happily holds anything, sealed forever with per-chunk BLAKE2b
integrity.

Highlights
----------
- Wizard hub:  add / search / watch / list / info / export / verify
- `--play QUERY` finds a file and launches mpv against it automatically
- Drag & drop ingest: drop files into the terminal at the `add` prompt
- Folder ingest: point add at a directory — structure preserved, or
  browse & multi-pick its tree with live Space-toggle selection
- Live activity feed: every request logged with status, bytes, duration
- Full RFC 7233 ranges: bytes=N-M, N-, -N suffix; 416; If-Range; 304 ETag
- Cache-Control immutable + ETag = content root hash
- Per-read integrity verification — bit-rot fails loudly
- Entropy gate: media stored raw on a coarse hot stride (~2x faster seal);
  compressible text gets fine-grained CDC + compression
- At-rest encryption: per-chunk AES-256-GCM via system OpenSSL,
  scrypt-wrapped key, dedup preserved (--encrypt / --decrypt)
- Per-vault message board: clients & server post notes/events (m)
- Optional password over HTTP Basic; network gate independent of
  encryption (--auth on|off)
- Space report: --du breaks down folders, finds double-sealed files
- Script-friendly: stable exit codes, SMOLVAULT_VAULT env var

Quick start
-----------
    python3 smolvault.py                  # wizard (creates vault.vault)
    python3 smolvault.py lib.vault --add movie.mkv
    python3 smolvault.py lib.vault --play movie
"""

import argparse
import bisect
import getpass
import glob
import hashlib
import hmac
import http.server
import json
import logging
import math
import mimetypes
import os
import re
import select
import shlex
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import zlib
from collections import Counter, namedtuple
from socketserver import ThreadingMixIn

__version__ = "0.2.2"

log = logging.getLogger("smolvault")

EXIT_OK, EXIT_NOMATCH, EXIT_USAGE = 0, 1, 2

NODE_NAME = None                   # set by --name / SMOLVAULT_NAME


# ---------------------------------------------------------------------------
# Terminal colors (auto-disable: pipe, NO_COLOR, dumb term)
# ---------------------------------------------------------------------------

def _color_ok():
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


_COLOR = _color_ok()


def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if _COLOR else str(text)


def bold(t):   return _c(t, "1")
def dim(t):    return _c(t, "2")
def red(t):    return _c(t, "91")
def green(t):  return _c(t, "92")
def yellow(t): return _c(t, "93")
def cyan(t):   return _c(t, "96")
def gray(t):   return _c(t, "90")


def _enable_debug_signal_dump():
    import faulthandler
    import signal
    try:
        faulthandler.register(signal.SIGUSR1)
    except Exception:
        pass


def setup_logging(verbose):
    for h in list(log.handlers):
        log.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S"))
    level = logging.DEBUG if verbose else logging.INFO
    log.setLevel(level)
    log.addHandler(handler)
    log.propagate = False


# ---------------------------------------------------------------------------
# Content-defined chunker (gear-hash rolling window, stride 32)
# ---------------------------------------------------------------------------

class Chunker:
    """Strided gear-hash CDC. Boundaries depend only on content, so identical
    prefixes chunk identically — that is what makes dedup work.

    *stride* is fixed per file (chosen by Store.put's entropy probe), never
    mid-stream: a per-region adaptive stride would make boundaries depend on
    scan history and break resync-after-insert."""

    def __init__(self, stride=32):
        state = 0x9E3779B97F4A7C15
        gear = []
        for _ in range(256):
            state += 0x9E3779B97F4A7C15
            z = state & 0xFFFFFFFFFFFFFFFF
            z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
            z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
            gear.append((z ^ (z >> 31)) & 0xFFFFFFFFFFFFFFFF)
        self.gear = tuple(gear)
        self.stride = stride
        self.min_s = 64 * 1024
        self.max_s = 1024 * 1024
        self.mask_s = 0x3FFF
        self.mask_l = 0x7FFFF

    def chunk(self, fobj):
        gear, stride = self.gear, self.stride
        min_s, max_s = self.min_s, self.max_s
        mask_s, mask_l = self.mask_s, self.mask_l
        buf, pos, read = bytearray(), 0, fobj.read

        while True:
            if len(buf) - pos < max_s + stride:
                if pos > 0:
                    buf = buf[pos:]
                    pos = 0
                data = read(4 * 1024 * 1024)
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


# ---------------------------------------------------------------------------
# Entropy-adaptive storage (media stays raw; text sidecars compressed)
# ---------------------------------------------------------------------------

ENTROPY_RAW = 7.5
MIN_RATIO = 1.05

STRIDE_PROBE = 262144         # bytes sampled to pick a stride (256 KB)
STRIDE_COLD = 32              # compressible content: fine-grained CDC
STRIDE_HOT = 64               # incompressible content: ~3x faster scan


class _PrefixedReader:
    """Replays the entropy-probe bytes before handing through to *rest*."""

    def __init__(self, prefix, rest):
        self.prefix, self.rest = prefix, rest

    def read(self, n=-1):
        if self.prefix:
            p, self.prefix = self.prefix, b""
            return p
        return self.rest.read(n)


def _entropy(data):
    n = len(data)
    if n <= 2048:
        sample = data
    else:
        t = 682
        sample = data[:t] + data[n // 2:n // 2 + t] + data[-t:]
    ent = 0.0
    for c in Counter(sample).values():
        p = c / len(sample)
        ent -= p * math.log2(p)
    return ent


def pack_chunk(raw):
    if _entropy(raw) >= ENTROPY_RAW:
        return raw, 0
    comp = zlib.compress(raw, 1)
    return (comp, 1) if len(raw) / len(comp) >= MIN_RATIO else (raw, 0)


def unpack_chunk(stored, flag):
    return zlib.decompress(stored) if flag else stored


def fmt(n):
    if n is None:
        return "?"
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def mime_type(path):
    special = {
        ".mkv": "video/x-matroska", ".m4a": "audio/mp4",
        ".flac": "audio/flac", ".opus": "audio/opus",
        ".ogg": "audio/ogg", ".oga": "audio/ogg",
        ".webp": "image/webp", ".m3u": "audio/x-mpegurl",
        ".nfo": "text/plain", ".srt": "text/plain",
        ".avi": "video/x-msvideo", ".mov": "video/quicktime",
    }
    ext = os.path.splitext(path)[1].lower()
    if ext in special:
        return special[ext]
    guess, _ = mimetypes.guess_type(path)
    return guess or "application/octet-stream"


PutResult = namedtuple("PutResult", "size root_hash new_bytes new_chunks")


class ExistsError(Exception):
    pass


class LockedVault(Exception):
    """Encrypted vault opened without its password."""
    pass


class CryptoUnavailable(Exception):
    """System OpenSSL (libcrypto) not found — at-rest encryption needs it."""
    pass


# ---------------------------------------------------------------------------
# AES-256-GCM via the system OpenSSL (zero PyPI dependencies)
# ---------------------------------------------------------------------------

class _Crypto:
    """Minimal ctypes binding to libcrypto's EVP interface.

    libcrypto ships wherever CPython runs — CPython's own _ssl module links
    it — so this stays zero-dependency in practice. We bind only stable
    symbols and documented ctrl codes (IVLEN=0x9, GET_TAG=0x10, SET_TAG=0x11).
    """

    _lib = None

    @classmethod
    def lib(cls):
        if cls._lib is not None:
            return cls._lib
        import ctypes, ctypes.util, sysconfig
        cands = []
        p = ctypes.util.find_library("crypto")
        if p:
            cands.append(p)
        prefixes = [sysconfig.get_config_var("LIBDIR") or "",
                    os.path.join(sys.base_prefix, "DLLs"),
                    "/usr/lib", "/usr/lib/x86_64-linux-gnu",
                    "/usr/lib/aarch64-linux-gnu",
                    "/usr/lib64",
                    "/data/data/com.termux/files/usr/lib"]
        for pre in prefixes:
            if pre and os.path.isdir(pre):
                cands += sorted(glob.glob(os.path.join(pre, "libcrypto.so*")))
                cands += sorted(glob.glob(os.path.join(pre, "libcrypto*.dll")))
        last_err = None
        import ctypes as c
        v, i, POINTER = c.c_void_p, c.c_int, c.POINTER
        for cand in cands:
            try:
                l = ctypes.CDLL(cand)
                getattr(l, "EVP_aes_256_gcm")
                l.EVP_CIPHER_CTX_new.restype = v
                l.EVP_CIPHER_CTX_free.argtypes = [v]
                l.EVP_aes_256_gcm.restype = v
                for f in ("EVP_EncryptInit_ex", "EVP_DecryptInit_ex"):
                    getattr(l, f).restype = i
                    getattr(l, f).argtypes = [v, v, v, c.c_char_p, c.c_char_p]
                for f in ("EVP_EncryptUpdate", "EVP_DecryptUpdate"):
                    getattr(l, f).restype = i
                    getattr(l, f).argtypes = [v, v, POINTER(i),
                                              c.c_char_p, i]
                for f in ("EVP_EncryptFinal_ex", "EVP_DecryptFinal_ex"):
                    getattr(l, f).restype = i
                    getattr(l, f).argtypes = [v, c.c_char_p, POINTER(i)]
                l.EVP_CIPHER_CTX_ctrl.restype = i
                l.EVP_CIPHER_CTX_ctrl.argtypes = [v, i, i, v]
                cls._lib = l
                return l
            except (OSError, AttributeError) as e:
                last_err = e
        raise CryptoUnavailable(
            f"system OpenSSL (libcrypto) not found ({last_err}) — at-rest "
            "encryption needs it; install openssl or drop --encrypt")

    @classmethod
    def seal(cls, key, nonce, pt, aad=b""):
        """AES-256-GCM encrypt. Returns (ciphertext, tag16)."""
        import ctypes as c
        v, i, POINTER = c.c_void_p, c.c_int, c.POINTER
        l = cls.lib()
        ctx = l.EVP_CIPHER_CTX_new()
        if not ctx:
            raise ValueError("EVP ctx alloc failed")
        try:
            o = c.c_int(0)
            ok = l.EVP_EncryptInit_ex(ctx, l.EVP_aes_256_gcm(), None,
                                      None, None)
            ok &= l.EVP_CIPHER_CTX_ctrl(ctx, 0x9, len(nonce), None)
            ok &= l.EVP_EncryptInit_ex(ctx, None, None, key, nonce)
            if aad:
                ok &= l.EVP_EncryptUpdate(ctx, None, c.byref(o), aad, len(aad))
            ct = c.create_string_buffer(len(pt) + 16)
            n1 = c.c_int(0)
            ok &= l.EVP_EncryptUpdate(ctx, ct, c.byref(n1), pt, len(pt))
            tail = c.create_string_buffer(16)
            n2 = c.c_int(0)
            ok &= l.EVP_EncryptFinal_ex(ctx, tail, c.byref(n2))
            tag = c.create_string_buffer(16)
            ok &= l.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tag)     # GET_TAG
            if not ok:
                raise ValueError("GCM encrypt failed")
            return bytes(ct[:n1.value]) + bytes(tail[:n2.value]), \
                tag.raw[:16]
        finally:
            l.EVP_CIPHER_CTX_free(ctx)

    @classmethod
    def open(cls, key, nonce, ct_with_tag, aad=b""):
        """AES-256-GCM decrypt+authenticate. ct_with_tag = ciphertext||tag.
        Raises ValueError on authentication failure."""
        import ctypes as c
        v, i, POINTER = c.c_void_p, c.c_int, c.POINTER
        l = cls.lib()
        if len(ct_with_tag) < 16:
            raise ValueError("ciphertext too short")
        pt_len = len(ct_with_tag) - 16
        ctx = l.EVP_CIPHER_CTX_new()
        if not ctx:
            raise ValueError("EVP ctx alloc failed")
        try:
            o = c.c_int(0)
            ok = l.EVP_DecryptInit_ex(ctx, l.EVP_aes_256_gcm(), None,
                                      None, None)
            ok &= l.EVP_CIPHER_CTX_ctrl(ctx, 0x9, len(nonce), None)
            ok &= l.EVP_DecryptInit_ex(ctx, None, None, key, nonce)
            if aad:
                ok &= l.EVP_DecryptUpdate(ctx, None, c.byref(o), aad, len(aad))
            pt = c.create_string_buffer(pt_len + 1)
            body = ct_with_tag[:-16]
            n1 = c.c_int(0)
            ok &= l.EVP_DecryptUpdate(ctx, pt, c.byref(n1), body, len(body))
            tag = c.create_string_buffer(ct_with_tag[-16:])
            ok &= l.EVP_CIPHER_CTX_ctrl(ctx, 0x11, 16, tag)      # SET_TAG
            fin = l.EVP_DecryptFinal_ex(ctx, pt, c.byref(o))
            if not ok or fin != 1:
                raise ValueError("authentication failed — tampered or "
                                 "wrong key")
            return bytes(pt[:n1.value + o.value])
        finally:
            l.EVP_CIPHER_CTX_free(ctx)


# ---------------------------------------------------------------------------
# Storage engine
# ---------------------------------------------------------------------------

class Store:
    """SQLite-backed content store. Thread-local connections; WAL mode lets
    readers run fully parallel against one writer. Ingest is deliberately
    single-threaded: on consumer CPUs (single-core turbo >> all-core) the
    GIL-bound chunker runs faster unpinned than under any worker pipeline —
    measured, not assumed. The wins live in the write path instead."""

    DB_BATCH = 100              # chunks per transaction (DenseVault discipline)

    def __init__(self, path):
        self.path = path
        self._local = threading.local()
        # WAL allows one writer; take it explicitly so contenders fail fast
        # (409) instead of stalling on lock timeouts.
        self._wlock = threading.Lock()
        conn = self.conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS files (
                path      TEXT PRIMARY KEY,
                size      INTEGER NOT NULL,
                root_hash TEXT NOT NULL,
                mime      TEXT,
                manifest  TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS chunks (
                hash TEXT PRIMARY KEY,
                data BLOB NOT NULL,
                comp INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                sender TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'user',
                body TEXT NOT NULL);
        """)
        conn.commit()

    def conn(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=60.0)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA mmap_size=536870912")
            c.execute("PRAGMA cache_size=-64000")
            c.execute("PRAGMA temp_store=MEMORY")
            c.row_factory = sqlite3.Row
            self._local.conn = c
        return c

    # ---- config key/values (port memory etc.) ---------------------------

    def cfg_get(self, key, default=None):
        r = self.conn().execute(
            "SELECT value FROM config WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default

    def cfg_set(self, key, value):
        c = self.conn()
        c.execute("INSERT OR REPLACE INTO config VALUES (?,?)", (key, str(value)))
        c.commit()

    # ---- passwords -------------------------------------------------------

    def set_password(self, password):
        salt = os.urandom(16)
        phash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        c = self.conn()
        c.executemany("INSERT OR REPLACE INTO config VALUES (?,?)",
                      [("salt", salt.hex()), ("hash", phash.hex())])
        c.commit()

    def has_password(self):
        return self.conn().execute(
            "SELECT 1 FROM config WHERE key='hash'").fetchone() is not None

    def check_password(self, password):
        rows = self.conn().execute(
            "SELECT key, value FROM config WHERE key IN ('salt','hash')").fetchall()
        d = {k: v for k, v in rows}
        if "salt" not in d or "hash" not in d:
            return True
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                   bytes.fromhex(d["salt"]), 100_000)
        return hmac.compare_digest(calc, bytes.fromhex(d["hash"]))

    # ---- HTTP auth gate (decoupled from at-rest encryption) ----------------

    def auth_required(self):
        """Whether network requests need the password. Independent of
        encryption: a vault can be sealed at rest while streaming openly on
        a trusted LAN."""
        if not self.has_password():
            return False
        v = self.cfg_get("auth_req")
        return True if v is None else v == "1"

    def set_auth_required(self, on):
        self.cfg_set("auth_req", "1" if on else "0")

    # ---- at-rest encryption (convergent, dedup-preserving) ----------------

    ENC_MAGIC = b"SVEN\x01"

    def _enc_cfg(self):
        rows = self.conn().execute(
            "SELECT key, value FROM config WHERE key LIKE 'enc_%'").fetchall()
        return {k: v for k, v in rows} or None

    def enc_enabled(self):
        return self._enc_cfg() is not None

    def is_unlocked(self):
        if not self.enc_enabled():
            return True
        return bool(getattr(self, "_mk", None))

    def unlock(self, password):
        """Derive KEK from password, unwrap the master key. Raises
        ValueError on wrong password; no-op when vault isn't encrypted."""
        cfg = self._enc_cfg()
        if not cfg:
            return
        kek = self._kek(password, bytes.fromhex(cfg["enc_salt"]))
        nonce, rest = cfg["enc_mk"][:24], cfg["enc_mk"][24:]
        mk = _Crypto.open(kek, bytes.fromhex(nonce),
                          bytes.fromhex(rest), aad=b"sv-mk")
        self._load_keys(mk)

    def enable_encryption(self, password):
        """Generate a master key, wrap it under *password*, mark the vault.
        Call migrate_encryption() afterwards to rewrite existing chunks."""
        if self.enc_enabled():
            self.unlock(password)
            return
        salt = os.urandom(16)
        mk = os.urandom(32)
        kek = self._kek(password, salt)
        wn = os.urandom(12)
        ct, tag = _Crypto.seal(kek, wn, mk, aad=b"sv-mk")
        blob = (wn + ct + tag).hex()
        c = self.conn()
        c.executemany("INSERT OR REPLACE INTO config VALUES (?,?)",
                      [("enc_ver", "1"), ("enc_alg", "aesgcm256"),
                       ("enc_salt", salt.hex()), ("enc_mk", blob)])
        c.commit()
        self._load_keys(mk)

    def disable_encryption(self, password):
        """Strip envelopes from all chunks (caller migrates first) and
        remove key material."""
        self.unlock(password)
        c = self.conn()
        c.execute("DELETE FROM config WHERE key LIKE 'enc_%'")
        c.commit()
        for attr in ("_mk", "_ek", "_nk"):
            setattr(self, attr, None)

    def migrate_encryption(self, progress=None):
        """Encrypt every legacy plaintext chunk in place. Resumable: blobs
        already carrying the SVEN magic are skipped. Returns count."""
        if not self.enc_enabled():
            raise LockedVault("vault is not encrypted")
        if not self.is_unlocked():
            raise LockedVault("vault is locked — unlock() first")
        c = self.conn()
        pred = (f"substr(hex(data),1,{len(self.ENC_MAGIC)*2})"
                f"<>'{self.ENC_MAGIC.hex().upper()}'")
        total = c.execute(
            f"SELECT COUNT(*) FROM chunks WHERE {pred}").fetchone()[0]
        done = 0
        while True:
            rows = c.execute(
                f"SELECT hash, data FROM chunks WHERE {pred} LIMIT ?",
                (self.DB_BATCH,)).fetchall()
            if not rows:
                break
            for h, data in rows:
                c.execute("UPDATE chunks SET data=? WHERE hash=?",
                          (self._seal(data, h), h))
            c.commit()
            done += len(rows)
            if progress:
                progress(done, total)
        return done

    def change_password(self, old, new):
        """Rotate the auth hash and re-wrap the master key under *new*.
        Data chunks are never re-encrypted."""
        if not self.check_password(old):
            raise ValueError("incorrect current password")
        self.set_password(new)
        if self.enc_enabled():
            cfg = self._enc_cfg()
            kek_old = self._kek(old, bytes.fromhex(cfg["enc_salt"]))
            nonce, rest = cfg["enc_mk"][:24], cfg["enc_mk"][24:]
            mk = _Crypto.open(kek_old, bytes.fromhex(nonce),
                              bytes.fromhex(rest), aad=b"sv-mk")
            kek_new = self._kek(new, bytes.fromhex(cfg["enc_salt"]))
            wn = os.urandom(12)
            ct, tag = _Crypto.seal(kek_new, wn, mk, aad=b"sv-mk")
            c = self.conn()
            c.execute("UPDATE config SET value=? WHERE key='enc_mk'",
                      ((wn + ct + tag).hex(),))
            c.commit()
            self._load_keys(mk)

    def _kek(self, password, salt):
        return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15,
                              r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)

    def _load_keys(self, mk):
        self._mk = mk
        self._ek = hashlib.blake2b(mk, person=b"sv-enc",
                                   digest_size=32).digest()
        self._nk = hashlib.blake2b(mk, person=b"sv-nonce",
                                   digest_size=12).digest()
        self._msg_k = hashlib.blake2b(mk, person=b"sv-msg",
                                      digest_size=32).digest()

    def _require_keys(self):
        if not self.is_unlocked():
            raise LockedVault(
                "vault is encrypted — provide the password to unlock")

    def _seal(self, blob, h_hex):
        if not self.enc_enabled() or blob.startswith(self.ENC_MAGIC):
            return blob
        self._require_keys()
        nonce = hashlib.blake2b(bytes.fromhex(h_hex), key=self._nk,
                                digest_size=12).digest()
        ct, tag = _Crypto.seal(self._ek, nonce, blob,
                               aad=self.ENC_MAGIC + bytes.fromhex(h_hex))
        return self.ENC_MAGIC + nonce + ct + tag

    def _open(self, data, h_hex):
        """Inverse of _seal. Legacy plaintext blobs pass through untouched
        (magic sniffing keeps mid-migration states fully readable)."""
        if not data.startswith(self.ENC_MAGIC):
            return data
        self._require_keys()
        nonce = data[5:17]
        ct = data[17:-16]
        pt = _Crypto.open(self._ek, nonce, ct + data[-16:],
                          aad=self.ENC_MAGIC + bytes.fromhex(h_hex))
        return pt

    def _seal_msg(self, body):
        data = body.encode() if isinstance(body, str) else body
        if not self.enc_enabled():
            return data.decode()
        import base64
        env_nonce = os.urandom(12)
        ct, tag = _Crypto.seal(self._msg_k, env_nonce, data,
                               aad=b"sv-msg")
        return "SVMSG:" + base64.b64encode(env_nonce + ct + tag).decode()

    def _open_msg(self, stored):
        if not stored.startswith("SVMSG:"):
            return stored
        import base64
        raw = base64.b64decode(stored[6:])
        pt = _Crypto.open(self._msg_k, raw[:12], raw[12:], aad=b"sv-msg")
        return pt.decode()

    # ---- stats -------------------------------------------------------------

    def stats(self):
        c = self.conn()
        nf, logical = c.execute(
            "SELECT COUNT(*), COALESCE(SUM(size),0) FROM files").fetchone()
        stored = c.execute(
            "SELECT COALESCE(SUM(LENGTH(data)),0) FROM chunks").fetchone()[0]
        nc = c.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        return {"files": nf, "logical": logical, "stored": stored, "chunks": nc}

    def all_files(self):
        return self.conn().execute(
            "SELECT path, size, mime, created_at, root_hash FROM files "
            "ORDER BY path"
        ).fetchall()

    # ---- message board (the one deliberately mutable thing) ---------------

    MAX_MESSAGES = 500
    _CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

    def post_msg(self, sender, kind, body):
        """Post to this vault's board. Returns the message id.
        Raises ValueError on empty/oversized bodies."""
        body = self._CTRL_RE.sub("", str(body)).strip()
        if not body:
            raise ValueError("empty message")
        if len(body) > 2000:
            raise ValueError("message too long (max 2000 chars)")
        c = self.conn()
        cur = c.execute(
            "INSERT INTO messages (sender,kind,body) VALUES (?,?,?)",
            (str(sender)[:64], "system" if kind == "system" else "user",
             self._seal_msg(body)))
        c.execute(
            "DELETE FROM messages WHERE id <= "
            "(SELECT MAX(id) - ? FROM messages)", (self.MAX_MESSAGES,))
        c.commit()
        return cur.lastrowid

    def note(self, text):
        """System-event post; best-effort, never raises."""
        try:
            self.post_msg(_node_name(), "system", text)
        except Exception:
            pass

    def msgs_since(self, after=0, limit=100):
        rows = self.conn().execute(
            "SELECT id, ts, sender, kind, body FROM messages "
            "WHERE id > ? ORDER BY id LIMIT ?",
            (after, max(1, min(limit, 500)))).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["body"] = self._open_msg(d["body"])
            except Exception:
                d["body"] = "[unreadable — wrong key?]"
            out.append(d)
        return out

    def msg_last_id(self):
        r = self.conn().execute(
            "SELECT COALESCE(MAX(id), 0) FROM messages").fetchone()
        return r[0]

    # ---- write ---------------------------------------------------------------

    def _flush_chunks(self, conn, batch, new_stored):
        """One explicit transaction per batch (keeps WAL checkpoints flowing
        instead of deferring a multi-GB commit). Per-row rowcount yields
        exact new-byte accounting with no lookup queries at all."""
        if not batch:
            return
        conn.execute("BEGIN TRANSACTION")
        try:
            for h, (stored, comp) in batch.items():
                cur = conn.execute("INSERT OR IGNORE INTO chunks VALUES (?,?,?)",
                                   (h, stored, comp))
                if cur.rowcount:
                    new_stored[0] += len(stored)
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def put(self, path, reader, progress=None):
        """Ingest a stream at *path*. Returns PutResult.
        Raises ExistsError when the path is already sealed.

        Single-writer discipline: concurrent ingests queue on _wlock, so a
        thundering herd on one path yields one 201 and fast 409s instead of
        60-second SQLite lock timeouts."""
        with self._wlock:
            return self._put(path, reader, progress)

    def _put(self, path, reader, progress=None):
        c = self.conn()
        if c.execute("SELECT 1 FROM files WHERE path=?", (path,)).fetchone():
            raise ExistsError(path)

        hashes, sizes, offsets = [], [], []
        off = 0
        batch = {}                            # hash -> (stored, comp), ordered
        new_stored = [0]

        # entropy probe picks the stride for this whole file: incompressible
        # media (the heavy case) scans at STRIDE_HOT — boundaries stay purely
        # content-defined because the choice is a deterministic function of
        # the file's own prefix. Cross-class dedup is unaffected in practice:
        # different-class files share no chunks anyway.
        probe = reader.read(STRIDE_PROBE)
        stride = STRIDE_HOT if _entropy(probe) >= ENTROPY_RAW else STRIDE_COLD
        stream = _PrefixedReader(probe, reader) if probe else reader

        for raw in Chunker(stride=stride).chunk(stream):
            if progress:
                progress(len(raw))
            stored, comp = pack_chunk(raw)
            h = hashlib.blake2b(raw, digest_size=32).hexdigest()
            stored = self._seal(stored, h)      # plaintext hash is the key
            if h not in batch:                # intra-batch dedup
                batch[h] = (stored, comp)
            hashes.append(h)
            offsets.append(off)
            sizes.append(len(raw))
            off += len(raw)
            if len(batch) >= self.DB_BATCH:
                self._flush_chunks(c, batch, new_stored)
                batch = {}
        self._flush_chunks(c, batch, new_stored)

        root = hashlib.blake2b("".join(hashes).encode(),
                               digest_size=32).hexdigest()
        manifest = json.dumps({"chunks": hashes, "sizes": sizes,
                               "offsets": offsets})
        try:
            c.execute(
                "INSERT INTO files (path,size,root_hash,mime,manifest) "
                "VALUES (?,?,?,?,?)",
                (path, off, root, mime_type(path), manifest))
            c.commit()
        except sqlite3.IntegrityError:
            raise ExistsError(path)       # lost a WORM race with another conn
        return PutResult(off, root, new_stored[0], len(hashes))

    # ---- read ---------------------------------------------------------------

    def lookup(self, path):
        return self.conn().execute(
            "SELECT * FROM files WHERE path=?", (path,)).fetchone()

    def list_dir(self, prefix):
        """Children (subdirs, files) of *prefix*, derived from file paths."""
        c = self.conn()
        n = len(prefix)
        rows = c.execute(
            "SELECT path, size, mime, created_at FROM files "
            "WHERE substr(path, 1, ?) = ?", (n, prefix)).fetchall()
        dirs, files = set(), []
        for r in rows:
            rest = r["path"][n:]
            if "/" in rest:
                dirs.add(rest.split("/", 1)[0])
            else:
                files.append(r)
        return sorted(dirs), files

    def _verified(self, stored, comp, h):
        stored = self._open(stored, h)          # AEAD-auth + decrypt
        raw = unpack_chunk(stored, comp)
        if hashlib.blake2b(raw, digest_size=32).hexdigest() != h:
            raise ValueError(f"corrupt chunk {h[:16]}")
        return raw

    def read_full(self, row):
        man = json.loads(row["manifest"])
        hashes = man["chunks"]
        c = self.conn()
        for i in range(0, len(hashes), self.DB_BATCH):
            part = hashes[i:i + self.DB_BATCH]
            q = ("SELECT hash,data,comp FROM chunks WHERE hash IN (%s)"
                 % ",".join("?" * len(part)))
            got = {r["hash"]: (r["data"], r["comp"]) for r in c.execute(q, part)}
            for h in part:
                if h not in got:
                    raise ValueError(f"missing chunk {h[:16]}")
                yield self._verified(*got[h], h)

    def read_range(self, row, start, end):
        """Yield bytes [start..end] inclusive. O(log n) chunk location."""
        man = json.loads(row["manifest"])
        hashes, sizes, offs = man["chunks"], man["sizes"], man["offsets"]
        i = max(0, bisect.bisect_right(offs, start) - 1)
        c = self.conn()
        while i < len(hashes) and offs[i] <= end:
            cs, ce = offs[i], offs[i] + sizes[i] - 1
            if ce >= start:
                r = c.execute("SELECT data,comp FROM chunks WHERE hash=?",
                              (hashes[i],)).fetchone()
                if not r:
                    raise ValueError(f"missing chunk {hashes[i][:16]}")
                raw = self._verified(r["data"], r["comp"], hashes[i])
                lo = max(0, start - cs)
                hi = min(sizes[i], end - cs + 1)
                yield raw[lo:hi]
            i += 1

    # ---- maintenance ----------------------------------------------------------

    def check(self):
        c = self.conn()
        owners = {}
        for path, manifest in c.execute("SELECT path, manifest FROM files"):
            for h in json.loads(manifest)["chunks"]:
                owners.setdefault(h, []).append(path)

        expected = len(owners)
        last_paint = time.perf_counter()
        bad = missing = tampered = total = 0
        for h, data, comp in c.execute("SELECT hash,data,comp FROM chunks"):
            total += 1
            try:
                raw = unpack_chunk(self._open(data, h), comp)
                if hashlib.blake2b(raw, digest_size=32).hexdigest() != h:
                    raise ValueError
            except LockedVault:
                raise
            except Exception as e:
                msg = str(e).lower()
                if "tampered" in msg or "auth" in msg or "decrypt" in msg:
                    tampered += 1
                    log.error(red("TAMPERED chunk %s…  files: %s"),
                              h[:16], ", ".join(owners.get(h, ["<orphan>"])))
                else:
                    bad += 1
                    log.error(red("CORRUPT chunk %s…  files: %s"),
                              h[:16], ", ".join(owners.get(h, ["<orphan>"])))
            now = time.perf_counter()
            if expected and now - last_paint > 2.0:
                last_paint = now
                if sys.stdout.isatty():
                    sys.stdout.write(f"\r  checked {total}/{expected} chunks…")
                    sys.stdout.flush()
                else:
                    log.info("checked %d/%d chunks", total, expected)
        if expected and total and sys.stdout.isatty():
            sys.stdout.write(f"\r  checked {total}/{expected} chunks…\n")
            sys.stdout.flush()
        for h in owners:
            if not c.execute("SELECT 1 FROM chunks WHERE hash=?", (h,)).fetchone():
                missing += 1
                log.error(red("MISSING chunk %s…  files: %s"),
                          h[:16], ", ".join(owners[h]))
        ok = bad == 0 and missing == 0 and tampered == 0
        log.info("%d chunks checked · %d corrupt · %d missing · %s",
                 total, bad, missing, green("PASS") if ok else red("FAIL"))
        if tampered:
            log.error(red("…of which %d TAMPERED (AEAD auth failed) — "
                          "wrong key or malicious edit"), tampered)
        return ok

    def gc(self):
        c = self.conn()
        referenced = set()
        for (manifest,) in c.execute("SELECT manifest FROM files"):
            referenced.update(json.loads(manifest)["chunks"])
        all_h = {r[0] for r in c.execute("SELECT hash FROM chunks")}
        orphans = all_h - referenced
        if orphans:
            c.executemany("DELETE FROM chunks WHERE hash=?",
                          [(h,) for h in orphans])
            c.commit()
        log.info("gc: %d orphaned chunk(s) removed", len(orphans))
        c.execute("VACUUM")


CACHE = "max-age=31536000, immutable"


class RangeError(Exception):
    pass


def parse_range(header, size):
    """
    Parse a single-range `bytes=` header. Returns (start, end) inclusive,
    None to ignore the header (serve 200), raises RangeError for 416.
    """
    m = re.fullmatch(r"\s*bytes\s*=\s*(\d*)\s*-\s*(\d*)\s*", header)
    if not m:
        return None                      # multi-range/other units: ignore
    a, b = m.group(1), m.group(2)
    if a == "" and b == "":
        return None
    if a == "":                          # suffix: final b bytes
        n = int(b)
        if n == 0:
            raise RangeError()
        return (max(0, size - n), size - 1)
    start = int(a)
    if start >= size:
        raise RangeError()
    end = int(b) if b else size - 1
    if end < start:
        return None                      # invalid spec: ignore header
    return (start, min(end, size - 1))


def _norm(path):
    return "/" + "/".join(p for p in urllib.parse.unquote(path).split("/") if p)


def _is_dir(store, path):
    prefix = _norm(path).rstrip("/") + "/"
    dirs, files = store.list_dir(prefix)
    return bool(dirs or files)


class _Counting:
    """write()-counting proxy around the socket writer."""

    def __init__(self, inner):
        self.inner = inner
        self.n = 0

    @property
    def closed(self):
        return self.inner.closed

    def close(self):
        try:
            return self.inner.close()
        except OSError:
            pass            # client already gone — nothing to send to

    def fileno(self):
        return self.inner.fileno()

    def write(self, b):
        self.n += len(b)
        return self.inner.write(b)

    def writelines(self, lines):
        for l in lines:
            self.write(l)

    def flush(self):
        try:
            return self.inner.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass            # same: client vanished mid-response

    def writable(self):
        return True


_STATUS_COLOR = {2: green, 3: cyan, 4: yellow, 5: red}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"        # keep-alive: cheap scrubbing
    server_version = "smolvault/" + __version__
    wbufsize = 256 * 1024

    @property
    def store(self):
        return self.server.store

    # ---- request activity feed ---------------------------------------------

    def setup(self):
        super().setup()
        self._wfile_count = _Counting(self.wfile)
        self.wfile = self._wfile_count

    def handle_one_request(self):
        t0 = time.perf_counter()
        base = self._wfile_count.n
        self._sm_code = None
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            # Player seeked away / closed mid-transfer: normal media-server
            # life, not an error. Drop the connection quietly.
            self.close_connection = True
        finally:
            code = self._sm_code
            if code:
                sent = self._wfile_count.n - base
                dur = (time.perf_counter() - t0) * 1000
                color = _STATUS_COLOR.get(code // 100, lambda t: t)
                log.info("%s %s  %s  %s  %s",
                         bold(f"{self.command or '-':<7}"),
                         color(f"{code}"),
                         cyan(fmt(sent).rjust(9)),
                         (self.path or "-")[:60],
                         dim(f"{dur:.0f}ms"))

    def send_response(self, code, message=None):
        self._sm_code = code
        super().send_response(code, message)

    def log_message(self, fmt, *args):     # silence default logger
        pass

    # ---- auth ---------------------------------------------------------------

    def _authed(self):
        if not self.store.has_password():
            return True
        if not self.store.auth_required():
            return True              # at-rest only: LAN streaming stays open
        hdr = self.headers.get("Authorization", "")
        try:
            kind, blob = hdr.split(None, 1)
            if kind.lower() != "basic":
                raise ValueError
            _, pw = __import__("base64").b64decode(blob).decode().split(":", 1)
            if self.store.check_password(pw):
                return True
        except Exception:
            pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="smolvault"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _head(self, code, size=None, etag=None, ctype=None, extra=None):
        self.send_response(code)
        if size is not None:
            self.send_header("Content-Length", str(size))
        if etag:
            self.send_header("ETag", f'"{etag}"')
        if ctype:
            self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        return code

    # ---- methods ---------------------------------------------------------------

    def do_OPTIONS(self):
        self._head(200, 0, extra={"Allow": "OPTIONS, GET, HEAD, PUT",
                                  "Accept-Ranges": "bytes", "DAV": "1"})
        self.end_headers()

    def do_PUT(self):
        if not self._authed():
            return
        norm = _norm(self.path)
        length = int(self.headers.get("Content-Length") or -1)
        if length < 0:
            self._head(411, 0, extra={"Connection": "close"})
            self.close_connection = True
            self.end_headers(); return
        if length == 0:
            self._head(400, 0, extra={"Connection": "close"})
            self.close_connection = True
            self.end_headers(); return

        reader = _Bounded(self.rfile, length)
        try:
            res = self.store.put(norm, reader)
        except ExistsError:
            log.warning(gray("WORM rejected overwrite of %s"), norm)
            # body not drained: poison the socket for keep-alive reuse
            self._head(409, 0,
                       extra={"Content-Type": "text/plain",
                              "Connection": "close"})
            self.close_connection = True
            self.end_headers()
            self.wfile.write(b"sealed: already exists\n")
            return
        except sqlite3.OperationalError as e:
            # cross-process writer contention survived the busy timeout
            log.error(red("db busy on PUT %s: %s"), norm, e)
            self._head(503, 0, extra={"Retry-After": "2",
                                      "Connection": "close"})
            self.close_connection = True
            self.end_headers()
            return
        dedup = f"{res.new_bytes/res.size*100:.0f}% new" if res.size else ""
        log.info("%s %s  (%s) · %s", green("sealed"), norm, fmt(res.size),
                 gray(dedup))
        self._head(201, 0, extra={"ETag": f'"{res.root_hash}"'})
        self.end_headers()

    def do_DELETE(self):
        if not self._authed():
            return
        self._head(403, 0, extra={"Content-Type": "text/plain"})
        self.end_headers()
        self.wfile.write(b"WORM: deletion disabled\n")

    def do_HEAD(self):
        if not self._authed():
            return
        row = self.store.lookup(_norm(self.path))
        if not row:
            self.send_error(404)
            return
        self._head(200, row["size"], row["root_hash"], row["mime"],
                   {"Accept-Ranges": "bytes", "Cache-Control": CACHE})
        self.end_headers()

    def do_GET(self):
        if not self._authed():
            return
        if _norm(self.path) == "/__api/list":
            self._api_list()
            return
        if _norm(self.path) == "/__api/auth":
            self._api_auth_state()
            return
        if _norm(self.path).split("?")[0] == "/__api/msg":
            self._api_msg()
            return
        row = self.store.lookup(_norm(self.path))
        if not row:
            if _is_dir(self.store, self.path):
                self._dir_page()
                return
            self.send_error(404)
            return

        etag = row["root_hash"]
        inm = self.headers.get("If-None-Match")
        if inm:
            candidates = [t.strip().removeprefix("W/").strip('"')
                          for t in inm.split(",")]
            if etag in candidates:
                self._head(304, 0, etag)
                self.end_headers()
                return

        base_extra = {"Accept-Ranges": "bytes", "Cache-Control": CACHE}
        rng_hdr = self.headers.get("Range")

        if rng_hdr and (not self.headers.get("If-Range")
                        or self.headers.get("If-Range").strip('"') == etag):
            try:
                rng = parse_range(rng_hdr, row["size"])
            except RangeError:
                self._head(416, 0, extra={
                    "Content-Range": f"bytes */{row['size']}"})
                self.end_headers()
                return
            if rng is not None:
                start, end = rng
                self._head(206, end - start + 1, etag, row["mime"],
                           dict(base_extra,
                                **{"Content-Range":
                                   f"bytes {start}-{end}/{row['size']}"}))
                self.end_headers()
                try:
                    for piece in self.store.read_range(row, start, end):
                        self.wfile.write(piece)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except ValueError as e:
                    log.error(red("read %s: %s"), row["path"], e)
                return

        self._head(200, row["size"], etag, row["mime"], base_extra)
        self.end_headers()
        try:
            for piece in self.store.read_full(row):
                self.wfile.write(piece)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except ValueError as e:
            log.error(red("read %s: %s"), row["path"], e)

    def _api_list(self):
        """Machine-readable listing for remote clients."""
        rows = self.store.all_files()
        payload = json.dumps(
            [{"path": r["path"], "size": r["size"], "mime": r["mime"],
              "created_at": r["created_at"], "root_hash": r["root_hash"]}
             for r in rows]
        ).encode()
        self._head(200, len(payload), None, "application/json",
                   {"Cache-Control": "no-store"})
        self.end_headers()
        self.wfile.write(payload)

    def _api_msg(self):
        """Board read: /__api/msg?since=N&limit=M"""
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        since = int(q.get("since", ["0"])[0] or 0)
        limit = int(q.get("limit", ["100"])[0] or 100)
        rows = self.store.msgs_since(since, limit)
        payload = json.dumps({
            "messages": [{"id": r["id"], "ts": r["ts"], "sender": r["sender"],
                          "kind": r["kind"], "body": r["body"]} for r in rows],
            "last": rows[-1]["id"] if rows else since,
        }).encode()
        self._head(200, len(payload), None, "application/json",
                   {"Cache-Control": "no-store"})
        self.end_headers()
        self.wfile.write(payload)

    def _api_auth_state(self):
        payload = json.dumps({"auth": self.store.auth_required()}).encode()
        self._head(200, len(payload), None, "application/json",
                   {"Cache-Control": "no-store"})
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if not self._authed():
            return
        norm = _norm(self.path).split("?")[0]
        length = int(self.headers.get("Content-Length") or -1)
        if norm != "/__api/msg" or length <= 0 or length > 16384:
            self._head(400, 0); self.end_headers(); return
        try:
            body = json.loads(self.rfile.read(length)).get("body", "")
            mid = self.store.post_msg(self.headers.get("X-Smv-Name")
                                      or _node_name(), "user", body)
        except (ValueError, json.JSONDecodeError) as e:
            payload = json.dumps({"error": str(e)}).encode()
            self._head(400, len(payload), None, "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        payload = json.dumps({"id": mid}).encode()
        self._head(201, len(payload), None, "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def _dir_page(self):
        prefix = _norm(self.path).rstrip("/") + "/"
        dirs, files = self.store.list_dir(prefix)
        base = prefix.rstrip("/")
        items = [f'<a href="{urllib.parse.quote(base + "/" + d)}/">{d}/</a>'
                 for d in dirs]
        for f in files:
            name = f["path"].rsplit("/", 1)[-1]
            items.append(
                f'<a href="{urllib.parse.quote(base + "/" + name)}">{name}</a>'
                f' <small>({fmt(f["size"])})</small>')
        body = ("<html><head><title>%s</title></head><body><h2>%s</h2><ul>%s</ul>"
                "</body></html>" % (prefix or "/", prefix or "/",
                                    "".join(f"<li>{i}</li>" for i in items)))
        payload = body.encode()
        self._head(200, len(payload), None, "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(payload)


class _Bounded:
    def __init__(self, raw, limit):
        self.raw, self.left = raw, limit

    def read(self, n=-1):
        if self.left <= 0:
            return b""
        want = self.left if n < 0 else min(n, self.left)
        data = self.raw.read(want)
        self.left -= len(data)
        return data


class MediaServer(ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


DISCOVERY_PORT = 8100          # UDP; answers SMOLVAULT_DISCOVER probes
DISCOVERY_MAGIC = b"SMOLVAULT_DISCOVER"


class DiscoveryResponder:
    """Answers LAN broadcast probes so clients find this vault without
    typing IPs. Lifecycle-bound to the HTTP server it belongs to."""

    def __init__(self, name, http_port, has_auth, files=None):
        self.reply = json.dumps({
            "proto": "smolvault",
            "name": name,
            "http_port": http_port,
            "auth": bool(has_auth),
            "files": files,
        }).encode()
        self.sock = None
        self.thread = None

    def start(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", DISCOVERY_PORT))
        except OSError:
            return False          # another smolvault owns discovery here
        self.sock = s
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return True

    def _loop(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                if data.strip() == DISCOVERY_MAGIC:
                    self.sock.sendto(self.reply, addr)
            except OSError:
                return

    def stop(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def cred_url(url, password):
    """Embed Basic-auth credentials as userinfo so players that never
    prompt (mpv, mpv-android intents) can fetch authenticated media.
    No-op when there's no password or it's already embedded."""
    import urllib.parse as up
    if not password or "@" in url.split("//", 1)[-1].split("/")[0]:
        return url
    return url.replace("//", "//smolvault:" + up.quote(password, safe="")
                       + "@", 1)


def _node_name():
    """This node's display name on the message board."""
    n = os.environ.get("SMOLVAULT_NAME") or NODE_NAME or \
        socket.gethostname() or "node"
    return n.strip()[:64] or "node"


def find_free_port(start, tries=20):
    for p in range(start, start + tries):
        try:
            s = socket.socket()
            s.bind(("0.0.0.0", p))
            s.close()
            return p
        except OSError:
            continue
    return None


def make_server(store, host, port):
    srv = MediaServer((host, port), Handler)
    srv.store = store
    return srv


# ---------------------------------------------------------------------------
# Progress bar (TTY: in-place redraw; pipe: periodic single lines)
# ---------------------------------------------------------------------------

class ProgressBar:
    WIDTH = 24

    def __init__(self, label, total):
        self.label = label[-38:]
        self.total = max(total, 1)
        self.done = 0
        self.t0 = time.perf_counter()
        self.tty = sys.stdout.isatty()
        self.last_draw = 0.0

    def update(self, n):
        self.done += n
        now = time.perf_counter()
        if self.tty:
            if now - self.last_draw > 0.08 or self.done >= self.total:
                self.draw()
                self.last_draw = now
        elif now - self.last_draw > 2.0:
            pct = self.done / self.total * 100
            log.info("  %s %3.0f%%  (%s / %s)",
                     self.label, pct, fmt(self.done), fmt(self.total))
            self.last_draw = now

    def draw(self):
        frac = min(1.0, self.done / self.total)
        filled = int(frac * self.WIDTH)
        speed = self.done / max(time.perf_counter() - self.t0, 1e-6)
        bar = "█" * filled + "░" * (self.WIDTH - filled)
        line = (f"  {self.label}  [{bar}] {frac*100:5.1f}%  "
                f"{fmt(self.done):>9} / {fmt(self.total):<9} {fmt(speed)+'/s'}")
        sys.stdout.write("\r" + line + " " * 4)
        sys.stdout.flush()

    def finish(self):
        if self.tty:
            self.draw()
            sys.stdout.write("\n")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Core operations (shared by wizard and flags)
# ---------------------------------------------------------------------------

PLAN_FILES = 50
PLAN_BYTES = 1024 ** 3


def collect_files(root):
    """Walk *root* recursively. Returns (items, hidden, broken) where items
    are (abspath, relpath) pairs with '/'-separated relpaths, natural-sorted.
    Dir symlinks are never descended (loop safety); file symlinks follow their
    target; dotfiles are skipped and counted."""
    items, hidden, broken = [], 0, 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for d in list(dirnames):
            if d.startswith("."):
                dirnames.remove(d)
                hidden += 1
            elif os.path.islink(os.path.join(dirpath, d)):
                dirnames.remove(d)                # prune link trees, no loops
        for f in filenames:
            if f.startswith("."):
                hidden += 1
                continue
            full = os.path.join(dirpath, f)
            if not os.path.isfile(full):          # broken link / special file
                broken += 1
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            items.append((full, rel))
    items.sort(key=lambda t: natural_key(t[1]))
    return items, hidden, broken


def gather_add_selections(paths, asker, interactive, force_pick=False):
    """Expand user-supplied paths into sealable items.

    Files stay loose (dest name None → caller picks basename). Folders walk
    via collect_files keeping relative structure; interactively each folder
    offers [Enter]=whole vs [b]=browse&pick. Returns (items, suggested_into).
    """
    items, suggest = [], ""
    for src in paths:
        src = os.path.expanduser(src)
        if os.path.isdir(src) and not os.path.islink(src):
            got, hidden, broken = collect_files(src)
            note = []
            if hidden:
                note.append(f"{hidden} hidden skipped")
            if broken:
                note.append(f"{broken} unreadable skipped")
            if note:
                print(dim(f"  ({src}: {', '.join(note)})"))
            if not got:
                print(yellow(f"  (nothing to ingest in {src})"))
                continue
            if force_pick:
                mode = "b"
            elif interactive:
                mode = (asker(f"  {src} — [Enter]=whole folder "
                              f"({len(got)} files) · [b]=browse & pick: ")
                        .strip().lower())
            else:
                mode = ""
            if mode == "b":
                picked = browse_picker(src)
                if not picked:
                    print(yellow("  (folder skipped)"))
                    continue
                items.extend(picked)
            else:
                items.extend(got)
            if not suggest:
                suggest = os.path.basename(
                    os.path.abspath(src).rstrip(os.sep))
        elif os.path.isfile(src):
            items.append((src, None))
        else:
            print(red(f"  ✗ no such file or folder: {src}"))
    return items, (("/" + suggest + "/") if suggest else "/")


def ingest_plan_ok(items, into, asker):
    """Print the sync-style transfer plan; confirm past the size/count gate."""
    try:
        total = sum(os.path.getsize(p) for p, _ in items)
    except OSError:
        total = 0                            # real failure surfaces per-file
    print(f"  plan: {len(items)} file(s) · {fmt(total)} → {into}")
    if len(items) <= PLAN_FILES and total <= PLAN_BYTES:
        return True
    try:
        return asker("  proceed? [y/N]: ").strip().lower() == "y"
    except (EOFError, KeyboardInterrupt):
        return False


def seal_many(store, items, into="/"):
    """Seal (abspath, dest_name) pairs under *into*. dest_name None → the
    file's basename; otherwise '/'-relative under into. Returns exit code.
    Ctrl+C mid-batch still prints the tally so you know what got sealed."""
    dest_dir = ("/" + into.strip("/") + "/") if into.strip("/") else "/"
    added = skipped = failed = 0
    tot_logical = tot_new = 0
    interrupted = False

    def tally():
        if len(items) > 1:
            saved = 100 - (tot_new / tot_logical * 100) if tot_logical else 0
            tail = dim(" (interrupted)") if interrupted else ""
            print(dim(f"  ── {added} added · {skipped} skipped · "
                      f"{failed} failed · "
                      f"{fmt(tot_new)} of {fmt(tot_logical)} newly stored "
                      f"({saved:.0f}% saved){tail}"))

    try:
        for src, dest_name in items:
            name = dest_name or os.path.basename(src)
            dest = dest_dir + name
            try:
                total_size = os.path.getsize(src)
            except OSError as e:
                print(red(f"  ✗ read error {src}: {e}"))
                failed += 1
                continue
            bar = ProgressBar(name.rsplit("/", 1)[-1], total_size)
            try:
                with open(src, "rb") as f:
                    res = store.put(dest, f, progress=bar.update)
                bar.finish()
                added += 1
                tot_logical += res.size
                tot_new += res.new_bytes
                note = gray(f"({res.new_bytes} new bytes)") \
                    if res.new_bytes == 0 else ""
                print(green(f"  ✓ sealed {dest}") +
                      dim(f"  {fmt(res.size)} · {res.new_chunks} chunks {note}"))
            except ExistsError:
                bar.finish()
                print(yellow(f"  = already sealed: {dest} (skipped)"))
                skipped += 1
            except OSError as e:
                print(red(f"  ✗ read error {src}: {e}"))
                failed += 1
    except KeyboardInterrupt:
        interrupted = True
        print()
    tally()
    if added:
        store.note(f"sealed {added} file(s) into {into}")
    if interrupted:
        raise KeyboardInterrupt
    return EXIT_OK if not failed else EXIT_NOMATCH


def add_files(store, src_paths, into="/"):
    """Ingest local files and/or folders. Folders walk recursively and keep
    their internal structure under *into*. Returns exit code."""
    items, _ = gather_add_selections(src_paths, None, interactive=False)
    if not items:
        return EXIT_NOMATCH
    return seal_many(store, items, into)


def vault_stats_line(s):
    dedup = (100 - s["stored"] / s["logical"] * 100) if s["logical"] else 0
    return (f"{s['files']} files · {fmt(s['logical'])} logical · "
            f"{fmt(s['stored'])} stored · {dedup:.0f}% deduped")


LIB_PAGE = 40


def render_library(rows, footer=None):
    """Paged library table shared by wizard and client. rows are sqlite3.Row
    or dicts with path/size/mime[/created_at]. Returns exit code."""
    if not rows:
        print(yellow("  (library is empty — drop files with [a] add)"))
        return EXIT_OK
    w = max(len(r["path"]) for r in rows)
    i = 0
    while True:
        for r in rows[i:i + LIB_PAGE]:
            keys = r.keys() if hasattr(r, "keys") else ()
            created = gray(str(r["created_at"])[:10]) \
                if "created_at" in keys else ""
            print(f"  {r['path']:<{w}}  {fmt(r['size']):>10}  "
                  f"{gray((r['mime'] or '?')[:24]):<24}"
                  + (f"  {created}" if created else ""))
        i += LIB_PAGE
        left = len(rows) - i
        if left <= 0:
            break
        try:
            ans = input(dim(f"  ── more ({left} remaining) · "
                            f"[Enter]=next · q=stop ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if ans == "q":
            break
    if footer:
        print(footer)
    return EXIT_OK


def list_library(store):
    rows = store.all_files()
    if not rows:
        return render_library(rows)
    w = min(max(len(r["path"]) for r in rows) + 50, 100)
    footer = "\n".join([dim("  " + "─" * w), dim("  " + vault_stats_line(store.stats()))])
    return render_library(rows, footer)


def du_rows(rows):
    """Group rows (path/size keys) by first path segment.
    Returns [(prefix, files, logical_bytes)] sorted by bytes desc."""
    groups = {}
    for r in rows:
        parts = r["path"].strip("/").split("/", 1)
        prefix = parts[0] if len(parts) == 2 else "(root)"
        n, b = groups.get(prefix, (0, 0))
        groups[prefix] = (n + 1, b + r["size"])
    return sorted(
        ((p, n, b) for p, (n, b) in groups.items()),
        key=lambda t: -t[2])


def find_duplicate_sets(rows):
    """Rows sharing a root_hash are byte-identical. Returns
    [(size, [paths…])] with len(paths) > 1, biggest waste first."""
    seen = {}
    for r in rows:
        entry = seen.setdefault(r["root_hash"], [r["size"], []])
        entry[1].append(r["path"])
    out = [(size, sorted(paths)) for size, paths in seen.values()
           if len(paths) > 1]
    out.sort(key=lambda t: -(t[0] * (len(t[1]) - 1)))
    return out


def show_du(rows, stats=None):
    """Space-by-folder table + byte-identical duplicate report.
    Works on local Store rows and remote /__api/list JSON alike."""
    if not rows:
        print(yellow("  (library is empty — drop files with [a] add)"))
        return EXIT_OK

    print(dim("  space by folder:"))
    for prefix, n, b in du_rows(rows):
        label = "/" + prefix if prefix != "(root)" else "(root)"
        print(f"  {label:<24}{dim('')}  {n:>4} files · {fmt(b):>10}")
    if stats:
        dedup = 0
        if stats.get("logical"):
            dedup = 100 - stats["stored"] / stats["logical"] * 100
        print(dim(f"  ── vault: {fmt(stats['logical'])} logical · "
                  f"{fmt(stats['stored'])} stored · {dedup:.0f}% deduped"))

    dups = find_duplicate_sets(rows)
    print()
    if not dups:
        print(green("  no duplicate paths — clean vault"))
        return EXIT_OK

    print(dim("  byte-identical sets (WORM keeps them all):"))
    wasted = 0
    for size, paths in dups:
        wasted += size * (len(paths) - 1)
        print(f"  {fmt(size)} ×{len(paths)}  {paths[0]}")
        for extra in paths[1:4]:
            print(dim(f"             = {extra}"))
        if len(paths) > 4:
            print(dim(f"             … +{len(paths) - 4} more copies"))
    word = "set" if len(dups) == 1 else "sets"
    print(dim(f"  ── {len(dups)} {word} · {fmt(wasted)} sealed twice "
              f"under different names"))
    return EXIT_OK


def render_board(rows, empty_hint="  (board is empty — post something)"):
    """Print board rows oldest→newest; system entries dimmed.
    rows are sqlite3.Row (local) or dicts (remote)."""
    if not rows:
        print(yellow(empty_hint))
        return
    for r in rows:
        ts = str(r["ts"])[5:16] if r["ts"] else ""
        if r["kind"] == "system":
            print(dim(f"  · [{ts}] {r['body']}"))
        else:
            print(f"  {cyan(str(r['sender']))} {dim('[' + ts + ']')}  "
                  f"{r['body']}")


def board_prompt(store=None, fetch=None, send=None):
    """Shared slim board loop: render tail → post / blank=refresh / q=back.
    Local mode passes `store`; remote mode passes fetch(after)→dict and
    send(text)→http-status. Returns exit code."""
    try:
        if store is not None:
            all_rows = list(store.msgs_since(0, 500))
        else:
            all_rows = list(fetch(0).get("messages", []))
        render_board(all_rows[-20:])
        last = all_rows[-1]["id"] if all_rows else 0

        while True:
            try:
                text = input(cyan("  post ❯ ")).strip()
            except (EOFError, KeyboardInterrupt):
                print(); return EXIT_OK
            if text.lower() in ("q", "quit", "exit"):
                return EXIT_OK
            if not text:
                if store is not None:
                    fresh = list(store.msgs_since(last, 500))
                else:
                    fresh = list(fetch(last).get("messages", []))
                if fresh:
                    render_board(fresh)
                    last = fresh[-1]["id"]
                continue
            if store is not None:
                try:
                    store.post_msg(_node_name(), "user", text)
                except ValueError as e:
                    print(red(f"  ✗ {e}")); continue
            else:
                st = send(text)
                if st != 201:
                    print(red(f"  ✗ post failed (HTTP {st})")); continue
            print(dim("  ✓ posted"))
    except RemoteError as e:
        print(red(f"  ✗ {e}"))
        return EXIT_NOMATCH


def score_query(query, path):
    """Score one path against a query. Higher = better; 0 = no match."""
    q = query.lower().strip()
    if not q:
        return 1.0
    base = path.rsplit("/", 1)[-1].lower()
    if base == q:
        return 300 - len(path) / 10000.0
    if base.startswith(q):
        return 200 - len(path) / 10000.0
    if q in base:
        return 100 - len(path) / 10000.0
    if q in path.lower():
        return 50 - len(path) / 10000.0
    return 0


def search_rank(store, query):
    """Scored, case-insensitive match over paths.
    exact basename > basename prefix > substring in path."""
    out = []
    for r in store.all_files():
        s = score_query(query, r["path"])
        if s > 0:
            out.append((s, r["path"], r))
    out.sort(reverse=True)
    return [(path, r) for _, path, r in out]


def show_matches(matches):
    for i, (path, r) in enumerate(matches[:12], 1):
        mark = cyan(f"[{i}]")
        print(f"  {mark} {path}"
              + dim(f"  ({fmt(r['size'])}, {r['mime']})"))
    if len(matches) > 12:
        print(dim(f"  … +{len(matches) - 12} more — refine the search"))


# ---------------------------------------------------------------------------
# Episode navigation (binge watching: next / previous)
# ---------------------------------------------------------------------------

_NUM_RE = re.compile(r"(\d+)")


def natural_key(path):
    """Sort key so E2 < E10 and [09] < [10] instead of lexicographic order."""
    return [int(t) if t.isdigit() else t.lower()
            for t in _NUM_RE.split(path)]


def episode_neighbors(paths, current):
    """Among files in the same directory, return (prev, next) of *current*
    by natural episode order."""
    siblings = sorted(
        (p for p in paths
         if p != current and os.path.dirname(p) == os.path.dirname(current)),
        key=natural_key)
    cur = natural_key(current)
    prev = nextp = None
    for p in siblings:
        k = natural_key(p)
        if k < cur and (prev is None or natural_key(prev) < k):
            prev = p
        if k > cur and (nextp is None or k < natural_key(nextp)):
            nextp = p
    return prev, nextp


# ---------------------------------------------------------------------------
# Player spawning — Termux-aware (CLI mpv there is audio-only)
# ---------------------------------------------------------------------------

TERMUX_MPV_APP = "is.xyz.mpv/is.xyz.mpv.MPVActivity"
_SYSTEM_AM_PATH = "/system/bin/am"          # raw Android am (<=13 usually)
MPV_ANDROID_NAMES = ("mpv-android", "mpvapp")


def _in_termux():
    return ("TERMUX_VERSION" in os.environ
            or "com.termux" in os.environ.get("PREFIX", ""))


def resolve_player(explicit=None):
    return explicit or os.environ.get("SMOLVAULT_PLAYER") or "mpv"


def _clipboard_set(text):
    """Best-effort Android clipboard write (needs termux-api pkg + app)."""
    binp = shutil.which("termux-clipboard-set")
    if not binp:
        return False
    try:
        p = subprocess.run([binp], input=text.encode(),
                           capture_output=True)
        return p.returncode == 0
    except OSError:
        return False


def _copy_or_show(url):
    """On launch failure: get the URL into the user's player with the
    least friction available."""
    if _clipboard_set(url):
        print(green("  ✓ stream link COPIED — open mpv/VLC → paste → play"))
    else:
        print(dim(f"  manual: open your player → 'Open URL' → {url}"))
    return EXIT_NOMATCH


def _termux_video_launch(url, mime, want_mpv_app):
    """Send *url* to Android video apps over an intent — the same
    MPVActivity recipe ani-cli uses on Termux.

    Runner cascade handles real-world Termux breakage:
      termux-am  → needs a recent Termux APP (socket server); Android 14+
                   kills raw /system/bin/am, hence termux-am first.
      system am  → still works on Android <= 13 on many devices.
    Falls back to `termux-open` (pure app-framework intent) at the end.
    Returns exit code."""
    intents = [["-n", TERMUX_MPV_APP, "-e", "filepath", url]]
    if not want_mpv_app:
        intents.append(["-a", "android.intent.action.VIEW",
                        "-d", url, "-t", mime or "video/*"])

    candidates = ["termux-am", _SYSTEM_AM_PATH]
    if os.environ.get("SMOLVAULT_DEBUG"):
        print(f"DEBUG am runners candidates={candidates}", flush=True)
    runners = [r for r in candidates
               if shutil.which(r) or os.path.exists(r)]
    if not runners:
        print(red("  ✗ no 'am' tool found — pkg install termux-am"))
        return EXIT_NOMATCH

    socket_broken, last_out = False, ""
    dead_runners = set()
    for argv in intents:
        target = "mpv-android" if argv[0] == "-n" else "video app"
        for runner in runners:
            if runner in dead_runners:
                continue
            print(dim(f"  ▶ android ({runner}) → {target}"))
            print(dim(f"     {url}"))
            p = subprocess.run([runner, "start"] + argv,
                               capture_output=True, text=True)
            out = ((p.stderr or "") + (p.stdout or "")).strip()
            if p.returncode == 0 and not (
                    "Exception" in out or "does not exist" in out
                    or out.startswith("Error")):
                return EXIT_OK
            if "Could not connect to socket" in out:
                # This runner has no working AM transport; every further
                # intent on it would fail identically.
                dead_runners.add(runner)
                socket_broken = True
                continue
            last_out = out
            log.debug("am output: %s", out)

    if socket_broken:
        print(red("  ✗ termux-am can't reach its control socket — your "
                  "Termux APP is too old for Android-14-safe 'am'."))
        print(dim("     Fix A: update the Termux APP itself from "
                  "github.com/termux/termux-app/releases, then fully"))
        print(dim("       close & reopen Termux (the AM socket server "
                  "lives in the app)."))
        print(dim("     Fix B: pkg reinstall termux-am, and make sure "
                  "~/.termux/termux.properties has no"))
        print(dim("       'run-termux-am-socket-server = false' line."))

    # Last resort that bypasses am entirely: the Termux app's own opener.
    opener = shutil.which("termux-open")
    if opener:
        print(dim("  ▶ termux-open fallback — choose your video player if "
                  "Android asks"))
        subprocess.run([opener, url])
        return EXIT_OK

    # Everything automated failed: hand the URL to the user's clipboard so
    # their manual flow is one paste away.
    hint = ("install mpv-android from F-Droid" if want_mpv_app
            else "install VLC or mpv-android")
    if last_out:
        print(red(f"  ✗ could not launch player ({last_out[:100]}) — {hint}"))
    else:
        print(red(f"  ✗ could not launch player — {hint}"))
    return _copy_or_show(url)


def play_url(url, mime=None, player=None):
    """Launch *url* in a player. On Termux, video is routed to Android's
    own apps (mpv-android first) because CLI mpv there has no video
    output. Returns process exit code semantics (0 = fine)."""
    env_player = os.environ.get("SMOLVAULT_PLAYER")
    explicit = bool(env_player) or bool(player)
    chosen = (player or env_player or "").lower()
    want_app = chosen in MPV_ANDROID_NAMES
    # On Termux, plain "mpv" IS the default — and its CLI cannot render
    # video at all, so it must never count as an explicit override.
    is_default_mpv = chosen == "mpv"

    if (_in_termux() and not os.environ.get("DISPLAY")
            and mime and mime.startswith("video/")):
        if not explicit or want_app or is_default_mpv:
            return _termux_video_launch(url, mime, want_mpv_app=want_app)
        # a genuinely different binary player was requested — below

    if not player and env_player and not want_app:
        player = env_player
    if not player:
        player = "mpv"
    if shutil.which(player) is None:
        print(red(f"  ✗ player '{player}' not found"))
        return EXIT_NOMATCH
    print(dim(f"  ▶ {player} {url}"))
    try:
        return subprocess.run([player, url]).returncode
    except KeyboardInterrupt:
        print()
        return EXIT_OK


def watch_flow(spawn, path, all_paths, player):
    """Play *path*, then offer next/previous/replay until the user quits.
    *spawn(url)* runs the player synchronously. Returns exit code."""
    current = path
    while True:
        try:
            rc = spawn(current)
        except KeyboardInterrupt:
            print()
            rc = 0
        if rc != 0:
            return EXIT_NOMATCH

        prev, nxt = episode_neighbors(all_paths, current)
        opts = {}
        if nxt:
            opts["n"] = ("next", nxt)
            opts[""] = ("next", nxt)          # Enter = binge on
        if prev:
            opts["p"] = ("prev", prev)
        opts["r"] = ("replay", current)

        if not nxt and not prev:
            return EXIT_OK
        hint = "  ▸ "
        if nxt:
            hint += f"[Enter]=next  {os.path.basename(nxt)[:48]}  "
        if prev:
            hint += f"[p]=prev  {os.path.basename(prev)[:40]}  "
        hint += "[r]=replay  anything else=quit: "
        try:
            raw = input(cyan(hint)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return EXIT_OK
        choice = opts.get(raw)
        if not choice:
            return EXIT_OK
        current = choice[1]


# ---------------------------------------------------------------------------
# Live search — results filter as you type (POSIX raw mode; fallback elsewhere)
# ---------------------------------------------------------------------------

LIVE_MAX_ROWS = 8


def _live_render(query, matches, sel, checked=None, label="watch"):
    """Draw prompt + live result rows; returns string to print."""
    checked = checked or set()
    count = dim(f" · {len(matches)}") if matches else ""
    lines = [f"\r\x1b[J  {cyan(label + ' ❯')} {query}{count}\x1b[K"]
    for i, (path, r) in enumerate(matches[:LIVE_MAX_ROWS]):
        if i == sel:
            mark = "\x1b[7m ❯ \x1b[27m"
        elif path in checked:
            mark = green(" ✓ ")
        else:
            mark = "   "
        name = path
        meta = f"  {fmt(r['size'])}"
        lines.append(f"\r\x1b[K{mark}{name}{dim(meta)}\x1b[K")
    if not matches and query:
        lines.append(f"\r\x1b[K{yellow('  no matches')}\x1b[K")
    elif len(matches) > LIVE_MAX_ROWS:
        lines.append(f"\r\x1b[K{dim(f'  … +{len(matches) - LIVE_MAX_ROWS} more')}\x1b[K")
    return "\n".join(lines) + f"\r\x1b[{len(lines)}A"


def live_search(rows, player_label="watch", multi=False):
    """Interactive as-you-type search.

    Single-select (default): returns chosen (path, row) or None.
    multi=True: Space toggles ✓ on the highlighted row (selections persist
    across re-filtering); Enter returns every checked row — or just the
    cursor row when none are checked. Esc/Ctrl+C/Ctrl+D cancel → None.

    POSIX terminals get true keystroke filtering with arrow-key selection;
    pipes/Windows fall back to a refine-loop with identical semantics.
    """
    dbg = os.environ.get("SMOLVAULT_DEBUG")
    if dbg:
        print(f"DEBUG live_search enter tty={sys.stdin.isatty()}", flush=True)
    use_raw = sys.stdin.isatty() and sys.stdout.isatty() and \
        hasattr(sys, "platform") and sys.platform != "win32" and \
        _termios_available()
    if dbg:
        print(f"DEBUG live_search raw={use_raw}", flush=True)
    if not use_raw:
        return _live_search_fallback(rows, player_label, multi)

    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    query, sel = "", 0
    checked, chosen = set(), None
    try:
        tty.setraw(fd)
        sys.stdout.write("\x1b[?25l")            # hide cursor
        while True:
            matches = sorted(
                (((score_query(query, r["path"]), r["path"], r))
                 for r in rows if score_query(query, r["path"]) > 0),
                key=lambda t: (-t[0], natural_key(t[1])))
            matches = [(p, r) for _, p, r in matches]
            sel = min(sel, max(len(matches) - 1, 0))
            sys.stdout.write(_live_render(query, matches, sel,
                                          checked, player_label))
            sys.stdout.flush()
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                # Escape: could be a bare Esc (cancel) or an arrow sequence.
                sel_ready, _, _ = select.select([sys.stdin], [], [], 0.05)
                if sel_ready:
                    b = sys.stdin.read(1)
                    if b == "[":
                        d = sys.stdin.read(1)
                        if d == "A":
                            sel = max(0, sel - 1)
                        elif d == "B":
                            sel = min(max(len(matches) - 1, 0), sel + 1)
                    continue
                query = None
                break
            if ch == "\x03":                     # Ctrl+C cancels
                query = None
                break
            elif ch in ("\r", "\n"):
                if multi:
                    picked = [(p, r) for p, r in matches if p in checked] \
                        or matches[sel:sel + 1]
                    chosen = picked or None
                break
            elif ch == " " and multi and matches:
                p = matches[min(sel, len(matches) - 1)][0]
                checked.symmetric_difference_update({p})
            elif ch in ("\x7f", "\b"):
                query = query[:-1]
                sel = 0
            elif ch == "\x04":                   # Ctrl+D
                query = None
                break
            elif ch == "\t":
                continue
            elif ch == "\x1b[A":                 # up (arrow arrives split)
                sel = max(0, sel - 1)
            elif ch == "\x1b[B":                 # down
                sel = min(max(len(matches) - 1, 0), sel + 1)
            elif ch >= " ":
                query += ch
                sel = 0
        sys.stdout.write("\r\x1b[J\x1b[?25h")    # clear + show cursor
        sys.stdout.flush()
    except Exception:
        sys.stdout.write("\r\x1b[J\x1b[?25h")
        sys.stdout.flush()
        if os.environ.get("SMOLVAULT_DEBUG"):
            import traceback
            traceback.print_exc()
        return None
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

    if dbg:
        print(f"DEBUG live_search exit q={query!r} sel={sel} n={len(matches)}", flush=True)
    if query is None or not matches:
        return None
    if multi:
        return chosen or [matches[min(sel, len(matches) - 1)]]
    return matches[min(sel, len(matches) - 1)]


def multi_pick(rows):
    """Folder-picker facade over live_search's multi mode.
    Returns list[(path, row)] or None on cancel."""
    return live_search(rows, player_label="add", multi=True)


# ---------------------------------------------------------------------------
# Browse navigator — a tiny file manager over the raw-mode toolkit
# ---------------------------------------------------------------------------

class BrowseState:
    """Pure-logic directory navigator (no I/O beyond directory listing).
    Selections are relpaths (posix) relative to *root*; selecting a
    directory means its entire subtree."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.cur = self.root
        self.checked = set()
        self.query = ""
        self.sel = 0
        self._subtree_cache = {}

    # -- listing ----------------------------------------------------------
    def _scan(self, d):
        out = []
        try:
            for e in os.scandir(d):
                if e.name.startswith("."):
                    continue
                try:
                    is_dir = e.is_dir(follow_symlinks=False)
                    size = 0 if is_dir else e.stat().st_size
                except OSError:
                    continue
                out.append((e.name, is_dir, size))
        except OSError:
            pass
        dirs = sorted(((n, True, s) for n, is_d, s in out if is_d),
                      key=lambda t: natural_key(t[0]))
        files = sorted(((n, False, s) for n, is_d, s in out if not is_d),
                       key=lambda t: natural_key(t[0]))
        return dirs + files

    def _rel(self, abspath):
        return os.path.relpath(abspath, self.root).replace(os.sep, "/")

    def entries(self):
        """Filtered, ordered visible entries:
        [(name, is_dir, size, relpath)]."""
        q = self.query.lower()
        out = []
        for name, is_dir, size in self._scan(self.cur):
            if q and q not in name.lower():
                continue
            out.append((name, is_dir, size,
                        self._rel(os.path.join(self.cur, name))))
        return out

    def current(self):
        es = self.entries()
        return es[self.sel] if 0 <= self.sel < len(es) else None

    # -- navigation -------------------------------------------------------
    def descend(self):
        e = self.current()
        if e and e[1]:
            self.cur = os.path.join(self.cur, e[0])
            self.query = ""
            self.sel = 0

    def parent(self):
        if os.path.abspath(self.cur) != self.root:
            self.cur = os.path.dirname(self.cur)
            self.query = ""
            self.sel = 0

    # -- selection --------------------------------------------------------
    def _subtree_files(self, rel_dir):
        if rel_dir not in self._subtree_cache:
            base = os.path.join(self.root, rel_dir)
            acc = set()
            for dp, dns, fns in os.walk(base):
                dns[:] = [x for x in dns if not x.startswith(".")]
                for fn in fns:
                    if fn.startswith("."):
                        continue
                    p = os.path.join(dp, fn)
                    if os.path.isfile(p):
                        acc.add(self._rel(p))
            self._subtree_cache[rel_dir] = frozenset(acc)
        return self._subtree_cache[rel_dir]

    def dir_marker(self, rel_dir):
        """(selected, total) file counts under a dir; None when empty."""
        files = self._subtree_files(rel_dir)
        if not files:
            return None
        return len(files & self.checked), len(files)

    def toggle(self):
        e = self.current()
        if not e:
            return
        name, is_dir, size, rel = e
        if is_dir:
            self.toggle_subtree(rel)
        else:
            self.checked.symmetric_difference_update({rel})

    def toggle_subtree(self, rel_dir):
        """Cycle: partial → fully selected → none."""
        files = self._subtree_files(rel_dir)
        if files <= self.checked:
            self.checked -= files
        else:
            self.checked |= files

    def select_visible(self):
        for name, is_dir, size, rel in self.entries():
            if is_dir:
                self.checked |= self._subtree_files(rel)
            else:
                self.checked.add(rel)

    def clear(self):
        self.checked.clear()

    def confirm_items(self):
        """Selection → [(abspath, relpath)], natural-sorted by relpath."""
        return [(os.path.join(self.root, rel), rel)
                for rel in sorted(self.checked, key=natural_key)]


def _browse_render(st):
    rel = os.path.relpath(st.cur, st.root)
    head = "  add ❯ " + ("/" if rel == "." else f"/{rel}")
    if st.query:
        head += dim(f"   filter '{st.query}'")
    es = st.entries()
    st.sel = min(st.sel, max(len(es) - 1, 0))
    partial = full = 0
    for name, is_dir, size, r in es:
        if is_dir:
            mk = st.dir_marker(r)
            if mk:
                if mk[0] == mk[1]:
                    full += 1
                elif mk[0]:
                    partial += 1
    counts = dim(f"   ✓{len(st.checked)}")
    if partial:
        counts += yellow(f" · ◐{partial}")
    if full:
        counts += green(f" · ✓{full} dirs")
    counts += dim(f"   {len(es)} shown")

    B = "─" * 66
    lines = [head + counts, dim("  " + B)]
    lo = max(0, min(st.sel - 6, len(es) - 12))
    for i, (name, is_dir, size, r) in enumerate(es[lo:lo + 12], lo):
        cursor = "  ❯ " if i == st.sel else "    "
        if is_dir:
            mk = st.dir_marker(r)
            if mk:
                sel_n, tot_n = mk
                mark = (green(f"✓ {sel_n}/{tot_n}") if sel_n == tot_n
                        else (yellow(f"◐ {sel_n}/{tot_n}") if sel_n
                              else dim(f"○ {tot_n}")))
            else:
                mark = dim("empty")
            pad = " " * max(1, 40 - len(name))
            lines.append(f"{cursor}{cyan(name + '/')}{pad}{mark}")
        else:
            tick = green("✓ ") if r in st.checked else "  "
            lines.append(f"{cursor}{tick}{name}"
                         + dim(f"   {fmt(size)}"))
    lines.append(dim("  " + B))
    lines.append(dim("  → open · ← up · space ✓ · a all · u none · "
                     "s seal ✓" + str(len(st.checked)) + " · esc"))
    return "\n".join(lines) + "\r"


def browse_picker(root):
    """Directory navigator. Returns [(abspath, relpath)] or None on cancel.

    Real terminal: full navigator (descend/ascend, subtree toggles,
    live filter). Non-TTY: falls back to the flat multi-pick."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()
            and _termios_available()):
        items, _h, _b = collect_files(root)
        rows = [{"path": rel, "size": os.path.getsize(full)}
                for full, rel in items]
        m = {rel: full for full, rel in items}
        picked = multi_pick(rows)
        if not picked:
            return None
        return [(m[p], p) for p, _ in picked]

    import termios
    import tty
    st = BrowseState(root)
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        sys.stdout.write("\x1b[?25l")
        while True:
            sys.stdout.write(_browse_render(st))
            sys.stdout.flush()
            ch = sys.stdin.read(1)
            n = len(st.entries())
            if ch == "\x1b":
                r, _, _ = select.select([sys.stdin], [], [], 0.05)
                if r:
                    b = sys.stdin.read(1)
                    if b == "[":
                        d = sys.stdin.read(1)
                        if d == "C":
                            st.descend()
                        elif d == "D":
                            st.parent()
                        elif d == "A":
                            st.sel = max(0, st.sel - 1)
                        elif d == "B":
                            st.sel = min(max(n - 1, 0), st.sel + 1)
                    continue
                return None                      # bare Esc cancels
            if ch == "\x03":
                return None
            if ch in ("\r", "\n"):
                e = st.current()
                if e and e[1]:
                    st.descend()
                else:
                    st.toggle()
            elif ch == " ":
                st.toggle()
            elif ch in ("\x7f", "\b"):
                if st.query:
                    st.query = st.query[:-1]
                    st.sel = 0
                else:
                    st.parent()
            elif ch == "a":
                st.select_visible()
            elif ch == "u":
                st.clear()
            elif ch == "s":
                return st.confirm_items()
            elif ch in ("\x04",):                # Ctrl+D cancels
                return None
            elif ch >= " ":
                st.query += ch
                st.sel = 0
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\r\x1b[J\x1b[?25h")
        sys.stdout.flush()


def _termios_available():
    try:
        import termios                              # noqa: F401
        return True
    except ImportError:
        return False


def _live_search_fallback(rows, player_label="watch", multi=False):
    """Line-based refinement loop for pipes / Windows: same semantics,
    one Enter per refinement. Multi: Enter takes all filtered hits,
    a number takes one, 'q' cancels the whole picker."""
    q = ""
    while True:
        try:
            q = input(cyan(f"  {player_label} ❯ ")).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        matches = search_rank(ListingStore(rows), q)
        if not matches:
            print(yellow("  no matches"))
            continue
        if not multi:
            chosen = choose_match(matches[:12], "play which")
            if chosen:
                return chosen
            continue
        raw = input(cyan(f"  take [Enter]=all {len(matches)} · "
                         f"<n>=one · q=cancel: ")).strip().lower()
        if raw == "q":
            return None
        if raw.isdigit() and 1 <= int(raw) <= min(len(matches), 12):
            return [matches[int(raw) - 1]]
        return matches


def choose_match(matches, prompt="choose"):
    if not matches:
        return None
    if len(matches) == 1:
        return matches[0]
    show_matches(matches)
    try:
        raw = input(cyan(f"  {prompt} [1-{min(len(matches),12)}]: ")).strip()
    except EOFError:
        return None
    if not raw:
        return matches[0]
    if not raw.isdigit() or not 1 <= int(raw) <= min(len(matches), 12):
        print(red("  invalid choice"))
        return None
    return matches[int(raw) - 1]


def play_query(store, query, player=None, password=None):
    """Search → pick → spawn player against a private loopback port."""
    explicit_player = player or os.environ.get("SMOLVAULT_PLAYER") or None
    if explicit_player and shutil.which(explicit_player) is None:
        print(red(f"  ✗ player '{explicit_player}' not found — install it "
                  f"or set SMOLVAULT_PLAYER"))
        return EXIT_NOMATCH

    matches = search_rank(store, query)
    if not matches:
        print(yellow(f"  no matches for '{query}'"))
        return EXIT_NOMATCH

    chosen = choose_match(matches, "play which")
    if chosen is None:
        return EXIT_NOMATCH
    path, row = chosen

    # Play-guard: mpv handles video/audio/images; anything else gets
    # offered an export instead.
    mime = row["mime"] or ""
    if not mime.startswith(("video/", "audio/", "image/")):
        print(yellow(f"  '{path}' is {mime} — not watchable."))
        if sys.stdin.isatty():
            try:
                ans = input(cyan("  export a copy instead? [y/N]: ")).strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = ""
            if ans == "y":
                return export_file(store, path)
        else:
            print(dim("  (use --get to export it)"))
        return EXIT_NOMATCH

    srv = make_server(store, "127.0.0.1", 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    url = f"http://127.0.0.1:{port}{urllib.parse.quote(path)}"
    if store.auth_required() and password:
        url = cred_url(url, password)
    try:
        rc = play_url(url, row.get("mime"), explicit_player)
    except KeyboardInterrupt:
        rc = 0
        print()
    finally:
        srv.shutdown()
        srv.server_close()
    return EXIT_OK if rc == 0 else EXIT_NOMATCH


def resolve_path_arg(store, arg):
    """Exact path first; fall back to top search hit(s). Always returns a
    fully-loaded row (with manifest)."""
    norm = _norm(arg)
    row = store.lookup(norm)
    if row:
        return norm, row
    matches = search_rank(store, arg)
    if not matches:
        return None, None
    if sys.stdin.isatty():
        print(dim(f"  exact path '{arg}' not found — closest match:"))
        chosen = choose_match(matches[:8], "use which")
    else:
        chosen = matches[0]
    if chosen is None:
        return None, None
    return chosen[0], store.lookup(chosen[0])


def show_info(store, arg):
    path, row = resolve_path_arg(store, arg)
    if row is None:
        print(yellow(f"  no match for '{arg}'"))
        return EXIT_NOMATCH
    man = json.loads(row["manifest"])
    chunks = len(man["chunks"])
    avg = row["size"] / chunks if chunks else 0
    print(f"""  {bold(path)}
    size     : {fmt(row['size'])}
    type     : {row['mime']}
    sealed   : {row['created_at']}
    chunks   : {chunks}  (avg {fmt(avg)}, {fmt(min(man['sizes']))}–{fmt(max(man['sizes']))})
    etag     : {row['root_hash'][:24]}…
    policy   : WORM — this file can never be changed or deleted""")
    if sys.stdin.isatty():
        print(dim("  ── [p] play · [g] export · [c] copy link"))
    return EXIT_OK


def export_file(store, arg, out=None):
    path, row = resolve_path_arg(store, arg)
    if row is None:
        print(yellow(f"  no match for '{arg}'"))
        return EXIT_NOMATCH
    out = out or os.path.basename(path)
    if os.path.exists(out):
        print(red(f"  ✗ refusing to overwrite local file: {out}"))
        return EXIT_NOMATCH
    bar = ProgressBar(os.path.basename(out), row["size"])
    try:
        with open(out, "wb") as f:
            for piece in store.read_full(row):
                f.write(piece)
                bar.update(len(piece))
        bar.finish()
    except ValueError as e:
        os.unlink(out)
        print(red(f"  ✗ integrity failure: {e}"))
        return EXIT_NOMATCH
    print(green(f"  ✓ exported {path}") + dim(f" → {out} ({fmt(row['size'])})"))
    return EXIT_OK


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner(vault, s, urls, auth_on, server_state="● running",
                 enc_on=False, auth_required=None):
    state_col = green(server_state) if "running" in server_state else yellow(server_state)
    if auth_on:
        auth = ("LAN streaming open" if auth_required is False
                else "password protected")
    else:
        auth = gray("none")
    if enc_on:
        auth += green(" · AES-256-GCM at rest")
    print(f"""  ┌────────────────────────────────────────────────────────┐
    {bold('smolvault')} {__version__}
    {dim('vault   ')} {vault}  {dim('·')} {vault_stats_line(s)}
    {dim('local   ')} {cyan(urls[0])}
    {dim('network ')} {cyan(urls[1])}  {state_col}
    {dim('auth    ')} {auth}
  └────────────────────────────────────────────────────────┘""")


WIZARD_MENU = f"""
    {cyan('a')} add       {dim('drag & drop files here, press Enter')}
    {cyan('s')} search    {dim('find something')}
    {cyan('p')} play      {dim('search → mpv  (w works too)')}
    {cyan('l')} library   {dim('browse everything')}
    {cyan('d')} du        {dim('space by folder · find double-sealed files')}
    {cyan('m')} board     {dim("this vault's messages · clients & server post here")}
    {cyan('i')} info      {dim('details about a file')}
    {cyan('g')} get       {dim('export a copy out of the vault')}
    {cyan('c')} copy      {dim('stream link → clipboard')}
    {cyan('y')} sync      {dim('mirror another smolvault')}
    {cyan('S')} server    {dim('start/stop network sharing')}
    {cyan('v')} verify    {dim('check vault integrity')}
    {cyan('q')} quit"""

CLIENT_MENU = f"""
    {cyan('a')} add       {dim('upload files to the remote vault')}
    {cyan('s')} search    {dim('find something')}
    {cyan('p')} watch     {dim('remote search → player')}   {dim('(w too)')}
    {cyan('l')} library   {dim('browse everything')}
    {cyan('d')} du        {dim('space by folder · find double-sealed files')}
    {cyan('m')} board     {dim("this vault's messages · post to the server")}
    {cyan('i')} info      {dim('details about a file')}
    {cyan('g')} get       {dim('export a copy')}
    {cyan('c')} copy      {dim('stream link → clipboard')}
    {cyan('r')} reconnect {dim('pick a different vault')}
    {cyan('q')} quit"""


# ---------------------------------------------------------------------------
# Wizard
# ---------------------------------------------------------------------------

def bootstrap_vault(explicit=None):
    """Pick or create a vault path. Returns (path, created)."""
    if explicit:
        return explicit, not os.path.exists(explicit)

    env = os.environ.get("SMOLVAULT_VAULT")
    if env:
        return env, not os.path.exists(env)

    existing = sorted(f for f in os.listdir(".") if f.endswith(".vault"))
    if len(existing) == 1:
        return existing[0], False
    if len(existing) > 1:
        print("  vaults in this directory:")
        for i, v in enumerate(existing, 1):
            print(f"    [{i}] {v}")
        try:
            raw = input("  use which? [1]: ").strip() or "1"
        except EOFError:
            sys.exit(EXIT_USAGE)
        if raw.isdigit() and 1 <= int(raw) <= len(existing):
            return existing[int(raw) - 1], False
        print(red("  invalid choice")); sys.exit(EXIT_USAGE)

    try:
        name = input("  create vault name [vault.vault]: ").strip() or "vault.vault"
    except EOFError:
        name = "vault.vault"
    if not name.endswith(".vault"):
        name += ".vault"
    return name, True


class Wizard:
    def __init__(self, store, vault, no_discover=False, player=None):
        self.store = store
        self.vault = vault
        self.no_discover = no_discover
        self.player = player
        self.discovery = None
        self.srv = None
        self.port = None
        self.last_interrupt = 0.0
        self.pw = None                    # remembered for player URLs

    # -- server toggle ------------------------------------------------------

    def start_server(self):
        preferred = int(self.store.cfg_get("lan_port") or 8100)
        port = find_free_port(preferred)
        if port is None:
            print(red("  ✗ no free port found near %d" % preferred))
            return False
        try:
            self.srv = make_server(self.store, "0.0.0.0", port)
        except OSError as e:
            print(red(f"  ✗ cannot bind: {e}"))
            return False
        self.port = port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        if not self.no_discover:
            name = os.path.basename(self.vault).replace(".vault", "")
            self.discovery = DiscoveryResponder(
                name, port, self.store.has_password(),
                files=self.store.stats()["files"])
            self.discovery.start()
        self.store.cfg_set("lan_port", port)          # stable URL next run
        return True

    def stop_server(self):
        if self.srv:
            self.srv.shutdown()
            self.srv.server_close()
            self.srv = None
            self.port = None
        if self.discovery:
            self.discovery.stop()
            self.discovery = None

    # -- banner ---------------------------------------------------------------

    def banner(self):
        s = self.store.stats()
        local = f"http://127.0.0.1:{self.port}/"
        net = f"http://{lan_ip()}:{self.port}/"
        state = "● running" if self.srv else "○ stopped"
        print_banner(self.vault, s, (local, net),
                     self.store.has_password(), state,
                     enc_on=self.store.enc_enabled(),
                     auth_required=self.store.auth_required())
        print(WIZARD_MENU)

    # -- prompts ----------------------------------------------------------------

    def ask(self, prompt):
        try:
            return input(prompt).strip()
        except EOFError:
            raise QuitWizard()

    # -- actions ------------------------------------------------------------------

    def do_add(self):
        line = self.ask("  drop files · type a path · [b]rowse a folder:"
                        "\n  ❯ ")
        if line.strip().lower() in ("b", "browse"):
            folder = self.ask(dim("  folder to browse [cwd]: ")).strip()
            folder = os.path.abspath(os.path.expanduser(folder or "."))
            if not os.path.isdir(folder):
                print(red(f"  ✗ no such folder: {folder}"))
                return
            picked = browse_picker(folder)
            if not picked:
                print(yellow("  (nothing selected)"))
                return
            items = list(picked)
            suggest = "/" + (os.path.basename(folder.rstrip(os.sep))
                             or "") + "/"
        elif line.strip():
            try:
                items, suggest = gather_add_selections(
                    shlex.split(line), lambda p: self.ask(p), interactive=True)
            except (EOFError, KeyboardInterrupt):
                print()
                return
        else:
            return
        if not items:
            return
        into = self.ask(dim(f"  into folder? [{suggest}]") + " ").strip() \
            or suggest
        if not ingest_plan_ok(items, into, lambda p: self.ask(p)):
            print(yellow("  cancelled"))
            return
        if seal_many(self.store, items, into) == EXIT_OK:
            print(dim("  (p watch · l list)"))

    def do_play(self):
        if os.environ.get("SMOLVAULT_DEBUG"):
            print("DEBUG do_play enter", flush=True)
        explicit_player = os.environ.get("SMOLVAULT_PLAYER") or self.player \
            or None
        if explicit_player and shutil.which(explicit_player) is None:
            print(red(f"  player '{explicit_player}' not found"))
            return
        rows = self.store.all_files()
        chosen = live_search(rows)
        if not chosen:
            return
        path, row = chosen
        mime = row["mime"] or ""
        if not mime.startswith(("video/", "audio/", "image/")):
            print(yellow(f"  '{path}' is {mime} — not watchable. Use [g]."))
            return

        base = f"http://127.0.0.1:{self.port}" if self.srv else None
        ephemeral = None
        if not base:
            # sharing stopped — spin a private loopback server for this
            # session instead of dead-ending on "press S first"
            ephemeral = make_server(self.store, "127.0.0.1", 0)
            port = ephemeral.server_address[1]
            threading.Thread(target=ephemeral.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{port}"
            print(dim(f"  · private loopback :{port}"))

        def spawn(p):
            url = base + urllib.parse.quote(p)
            if self.store.auth_required() and self.pw:
                url = cred_url(url, self.pw)
            return play_url(url, mime, explicit_player)

        try:
            all_paths = [r["path"] for r in rows]
            watch_flow(spawn, path, all_paths, explicit_player or "mpv")
        finally:
            if ephemeral:
                ephemeral.shutdown()
                ephemeral.server_close()

    def do_search(self):
        q = self.ask("  search: ")
        if not q:
            return
        matches = search_rank(self.store, q)
        if not matches:
            print(yellow(f"  no matches for '{q}'"))
            return
        show_matches(matches)
        ans = self.ask(dim("  play one? number / Enter to skip: ")).strip()
        if ans.isdigit():
            idx = int(ans) - 1
            if 0 <= idx < min(len(matches), 12):
                play_query(self.store, matches[idx][0].rsplit("/", 1)[-1])

    def do_info(self):
        q = self.ask("  file (path or search term): ")
        if q:
            show_info(self.store, q)

    def do_get(self):
        q = self.ask("  export which (path or search term): ")
        if not q:
            return
        out = self.ask(dim("  save as? [default: same name]") + " ").strip()
        export_file(self.store, q, out or None)

    def _verify(self):
        ok = self.store.check()
        self.store.note(f"verify {'PASS' if ok else 'FAIL'}")
        return ok

    def do_board(self):
        board_prompt(store=self.store)

    def do_server(self):
        if self.srv:
            self.stop_server()
            self.store.note("server stopped")
            print(yellow("  ○ server stopped"))
        else:
            if self.start_server():
                self.store.note(f"sharing on port {self.port}")
                print(green(f"  ● serving on http://{lan_ip()}:{self.port}/"))

    # -- main loop --------------------------------------------------------------------

    def status_prompt(self):
        """One-line context carrier: vault · files · server state."""
        state = green("●") if self.srv else yellow("○")
        port = dim(f":{self.port}") if self.port else ""
        return (f"\n  {dim(self.vault)} {dim('·')} "
                f"{self.store.stats()['files']}f {state}{port} {cyan('❯')} ")

    def run(self):
        print(bold(f"\n  smolvault {__version__}\n"))
        try:
            if self.store.enc_enabled():
                for attempt in range(3):
                    pw = getpass.getpass(
                        dim(f"  {self.vault} — password to unlock: ")).strip()
                    if not pw:
                        return EXIT_NOMATCH
                    try:
                        self.store.unlock(pw)
                        self.pw = pw; break
                    except ValueError:
                        print(red("  ✗ wrong password"))
                else:
                    return EXIT_NOMATCH
            elif not self.store.has_password():
                pwd = getpass.getpass(
                    dim(f"  {self.vault} — set password (Enter = no auth): ")).strip()
                if pwd:
                    self.store.set_password(pwd)
                    self.pw = pwd
                    print(green("  ✓ password set"))
                    if sys.stdin.isatty():
                        try:
                            ans = input(cyan(
                                "  encrypt vault at rest? [y/N]: "
                            )).strip().lower()
                        except (EOFError, KeyboardInterrupt):
                            ans = ""
                        if ans == "y":
                            self.store.enable_encryption(pwd)
                            self.pw = pwd
                            n = self.store.migrate_encryption()
                            print(green(f"  ✓ encrypted at rest · "
                                        f"{n} chunk(s) rewritten"))
                            try:
                                open_ans = input(cyan(
                                    "  require password for network "
                                    "access? [Y/n]: ")).strip().lower()
                            except (EOFError, KeyboardInterrupt):
                                open_ans = ""
                            if open_ans == "n":
                                self.store.set_auth_required(False)
                                print(yellow("  ○ LAN streaming stays open "
                                             "(files still encrypted)"))
        except EOFError:
            print()

        if not self.start_server():
            print(yellow("  continuing without network sharing"))
        else:
            self.store.note(f"vault opened · sharing on port {self.port}")

        self.banner()                      # full paint once; menu on demand
        try:
            while True:
                try:
                    raw = input(self.status_prompt()).strip()
                    if os.environ.get("SMOLVAULT_DEBUG"):
                        print(f"DEBUG menu raw={raw!r}", flush=True)
                    key = raw[:1] if raw else ""
                except KeyboardInterrupt:
                    self._interrupt()
                    continue
                except EOFError:
                    raise QuitWizard()
                if key.lower() in ("q", "quit", "exit"):
                    print(dim("  bye 👋"))
                    return EXIT_OK
                if not raw or raw in ("h", "?", "help"):
                    print(WIZARD_MENU)
                    continue
                try:
                    self.dispatch(key)
                except KeyboardInterrupt:
                    self._interrupt()
        except QuitWizard:
            print(dim("\n  bye 👋"))
            return EXIT_OK
        finally:
            self.stop_server()

    def _interrupt(self):
        now = time.time()
        if now - self.last_interrupt < 2.0:
            raise QuitWizard()
        self.last_interrupt = now
        print(yellow("  cancelled (Ctrl+C again to quit)"))

    def do_copy(self):
        q = self.ask("  copy link for (path or term): ").strip()
        if not q:
            return
        if not self.srv:
            print(red("  ✗ server not running — press S first"))
            return
        row = self.store.lookup(_norm(q))
        if not row:
            matches = search_rank(self.store, q)
            chosen = choose_match(matches[:8], "use which") if matches else None
            if not chosen:
                print(yellow("  no match"))
                return
            path = chosen[0]
        else:
            path = _norm(q)
        url = f"http://{lan_ip()}:{self.port}{urllib.parse.quote(path)}"
        if self.store.auth_required():
            print(dim("  (players will ask for the vault password — "
                      "VLC prompts; mpv needs user:pass@ in the URL)"))
        if _clipboard_set(url):
            print(green(f"  ✓ copied {url}"))
        else:
            print(url)
            print(dim("  (pkg install termux-api + Termux:API app for "
                      "direct clipboard)"))

    def do_sync(self):
        d = self.ask(cyan("  direction — push to peer [p] or pull from "
                          "peer [f]? ")).strip().lower()
        if d == "p":
            direction = "to"
        elif d == "f":
            direction = "from"
        else:
            print(yellow("  cancelled"))
            return
        tgt = self.ask(dim("  target host[:port] (Enter = discover LAN)")
                       + " ").strip() or "auto"
        targets = resolve_target(tgt)
        if not targets:
            return
        host, port, _info = targets[0]
        sync_vault(self.store, direction, host, int(port))

    def dispatch(self, key):
        if os.environ.get("SMOLVAULT_DEBUG"):
            print(f"DEBUG dispatch key={key!r}", flush=True)
        actions = {
            "a": self.do_add, "s": self.do_search,
            "p": self.do_play, "w": self.do_play,
            "l": lambda: list_library(self.store),
            "d": lambda: show_du(self.store.all_files(), self.store.stats()),
            "m": self.do_board,
            "i": self.do_info,
            "g": self.do_get, "c": self.do_copy,
            "y": self.do_sync, "S": self.do_server,
            "v": lambda: self._verify(),
        }
        if key in ("", "h", "help", "?"):
            return
        fn = actions.get(key)                  # case matters: 'S' = server
        if fn:
            fn()
        else:
            lows = sorted({k.lower() for k in actions if k.islower()})
            ups = sorted({k for k in actions if k.isupper()})
            print(red(f"  unknown key '{key}' — keys: "
                      f"{' '.join(lows + ups)} · h menu · q quit"))


class QuitWizard(Exception):
    pass


# ---------------------------------------------------------------------------
# Remote client — smolvault.py can act as both server and client
# ---------------------------------------------------------------------------

class ListingStore:
    """Duck-type shim so search_rank()/show_matches() work on JSON listings."""

    def __init__(self, rows):
        self.rows = rows

    def all_files(self):
        return self.rows


class RemoteVault:
    def __init__(self, host, port):
        self.host, self.port = host, int(port)
        self.password = None
        self.rows = None

    @property
    def base(self):
        return f"http://{self.host}:{self.port}"

    def _headers(self):
        if not self.password:
            return {}
        token = __import__("base64").b64encode(
            f":{self.password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def _fetch(self, path, out=None, method="GET", body=None,
               headers=None, progress=None, timeout=300):
        conn = http.client.HTTPConnection(self.host, self.port,
                                          timeout=timeout)
        try:
            return self._fetch_inner(conn, path, out, method, body,
                                     headers, progress)
        except (AuthRequired, RemoteError):
            raise
        except OSError as e:
            raise RemoteError(
                _friendly_oserror(e, self.host, self.port)) from e
        finally:
            conn.close()

    def _fetch_inner(self, conn, path, out, method, body,
                     headers, progress):
            conn.request(method, path, body=body,
                         headers={**self._headers(), **(headers or {})})
            r = conn.getresponse()
            if r.status in (401, 403) and self.password is None:
                raise AuthRequired()
            if r.status != 200:
                raise RemoteError(f"HTTP {r.status} on {path}")
            if out is None:
                return json.loads(r.read())
            total = int(r.getheader("Content-Length") or 0)
            bar = ProgressBar(os.path.basename(out), total or 1)
            with open(out, "wb") as f:
                while True:
                    chunk = r.read(256 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    if progress:
                        progress(len(chunk), bar)
                    else:
                        bar.update(len(chunk))
            bar.finish()
            return True

    def authenticate(self):
        """Fetch listing; prompt for password once if the vault has auth."""
        try:
            self.rows = self._fetch("/__api/list", timeout=6)
            return True
        except AuthRequired:
            pass
        try:
            self.password = getpass.getpass(
                dim(f"  password for {self.host}:{self.port}: ")).strip()
        except EOFError:
            return False
        try:
            self.rows = self._fetch("/__api/list", timeout=6)
            return True
        except (AuthRequired, RemoteError):
            print(red("  ✗ authentication failed"))
            return False

    def url_for(self, path):
        return self.base + urllib.parse.quote(path)

    def cred_url(self, path):
        url = self.url_for(path)
        if self.password and self.store_requires_auth():
            url = url.replace("//", "//smolvault:"
                              + urllib.parse.quote(self.password,
                                                   safe="") + "@", 1)
        return url

    def store_requires_auth(self):
        """Probe the vault once without credentials: 401 ⇒ gated."""
        import http.client as hc
        try:
            conn = hc.HTTPConnection(self.host, self.port, timeout=5)
            conn.request("GET", "/__api/auth")
            r = conn.getresponse(); r.read(); conn.close()
            return r.status == 401
        except Exception:
            return True                      # assume gated on uncertainty

    def watch(self, path, mime, player=None):
        if not (mime or "").startswith(("video/", "audio/", "image/")):
            print(yellow(f"  '{path}' is {mime} — not watchable. Use [g]."))
            return EXIT_NOMATCH
        return play_url(self.cred_url(path), mime, player)

    def export(self, path, out=None):
        out = out or os.path.basename(path)
        if os.path.exists(out):
            print(red(f"  ✗ refusing to overwrite local file: {out}"))
            return EXIT_NOMATCH
        row = next((r for r in self.rows if r["path"] == path), None)
        expected = row["size"] if row else None
        try:
            self._fetch(urllib.parse.quote(path), out=out)
        except RemoteError as e:
            print(red(f"  ✗ export failed: {e}"))
            return EXIT_NOMATCH
        got = os.path.getsize(out)
        if expected is not None and got != expected:
            os.unlink(out)
            print(red(f"  ✗ size mismatch (wanted {fmt(expected)}, "
                      f"got {fmt(got)})"))
            return EXIT_NOMATCH
        print(green(f"  ✓ exported {path}") + dim(f" → {out} ({fmt(got)})"))
        return EXIT_OK

    def put_stream(self, dest, reader, total):
        """PUT an arbitrary stream to *dest* on the remote. Returns status."""
        conn = http.client.HTTPConnection(self.host, self.port, timeout=1800)
        try:
            conn.request("PUT", urllib.parse.quote(dest), body=reader,
                         headers={**self._headers(),
                                  "Content-Length": str(total)})
            r = conn.getresponse()
            r.read()
            return r.status
        finally:
            conn.close()

    def upload(self, local_path, into="/", dest_name=None):
        dest_dir = ("/" + into.strip("/") + "/") if into.strip("/") else "/"
        dest = dest_dir + (dest_name or os.path.basename(local_path))
        quoted = urllib.parse.quote(dest)
        total = os.path.getsize(local_path)
        bar = ProgressBar(os.path.basename(dest), total)
        sent = [0]

        def reader():
            with open(local_path, "rb") as f:
                while True:
                    b = f.read(256 * 1024)
                    if not b:
                        break
                    sent[0] += len(b)
                    bar.update(len(b))
                    yield b

        conn = http.client.HTTPConnection(self.host, self.port, timeout=1800)
        try:
            conn.request("PUT", quoted, body=reader(),
                         headers={**self._headers(),
                                  "Content-Length": str(total)})
            r = conn.getresponse()
            r.read()
            bar.finish()
            if r.status == 201:
                print(green(f"  ✓ sealed on remote: {dest} ({fmt(total)})"))
                self.rows = None          # refresh cache lazily
                return EXIT_OK
            if r.status == 409:
                print(yellow(f"  = already sealed there: {dest}"))
                return EXIT_OK
            print(red(f"  ✗ upload failed: HTTP {r.status}"))
            return EXIT_NOMATCH
        finally:
            conn.close()


def _ensure_rows(rv):
    """Refresh the cached listing lazily (after uploads etc.)."""
    if rv.rows is None:
        rv.rows = rv._fetch("/__api/list")
    return rv.rows


class AuthRequired(Exception):
    pass


class RemoteError(Exception):
    pass


def _friendly_oserror(e, host, port):
    """Translate socket errors into human guidance."""
    n = getattr(e, "errno", None)
    if isinstance(e, TimeoutError) or n == 110:
        return (f"timed out reaching {host}:{port} — firewall silently "
                f"dropping (vault side: ufw allow {port}/tcp), or wrong IP")
    if n == 111:
        return (f"connection refused — smolvault isn't running on "
                f"{host}:{port}")
    if n == 113:
        return (f"no route to {host} — phone and vault are on different "
                f"networks, or the vault's firewall blocks port {port}. "
                f"On the vault machine: ufw allow {port}/tcp")
    if n == 101:
        return "network unreachable — this device has no usable network"
    return str(e)


def discover_vaults(timeout=2.0):
    """Broadcast a discovery probe; return list of (host, port, info)."""
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(0.4)
    targets = [("<broadcast>", DISCOVERY_PORT), ("127.0.0.1", DISCOVERY_PORT)]
    end = time.time() + timeout
    while time.time() < end:
        for t in targets:
            try:
                s.sendto(DISCOVERY_MAGIC, t)
            except OSError:
                pass
        try:
            data, addr = s.recvfrom(2048)
            info = json.loads(data)
            if info.get("proto") == "smolvault":
                key = (addr[0], info["http_port"])
                found[key] = info
        except (socket.timeout, OSError, ValueError):
            pass
    s.close()
    return [(host, port, info) for (host, port), info in sorted(found.items())]


def resolve_target(spec):
    """--connect value -> (host, port). 'auto' triggers discovery."""
    if spec and spec != "auto":
        host, _, port = spec.partition(":")
        return [(host, int(port or 8100), None)]
    env = os.environ.get("SMOLVAULT_SERVER")
    if env:
        host, _, port = env.partition(":")
        return [(host, int(port or 8100), None)]
    print(dim("  searching LAN for smolvaults…"))
    hits = discover_vaults()
    if not hits:
        print(yellow("  no vaults found on the LAN."))
        print(dim("  start one on the other machine, or connect directly:"))
        print(dim("      smolvault.py --connect 192.168.1.14:8100"))
        return []
    if len(hits) == 1:
        return hits
    for i, (host, port, info) in enumerate(hits, 1):
        extra = dim(f"  · {info['files']} files · "
                    f"auth {'yes' if info['auth'] else 'no'}") \
            if info.get("files") is not None else ""
        print(f"    [{i}] {info.get('name', '?')} @ {cyan(host + ':' + str(port))}{extra}")
    raw = input(cyan("  connect to which? [1]: ")).strip() or "1"
    if not raw.isdigit() or not 1 <= int(raw) <= len(hits):
        print(red("  invalid choice"))
        return []
    return [hits[int(raw) - 1]]


def remote_info(rv, q):
    matches = search_rank(ListingStore(rv.rows or []), q)
    exact = _norm(q)
    row = next((r for r in (rv.rows or []) if r["path"] == exact), None)
    if row is None and matches:
        chosen = choose_match(matches[:8], "use which")
        if chosen is None:
            return EXIT_NOMATCH
        row = chosen[1]
    if row is None:
        print(yellow(f"  no match for '{q}'"))
        return EXIT_NOMATCH
    print(f"""  {bold(row['path'])}
    size     : {fmt(row['size'])}
    type     : {row['mime']}
    sealed   : {row['created_at']}
    policy   : WORM on the remote vault""")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Vault sync — additive gap-filling between two smolvault instances
# ---------------------------------------------------------------------------

class _RespReader:
    """Adapts an http response to the .read(n) interface Chunker expects."""

    def __init__(self, resp):
        self.r = resp

    def read(self, n=-1):
        return self.r.read(n if n and n > 0 else 262144)


def sync_vault(store, direction, host, port, assume_yes=False):
    """Mirror *direction* ('to'/'from') between this vault and a peer.
    Additive-only: fills gaps, skips sealed paths, deletes nothing."""
    rv = RemoteVault(host, port)
    try:
        if not rv.authenticate():
            return EXIT_NOMATCH
    except RemoteError as e:
        print(red(f"  ✗ {e}"))
        return EXIT_NOMATCH

    # normalize aliases
    if direction == "pull":
        direction = "from"
    if direction == "push":
        direction = "to"

    mine = {r["path"]: r for r in store.all_files()}
    theirs = {r["path"]: r for r in rv.rows}

    if direction == "to":
        todo = sorted(p for p in mine if p not in theirs)
        sizes = {p: mine[p]["size"] for p in todo}
        arrow = "here ──▶ peer"
    else:
        todo = sorted(p for p in theirs if p not in mine)
        sizes = {p: theirs[p]["size"] for p in todo}
        arrow = "peer ──▶ here"

    total_b = sum(sizes.values())
    print(f"\n  sync plan   {arrow}   ({host}:{port})")
    if not todo:
        print(green("  ✓ already mirrored — nothing to do"))
        return EXIT_OK
    for p in todo[:15]:
        print(f"    {p}  {dim(fmt(sizes[p]))}")
    if len(todo) > 15:
        print(dim(f"    … and {len(todo) - 15} more"))
    print(dim(f"  {len(todo)} file(s) · {fmt(total_b)} · "
              f"additive-only (nothing gets deleted)"))

    if not assume_yes:
        try:
            ans = input(cyan("  proceed? [y/N]: ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans != "y":
            print(yellow("  cancelled"))
            return EXIT_OK

    sent = skipped = failed = 0
    moved = 0
    for path in todo:
        name = os.path.basename(path)
        bar = ProgressBar(name, max(sizes[path], 1))
        try:
            if direction == "from":
                conn = http.client.HTTPConnection(host, port, timeout=600)
                try:
                    conn.request("GET", urllib.parse.quote(path),
                                 headers=rv._headers())
                    resp = conn.getresponse()
                    if resp.status != 200:
                        print(red(f"  ✗ GET {path}: HTTP {resp.status}"))
                        failed += 1
                        continue
                    store.put(path, _RespReader(resp), progress=bar.update)
                finally:
                    conn.close()
            else:
                frow = store.lookup(path)

                def gen(frow=frow, bar=bar):
                    for piece in store.read_full(frow):
                        bar.update(len(piece))
                        yield piece

                st_code = rv.put_stream(path, gen(), sizes[path])
                if st_code == 409:
                    skipped += 1
                    print(yellow(f"  = already sealed there: {path}"))
                    continue
                if st_code != 201:
                    print(red(f"  ✗ PUT {path}: HTTP {st_code}"))
                    failed += 1
                    continue
            bar.finish()
            sent += 1
            moved += sizes[path]
            print(green(f"  ✓ synced {path}") + dim(f"  ({fmt(sizes[path])})"))
        except ExistsError:
            bar.finish()
            skipped += 1
            print(yellow(f"  = already sealed: {path}"))
        except (RemoteError, OSError, ValueError) as e:
            bar.finish()
            failed += 1
            print(red(f"  ✗ {path}: {e}"))

    print(dim(f"  ── {sent} synced · {skipped} skipped · {failed} failed · "
              f"{fmt(moved)} transferred"))
    if sent:
        store.note(f"sync {direction} peer {host}:{port} · "
                   f"{sent} file(s), {fmt(moved)}")
    return EXIT_OK if not failed else EXIT_NOMATCH


def run_client(spec, player=None):
    targets = resolve_target(spec)
    if not targets:
        return EXIT_NOMATCH
    host, port, _info = targets[0]
    rv = RemoteVault(host, port)
    print(bold(f"\n  smolvault client ") +
          dim(f"→ {host}:{port}") +
          dim(f"   (this device: {lan_ip()})\n"))
    try:
        if not rv.authenticate():
            return EXIT_NOMATCH
    except RemoteError as e:
        print(red(f"  ✗ {e}"))
        return EXIT_NOMATCH

    s = {"logical": sum(r["size"] for r in rv.rows), "stored": 0, "files": len(rv.rows)}
    print_banner(f"{host}:{port}", s,
                 (rv.base + "/", "(remote)"), bool(rv.password),
                 "● connected")
    print(CLIENT_MENU)

    last_interrupt = 0.0
    try:
        while True:
            try:
                nfiles = len(rv.rows or [])
                raw = input(f"\n  {dim(f'{rv.host}:{rv.port}')} {dim('·')} "
                            f"{nfiles}f {cyan('❯')} ").strip()
                key = raw[:1] if raw else ""
            except KeyboardInterrupt:
                now = time.time()
                if now - last_interrupt < 2.0:
                    break
                last_interrupt = now
                print(yellow("  cancelled (Ctrl+C again to quit)"))
                continue
            except EOFError:
                break

            if key.lower() in ("q", "quit", "exit"):
                print(dim("  bye 👋"))
                return EXIT_OK
            if not raw or raw in ("h", "?", "help"):
                print(CLIENT_MENU)
                continue
            try:
                if key == "l":
                    rows = rv.rows = rv._fetch("/__api/list")
                    logical = sum(r["size"] for r in rows)
                    render_library(
                        rows, dim(f"  ── {len(rows)} files · "
                                  f"{fmt(logical)} logical"))
                elif key == "d":
                    rows = rv.rows = rv._fetch("/__api/list")
                    show_du(rows)   # remote vault's stored-bytes stay server-side
                elif key == "s":
                    q = input("  search: ").strip()
                    matches = search_rank(ListingStore(_ensure_rows(rv)), q)
                    if not matches:
                        print(yellow("  no matches"))
                        continue
                    show_matches(matches)
                elif key in ("p", "w"):
                    rows = _ensure_rows(rv)
                    chosen = live_search(rows)
                    if not chosen:
                        continue
                    path, rrow = chosen
                    mime = rrow.get("mime") or ""
                    if not mime.startswith(("video/", "audio/", "image/")):
                        print(yellow(f"  '{path}' is {mime} — not watchable. "
                                     f"Use [g]."))
                        continue
                    explicit_pl = player or os.environ.get("SMOLVAULT_PLAYER") \
                        or None
                    if explicit_pl and shutil.which(explicit_pl) is None:
                        print(red(f"  player '{explicit_pl}' not found"))
                        continue

                    def spawn(p, _rv=rv, _pl=explicit_pl):
                        return play_url(_rv.cred_url(p), mime, _pl)

                    watch_flow(spawn, path,
                               [r["path"] for r in rows],
                               explicit_pl or "mpv")
                elif key == "i":
                    q = input("  file (path or term): ").strip()
                    if q:
                        remote_info(rv, q)
                elif key == "g":
                    q = input("  export which (path or term): ").strip()
                    if not q:
                        continue
                    out = input(dim("  save as? [default: same name]")
                                + " ").strip()
                    rows = _ensure_rows(rv)
                    matches = search_rank(ListingStore(rows), q)
                    path = _norm(q)
                    if not any(r["path"] == path for r in rows):
                        if matches:
                            path = matches[0][0]
                        else:
                            print(yellow("  no match")); continue
                    rv.export(path, out or None)
                elif key == "c":
                    q = input("  copy link for (path or term): ").strip()
                    if not q:
                        continue
                    rows = _ensure_rows(rv)
                    path = _norm(q)
                    if not any(r["path"] == path for r in rows):
                        m = search_rank(ListingStore(rows), q)
                        if not m:
                            print(yellow("  no match")); continue
                        path = m[0][0]
                    url = rv.url_for(path)
                    if _clipboard_set(url):
                        print(green(f"  ✓ copied {url}"))
                    else:
                        print(url)
                        print(dim("  (pkg install termux-api + Termux:API app "
                                  "for direct clipboard)"))

                elif key == "a":
                    line = input("  drop files · type a path · [b]rowse:"
                                 "\n  ❯ ").strip()
                    if not line:
                        continue
                    if line.lower() in ("b", "browse"):
                        folder = input(dim("  folder to browse [cwd]: ")
                                       ).strip()
                        folder = os.path.abspath(
                            os.path.expanduser(folder or "."))
                        if not os.path.isdir(folder):
                            print(red(f"  ✗ no such folder: {folder}"))
                            continue
                        picked = browse_picker(folder)
                        if not picked:
                            print(yellow("  (nothing selected)"))
                            continue
                        items = list(picked)
                        suggest = "/" + (
                            os.path.basename(folder.rstrip(os.sep))
                            or "") + "/"
                    else:
                        items, suggest = gather_add_selections(
                            shlex.split(line),
                            lambda p: input(p).strip(), interactive=True)
                    if not items:
                        continue
                    into = input(dim(f"  into folder? [{suggest}]") + " ") \
                        .strip() or suggest
                    if not ingest_plan_ok(items, into,
                                          lambda p: input(p).strip()):
                        print(yellow("  cancelled"))
                        continue
                    for p, dn in items:
                        rv.upload(p, into, dest_name=dn)
                    print(dim("  (p watch · l library)"))
                elif key == "m":
                    def bfetch(after):
                        return rv._fetch(f"/__api/msg?since={after}&limit=500")

                    def bsend(text):
                        conn = http.client.HTTPConnection(
                            rv.host, rv.port, timeout=15)
                        try:
                            conn.request(
                                "POST", "/__api/msg",
                                body=json.dumps({"body": text}),
                                headers={**rv._headers(),
                                         "Content-Type": "application/json",
                                         "X-Smv-Name": _node_name()})
                            r = conn.getresponse(); r.read()
                            return r.status
                        finally:
                            conn.close()

                    board_prompt(fetch=bfetch, send=bsend)
                elif key == "r":
                    newt = resolve_target("auto")
                    if not newt:
                        print(yellow("  no other vaults found"))
                    else:
                        nh, np_, _i = newt[0]
                        rv2 = RemoteVault(nh, np_)
                        if rv2.authenticate():
                            rv.host, rv.port, rv.password = nh, np_, rv2.password
                            rv.rows = rv2.rows
                            print(green(f"  ● now connected to {nh}:{np_}"))
                        else:
                            print(red("  ✗ could not authenticate to target"))
                else:
                    print(red(f"  unknown key '{key}' — "
                              f"keys: a c d g i l m p r s w · h menu · q quit"))
            except KeyboardInterrupt:
                now = time.time()
                if now - last_interrupt < 2.0:
                    break
                last_interrupt = now
                print(yellow("  cancelled (Ctrl+C again to quit)"))
            except RemoteError as e:
                print(red(f"  ✗ {e}"))
    except QuitWizard:
        print(dim("\n  bye 👋"))
        return EXIT_OK
    return EXIT_OK


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(
        prog="smolvault",
        description="an immutable vault for everything — wizard-first, "
                    "media front-row (see docstring)")
    ap.add_argument("vault", nargs="?", default=None,
                    help="vault file (default: $SMOLVAULT_VAULT or wizard)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="serve-mode bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=None,
                    help="port (default 8100, remembered per-vault)")
    ap.add_argument("-p", "--password", default="")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--check", action="store_true", help="verify chunks, exit")
    ap.add_argument("--auth", choices=["on", "off"], metavar="on|off",
                    help="require the vault password for network access "
                         "(independent of encryption; default on)")
    ap.add_argument("--encrypt", action="store_true",
                    help="encrypt the whole vault at rest (AES-256-GCM), exit")
    ap.add_argument("--decrypt", action="store_true",
                    help="remove at-rest encryption, exit")
    ap.add_argument("--gc", action="store_true", help="collect garbage, exit")
    ap.add_argument("--serve", action="store_true",
                    help="run the plain HTTP server (skip the wizard)")
    ap.add_argument("-i", "--wizard", action="store_true",
                    help="force the interactive wizard (even with a vault)")
    ap.add_argument("--name", help="node name on the message board (default: hostname or $SMOLVAULT_NAME)")
    ap.add_argument("--no-discover", action="store_true",
                    help="do not answer LAN discovery probes")

    cx = ap.add_argument_group("remote client")
    cx.add_argument("--connect", nargs="?", const="auto", default=None,
                    metavar="HOST[:PORT]",
                    help="act as a client: connect to a remote smolvault "
                         "(no argument = discover on LAN; "
                         "or $SMOLVAULT_SERVER)")

    mg = ap.add_argument_group("media manager")
    mg.add_argument("--add", nargs="+", metavar="PATH",
                    help="seal local file(s)/folder(s) into the vault "
                         "(folders walk recursively, keeping structure)")
    mg.add_argument("--into", default="/", help="destination folder for --add")
    mg.add_argument("--list", action="store_true", help="print library table")
    mg.add_argument("--du", action="store_true",
                    help="space by folder + byte-identical duplicate report")
    mg.add_argument("--search", metavar="Q", help="search the library")
    mg.add_argument("--play", metavar="Q", help="search + play in mpv")
    mg.add_argument("--player", help="player binary (default mpv)")
    mg.add_argument("--sync-to", metavar="HOST[:PORT]",
                    help="push this vault's files to a peer smolvault")
    mg.add_argument("--sync-from", metavar="HOST[:PORT]",
                    help="pull a peer's files into this vault")
    mg.add_argument("--info", metavar="PATH_OR_Q", help="file details")
    mg.add_argument("--get", metavar="PATH_OR_Q", help="export a file")
    mg.add_argument("-o", "--out", help="output filename for --get")
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    global NODE_NAME
    NODE_NAME = args.name
    setup_logging(args.verbose)
    if os.environ.get("SMOLVAULT_DEBUG"):
        _enable_debug_signal_dump()

    # maintenance short-circuits
    if args.check or args.gc:
        if not args.vault:
            ap.error("vault required for --check/--gc")
        store = Store(args.vault)
        if args.check:
            return EXIT_OK if store.check() else EXIT_NOMATCH
        store.gc()
        return EXIT_OK

    # ---- network-auth gate toggle --------------------------------------
    if getattr(args, "auth", None):
        if not args.vault:
            ap.error("vault required for --auth")
        st_ = Store(args.vault)
        st_.set_auth_required(args.auth == "on")
        print(green(f"  ✓ network auth {'required' if args.auth == 'on' else 'disabled'}"
                    + (" (files stay encrypted at rest)"
                       if st_.enc_enabled() else "")))
        return EXIT_OK

    # ---- at-rest encryption -------------------------------------------
    if args.encrypt or args.decrypt:
        if not args.vault:
            ap.error("vault required for --encrypt/--decrypt")
        store = Store(args.vault)

        def ask_pw(prompt):
            return args.password or getpass.getpass(dim(prompt)).strip()

        try:
            if args.encrypt:
                if store.has_password():
                    cur = ask_pw("current password: ")
                    if not store.check_password(cur):
                        print(red("incorrect password"))
                        return EXIT_NOMATCH
                else:
                    if not sys.stdin.isatty() and not args.password:
                        ap.error("--encrypt needs -p/--password or a terminal")
                    cur = ask_pw("set vault password: ")
                    pw2 = (args.password if args.password else
                           getpass.getpass(dim("confirm: ")).strip())
                    if not cur or cur != pw2:
                        print(red("passwords empty or mismatch"))
                        return EXIT_NOMATCH
                    store.set_password(cur)
                store.enable_encryption(cur)
            else:
                pw = ask_pw("vault password: ")
                store.unlock(pw)
        except ValueError as e:
            print(red(str(e)))
            return EXIT_NOMATCH
        except CryptoUnavailable as e:
            print(red(str(e)))
            return EXIT_NOMATCH

        verb = "encrypting" if args.encrypt else "decrypting"
        _like = ("<>", "LIKE") if args.encrypt else ("=", "NOT")
        n_all = store.conn().execute(
            "SELECT COUNT(*) FROM chunks WHERE "
            "substr(hex(data),1,10) "
            f"{'<>' if args.encrypt else '='} '5356454E01'"
        ).fetchone()[0]
        bar = ProgressBar("chunks", max(n_all, 1))

        def prog(done, total):
            bar.done = done; bar.total = max(total, 1); bar.update(0)

        try:
            if args.decrypt:
                c_ = store.conn()
                rows = c_.execute(
                    "SELECT hash, data FROM chunks WHERE "
                    "substr(hex(data),1,10)='5356454E01'").fetchall()
                done = 0
                for h, data in rows:
                    plain = store._open(data, h)
                    c_.execute("UPDATE chunks SET data=? WHERE hash=?",
                               (plain, h))
                    done += 1
                    bar.done = done; bar.update(0)
                    if done % 100 == 0:
                        c_.commit()
                c_.commit()
                store.disable_encryption(args.password)
            else:
                store.migrate_encryption(progress=prog)
            bar.finish()
            print(green(f"  ✓ vault {'encrypted' if args.encrypt else 'decrypted'}"
                        f" · {n_all} chunk(s) rewritten"))
            return EXIT_OK
        except LockedVault as e:
            print(red(f"  ✗ {e}"))
            return EXIT_NOMATCH

    # ---- client mode (no local vault needed) ------------------------------
    if args.connect is not None:
        return run_client(args.connect, args.player)

    vault, created = bootstrap_vault(args.vault)
    store = Store(vault)
    if created:
        print(green(f"  ✓ created {vault}"))

    if args.password:
        if not store.has_password():
            store.set_password(args.password)
            log.info("password set")
        elif not store.check_password(args.password):
            print(red("incorrect password"))
            return EXIT_NOMATCH

    action_flags = any([args.add, args.list, args.du, args.search,
                        args.play, args.info, args.get])
    interactive_wizard = (
        not args.serve and sys.stdin.isatty() and not action_flags
        and (args.wizard or (
            args.vault is None and not args.password)))

    # ---- encrypted vault: unlock once, everything downstream works -------
    if store.enc_enabled() and not store.is_unlocked() \
            and not interactive_wizard:
        if not sys.stdin.isatty() and not args.password:
            print(red("vault is encrypted — provide -p/--password"))
            return EXIT_NOMATCH
        unlocked = False
        for _ in range(3):
            pw_try = args.password or getpass.getpass(
                dim("  vault password: ")).strip()
            if not pw_try:
                return EXIT_NOMATCH
            try:
                store.unlock(pw_try)
                args.password = pw_try      # players may embed it
                unlocked = True
                break
            except ValueError:
                print(red("  ✗ incorrect password"))
                if args.password:
                    break
        if not unlocked:
            return EXIT_NOMATCH

    # ---- vault sync -------------------------------------------------------
    if args.sync_to or args.sync_from:
        targets = resolve_target(args.sync_to or args.sync_from)
        if not targets:
            return EXIT_NOMATCH
        h, p_, _i = targets[0]
        return sync_vault(store, d := ("to" if args.sync_to else "from"),
                          h, int(p_), assume_yes=True)

    # ---- flag mode ------------------------------------------------------
    if args.add:
        return add_files(store, args.add, args.into)
    if args.list:
        return list_library(store)
    if args.du:
        return show_du(store.all_files(), store.stats())
    if args.search:
        matches = search_rank(store, args.search)
        if not matches:
            print(yellow(f"no matches for '{args.search}'"))
            return EXIT_NOMATCH
        show_matches(matches)
        return EXIT_OK
    if args.play:
        return play_query(store, args.play, args.player,
                          password=args.password or None)
    if args.info:
        return show_info(store, args.info)
    if args.get:
        return export_file(store, args.get, args.out)

    # ---- wizard vs plain serve -------------------------------------------
    if interactive_wizard:
        return Wizard(store, vault,
                          no_discover=args.no_discover,
                          player=args.player).run()

    # plain serve mode (scripts / piped stdin)
    if store.enc_enabled() and not store.is_unlocked():
        if not args.password:
            print(red("vault is encrypted — provide -p/--password to unlock"))
            return EXIT_NOMATCH
        try:
            store.unlock(args.password)
            log.info("vault unlocked")
        except ValueError:
            print(red("incorrect password"))
            return EXIT_NOMATCH
    port = args.port or int(store.cfg_get("lan_port") or 8100)
    try:
        srv = make_server(store, args.host, port)
    except OSError as e:
        alt = find_free_port(port + 1)
        hint = f"try: --port {alt}" if alt else "no free port found"
        print(red(f"cannot bind {args.host}:{port} ({e}) — {hint}"))
        return EXIT_NOMATCH
    if args.host != "127.0.0.1":
        store.cfg_set("lan_port", port)
    discovery = None
    if not args.no_discover and args.host != "127.0.0.1":
        name = os.path.basename(vault).replace(".vault", "")
        discovery = DiscoveryResponder(name, port, store.has_password(),
                                       files=store.stats()["files"])
        discovery.start()
    s = store.stats()
    print_banner(vault, s,
                 (f"http://127.0.0.1:{port}/", f"http://{lan_ip()}:{port}/"),
                 store.has_password(),
                 enc_on=store.enc_enabled(),
                 auth_required=store.auth_required())
    print(dim("\n  Ctrl+C to stop.\n"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(dim("\n  bye"))
    finally:
        srv.server_close()
        if discovery:
            discovery.stop()
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(dim("\n  bye"))
        sys.exit(EXIT_OK)
