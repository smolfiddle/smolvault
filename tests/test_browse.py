"""Browse navigator tests — BrowseState logic, wiring, fallback.

Run: python -m unittest tests.test_browse -v
"""
import os
import shutil
import tempfile
import io
import unittest
from unittest import mock

import smolvault as sv


class BrowseTestBase(unittest.TestCase):
    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="svbrowse_")
        self.videos = os.path.join(self.W, "Videos")
        os.makedirs(os.path.join(self.videos, "movies", "s01"))
        os.makedirs(os.path.join(self.videos, "books"))
        for f in ["movies/big.mkv", "movies/s01/e01.mkv",
                  "movies/s01/e02.mkv", "movies/poster.jpg",
                  "books/a.pdf", "books/b.epub"]:
            p = os.path.join(self.videos, *f.split("/"))
            with open(p, "wb") as fh:
                fh.write(b"x" * 100)
        with open(os.path.join(self.W, ".hidden"), "wb") as fh:
            fh.write(b"h")
    def tearDown(self):
        shutil.rmtree(self.W, ignore_errors=True)


class TestBrowseState(BrowseTestBase):
    def test_root_listing_dirs_first_hidden_skipped(self):
        st = sv.BrowseState(self.W, anchor=self.videos)
        self.assertEqual([(n, d) for n, d, s, a, r in st.entries()],
                         [("books", True), ("movies", True)])
        self.assertTrue(all(r is None for *_, r in st.entries()),
                        "a filesystem scan has no backing row")

    def test_start_at_anchor(self):
        st = sv.BrowseState(self.W, anchor=self.videos)
        self.assertEqual(os.path.abspath(st.cur), self.videos)

    def test_filter(self):
        st = sv.BrowseState(self.W, anchor=self.videos)
        st.query = "e"
        self.assertEqual({n for n, *_ in st.entries()},
                         {"movies"})

    def test_parent_climbs_to_ceiling_and_stops(self):
        st = sv.BrowseState(self.W, anchor=self.videos)
        st.parent()
        self.assertEqual(os.path.abspath(st.cur), self.W)
        st.parent()
        self.assertEqual(os.path.abspath(st.cur), self.W)

    def test_descend_toggle_persist_across_nav(self):
        st = sv.BrowseState(self.W, anchor=self.videos)
        st.parent(); st.parent()
        st.descend()                      # W -> Videos
        st.sel = 1; st.descend()          # Videos -> movies
        st.descend()                      # movies -> s01
        st.toggle()                       # e01 (first entry)
        self.assertIn(os.path.join(self.videos, "movies", "s01", "e01.mkv"),
                      st.checked)
        st.parent(); st.parent()          # navigate away & back
        self.assertIn(os.path.join(self.videos, "movies", "s01", "e01.mkv"),
                      st.checked)

    def test_subtree_cycle_partial_full_none(self):
        st = sv.BrowseState(self.W, anchor=self.videos)
        m = os.path.join(self.videos, "movies")
        st.toggle_subtree(m)                        # empty -> full
        self.assertEqual(st.dir_marker(m), (4, 4))
        st.checked.discard(os.path.join(m, "poster.jpg"))
        self.assertEqual(st.dir_marker(m), (3, 4))  # partial
        st.toggle_subtree(m)                        # partial -> full
        self.assertEqual(st.dir_marker(m), (4, 4))
        st.toggle_subtree(m)                        # full -> none
        self.assertEqual(st.dir_marker(m), (0, 4))

    def test_select_visible_includes_subtrees(self):
        st = sv.BrowseState(self.W, anchor=self.videos)
        st.cur = os.path.join(self.videos, "books")
        st.select_visible()
        self.assertEqual({os.path.join(self.videos, "books", "a.pdf"),
                          os.path.join(self.videos, "books", "b.epub")},
                         st.checked)

    def test_confirm_items_anchor_relative_natural_order(self):
        st = sv.BrowseState(self.W, anchor=self.videos)
        st.checked |= {
            os.path.join(self.videos, "books", "a.pdf"),
            os.path.join(self.videos, "movies", "big.mkv"),
            os.path.join(self.videos, "movies", "s01", "e01.mkv"),
            os.path.join(self.videos, "movies", "s01", "e02.mkv"),
        }
        items = st.confirm_items()
        rels = [r for _, r in items]
        self.assertEqual(rels, sorted(rels, key=sv.natural_key))
        self.assertEqual(set(rels),
                         {"books/a.pdf", "movies/big.mkv",
                          "movies/s01/e01.mkv", "movies/s01/e02.mkv"})
        for abs_p, _ in items:
            self.assertTrue(os.path.isfile(abs_p))

    def test_outside_anchor_collapses_to_basename(self):
        st = sv.BrowseState(self.W, anchor=self.videos)
        outside = os.path.join(self.W, ".hidden")
        st.checked.add(outside)
        items = st.confirm_items()
        self.assertEqual([r for _, r in items], [".hidden"])


class TestWiring(BrowseTestBase):
    def test_wizard_b_flow_seals_picked(self):
        import builtins
        store = sv.Store(os.path.join(self.W, "t.vault"))
        fixed = [(os.path.join(self.videos, "a.mkv"), "a.mkv")]
        with open(os.path.join(self.videos, "a.mkv"), "wb") as fh:
            fh.write(b"a")
        answers = iter(["b", "/Videos"])
        with mock.patch.object(sv, "browse_picker", return_value=list(fixed)), \
             mock.patch.object(builtins, "input", lambda p="": next(answers)):
            w = sv.Wizard(store, "t.vault", no_discover=True)
            w.srv = None; w.port = None
            buf = io.StringIO()
            from contextlib import redirect_stdout
            with redirect_stdout(buf):
                w.do_add()
        paths = {r["path"] for r in store.all_files()}
        self.assertIn("/Videos/a.mkv", paths)

    def test_browse_picker_cancel_returns_none(self):
        # non-TTY: multi_pick falls back to input() -> EOF -> None
        import builtins
        with mock.patch.object(builtins, "input",
                               lambda p="": (_ for _ in ()).throw(EOFError)):
            picked = sv.browse_picker(self.videos)
        self.assertIsNone(picked)


class TestFrameProtocol(BrowseTestBase):
    def _frame(self, st):
        return sv._browse_render(st)

    def _grow(self, prefix, n=30):
        for i in range(n):
            with open(os.path.join(self.W, f"{prefix}{i:02}.txt"), "wb") as fh:
                fh.write(b"x")

    def test_clear_below_on_first_line(self):
        st = sv.BrowseState(self.W, anchor=self.W)
        f = self._frame(st)
        self.assertTrue(f.split("\n")[0].startswith("\x1b[J"))

    def test_all_lines_carriage_return_led(self):
        self._grow("f")
        st = sv.BrowseState(self.W, anchor=self.W)
        f = self._frame(st)
        for i, l in enumerate(f.split("\n")):
            self.assertTrue(l.startswith("\r") or l.startswith("\x1b[J"),
                            f"line {i} not CR-led: {l[:12]!r}")

    def test_constant_frame_height(self):
        st = sv.BrowseState(self.W, anchor=self.W)
        h1 = len(self._frame(st).split("\n"))
        self._grow("g")
        st = sv.BrowseState(self.W, anchor=self.W)
        h2 = len(self._frame(st).split("\n"))
        self.assertEqual(h1, h2)

    def test_single_footer_no_stale_lines(self):
        st = sv.BrowseState(self.W, anchor=self.W)
        f1 = self._frame(st)
        self._grow("h")
        st = sv.BrowseState(self.W, anchor=self.W)
        f2 = self._frame(st)
        for frame in (f1, f2):
            self.assertEqual(
                sum(1 for l in frame.split("\n") if "↑↓ move" in l), 1)


class TestParseEscape(unittest.TestCase):
    def test_arrows_both_encodings(self):
        for seq, want in [("\x1b[A", "up"), ("\x1bOA", "up"),
                          ("\x1b[B", "down"), ("\x1bOB", "down"),
                          ("\x1b[C", "right"), ("\x1bOC", "right"),
                          ("\x1b[D", "left"), ("\x1bOD", "left")]:
            self.assertEqual(sv._parse_escape(seq), want, seq)

    def test_modified_arrows(self):
        self.assertEqual(sv._parse_escape("\x1b[1;5C"), "right")
        self.assertEqual(sv._parse_escape("\x1b[1;2A"), "up")

    def test_bare_esc_and_unknown(self):
        self.assertEqual(sv._parse_escape("\x1b"), "esc")
        self.assertEqual(sv._parse_escape("\x1b[999~"), "ignore")
        self.assertEqual(sv._parse_escape("\x1b[Z"), "shifttab")

    def test_no_bracket_leak(self):
        for seq in ("\x1b[C", "\x1bOC", "\x1b[1;5C", "\x1b[Z", "\x1b[999~"):
            self.assertNotIn("[", sv._parse_escape(seq))


class TestFilterKeymap(BrowseTestBase):
    """Regression: a/u/s used to be bound as bare action keys *before* the
    printable branch, so those three letters could never reach the filter --
    typing 'usa' wiped the selection, selected everything, and sealed."""

    def _drive(self, st, keys, picker=sv.browse_picker):
        """Replay a key script through a picker's loop without a terminal."""
        for k in keys:
            if k in ("up",):
                st.sel = max(0, st.sel - 1)
            elif k in ("down",):
                st.sel = min(max(len(st.entries()) - 1, 0), st.sel + 1)
            elif k in ("right",):
                st.descend()
            elif k in ("left",):
                st.parent()
            elif k == " ":
                st.toggle()
            elif k in ("\x7f", "\b"):
                if st.query:
                    st.query = st.query[:-1]
                    st.sel = 0
                else:
                    st.parent()
            elif k == sv.BROWSE_CMD:
                st._cmd = True          # next key is a command
            elif getattr(st, "_cmd", False):
                st._cmd = False
                if k == "a":
                    st.select_visible()
                elif k == "u":
                    st.clear()
                elif k == "s":
                    return st.confirm_items()
            elif len(k) == 1 and k >= " ":
                st.query += k
                st.sel = 0
        return None

    def test_every_letter_reaches_the_filter(self):
        st = sv.BrowseState(self.W, anchor=self.W)
        self._drive(st, list("aus"))
        self.assertEqual(st.query, "aus",
                         "a/u/s must be typable in the filter")

    def test_words_with_a_u_s_are_filterable(self):
        for word in ["usa", "sunset", "anna", "sa", "a", "u", "s"]:
            st = sv.BrowseState(self.W, anchor=self.W)
            self._drive(st, list(word))
            self.assertEqual(st.query, word, word)

    def test_colon_does_not_leak_into_the_filter(self):
        st = sv.BrowseState(self.W, anchor=self.W)
        self._drive(st, list("ab"))
        self._drive(st, [sv.BROWSE_CMD])
        self._drive(st, list("s"))
        self.assertEqual(st.query, "ab",
                         "a command prefix must not become filter text")

    def test_u_command_clears_selection_only_via_the_prefix(self):
        st = sv.BrowseState(self.W, anchor=self.W)
        st.checked |= {os.path.join(self.W, ".hidden")}
        self._drive(st, list("u"))
        self.assertEqual(len(st.checked), 1,
                         "bare 'u' must not wipe the selection")
        self._drive(st, [sv.BROWSE_CMD, "u"])
        self.assertEqual(len(st.checked), 0)


class TestVaultBrowseState(BrowseTestBase):
    """#38: VaultBrowseState claimed to reuse BrowseState's keymap. It now
    actually does, and carries the row through _scan so rendering is O(1)
    per visible row instead of a linear rescan."""

    def setUp(self):
        super().setUp()
        self.store = sv.Store(os.path.join(self.W, "v.vault"))
        for p in ["/top.txt", "/zz.mkv", "/a/one.mkv", "/a/b/two.mkv",
                  "/a/c/three.mkv", "/d/four.mkv"]:
            self.store.put(p, io.BytesIO(b"y" * 50))

    def test_is_a_browsestate(self):
        self.assertTrue(issubclass(sv.VaultBrowseState, sv.BrowseState))

    def test_root_lists_dirs_and_files(self):
        st = sv.VaultBrowseState(self.store)
        self.assertEqual([(n, d) for n, d, *_ in st.entries()],
                         [("a", True), ("d", True), ("top.txt", False),
                          ("zz.mkv", False)])

    def test_navigation_ceiling(self):
        st = sv.VaultBrowseState(self.store)
        st.cur = "/a"
        st.parent()
        st.parent()
        self.assertEqual(st.cur, "/")

    def test_rows_are_carried_in_entries(self):
        st = sv.VaultBrowseState(self.store)
        entries = st.entries()
        self.assertTrue(all(len(e) == 5 for e in entries),
                        "entries must be (name, is_dir, size, abspath, row)")
        for e in entries:
            if not e[1]:
                self.assertIsNotNone(e[4], "file entries carry their row")
                self.assertEqual(e[3], e[4]["path"])

    def test_file_row_matches_the_carried_row(self):
        st = sv.VaultBrowseState(self.store)
        for name, is_dir, size, abspath, row in st.entries():
            if not is_dir:
                self.assertIs(st.file_row(abspath), row)

    def test_scan_is_memoised(self):
        st = sv.VaultBrowseState(self.store)
        st.entries()
        self.assertIsNotNone(getattr(st, "_scan_cache", None),
                             "_scan must memoise on (cur, query)")
        st.entries()
        self.assertEqual(st.entries(), st.entries())

    def test_invalidation_on_navigate_and_filter(self):
        st = sv.VaultBrowseState(self.store)
        before = st.entries()
        st.sel = 1                       # "d"
        st.descend()
        self.assertNotEqual(st.entries(), before)
        st.sel = 0
        st.parent()
        st.query = "top"
        self.assertEqual([n for n, *_ in st.entries()], ["top.txt"])

    def test_select_visible_and_confirm_items(self):
        st = sv.VaultBrowseState(self.store)
        st.cur = "/a"
        st.select_visible()
        items = st.confirm_items()
        # relpaths are anchor-relative, and the anchor is the vault root
        self.assertEqual([rel for _, rel in items],
                         ["a/b/two.mkv", "a/c/three.mkv", "a/one.mkv"])
        self.assertEqual([vp for vp, _ in items],
                         ["/a/b/two.mkv", "/a/c/three.mkv", "/a/one.mkv"])

    def test_subtree_toggle_and_marker(self):
        st = sv.VaultBrowseState(self.store)
        st.toggle_subtree("/a")
        self.assertEqual(st.dir_marker("/a"), (3, 3))
        st.checked.discard("/a/one.mkv")
        self.assertEqual(st.dir_marker("/a"), (2, 3))
        st.toggle_subtree("/a")
        self.assertEqual(st.dir_marker("/a"), (3, 3))
        st.toggle_subtree("/a")
        self.assertEqual(st.dir_marker("/a"), (0, 3))

    def test_clear(self):
        st = sv.VaultBrowseState(self.store)
        st.toggle_subtree("/a")
        self.assertTrue(st.checked)
        st.clear()
        self.assertEqual(st.checked, set())


class TestBoardLive(BrowseTestBase):
    def test_live_poll_and_post(self):
        import builtins
        store = sv.Store(os.path.join(self.W, "b.vault"))
        store.post_msg("alice", "user", "first message")

        # scripted keys: type "hi", Enter (posts), then Esc repeats -> exit
        import itertools
        keys = itertools.chain(list("hi") + ["\r"],
                               itertools.repeat("\x1b"))
        with mock.patch.object(builtins, "input", lambda p="": (_ for _ in ()).throw(
                AssertionError("fallback must not run"))):
            buf = io.StringIO()
            from contextlib import redirect_stdout
            with redirect_stdout(buf):
                rc = sv.board_live(store=store, poll=60,
                                   read_key=lambda: next(keys),
                                   assume_tty=True)

        self.assertEqual(rc, sv.EXIT_OK)
        msgs = [m["body"] for m in store.msgs_since(0)]
        self.assertIn("first message", msgs)
        self.assertIn("hi", msgs)          # posted from the live editor

    def test_fallback_on_non_tty(self):
        # non-TTY: board_live delegates to the refresh loop (EOF exits)
        import builtins
        real = builtins.input
        builtins.input = lambda p="": (_ for _ in ()).throw(EOFError)
        try:
            rc = sv.board_live(store=None, fetch=lambda a: {"messages": []},
                               send=lambda t: 201)
        finally:
            builtins.input = real
        self.assertEqual(rc, sv.EXIT_OK)


if __name__ == "__main__":
    unittest.main()
