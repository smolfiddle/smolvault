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
        self.assertEqual([(n, d) for n, d, s, a in st.entries()],
                         [("books", True), ("movies", True)])

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
        open(os.path.join(self.videos, "a.mkv"), "wb").write(b"a")
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
        picked = sv.browse_picker(self.videos)
        self.assertIsNone(picked)


if __name__ == "__main__":
    unittest.main()
