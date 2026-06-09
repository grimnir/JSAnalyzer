# -*- coding: utf-8 -*-
"""Tests for discovery_logic pure helpers (CPython3, no burp/java)."""
import unittest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestSanitize(unittest.TestCase):
    """_sanitize(lines) spec §3.3:
    strip blanks/#comments, cut at ?,#,|, ensure single leading /, dedup,
    preserve order.
    """

    def setUp(self):
        from discovery_logic import _sanitize
        self._sanitize = _sanitize

    # --- blank / comment stripping ---

    def test_empty_list_returns_empty(self):
        self.assertEqual(self._sanitize([]), [])

    def test_blank_lines_removed(self):
        self.assertEqual(self._sanitize(['', '   ', '\t']), [])

    def test_comment_lines_removed(self):
        self.assertEqual(self._sanitize(['# comment', '  # indented']), [])

    def test_inline_comment_not_treated_as_comment(self):
        result = self._sanitize(['/api/v1  # note'])
        self.assertEqual(result, ['/api/v1'])

    # --- query / fragment / pipe cutting ---

    def test_question_mark_cut(self):
        result = self._sanitize(['/api/v1/users?format=json'])
        self.assertEqual(result, ['/api/v1/users'])

    def test_hash_cut(self):
        result = self._sanitize(['/api/v1/users#section'])
        self.assertEqual(result, ['/api/v1/users'])

    def test_pipe_cut(self):
        result = self._sanitize(['/api/v1/users|extra'])
        self.assertEqual(result, ['/api/v1/users'])

    def test_multiple_separators_cuts_at_first(self):
        result = self._sanitize(['/api/v1?foo=1#bar|baz'])
        self.assertEqual(result, ['/api/v1'])

    # --- leading slash enforcement ---

    def test_no_leading_slash_gets_one(self):
        result = self._sanitize(['api/v1/users'])
        self.assertEqual(result, ['/api/v1/users'])

    def test_already_has_slash_unchanged(self):
        result = self._sanitize(['/api/v1/users'])
        self.assertEqual(result, ['/api/v1/users'])

    def test_double_slash_collapsed_to_single(self):
        result = self._sanitize(['//api/v1/users'])
        self.assertEqual(result, ['/api/v1/users'])

    # --- dedup ---

    def test_dedup_removes_second_occurrence(self):
        result = self._sanitize(['/api/v1', '/api/v1'])
        self.assertEqual(result, ['/api/v1'])

    def test_dedup_preserves_order(self):
        result = self._sanitize(['/b', '/a', '/b', '/c', '/a'])
        self.assertEqual(result, ['/b', '/a', '/c'])

    def test_dedup_considers_normalized_path(self):
        result = self._sanitize(['/api/v1', 'api/v1'])
        self.assertEqual(result, ['/api/v1'])

    # --- combined ---

    def test_full_pipeline(self):
        lines = [
            '# header',
            '',
            'api/v1/users?foo=1',
            '/api/v1/users',   # duplicate after normalisation
            '  /admin/panel  ',
            '/api/v1/delete#anchor',
        ]
        result = self._sanitize(lines)
        self.assertEqual(result, ['/api/v1/users', '/admin/panel', '/api/v1/delete'])

    def test_after_cut_becomes_empty_string_excluded(self):
        result = self._sanitize(['?only-query'])
        self.assertEqual(result, [])

    def test_whitespace_stripped_from_path(self):
        result = self._sanitize(['  /api/v1/users  '])
        self.assertEqual(result, ['/api/v1/users'])

    def test_sanitize_preserves_literal_braces(self):
        # G3 / decision #6: wordlist containing {id} is passed through as-is
        out = self._sanitize(['api/v1/users/{id}'])
        self.assertEqual(out, ['/api/v1/users/{id}'])


if __name__ == '__main__':
    unittest.main()
