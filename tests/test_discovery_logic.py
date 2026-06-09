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


class TestIsDestructive(unittest.TestCase):
    """is_destructive(path) — §3.2"""

    def setUp(self):
        from discovery_logic import is_destructive
        self._fn = is_destructive

    # paths that MUST be skipped
    def test_delete_exact(self):
        self.assertTrue(self._fn('/delete'))

    def test_del_segment(self):
        self.assertTrue(self._fn('/api/v1/del'))

    def test_delete_as_prefix_segment(self):
        self.assertTrue(self._fn('/api/v1/delete/resource'))

    def test_remove_segment(self):
        self.assertTrue(self._fn('/users/remove'))

    def test_destroy_segment(self):
        self.assertTrue(self._fn('/destroy'))

    def test_drop_segment(self):
        self.assertTrue(self._fn('/admin/drop'))

    def test_deactivate(self):
        self.assertTrue(self._fn('/account/deactivate'))

    def test_disable(self):
        self.assertTrue(self._fn('/feature/disable'))

    def test_revoke(self):
        self.assertTrue(self._fn('/token/revoke'))

    def test_purge(self):
        self.assertTrue(self._fn('/cache/purge'))

    def test_wipe(self):
        self.assertTrue(self._fn('/data/wipe'))

    def test_reset(self):
        self.assertTrue(self._fn('/password/reset'))

    def test_logout(self):
        self.assertTrue(self._fn('/logout'))

    def test_signout(self):
        self.assertTrue(self._fn('/signout'))

    def test_signoff(self):
        self.assertTrue(self._fn('/signoff'))

    def test_terminate(self):
        self.assertTrue(self._fn('/session/terminate'))

    def test_cancel(self):
        self.assertTrue(self._fn('/order/cancel'))

    def test_expire(self):
        self.assertTrue(self._fn('/token/expire'))

    def test_kill(self):
        self.assertTrue(self._fn('/process/kill'))

    def test_unsubscribe(self):
        self.assertTrue(self._fn('/unsubscribe'))

    def test_case_insensitive(self):
        self.assertTrue(self._fn('/api/DELETE/resource'))

    # paths that MUST be kept
    def test_benign_users(self):
        self.assertFalse(self._fn('/api/v1/users'))

    def test_benign_admin(self):
        self.assertFalse(self._fn('/admin/dashboard'))

    def test_benign_model(self):
        self.assertFalse(self._fn('/api/v1/models'))

    def test_benign_resets_not_matching(self):
        # 'resets' contains 'reset' as substring but regex requires word boundary
        self.assertFalse(self._fn('/api/v1/resets'))

    def test_benign_deltas(self):
        # 'deltas' starts with 'del' but not followed by boundary char
        self.assertFalse(self._fn('/api/v1/deltas'))


class TestIsInteresting(unittest.TestCase):
    """is_interesting(status, has_location) — §3.6"""

    def setUp(self):
        from discovery_logic import is_interesting
        self._fn = is_interesting

    def test_200(self):
        self.assertTrue(self._fn(200))

    def test_201(self):
        self.assertTrue(self._fn(201))

    def test_204(self):
        self.assertTrue(self._fn(204))

    def test_401(self):
        self.assertTrue(self._fn(401))

    def test_403(self):
        self.assertTrue(self._fn(403))

    def test_405(self):
        self.assertTrue(self._fn(405))

    def test_500(self):
        self.assertTrue(self._fn(500))

    def test_502(self):
        self.assertTrue(self._fn(502))

    def test_503(self):
        self.assertTrue(self._fn(503))

    def test_301_with_location(self):
        self.assertTrue(self._fn(301, has_location=True))

    def test_302_with_location(self):
        self.assertTrue(self._fn(302, has_location=True))

    def test_307_with_location(self):
        self.assertTrue(self._fn(307, has_location=True))

    def test_308_with_location(self):
        self.assertTrue(self._fn(308, has_location=True))

    def test_301_without_location_dropped(self):
        self.assertFalse(self._fn(301, has_location=False))

    def test_302_without_location_dropped(self):
        self.assertFalse(self._fn(302))

    def test_404_dropped(self):
        self.assertFalse(self._fn(404))

    def test_400_dropped(self):
        self.assertFalse(self._fn(400))

    def test_429_dropped(self):
        self.assertFalse(self._fn(429))

    def test_200_default_no_location_arg(self):
        self.assertTrue(self._fn(200))


class TestSoft404Fingerprint(unittest.TestCase):
    """soft404_fingerprint(status, body_len, body) — §3.5"""

    def setUp(self):
        from discovery_logic import soft404_fingerprint
        self._fn = soft404_fingerprint

    def test_len_bucket_64_granularity(self):
        status, lb, wb = self._fn(200, 128, 'hello world')
        self.assertEqual(lb, 128)

    def test_len_bucket_rounds_down(self):
        status, lb, wb = self._fn(200, 130, 'hello world')
        self.assertEqual(lb, 128)

    def test_len_bucket_zero(self):
        status, lb, wb = self._fn(404, 0, '')
        self.assertEqual(lb, 0)

    def test_status_preserved(self):
        status, lb, wb = self._fn(404, 0, '')
        self.assertEqual(status, 404)

    def test_word_bucket_granularity_10(self):
        body = ' '.join(['word'] * 15)
        status, lb, wb = self._fn(200, len(body), body)
        self.assertEqual(wb, 10)

    def test_word_bucket_exact_multiple(self):
        body = ' '.join(['word'] * 20)
        status, lb, wb = self._fn(200, len(body), body)
        self.assertEqual(wb, 20)

    def test_word_bucket_zero_words(self):
        status, lb, wb = self._fn(200, 10, '')
        self.assertEqual(wb, 0)

    def test_same_response_same_fingerprint(self):
        body = 'Not found. Go away.'
        fp1 = self._fn(404, len(body), body)
        fp2 = self._fn(404, len(body), body)
        self.assertEqual(fp1, fp2)

    def test_different_lengths_different_buckets(self):
        body_a = 'x' * 64
        body_b = 'x' * 200
        fp_a = self._fn(200, 64, body_a)
        fp_b = self._fn(200, 200, body_b)
        self.assertNotEqual(fp_a[1], fp_b[1])

    def test_only_first_8kb_used_for_words(self):
        body = ('word ' * 2000)  # 10000 chars, 2000 words
        status, lb, wb = self._fn(200, len(body), body)
        self.assertLess(wb, 2000)


class TestBuildRequestLine(unittest.TestCase):
    """build_request_line(original_line, path) -- pure string helper."""

    def setUp(self):
        from discovery_logic import build_request_line
        self._fn = build_request_line

    def test_replaces_path(self):
        result = self._fn('GET /old/path HTTP/1.1', '/new/path')
        self.assertEqual(result, 'GET /new/path HTTP/1.1')

    def test_preserves_method(self):
        result = self._fn('GET /x HTTP/1.1', '/y')
        self.assertTrue(result.startswith('GET '))

    def test_preserves_protocol(self):
        result = self._fn('GET /x HTTP/1.1', '/y')
        self.assertTrue(result.endswith('HTTP/1.1'))

    def test_multiple_spaces_handled(self):
        # If original line has multiple spaces, only first token is method,
        # last token is protocol.
        result = self._fn('GET /foo/bar HTTP/1.1', '/baz')
        self.assertEqual(result, 'GET /baz HTTP/1.1')

    def test_path_with_query_param(self):
        # Path may contain ?; function passes it through unchanged
        result = self._fn('GET /old HTTP/1.1', '/new?a=1')
        self.assertEqual(result, 'GET /new?a=1 HTTP/1.1')

    def test_empty_path_raises(self):
        with self.assertRaises(ValueError):
            self._fn('GET /old HTTP/1.1', '')


if __name__ == '__main__':
    unittest.main()
