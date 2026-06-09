# tests/test_normalization.py
# -*- coding: utf-8 -*-
"""
Normalization tests for _norm_seg and _norm_path.
These run under CPython3 only (zero Burp deps).
"""
import unittest
import sys
import os

# Allow import from project root when tests/ is a subdirectory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from js_analyzer_engine import _norm_seg, _norm_path


class TestNormSeg(unittest.TestCase):

    # --- segments that MUST collapse to {id} ---

    def test_pure_numeric(self):
        self.assertEqual(_norm_seg('12345'), '{id}')

    def test_single_digit(self):
        self.assertEqual(_norm_seg('0'), '{id}')

    def test_version_dotted(self):
        self.assertEqual(_norm_seg('1.0'), '{id}')

    def test_version_dotted_three(self):
        self.assertEqual(_norm_seg('24.8.0'), '{id}')

    def test_version_underscored(self):
        self.assertEqual(_norm_seg('24_8_0'), '{id}')

    def test_version_hyphenated(self):
        self.assertEqual(_norm_seg('85-88-31'), '{id}')

    def test_uuid_lowercase(self):
        self.assertEqual(_norm_seg('550e8400-e29b-41d4-a716-446655440000'), '{id}')

    def test_uuid_uppercase(self):
        self.assertEqual(_norm_seg('550E8400-E29B-41D4-A716-446655440000'), '{id}')

    def test_long_hex_exactly_16(self):
        self.assertEqual(_norm_seg('deadbeefcafe0000'), '{id}')

    def test_long_hex_32_chars(self):
        self.assertEqual(_norm_seg('abcdef0123456789abcdef0123456789'), '{id}')

    def test_long_hex_uppercase(self):
        self.assertEqual(_norm_seg('ABCDEF0123456789ABCDEF01'), '{id}')

    # --- segments that MUST NOT collapse ---

    def test_v1_not_collapsed(self):
        self.assertEqual(_norm_seg('v1'), 'v1')

    def test_v2_not_collapsed(self):
        self.assertEqual(_norm_seg('v2'), 'v2')

    def test_camel_case_not_collapsed(self):
        self.assertEqual(_norm_seg('getUserById'), 'getUserById')

    def test_alpha_word(self):
        self.assertEqual(_norm_seg('users'), 'users')

    def test_short_hex_15(self):
        # 15 hex chars is below the >= 16 floor, must NOT collapse
        self.assertEqual(_norm_seg('deadbeefcafe000'), 'deadbeefcafe000')

    def test_mixed_alnum_not_collapsed(self):
        # letter+digit mix that is NOT a version/uuid/pure-hex -> keep
        self.assertEqual(_norm_seg('abc123'), 'abc123')

    def test_hyphen_word_not_collapsed(self):
        # readable slug: letters + hyphens, no digits -> keep
        self.assertEqual(_norm_seg('my-resource'), 'my-resource')


class TestNormPath(unittest.TestCase):

    def test_api_v1_users_id(self):
        self.assertEqual(_norm_path('api/v1/users/42'), 'api/v1/users/{id}')

    def test_uuid_segment_in_path(self):
        result = _norm_path('api/objects/550e8400-e29b-41d4-a716-446655440000/detail')
        self.assertEqual(result, 'api/objects/{id}/detail')

    def test_version_segment_not_collapsed(self):
        self.assertEqual(_norm_path('api/v1/health'), 'api/v1/health')

    def test_all_literal(self):
        self.assertEqual(_norm_path('api/v1/users'), 'api/v1/users')

    def test_leading_slash_preserved(self):
        # _norm_path does a plain split('/') so a leading slash produces an empty first seg
        self.assertEqual(_norm_path('/api/v1/users/99'), '/api/v1/users/{id}')

    def test_long_hex_in_path(self):
        self.assertEqual(
            _norm_path('repos/abcdef0123456789abcdef0123456789/commits'),
            'repos/{id}/commits'
        )

    def test_dotted_version_in_path(self):
        self.assertEqual(_norm_path('sdk/24.8.0/release'), 'sdk/{id}/release')


if __name__ == '__main__':
    unittest.main()
