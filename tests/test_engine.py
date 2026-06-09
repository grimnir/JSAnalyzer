# -*- coding: utf-8 -*-
"""
Contract and regression tests for js_analyzer_engine.
Run with: python3 -m unittest discover tests -v
All tests here target the pure engine only -- zero burp/java/javax imports.
"""
import unittest


class TestEngineImport(unittest.TestCase):
    """The engine must import without any burp/java/javax dependency."""

    def test_import_succeeds(self):
        import js_analyzer_engine  # noqa: F401 -- must not raise

    def test_engine_class_exists(self):
        from js_analyzer_engine import JSAnalyzerEngine
        self.assertTrue(callable(JSAnalyzerEngine))

    def test_module_level_validators_exist(self):
        import js_analyzer_engine as m
        for name in ('_is_valid_endpoint', '_is_valid_url',
                     '_is_valid_secret', '_is_valid_email', '_is_valid_file'):
            self.assertTrue(
                hasattr(m, name),
                'Missing module-level function: %s' % name,
            )


class TestAnalyzeReturnContract(unittest.TestCase):
    """analyze() must always return a dict with exactly 6 required keys."""

    REQUIRED_KEYS = frozenset(['endpoints', 'urls', 'secrets', 'emails', 'files', 'dictionary'])

    def setUp(self):
        from js_analyzer_engine import JSAnalyzerEngine
        self.engine = JSAnalyzerEngine()

    def test_empty_string_returns_all_six_keys(self):
        result = self.engine.analyze('')
        self.assertEqual(set(result.keys()), self.REQUIRED_KEYS)

    def test_none_body_returns_all_six_keys(self):
        result = self.engine.analyze(None)
        self.assertEqual(set(result.keys()), self.REQUIRED_KEYS)

    def test_empty_body_all_lists_empty(self):
        result = self.engine.analyze('')
        for key in self.REQUIRED_KEYS:
            self.assertIsInstance(result[key], list,
                                  'Key %s must be a list' % key)
            self.assertEqual(result[key], [],
                             'Key %s must be empty for empty body' % key)

    def test_whitespace_body_all_lists_empty(self):
        result = self.engine.analyze('   \n\t  ')
        for key in self.REQUIRED_KEYS:
            self.assertEqual(result[key], [],
                             'Key %s must be empty for whitespace body' % key)

    def test_source_parameter_is_optional(self):
        from js_analyzer_engine import JSAnalyzerEngine
        engine = JSAnalyzerEngine()
        result = engine.analyze('var x = 1;')
        self.assertIn('endpoints', result)

    def test_source_parameter_accepted(self):
        from js_analyzer_engine import JSAnalyzerEngine
        engine = JSAnalyzerEngine()
        result = engine.analyze('var x = 1;', source='app.js')
        self.assertIn('endpoints', result)


class TestAnalyzeStateless(unittest.TestCase):
    """Same input twice on the same instance must return identical output."""

    def test_analyze_is_stateless(self):
        from js_analyzer_engine import JSAnalyzerEngine
        engine = JSAnalyzerEngine()
        body = (
            'fetch("/api/v1/users");'
            ' var email = "real@example.org";'
        )
        r1 = engine.analyze(body)
        r2 = engine.analyze(body)
        self.assertEqual(r1, r2)

    def test_two_separate_instances_agree(self):
        from js_analyzer_engine import JSAnalyzerEngine
        body = 'fetch("/api/v1/users");'
        r1 = JSAnalyzerEngine().analyze(body)
        r2 = JSAnalyzerEngine().analyze(body)
        self.assertEqual(r1, r2)


class TestSecretSchema(unittest.TestCase):
    """Each item in result['secrets'] must be a dict with type/value/masked."""

    def test_aws_key_has_all_three_fields(self):
        from js_analyzer_engine import JSAnalyzerEngine
        engine = JSAnalyzerEngine()
        # AKIA prefix is a fixed-prefix pattern -- must always be reported.
        # Avoid noise keywords: 'EXAMPL2' has no 'example'/'test'/etc.
        body = 'var key = "AKIAIOSFODNN7EXAMPL2";'
        result = engine.analyze(body)
        self.assertTrue(
            len(result['secrets']) > 0,
            'Expected at least one secret for AKIA key',
        )
        secret = result['secrets'][0]
        self.assertIn('type', secret, 'Secret must have "type" field')
        self.assertIn('value', secret, 'Secret must have "value" field')
        self.assertIn('masked', secret, 'Secret must have "masked" field')

    def test_masked_format_long_value(self):
        """masked = value[:10] + '...' + value[-4:] when len > 20."""
        from js_analyzer_engine import JSAnalyzerEngine
        engine = JSAnalyzerEngine()
        # AKIA + 16 uppercase chars = 20 chars total; add one more to make len=21
        body = 'var key = "AKIAIOSFODNN7EXAMPL23";'
        result = engine.analyze(body)
        for s in result['secrets']:
            v = s['value']
            m = s['masked']
            if len(v) > 20:
                expected_masked = v[:10] + '...' + v[-4:]
                self.assertEqual(m, expected_masked,
                                 'Masked format wrong for value len=%d' % len(v))

    def test_masked_format_short_value(self):
        """masked = value when len <= 20."""
        from js_analyzer_engine import JSAnalyzerEngine
        engine = JSAnalyzerEngine()
        # AKIA + 16 chars = 20 chars exactly -> masked == raw value
        body = 'var k = "AKIAIOSFODNN7EXAMPL2";'
        result = engine.analyze(body)
        for s in result['secrets']:
            v = s['value']
            m = s['masked']
            if len(v) <= 20:
                self.assertEqual(m, v,
                                 'Short secret masked must equal raw value')


class TestDictionaryKeyIsListOfTuples(unittest.TestCase):
    """result['dictionary'] must be a list (may be empty -- wordlist not loaded)."""

    def test_dictionary_is_list(self):
        from js_analyzer_engine import JSAnalyzerEngine
        engine = JSAnalyzerEngine()
        result = engine.analyze('')
        self.assertIsInstance(result['dictionary'], list)

    def test_dictionary_empty_when_no_wordlist(self):
        """Without a wordlist the index is empty, so dictionary must be []."""
        from js_analyzer_engine import JSAnalyzerEngine
        engine = JSAnalyzerEngine(wordlist=None)
        result = engine.analyze('fetch("api/v1/users/42");')
        self.assertEqual(result['dictionary'], [])


class TestValidators(unittest.TestCase):
    """Regression lock for the five _is_valid_* module-level functions.

    These tests encode the CURRENT behavior (Phase 0 baseline).
    They must stay GREEN through all subsequent phases.
    """

    # ------------------------------------------------------------------
    # _is_valid_endpoint
    # ------------------------------------------------------------------

    def test_endpoint_no_leading_slash_rejected(self):
        from js_analyzer_engine import _is_valid_endpoint
        # Paths without a leading '/' must be rejected (js_analyzer.py:399)
        self.assertFalse(_is_valid_endpoint('api/v1/users'))
        self.assertFalse(_is_valid_endpoint('v1/products'))

    def test_endpoint_too_short_rejected(self):
        from js_analyzer_engine import _is_valid_endpoint
        self.assertFalse(_is_valid_endpoint('/a'))
        self.assertFalse(_is_valid_endpoint(''))

    def test_endpoint_noise_string_rejected(self):
        from js_analyzer_engine import _is_valid_endpoint
        # NOISE_STRINGS exact match -- '/a', '/R', '/V' (js_analyzer.py:207-211)
        self.assertFalse(_is_valid_endpoint('/a'))
        self.assertFalse(_is_valid_endpoint('/R'))
        self.assertFalse(_is_valid_endpoint('/V'))

    def test_endpoint_single_segment_with_short_parts_rejected(self):
        from js_analyzer_engine import _is_valid_endpoint
        # All non-empty parts shorter than 2 chars (js_analyzer.py:404)
        self.assertFalse(_is_valid_endpoint('/a/b'))

    def test_endpoint_valid_api_path_accepted(self):
        from js_analyzer_engine import _is_valid_endpoint
        self.assertTrue(_is_valid_endpoint('/api/v1/users'))
        self.assertTrue(_is_valid_endpoint('/auth/login'))
        self.assertTrue(_is_valid_endpoint('/internal/health'))

    def test_endpoint_noise_pattern_dotslash_rejected(self):
        from js_analyzer_engine import _is_valid_endpoint
        # Starts with ./ -- matches NOISE_PATTERNS[0] (js_analyzer.py:163)
        self.assertFalse(_is_valid_endpoint('./utils/helper'))

    # ------------------------------------------------------------------
    # _is_valid_url
    # ------------------------------------------------------------------

    def test_url_noise_domain_rejected(self):
        from js_analyzer_engine import _is_valid_url
        # NOISE_DOMAINS (js_analyzer.py:141-150)
        self.assertFalse(_is_valid_url('https://www.w3.org/2001/XMLSchema'))
        self.assertFalse(_is_valid_url('https://example.com/api/resource'))
        self.assertFalse(_is_valid_url('https://schemas.microsoft.com/winfx'))

    def test_url_data_uri_rejected(self):
        from js_analyzer_engine import _is_valid_url
        self.assertFalse(_is_valid_url('data:image/png;base64,iVBORw0KGgo='))

    def test_url_too_short_rejected(self):
        from js_analyzer_engine import _is_valid_url
        self.assertFalse(_is_valid_url('http://x.co'))   # len < 15

    def test_url_static_asset_rejected(self):
        from js_analyzer_engine import _is_valid_url
        self.assertFalse(_is_valid_url('https://cdn.example.org/logo.png'))
        self.assertFalse(_is_valid_url('https://cdn.example.org/fonts/main.woff'))

    def test_url_real_url_accepted(self):
        from js_analyzer_engine import _is_valid_url
        self.assertTrue(_is_valid_url('https://api.stripe.com/v1/charges'))
        self.assertTrue(_is_valid_url('wss://realtime.example.org/socket'))

    def test_url_with_placeholder_rejected(self):
        from js_analyzer_engine import _is_valid_url
        self.assertFalse(_is_valid_url('https://api.example.org/{resource}/list'))
        self.assertFalse(_is_valid_url('https://api.example.org/null'))

    # ------------------------------------------------------------------
    # _is_valid_secret
    # ------------------------------------------------------------------

    def test_secret_with_example_keyword_rejected(self):
        from js_analyzer_engine import _is_valid_secret
        self.assertFalse(_is_valid_secret('AKIAIOSFODNN7EXAMPLE'))

    def test_secret_with_placeholder_keyword_rejected(self):
        from js_analyzer_engine import _is_valid_secret
        self.assertFalse(_is_valid_secret('your-api-key-here-placeholder'))

    def test_secret_with_test_keyword_rejected(self):
        from js_analyzer_engine import _is_valid_secret
        self.assertFalse(_is_valid_secret('sk_test_abcdefghijklmnop'))

    def test_secret_too_short_rejected(self):
        from js_analyzer_engine import _is_valid_secret
        self.assertFalse(_is_valid_secret('AKIA123'))   # len < 10

    def test_secret_real_aws_key_accepted(self):
        from js_analyzer_engine import _is_valid_secret
        # Length 20, no noise keyword, passes current Phase 0 gate
        self.assertTrue(_is_valid_secret('AKIAIOSFODNN7EXAMPL2'))

    # ------------------------------------------------------------------
    # _is_valid_email
    # ------------------------------------------------------------------

    def test_email_example_domain_rejected(self):
        from js_analyzer_engine import _is_valid_email
        self.assertFalse(_is_valid_email('user@example.com'))
        self.assertFalse(_is_valid_email('admin@test.com'))
        self.assertFalse(_is_valid_email('info@domain.com'))

    def test_email_noreply_rejected(self):
        from js_analyzer_engine import _is_valid_email
        # 'noreply' in value (js_analyzer.py:457)
        self.assertFalse(_is_valid_email('noreply@real-company.com'))

    def test_email_test_keyword_rejected(self):
        from js_analyzer_engine import _is_valid_email
        self.assertFalse(_is_valid_email('test.user@real-company.com'))

    def test_email_real_email_accepted(self):
        from js_analyzer_engine import _is_valid_email
        self.assertTrue(_is_valid_email('alice@company.io'))
        self.assertTrue(_is_valid_email('support@startup.ai'))

    def test_email_without_at_rejected(self):
        from js_analyzer_engine import _is_valid_email
        self.assertFalse(_is_valid_email('notanemail.com'))

    # ------------------------------------------------------------------
    # _is_valid_file
    # ------------------------------------------------------------------

    def test_file_package_json_rejected(self):
        from js_analyzer_engine import _is_valid_file
        self.assertFalse(_is_valid_file('package.json'))
        self.assertFalse(_is_valid_file('tsconfig.json'))

    def test_file_webpack_artifact_rejected(self):
        from js_analyzer_engine import _is_valid_file
        self.assertFalse(_is_valid_file('main.chunk.js'))
        self.assertFalse(_is_valid_file('vendor.bundle.js'))

    def test_file_source_map_rejected(self):
        from js_analyzer_engine import _is_valid_file
        self.assertFalse(_is_valid_file('app.js.map'))

    def test_file_backup_sql_accepted(self):
        from js_analyzer_engine import _is_valid_file
        self.assertTrue(_is_valid_file('backup.sql'))
        self.assertTrue(_is_valid_file('database_dump.sql'))

    def test_file_certificate_accepted(self):
        from js_analyzer_engine import _is_valid_file
        self.assertTrue(_is_valid_file('server.pem'))
        self.assertTrue(_is_valid_file('private.key'))

    def test_file_short_locale_json_rejected(self):
        from js_analyzer_engine import _is_valid_file
        # Filename <= 7 chars ending in .json (js_analyzer.py:482-483)
        # "en.json" -> split('/')[-1] = "en.json" len=7 -> rejected
        self.assertFalse(_is_valid_file('en.json'))

    def test_file_longer_json_accepted(self):
        from js_analyzer_engine import _is_valid_file
        # "settings.json" -> len=13 > 7 -> accepted
        self.assertTrue(_is_valid_file('settings.json'))


if __name__ == '__main__':
    unittest.main()
