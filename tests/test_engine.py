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
