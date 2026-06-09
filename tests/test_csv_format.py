# tests/test_csv_format.py
# -*- coding: utf-8 -*-
import unittest
import sys, os
# Add ui/ dir so 'from csv_utils import ...' resolves without javax
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ui'))

# We import only the pure function from csv_utils (NOT from results_panel)
from csv_utils import format_csv_row   # will fail until ui/csv_utils.py is created


class TestCsvFormatRow(unittest.TestCase):

    def test_simple_row(self):
        row = format_csv_row('secrets', 'AKIA1234', 'app.js', 'AWS Key')
        self.assertEqual(row, 'secrets,AKIA1234,app.js,AWS Key')

    def test_value_with_comma_gets_quoted(self):
        row = format_csv_row('endpoints', '/api/v1,v2/users', 'main.js', '')
        self.assertIn('"/api/v1,v2/users"', row)

    def test_value_with_double_quote_escaped(self):
        row = format_csv_row('secrets', 'he said "hello"', 'x.js', 'Test')
        # RFC 4180: double-quotes doubled inside quoted field
        self.assertIn('"he said ""hello"""', row)

    def test_value_with_newline_gets_quoted(self):
        row = format_csv_row('emails', 'foo\nbar@example.org', 'y.js', '')
        self.assertIn('"foo\nbar@example.org"', row)

    def test_label_with_comma_gets_quoted(self):
        row = format_csv_row('secrets', 'val', 'src.js', 'Type, subtype')
        self.assertIn('"Type, subtype"', row)

    def test_empty_label_allowed(self):
        row = format_csv_row('urls', 'https://example.com', 'a.js', '')
        self.assertEqual(row, 'urls,https://example.com,a.js,')

    def test_no_special_chars_no_quotes(self):
        row = format_csv_row('files', 'backup.sql', 'b.js', '')
        self.assertNotIn('"', row)

    def test_source_with_comma_quoted(self):
        row = format_csv_row('endpoints', '/api', 'file, v2.js', '')
        self.assertIn('"file, v2.js"', row)

    def test_returns_string(self):
        row = format_csv_row('endpoints', '/api', 'x.js', '')
        self.assertIsInstance(row, str)

    def test_unicode_value(self):
        row = format_csv_row('emails', u'useré@corp.com', 'x.js', '')
        self.assertIn(u'useré@corp.com', row)


if __name__ == '__main__':
    unittest.main()
