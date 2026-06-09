# -*- coding: utf-8 -*-
"""
ui/csv_utils.py -- Pure CSV helpers (zero javax/burp imports).

Safe to import under CPython3 for unit testing.
Used by results_panel.py (and active_scan_panel.py) for CSV export.
"""


def _csv_field(value):
    """RFC 4180 field quoting.

    Quote if value contains comma, double-quote, or newline; double any embedded
    double-quotes. Pure Python -- no Swing/Java imports.
    """
    s = value if isinstance(value, str) else str(value)
    if ',' in s or '"' in s or '\n' in s or '\r' in s:
        return '"' + s.replace('"', '""') + '"'
    return s


def format_csv_row(category, value, source, label):
    """Format one CSV row (no trailing newline). Columns: category,value,source,label.

    Pure function -- safe to unit-test under CPython3.
    """
    return ','.join([
        _csv_field(category),
        _csv_field(value),
        _csv_field(source),
        _csv_field(label),
    ])
