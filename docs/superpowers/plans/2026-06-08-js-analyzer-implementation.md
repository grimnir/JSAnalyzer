# JS Analyzer — Dictionary Matching + Active Scan + Improvements: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the Burp JS Analyzer (Jython 2.7) to (1) passively match the api.txt endpoint dictionary inside analyzed JS, (2) actively probe a target host with that wordlist (safe-by-default), and (3) ship an accuracy/UX improvement package — all behind a pure, unit-tested engine.

**Architecture:** Extract all detection into a pure `js_analyzer_engine.py` (zero burp/java imports, py2/py3) unit-tested under CPython3; `js_analyzer.py` becomes a thin Burp adapter; new `ui/active_scan_panel.py` holds the active scanner. TDD: only the pure engine runs under python3 — Burp/Swing/threading parts use explicit "Manual verification in Burp" steps.

**Tech Stack:** Jython 2.7, Python 2 syntax, Java stdlib (java.util.concurrent, javax.swing), legacy Burp Extender API, CPython3 + stdlib `unittest`.

**Spec:** `docs/superpowers/specs/2026-06-08-js-analyzer-dictionary-design.md`
**Beads epic:** JSAnalyzer-main-d4k

---

## File Structure (all phases)

### Phase 0 — Foundation: Extract pure engine, test harness, wire adapter

- `tests/__init__.py` — Created — empty marker so unittest discovers the package
- `tests/test_engine.py` — Created — all contract, validator, and regression tests for the pure engine
- `js_analyzer_engine.py` — Created — pure Python engine (no burp/java imports); all regex tables, noise tables, validators, JSAnalyzerEngine class
- `js_analyzer.py` — Modified — remove duplicated module-level tables and inline detection; import and delegate to JSAnalyzerEngine
- `.gitignore` — Created — ignore *.pyc, __pycache__, .DS_Store

### Phase 1 — WS1 Passive Dictionary Matching

- `tests/__init__.py` — Created: empty marker so unittest discover works
- `tests/test_normalization.py` — Created: RED tests for _norm_seg / _norm_path
- `tests/test_engine.py` — Modified: add TestDictionaryMatching class (was created in P0)
- `js_analyzer_engine.py` — Modified: add _SEG_* regexes, _norm_seg, _norm_path, _build_index, _DICT_CAND, _match_dict; wire analyze() dictionary key; __init__ builds frozenset
- `js_analyzer.py` — Modified: registerExtenderCallbacks reads api.txt + passes lines to JSAnalyzerEngine(wordlist=lines); analyze_response loops result['dictionary'] and calls _add_finding
- `ui/results_panel.py` — Modified: add 'dictionary' to findings dict; add Dictionary tab to categories list; update titles/keys lists in _refresh_tables; update _get_current_table/_get_current_key; update _update_stats to add D:0; fix initial stats_label string; add 'dictionary' key to export map

### Phase 2 — WS3 Improvements

- `js_analyzer_engine.py` **Modified** — add `_entropy`, `_ENTROPY_HEX_RE`, `_UUID_RE`, `_HEX64_RE`, `_COLOR_RE`, `_COMMON_WORDS`, `_SECRET_KEEP_LABELS` frozenset; rewrite `_is_valid_secret`; rewrite SECRET_PATTERNS with context-gated Bugsnag/Datadog/Telegram/Twilio/Dropbox; per-response span dedup in `analyze()`; add relative-path ENDPOINT pattern; make `_is_valid_endpoint` leading-slash conditional; add `SETTING_KEYS` cast table and `cast_setting` helper
- `tests/test_engine.py` **Modified** — add `TestSecretFalsePositives`, `TestRelativePaths`, `TestSettingCasts`, `TestCsvFormat` test classes
- `tests/test_csv_format.py` **Created** — pure CSV row formatting tests (quote-escaping)
- `js_analyzer.py` **Modified** — `_add_finding(category, value, source, label=None)`; dedup key on raw secret value; `DEDUP_CAP = 50000` guard; `_load_setting`/`_save_setting` using engine's `cast_setting`; load settings in `registerExtenderCallbacks`
- `ui/results_panel.py` **Modified** — add "Type" column for secrets table; stats label with dup counters; search debounce via `javax.swing.Timer(150)`; "Export CSV" button + `_export_csv`; per-tab CSV via `JPopupMenu`; `format_csv_row` extracted as module-level pure function

### Phase 3 — WS2 Active Scanner

- `discovery_logic.py` — **Create** — Pure Python (zero java/burp imports): `_sanitize(lines)`, `_DESTRUCTIVE` regex, `is_destructive(path)`, `is_interesting(status, has_location)`, `soft404_fingerprint(status, body_len, body)`. Importable under CPython3 and Jython 2.7.
- `tests/test_discovery_logic.py` — **Create** — python3 unittest covering every rule in `_sanitize`, `is_destructive`, `is_interesting`, and `soft404_fingerprint`.
- `ui/active_scan_panel.py` — **Create** — `DiscoveryConfig` (dataclass-style, defaults + ceilings), `WordlistLoader` (calls `_sanitize`), `DiscoveryPanel` JPanel (table/progressbar/start-stop/filter/export). Imports burp/javax — Burp-side only, no python3 tests.
- `ui/__init__.py` — **Modify** — no change needed (already exists).
- `js_analyzer.py` — **Modify** — add `IExtensionStateListener`; add `self._discovery_engine = None`; `_load_setting`/`_save_setting` helpers (if Phase 2 not yet done, add stubs here); second context-menu item "Probe endpoints with wordlist"; `extensionUnloaded` shutdown hook.
- `tests/__init__.py` — **Modify** — already exists (empty), no change needed.


---


## Phase 0 — Foundation: Extract pure engine, test harness, wire adapter

### Task P0.1: Bootstrap test package and write RED contract tests

**Goal:** Create `tests/__init__.py` and the initial contract tests in `tests/test_engine.py`.
All tests must fail (RED) because `js_analyzer_engine` does not exist yet.

**Files:**
- `tests/__init__.py` — Create
- `tests/test_engine.py` — Create

---

- [ ] **Step 1: Verify the tests directory does not yet exist and create `.gitignore`**

```bash
ls /Users/gg/Downloads/JSAnalyzer-main/tests 2>/dev/null || echo "tests dir absent — good"
```

Expected output: `tests dir absent — good`

Create `.gitignore` at project root:

```bash
cat > /Users/gg/Downloads/JSAnalyzer-main/.gitignore << 'EOF'
*.pyc
__pycache__/
.DS_Store
*.egg-info/
.pytest_cache/
EOF
```

---

- [ ] **Step 2: Create `tests/__init__.py`**

Create the file (empty marker):

```python
# tests/__init__.py
```

Exact path: `/Users/gg/Downloads/JSAnalyzer-main/tests/__init__.py`

---

- [ ] **Step 3: Write the failing tests in `tests/test_engine.py`**

Create `/Users/gg/Downloads/JSAnalyzer-main/tests/test_engine.py` with the following content:

```python
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
```

---

- [ ] **Step 4: Run tests — verify RED**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest discover tests -v 2>&1 | head -40
```

Expected failure output (the module does not exist yet):

```
ERROR: test_import_succeeds (tests.test_engine.TestEngineImport)
----------------------------------------------------------------------
ModuleNotFoundError: No module named 'js_analyzer_engine'
...
Ran 18 tests in 0.00Xs
FAILED (errors=18)
```

---

- [ ] **Step 5: Commit skeleton**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && git add .gitignore tests/__init__.py tests/test_engine.py && git commit -m "$(cat <<'EOF'
test(P0.1): add RED contract tests for JSAnalyzerEngine

Create tests/ package with contract, stateless, secret-schema and
dictionary-key tests. All 18 tests error on missing js_analyzer_engine
module -- this is the expected RED state before engine extraction.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P0.2: Create `js_analyzer_engine.py` — copy tables, validators, engine stub

**Goal:** Create the pure engine module with all regex/noise tables verbatim from `js_analyzer.py`, promote the 5 `_is_valid_*` methods to module-level functions, and implement `JSAnalyzerEngine.analyze()` that runs the same extraction logic but returns a plain dict. `dictionary=[]` for now (Phase 1). No burp/java imports. All contract tests turn GREEN.

**Files:**
- `js_analyzer_engine.py` — Create

---

- [ ] **Step 1: Create `/Users/gg/Downloads/JSAnalyzer-main/js_analyzer_engine.py`**

```python
# -*- coding: utf-8 -*-
"""
JS Analyzer Engine -- pure Python, no burp/java/javax imports.
Dual-runtime: CPython 3 (tests) and Jython 2.7 (Burp production).

Compatibility rules enforced throughout:
  - range() only (no xrange)
  - .items() / .values() (no iteritems / itervalues)
  - '%s' % v string formatting (no f-strings)
  - no print()
  - float(c)/n for division
  - math.log(p)/math.log(2) (no math.log2)
  - except E as e
  - ASCII-only literals
"""

import re
import math


# ==================== ENDPOINT PATTERNS ====================
# Copied verbatim from js_analyzer.py lines 38-67

ENDPOINT_PATTERNS = [
    # API endpoints
    re.compile(r'["\']((?:https?:)?//[^"\']+/api/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # OAuth/Auth endpoints
    re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Sensitive paths
    re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/private[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/download[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Well-known paths
    re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/idp/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
]

# ==================== URL PATTERNS ====================
# Copied verbatim from js_analyzer.py lines 70-81

URL_PATTERNS = [
    re.compile(r'["\'](https?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](sftp://[^\s"\'<>]{10,})["\']'),
    # Cloud storage
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)'),
    # Firebase URL
    re.compile(r'https:\/\/[a-z0-9-]+\.firebaseio\.com'),
]

# ==================== SECRET PATTERNS ====================
# Copied verbatim from js_analyzer.py lines 84-118

SECRET_PATTERNS = [
    (re.compile(r'(AKIA[0-9A-Z]{16})'), 'AWS Key'),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), 'Google API'),
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'), 'Stripe Live'),
    (re.compile(r'(ghp_[0-9a-zA-Z]{36})'), 'GitHub PAT'),
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'), 'Slack Token'),
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'), 'JWT'),
    (re.compile(r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)'), 'Private Key'),
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]+)'), 'MongoDB'),
    (re.compile(r'(postgres(?:ql)?://[^\s"\'<>]+)'), 'PostgreSQL'),
    (re.compile(r'(?i)algolia.{0,32}([a-z0-9]{32})\b'), 'Algolia Admin API Key'),
    (re.compile(r'(?i)algolia.{0,16}([A-Z0-9]{10})\b'), 'Algolia Application ID'),
    (re.compile(r'(?i)cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b'), 'Cloudflare API Token'),
    (re.compile(r'(?i)(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b'), 'Cloudflare Service Key'),
    (re.compile(r'(mysql:\/\/[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:\/[^\s"\'?:]+)?(?:\?[^\s"\']*)?)'), 'MySQL URI with Credentials'),
    (re.compile(r'\b(sgp_[A-Z0-9_-]{60,70})\b'), 'Segment Public API Token'),
    (re.compile(r'(?i)(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}([A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})'), 'Segment API Key'),
    (re.compile(r'(?i)(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})\b'), 'Facebook App ID'),
    (re.compile(r'(?i)(?:facebook|fb).{0,32}(?:api|app|application|client|consumer|secret|key).{0,32}([a-z0-9]{32})\b'), 'Facebook Secret Key'),
    (re.compile(r'(EAACEdEose0cBA[A-Z0-9]{20,})\b'), 'Facebook Access Token'),
    (re.compile(r'\b(ya29\.[a-z0-9_-]{30,})\b'), 'Google OAuth2 Access Token'),
    # New
    (re.compile(r'\d{9}:[a-zA-Z0-9_-]{35}'), 'Telegram Bot Token'),
    (re.compile(r'lin_api_[a-zA-Z0-9]{40}'), 'Linear API Key'),
    (re.compile(r"[hH]eroku['\"][0-9a-f]{32}['\"]"), 'Heroku API Key'),
    (re.compile(r'dop_v1_[a-z0-9]{64}'), 'DigitalOcean Token'),
    (re.compile(r'SK[0-9a-fA-F]{32}'), 'Twilio API Key'),
    (re.compile(r'SG\.[\w\d\-_]{22}\.[\w\d\-_]{43}'), 'SendGrid API Key'),
    (re.compile(r'sl.[A-Za-z0-9_-]{20,100}'), 'Dropbox Access Token'),
    (re.compile(r'glpat-[0-9a-zA-Z-_]{20}'), 'GitLab Token'),
    (re.compile(r'shpat_[0-9a-fA-F]{32}'), 'Shopify Access Token'),
    (re.compile(r'[a-f0-9]{32}'), 'Bugsnag API Key'),
    (re.compile(r'[a-z0-9]{32}'), 'Datadog API Key'),
    (re.compile(r'NRII-[a-zA-Z0-9]{20,}'), 'New Relic Key'),
]

# ==================== EMAIL PATTERN ====================
# Copied verbatim from js_analyzer.py line 121

EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')

# ==================== FILE PATTERNS ====================
# Copied verbatim from js_analyzer.py lines 124-135

FILE_PATTERNS = re.compile(
    r'["\']([a-zA-Z0-9_/.-]+\.(?:'
    r'sql|csv|xlsx|xls|json|xml|yaml|yml|'
    r'txt|log|conf|config|cfg|ini|env|'
    r'bak|backup|old|orig|copy|'
    r'key|pem|crt|cer|p12|pfx|'
    r'doc|docx|pdf|'
    r'zip|tar|gz|rar|7z|'
    r'sh|bat|ps1|py|rb|pl'
    r'))["\']',
    re.IGNORECASE
)

# ==================== NOISE FILTERS ====================
# Copied verbatim from js_analyzer.py lines 141-211

NOISE_DOMAINS = {
    'www.w3.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com',
    'purl.org', 'purl.oclc.org', 'openoffice.org', 'docs.oasis-open.org',
    'sheetjs.openxmlformats.org', 'ns.adobe.com', 'www.xml.org',
    'example.com', 'test.com', 'localhost', '127.0.0.1',
    'fusioncharts.com', 'jspdf.default.namespaceuri',
    'npmjs.org', 'registry.npmjs.org',
    'github.com/indutny', 'github.com/crypto-browserify',
    'jqwidgets.com', 'ag-grid.com',
}

MODULE_PREFIXES = (
    './', '../', '.../',
    './lib', '../lib', './utils', '../utils',
    './node_modules', '../node_modules',
    './src', '../src', './dist', '../dist',
)

NOISE_PATTERNS = [
    re.compile(r'^\.\.?/'),
    re.compile(r'^[a-z]{2}(-[a-z]{2})?\.js$'),
    re.compile(r'^[a-z]{2}(-[a-z]{2})?$'),
    re.compile(r'-xform$'),
    re.compile(r'^sha\d*$'),
    re.compile(r'^aes$|^des$|^md5$'),
    re.compile(r'^/[A-Z][a-z]+\s'),
    re.compile(r'^/[A-Z][a-z]+$'),
    re.compile(r'^\d+ \d+ R$'),
    re.compile(r'^xl/'),
    re.compile(r'^docProps/'),
    re.compile(r'^_rels/'),
    re.compile(r'^META-INF/'),
    re.compile(r'\.xml$'),
    re.compile(r'^worksheets/'),
    re.compile(r'^theme/'),
    re.compile(r'^webpack'),
    re.compile(r'^zone\.js$'),
    re.compile(r'^readable-stream/'),
    re.compile(r'^process/'),
    re.compile(r'^stream/'),
    re.compile(r'^buffer$'),
    re.compile(r'^events$'),
    re.compile(r'^util$'),
    re.compile(r'^path$'),
    re.compile(r'^\+'),
    re.compile(r'^\$\{'),
    re.compile(r'^#'),
    re.compile(r'^\?\ref='),
    re.compile(r'^/[a-z]$'),
    re.compile(r'^/[A-Z]$'),
    re.compile(r'^http://$'),
    re.compile(r'_ngcontent'),
]

NOISE_STRINGS = {
    'http://', 'https://', '/a', '/P', '/R', '/V', '/W',
    'zone.js', 'bn.js', 'hash.js', 'md5.js', 'sha.js', 'des.js',
    'asn1.js', 'declare.js', 'elliptic.js',
}


# ==================== MODULE-LEVEL VALIDATORS ====================
# Promoted from BurpExtender instance methods (js_analyzer.py lines 384-485)
# so they can be called and tested under CPython3 without any Burp dependency.

def _is_valid_endpoint(value):
    """Return True if value is a real API endpoint path worth reporting.

    Copied from BurpExtender._is_valid_endpoint (js_analyzer.py:384-407).
    """
    if not value or len(value) < 3:
        return False
    if value in NOISE_STRINGS:
        return False
    for pattern in NOISE_PATTERNS:
        if pattern.search(value):
            return False
    if not value.startswith('/'):
        return False
    parts = value.split('/')
    if len(parts) < 2 or all(len(p) < 2 for p in parts if p):
        return False
    return True


def _is_valid_url(value):
    """Return True if value is a non-noise full URL.

    Copied from BurpExtender._is_valid_url (js_analyzer.py:409-433).
    """
    if not value or len(value) < 15:
        return False
    val_lower = value.lower()
    for domain in NOISE_DOMAINS:
        if domain in val_lower:
            return False
    if '{' in value or 'undefined' in val_lower or 'null' in val_lower:
        return False
    if val_lower.startswith('data:'):
        return False
    if any(val_lower.endswith(ext) for ext in ['.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf']):
        return False
    return True


def _is_valid_secret(value):
    """Return True if value looks like a real secret.

    Copied from BurpExtender._is_valid_secret (js_analyzer.py:435-444).
    NOTE: Phase 0 preserves the existing (lenient) logic exactly.
    Phase 2 will add entropy gating and context requirements per spec s4.3.
    """
    if not value or len(value) < 10:
        return False
    val_lower = value.lower()
    if any(x in val_lower for x in ['example', 'placeholder', 'your', 'xxxx', 'test']):
        return False
    return True


def _is_valid_email(value):
    """Return True if value is a real (non-placeholder) email address.

    Copied from BurpExtender._is_valid_email (js_analyzer.py:446-460).
    """
    if not value or '@' not in value:
        return False
    val_lower = value.lower()
    domain = value.split('@')[-1].lower()
    if domain in {'example.com', 'test.com', 'domain.com', 'placeholder.com'}:
        return False
    if any(x in val_lower for x in ['example', 'test', 'placeholder', 'noreply']):
        return False
    return True


def _is_valid_file(value):
    """Return True if value is a sensitive file reference worth reporting.

    Copied from BurpExtender._is_valid_file (js_analyzer.py:462-485).
    """
    if not value or len(value) < 3:
        return False
    val_lower = value.lower()
    if any(x in val_lower for x in [
        'package.json', 'tsconfig.json', 'webpack', 'babel',
        'eslint', 'prettier', 'node_modules', '.min.',
        'polyfill', 'vendor', 'chunk', 'bundle',
    ]):
        return False
    if val_lower.endswith('.map'):
        return False
    if val_lower.endswith('.json') and len(value.split('/')[-1]) <= 7:
        return False
    return True


# ==================== ENGINE ====================

class JSAnalyzerEngine(object):
    """Pure Python JS analysis engine.

    Stateless per call. Dedup, persistence, and file I/O live in the adapter.

    Args:
        wordlist: iterable of path strings for dictionary matching (Phase 1).
                  Pass None (default) to disable dictionary matching.
    """

    def __init__(self, wordlist=None):
        # Phase 0: index deferred to Phase 1. Store empty frozenset.
        self._index = frozenset()
        # wordlist stored for Phase 1 wiring; unused in Phase 0.
        self._wordlist = wordlist

    def analyze(self, js_text, source=None):
        """Analyze a JavaScript body and return findings.

        Args:
            js_text: str -- the JS response body.
            source:  str or None -- display name for the origin file.

        Returns:
            dict with keys:
                'endpoints'  : list of str
                'urls'       : list of str
                'secrets'    : list of {'type': str, 'value': str, 'masked': str}
                'emails'     : list of str
                'files'      : list of str
                'dictionary' : list of (template: str, evidence: str)
                               Always [] in Phase 0.
        """
        result = {
            'endpoints': [],
            'urls': [],
            'secrets': [],
            'emails': [],
            'files': [],
            'dictionary': [],
        }

        if not js_text:
            return result

        body = js_text

        # 1. Endpoints
        # NOTE (fix [1]): ENDPOINT_PATTERNS is still a plain list of re objects
        # in Phase 0. It is converted to (compiled_re, label) tuples in Phase 2
        # Task P2.2 and the loop becomes: for pattern, label in ENDPOINT_PATTERNS
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(body):
                try:
                    value = match.group(1).strip()
                    if _is_valid_endpoint(value) and value not in result['endpoints']:
                        result['endpoints'].append(value)
                except (IndexError, Exception):
                    continue

        # 2. URLs
        for pattern in URL_PATTERNS:
            for match in pattern.finditer(body):
                try:
                    value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                    if _is_valid_url(value) and value not in result['urls']:
                        result['urls'].append(value)
                except (IndexError, Exception):
                    continue

        # 3. Secrets -- preserved exactly as in analyze_response (js_analyzer.py:320-330)
        for pattern, label in SECRET_PATTERNS:
            for match in pattern.finditer(body):
                try:
                    value = match.group(1).strip()
                    if _is_valid_secret(value):
                        masked = (value[:10] + '...' + value[-4:]
                                  if len(value) > 20 else value)
                        entry = {
                            'type': label,
                            'value': value,
                            'masked': masked,
                        }
                        # Per-engine local dedup by raw value (adapter owns global dedup)
                        if not any(s['value'] == value for s in result['secrets']):
                            result['secrets'].append(entry)
                except (IndexError, Exception):
                    continue

        # 4. Emails
        for match in EMAIL_PATTERN.finditer(body):
            try:
                value = match.group(1).strip()
                if _is_valid_email(value) and value not in result['emails']:
                    result['emails'].append(value)
            except (IndexError, Exception):
                continue

        # 5. Files
        for match in FILE_PATTERNS.finditer(body):
            try:
                value = match.group(1).strip()
                if _is_valid_file(value) and value not in result['files']:
                    result['files'].append(value)
            except (IndexError, Exception):
                continue

        # 6. Dictionary -- Phase 0 stub (always empty until Phase 1)
        # result['dictionary'] stays []

        return result

    @staticmethod
    def _build_index(lines):
        """Build a frozenset index of normalized paths from an iterable of strings.

        Used in Phase 1. Defined here so tests can call it directly.
        """
        idx = set()
        for ln in lines:
            p = ln.strip().lower()
            if p:
                idx.add(JSAnalyzerEngine._norm_path(p))
        return frozenset(idx)

    @staticmethod
    def _norm_seg(s):
        """Delegate to module-level _norm_seg (defined in P1.2)."""
        return _norm_seg(s)

    @staticmethod
    def _norm_path(p):
        """Delegate to module-level _norm_path (defined in P1.2)."""
        return _norm_path(p)
    # NOTE (fix [2]): _norm_seg, _norm_path, _SEG_NUM, _SEG_VER, _SEG_UUID,
    # _SEG_HEX are module-level names added in Phase 1 Task P1.2. These
    # staticmethods simply delegate — they do NOT inline re.compile().
    # The module-level definitions are the single source of truth.

    @staticmethod
    def _entropy(s):
        """Shannon entropy of string s (bits per character).

        Uses math.log(p)/math.log(2) for Py2/Py3 compatibility
        (no math.log2 in Python 2).
        """
        if not s:
            return 0.0
        n = len(s)
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        h = 0.0
        for c in freq.values():
            p = float(c) / n
            h -= p * (math.log(p) / math.log(2))
        return h
```

---

- [ ] **Step 2: Run tests — verify contract tests GREEN**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest tests.test_engine.TestEngineImport tests.test_engine.TestAnalyzeReturnContract tests.test_engine.TestAnalyzeStateless tests.test_engine.TestSecretSchema tests.test_engine.TestDictionaryKeyIsListOfTuples -v 2>&1
```

Expected output (all PASS):

```
test_import_succeeds (tests.test_engine.TestEngineImport) ... ok
test_engine_class_exists (tests.test_engine.TestEngineImport) ... ok
test_module_level_validators_exist (tests.test_engine.TestEngineImport) ... ok
test_empty_string_returns_all_six_keys (tests.test_engine.TestAnalyzeReturnContract) ... ok
test_none_body_returns_all_six_keys (tests.test_engine.TestAnalyzeReturnContract) ... ok
test_empty_body_all_lists_empty (tests.test_engine.TestAnalyzeReturnContract) ... ok
...
Ran 18 tests in 0.0XXs
OK
```

---

- [ ] **Step 3: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && git add js_analyzer_engine.py && git commit -m "$(cat <<'EOF'
feat(P0.2): extract pure JSAnalyzerEngine with all regex/noise tables

Copy all ENDPOINT_PATTERNS, URL_PATTERNS, SECRET_PATTERNS, EMAIL_PATTERN,
FILE_PATTERNS, NOISE_DOMAINS, MODULE_PREFIXES, NOISE_PATTERNS, NOISE_STRINGS
verbatim from js_analyzer.py lines 38-211. Promote _is_valid_* instance
methods to module-level functions. Implement JSAnalyzerEngine.analyze()
returning 6-key dict. dictionary=[] stub for Phase 1. 18 contract tests GREEN.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P0.3: Add validator regression tests — lock current detection behavior

**Goal:** Extend `tests/test_engine.py` with a `TestValidators` class that pins the observable behavior of all five `_is_valid_*` functions against the specific cases from spec §5. These tests serve as a regression lock: if any phase accidentally changes existing behavior for non-gated patterns, at least one test breaks.

**Files:**
- `tests/test_engine.py` — Modify (append `TestValidators` class)

---

- [ ] **Step 1: Append `TestValidators` to `tests/test_engine.py`**

Add the following class at the bottom of `/Users/gg/Downloads/JSAnalyzer-main/tests/test_engine.py`, before the `if __name__ == '__main__':` guard (which should also be added if absent):

```python
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
```

---

- [ ] **Step 2: Run all tests — verify full suite GREEN**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest discover tests -v 2>&1
```

Expected output (all pass):

```
test_import_succeeds (tests.test_engine.TestEngineImport) ... ok
...
test_file_longer_json_accepted (tests.test_engine.TestValidators) ... ok
----------------------------------------------------------------------
Ran 47 tests in 0.0XXs
OK
```

---

- [ ] **Step 3: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && git add tests/test_engine.py && git commit -m "$(cat <<'EOF'
test(P0.3): add TestValidators regression lock for all five _is_valid_* functions

Pin current detection behavior with 29 targeted cases covering endpoint
leading-slash rule, noise-domain/data-uri/placeholder rejection, email
example-domain and noreply rejection, package.json/webpack/map rejection,
and backup.sql/certificate acceptance. Full suite of 47 tests GREEN.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P0.4: Wire the adapter — import engine, delegate, delete duplicates

**Goal:** In `js_analyzer.py`, import `JSAnalyzerEngine`, construct `self._engine = JSAnalyzerEngine()` in `registerExtenderCallbacks`, rewrite `analyze_response` to call `self._engine.analyze(body, source_name)` and loop the result keys into `self._add_finding`, then DELETE the now-redundant module-level tables (lines 38-211) and the five `_is_valid_*` instance methods (lines 384-485). This step cannot run under CPython3; a manual Burp verification step follows.

**Files:**
- `js_analyzer.py` — Modify

---

- [ ] **Step 1: Replace `js_analyzer.py` with the thin adapter**

Write the following content to `/Users/gg/Downloads/JSAnalyzer-main/js_analyzer.py`:

```python
# -*- coding: utf-8 -*-
"""
JS Analyzer - Burp Suite Extension
Thin adapter: IBurpExtender, IContextMenuFactory, ITab.
All detection logic lives in js_analyzer_engine (pure Python, no Burp deps).
"""

from burp import IBurpExtender, IContextMenuFactory, ITab

from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.util import ArrayList
from java.io import PrintWriter

import sys
import os
import inspect

# Add extension directory to path so Jython can find js_analyzer_engine.py
# and ui/results_panel.py at the same level.
try:
    _frame = inspect.currentframe()
    if _frame and hasattr(_frame, 'f_code'):
        ext_dir = os.path.dirname(os.path.abspath(_frame.f_code.co_filename))
    else:
        ext_dir = os.getcwd()
except Exception:
    ext_dir = os.getcwd()

if ext_dir and ext_dir not in sys.path:
    sys.path.insert(0, ext_dir)

from ui.results_panel import ResultsPanel
from js_analyzer_engine import JSAnalyzerEngine


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    """JS Analyzer -- thin Burp adapter delegating all detection to JSAnalyzerEngine."""

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName('JS Analyzer')

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # Results storage (dedup and persistence live here, NOT in the engine)
        self.all_findings = []
        self.seen_values = set()

        # Pure detection engine -- stateless per call
        self._engine = JSAnalyzerEngine()

        # Initialize UI
        self.panel = ResultsPanel(callbacks, self)

        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

        self._log('JS Analyzer loaded - Right-click JS responses to analyze')

    def _log(self, msg):
        self._stdout.println('[JS Analyzer] ' + str(msg))

    def getTabCaption(self):
        return 'JS Analyzer'

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu = ArrayList()
        try:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                item = JMenuItem('Analyze JS with JS Analyzer')
                item.addActionListener(AnalyzeAction(self, invocation))
                menu.add(item)
        except Exception as e:
            self._log('Menu error: ' + str(e))
        return menu

    def analyze_response(self, message_info):
        """Analyze a response using the pure engine and push findings to the UI."""
        response = message_info.getResponse()
        if not response:
            return

        # Determine display name for the source file
        try:
            req_info = self._helpers.analyzeRequest(message_info)
            url = str(req_info.getUrl())
            source_name = url.split('/')[-1].split('?')[0] if '/' in url else url
            if len(source_name) > 40:
                source_name = source_name[:40] + '...'
        except Exception:
            url = 'Unknown'
            source_name = 'Unknown'

        # Extract body as string
        resp_info = self._helpers.analyzeResponse(response)
        body_offset = resp_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])

        if len(body) < 50:
            return

        self._log('Analyzing: ' + source_name)

        # Delegate all detection to the pure engine
        result = self._engine.analyze(body, source_name)

        new_findings = []

        # endpoints, urls, emails, files -- values are plain strings
        for category in ('endpoints', 'urls', 'emails', 'files'):
            for value in result[category]:
                finding = self._add_finding(category, value, source_name)
                if finding:
                    new_findings.append(finding)

        # secrets -- values are {'type', 'value', 'masked'};
        # store the masked form in seen_values and display (per existing behavior)
        for secret in result['secrets']:
            masked = secret['masked']
            finding = self._add_finding('secrets', masked, source_name)
            if finding:
                new_findings.append(finding)

        # dictionary -- Phase 0: always [] so this loop is a no-op until Phase 1
        for template, evidence in result['dictionary']:
            finding = self._add_finding('dictionary', template, source_name)
            if finding:
                new_findings.append(finding)

        if new_findings:
            self._log('Found %d new items' % len(new_findings))
            self.panel.add_findings(new_findings, source_name)
        else:
            self._log('No new findings')

    def _add_finding(self, category, value, source):
        """Add a finding to the global list if not already seen (dedup by key)."""
        key = category + ':' + value
        if key in self.seen_values:
            return None
        self.seen_values.add(key)
        finding = {
            'category': category,
            'value': value,
            'source': source,
        }
        self.all_findings.append(finding)
        return finding

    def clear_results(self):
        self.all_findings = []
        self.seen_values = set()

    def get_all_findings(self):
        return self.all_findings


class AnalyzeAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        try:
            messages = self.invocation.getSelectedMessages()
            for msg in messages:
                try:
                    self.extender.analyze_response(msg)
                except Exception as e:
                    self.extender._log('Error analyzing response: ' + str(e))
        except Exception as e:
            if self.extender:
                self.extender._log('Action error: ' + str(e))
```

---

- [ ] **Step 2: Verify no duplicate table definitions remain in the adapter**

```bash
grep -n 'ENDPOINT_PATTERNS\s*=\|URL_PATTERNS\s*=\|SECRET_PATTERNS\s*=\|EMAIL_PATTERN\s*=\|FILE_PATTERNS\s*=\|NOISE_DOMAINS\s*=\|NOISE_STRINGS\s*=\|def _is_valid_endpoint\|def _is_valid_url\|def _is_valid_secret\|def _is_valid_email\|def _is_valid_file' /Users/gg/Downloads/JSAnalyzer-main/js_analyzer.py
```

Expected: no output (all definitions deleted from adapter).

---

- [ ] **Step 3: Verify engine tests still pass after adapter rewrite**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest discover tests -v 2>&1
```

Expected: `Ran 47 tests in 0.0XXs` `OK`

---

- [ ] **Step 4: Manual verification in Burp Suite**

This step cannot be automated (js_analyzer.py imports burp.*). Perform manually:

1. Open Burp Suite Pro/Community.
2. Go to **Extender > Extensions > Add**, select `js_analyzer.py`, type **Python**.
3. Confirm **Output** tab shows exactly: `[JS Analyzer] JS Analyzer loaded - Right-click JS responses to analyze`. Confirm **Errors** tab is empty.
4. Intercept a real JS response in Proxy History (any site with a non-trivial `app.js` or `main.js`). Right-click the row > **Analyze JS with JS Analyzer**.
5. Go to the **JS Analyzer** tab. Confirm at least one tab (Endpoints, URLs, Secrets, Emails, or Files) shows results.
6. Confirm **Endpoints** values all begin with `/` (no bare `api/v1/...` slipping through).
7. Confirm **Secrets** values for entries longer than 20 chars show the masked form `XXXXXXXXXX...XXXX`.
8. Right-click the same message a second time > **Analyze JS with JS Analyzer**. Confirm finding counts do not change (dedup working).
9. Click **Clear** in the JS Analyzer tab. Counts drop to zero. Re-analyze. Counts repopulate. No errors in **Extender > Errors**.

Success criteria: findings identical in content to the pre-refactor extension on the same JS body.

---

- [ ] **Step 5: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && git add js_analyzer.py && git commit -m "$(cat <<'EOF'
refactor(P0.4): wire adapter to JSAnalyzerEngine; delete duplicate tables

Import JSAnalyzerEngine in js_analyzer.py and construct self._engine in
registerExtenderCallbacks. Rewrite analyze_response to delegate all
detection to self._engine.analyze() and loop result keys into _add_finding.
Delete the now-redundant ENDPOINT_PATTERNS, URL_PATTERNS, SECRET_PATTERNS,
EMAIL_PATTERN, FILE_PATTERNS, NOISE_DOMAINS, MODULE_PREFIXES, NOISE_PATTERNS,
NOISE_STRINGS and the five _is_valid_* instance methods from the adapter.
Detection behavior is unchanged; 47 engine tests stay GREEN.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

**Risks for executor (this phase):**
- js_analyzer.py holds the five _is_valid_* methods as instance methods on BurpExtender (lines 384-485) referencing module-level NOISE_PATTERNS, NOISE_DOMAINS, NOISE_STRINGS directly via bare name (no self.). When promoting them to module-level functions in js_analyzer_engine.py, confirm each function still references the correct module-level names. Run 'grep -n self\. js_analyzer_engine.py' after creation; it must return only lines inside the JSAnalyzerEngine class body, never inside the five validator functions.
- The SECRET_PATTERNS loop in analyze_response (js_analyzer.py:320-330) uses 'for pattern, _ in SECRET_PATTERNS' and reads match.group(1). Two patterns -- Telegram Bot Token (line 106) and Heroku API Key (line 108) -- have no capture group in their compiled regex, so match.group(1) raises IndexError. The original code silently swallows this via 'except (IndexError, Exception): continue'. The engine must preserve identical exception handling. After the engine is written, run: python3 -c "from js_analyzer_engine import JSAnalyzerEngine; e=JSAnalyzerEngine(); print(e.analyze('123456789:abcdefghijklmnopqrstuvwxyz1234a'))" and confirm no uncaught exception.
- The TestSecretSchema tests use 'AKIAIOSFODNN7EXAMPL2' (not 'AKIAIOSFODNN7EXAMPLE'). Double-check that the string 'EXAMPL2' does not contain any of the noise keywords ['example','placeholder','your','xxxx','test'] in lowercase -- it does not contain 'example' because 'exampl2' != 'example'. This is intentional and correct.
- The _norm_seg static method in JSAnalyzerEngine recompiles four regex patterns on every call. For Phase 0 this is acceptable (tests only). Phase 1 must hoist those four patterns to module level for Jython performance. Do NOT hoist them in Phase 0 to keep this PR minimal.
- In Jython 2.7, frozenset(generator) can silently produce an empty frozenset in edge cases. The spec (s4.2) recommends frozenset(list(gen)). The Phase 0 _build_index uses a plain set with .add() and then frozenset() which is safe. Phase 1 must keep this pattern when processing the full 49675-line api.txt wordlist.


## Phase 1 — WS1 Passive Dictionary Matching

### Task P1.1: Write failing normalization tests

**Files:**
- `tests/__init__.py` — Create (empty)
- `tests/test_normalization.py` — Create

---

- [ ] **Step 1: Write the failing tests**

```python
# tests/__init__.py
# (empty)
```

```python
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
```

- [ ] **Step 2: Run to verify RED**

```
python3 -m unittest tests.test_normalization -v
```

Expected failure:
```
ImportError: cannot import name '_norm_seg' from 'js_analyzer_engine'
```
(or `ModuleNotFoundError: No module named 'js_analyzer_engine'` if Phase 0 engine stub has no normalization exports yet).

---

### Task P1.2: Implement _norm_seg / _norm_path in js_analyzer_engine.py

**Files:**
- `js_analyzer_engine.py` — Modify (Phase 0 created the stub)

---

- [ ] **Step 1: Write minimal implementation**

Add the following block to `js_analyzer_engine.py` immediately after the `import` block (before any existing regex tables). This defines all four segment-regex constants at **module level** (single definition, no duplication) and the two **module-level functions** `_norm_seg` / `_norm_path`. The `JSAnalyzerEngine` staticmethods (added in Phase 0 P0.2) already delegate to these module-level names, so no staticmethod changes are needed here.

```python
# ---------------------------------------------------------------------------
# §2.1  Normalization helpers — module-level constants (ONE definition each)
# ---------------------------------------------------------------------------
# Note: re is already imported at the top of js_analyzer_engine.py.
# Do NOT add a second `import re`. math is also already present.

_SEG_NUM  = re.compile(r'^\d+$')
_SEG_VER  = re.compile(r'^\d+([._-]\d+)+$')          # 1.0  24_8_0  85-88-31
_SEG_UUID = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)
_SEG_HEX  = re.compile(r'^[0-9a-f]{16,}$', re.IGNORECASE)   # >= 16 hex chars


def _norm_seg(s):
    """Collapse dynamic path segments to '{id}'; first match wins.

    Module-level so it can be imported directly:
        from js_analyzer_engine import _norm_seg
    JSAnalyzerEngine._norm_seg delegates here.
    """
    if (_SEG_NUM.match(s) or _SEG_UUID.match(s) or
            _SEG_HEX.match(s) or _SEG_VER.match(s)):
        return '{id}'
    return s


def _norm_path(p):
    """Normalise every segment of a URL path independently.

    Module-level so it can be imported directly:
        from js_analyzer_engine import _norm_path
    JSAnalyzerEngine._norm_path delegates here.
    """
    return '/'.join(_norm_seg(s) for s in p.split('/'))
```

> **Architecture note (fix [2]):** `_SEG_NUM`, `_SEG_VER`, `_SEG_UUID`, `_SEG_HEX` are compiled **once** at module level here (P1.2). The `JSAnalyzerEngine` staticmethods introduced in P0.2 simply `return _norm_seg(s)` / `return _norm_path(p)` — they do not recompile the regexes. There is exactly one definition of each constant.

- [ ] **Step 2: Run to verify GREEN**

```
python3 -m unittest tests.test_normalization -v
```

Expected output (all 20 tests pass):
```
test_all_literal (tests.test_normalization.TestNormPath) ... ok
test_api_v1_users_id (tests.test_normalization.TestNormPath) ... ok
...
test_v1_not_collapsed (tests.test_normalization.TestNormSeg) ... ok
test_version_dotted (tests.test_normalization.TestNormSeg) ... ok
...
----------------------------------------------------------------------
Ran 20 tests in 0.XXXs

OK
```

- [ ] **Step 3: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main
git add tests/__init__.py tests/test_normalization.py js_analyzer_engine.py
git commit -m "$(cat <<'EOF'
P1.1-1.2: add _norm_seg/_norm_path + normalization tests (GREEN)

Implements §2.1 four-regex normalization scheme: numeric, version,
UUID, and long-hex (>=16) segments collapse to {id}; v1/camelCase
preserved. 20 tests GREEN under CPython3.
EOF
)"
```

---

### Task P1.3: Write failing dictionary-matching tests

**Files:**
- `tests/test_engine.py` — Modify: append TestDictionaryMatching class

---

- [ ] **Step 1: Write the failing tests**

Append the following class to the bottom of `tests/test_engine.py` (do NOT replace the existing Phase 0 tests):

```python
# ---------------------------------------------------------------------------
# TestDictionaryMatching  (spec §5 dictionary tests, verbatim)
# ---------------------------------------------------------------------------

class TestDictionaryMatching(unittest.TestCase):
    """Spec §5 dictionary tests — all must pass once _build_index/_match_dict
    are wired into JSAnalyzerEngine.analyze()."""

    # Minimal wordlist that exercises the index
    WORDLIST = [
        'api/v1/users/{id}',        # stored as-is after lowercasing; {id} passes through _norm_seg unchanged (contains '{')
        'api/v1/users',
        'api/v1/settings',
        'api/v1/users/{id}/settings',  # prefix of a longer path
        # raw (un-normalised) line: engine must normalise before storing
        'reports/2024/summary',
        'repos/deadbeefcafe0001deadbeef/commits',   # long-hex seg in wordlist
    ]

    def setUp(self):
        from js_analyzer_engine import JSAnalyzerEngine
        self.engine = JSAnalyzerEngine(wordlist=self.WORDLIST)

    # --- numeric id matches template ---
    def test_numeric_id_matches_template(self):
        body = 'fetch("/api/v1/users/99999")'
        result = self.engine.analyze(body)
        templates = [t for t, _ in result['dictionary']]
        self.assertIn('api/v1/users/{id}', templates)

    # --- uuid segment matches ---
    def test_uuid_segment_matches(self):
        body = 'url = "api/v1/users/550e8400-e29b-41d4-a716-446655440000"'
        result = self.engine.analyze(body)
        templates = [t for t, _ in result['dictionary']]
        self.assertIn('api/v1/users/{id}', templates)

    # --- alpha-only extra segment NOT promoted to {id} match ---
    def test_alpha_segment_not_promoted(self):
        # 'api/v1/users/abc' — 'abc' is alpha, not a number/uuid/hex16
        # 'api/v1/users/abc' does NOT match 'api/v1/users/{id}'
        body = '"api/v1/users/abc"'
        result = self.engine.analyze(body)
        templates = [t for t, _ in result['dictionary']]
        self.assertNotIn('api/v1/users/{id}', templates)

    # --- exact match (lowercased) ---
    def test_exact_match_lowercased(self):
        body = 'path = "API/V1/SETTINGS"'
        result = self.engine.analyze(body)
        templates = [t for t, _ in result['dictionary']]
        self.assertIn('api/v1/settings', templates)

    # --- no-match returns empty ---
    def test_no_match_returns_empty(self):
        body = 'console.log("hello world")'
        result = self.engine.analyze(body)
        self.assertEqual(result['dictionary'], [])

    # --- _build_index deduplicates ---
    def test_build_index_dedup(self):
        from js_analyzer_engine import JSAnalyzerEngine
        duped = ['api/v1/users', 'api/v1/users', 'API/V1/USERS']
        e = JSAnalyzerEngine(wordlist=duped)
        # Frozenset — length must be 1
        self.assertEqual(len(e._index), 1)

    # --- prefix match on extra trailing segment ---
    def test_prefix_match_extra_trailing_segment(self):
        # candidate 'api/v1/users/42/settings/extra' should match the
        # longest prefix that exists in the index:
        # 'api/v1/users/{id}/settings' (4 segs match the 4-seg wordlist entry)
        body = '"api/v1/users/42/settings/extra"'
        result = self.engine.analyze(body)
        templates = [t for t, _ in result['dictionary']]
        self.assertIn('api/v1/users/{id}/settings', templates)

    # --- cap enforced ---
    def test_cap_enforced(self):
        from js_analyzer_engine import JSAnalyzerEngine, _match_dict
        # Build a large wordlist of distinct paths
        lines = ['api/v1/item%d' % i for i in range(1000)]
        e = JSAnalyzerEngine(wordlist=lines)
        # Build body with many distinct matching candidates (with a numeric id)
        candidates = ' '.join('"api/v1/item%d/42"' % i for i in range(1000))
        result = e.analyze(candidates)
        self.assertLessEqual(len(result['dictionary']), 500)

    # --- result has all 6 keys ---
    def test_analyze_always_has_dictionary_key(self):
        from js_analyzer_engine import JSAnalyzerEngine
        e = JSAnalyzerEngine()   # no wordlist
        result = e.analyze('')
        self.assertIn('dictionary', result)
        self.assertIsInstance(result['dictionary'], list)

    # --- two differing concrete ids -> exactly 1 template finding ---
    def test_two_concrete_ids_one_template(self):
        body = '"api/v1/users/1" "api/v1/users/2"'
        result = self.engine.analyze(body)
        templates = [t for t, _ in result['dictionary']]
        self.assertEqual(templates.count('api/v1/users/{id}'), 1)

    # --- long-hex segment in candidate matches long-hex wordlist entry ---
    def test_long_hex_wordlist_entry(self):
        body = '"repos/abcdef0123456789abcdef0123456789/commits"'
        result = self.engine.analyze(body)
        templates = [t for t, _ in result['dictionary']]
        # wordlist has 'repos/deadbeefcafe0001deadbeef/commits'
        # normalised: 'repos/{id}/commits'
        self.assertIn('repos/{id}/commits', templates)
```

- [ ] **Step 2: Run to verify RED**

```
python3 -m unittest tests.test_engine.TestDictionaryMatching -v
```

Expected failure (engine has no `_index` attribute and `analyze()` has no `'dictionary'` key yet):
```
ERROR: test_analyze_always_has_dictionary_key ...
AttributeError: 'JSAnalyzerEngine' object has no attribute '_index'
  (or KeyError: 'dictionary')
...
FAILED (errors=11)
```

---

### Task P1.4: Implement _build_index, _DICT_CAND, _match_dict; wire analyze()

**Files:**
- `js_analyzer_engine.py` — Modify

---

- [ ] **Step 1: Write minimal implementation**

In `js_analyzer_engine.py`, inside the `JSAnalyzerEngine` class:

**__init__ change** — add `wordlist` parameter and build the frozenset:

```python
class JSAnalyzerEngine(object):

    def __init__(self, wordlist=None):
        if wordlist is not None:
            self._index = JSAnalyzerEngine._build_index(wordlist)
        else:
            self._index = frozenset()
```

**_build_index staticmethod** (spec §2.2):

```python
    @staticmethod
    def _build_index(lines):
        idx = set()
        for ln in lines:
            p = ln.strip().lower()
            if p:
                idx.add(_norm_path(p))
        return frozenset(idx)
```

**_norm_path and _norm_seg staticmethods** — expose as staticmethods on the class too (the module-level functions already exist; just delegate):

```python
    @staticmethod
    def _norm_seg(s):
        return _norm_seg(s)

    @staticmethod
    def _norm_path(p):
        return _norm_path(p)
```

**Module-level regex and function** (spec §2.3) — add after `_norm_path`:

```python
# ---------------------------------------------------------------------------
# §2.3  Candidate extraction & match
# ---------------------------------------------------------------------------
_DICT_CAND = re.compile(r'[A-Za-z0-9_.~-]+(?:/[A-Za-z0-9_.~-]+)+')


def _match_dict(body, idx, cap=500):
    """Extract path-like candidates from body and match against the index.

    Returns a list of (template, evidence) tuples capped at `cap`.
    """
    out = []
    seen = set()
    for m in _DICT_CAND.finditer(body):
        c = m.group(0).lower().lstrip('/')
        if len(c) > 512 or c.count('/') > 12:
            continue
        segs = [_norm_seg(s) for s in c.split('/')]
        if len(segs) < 2:
            continue
        for k in range(len(segs), 1, -1):     # longest-prefix walk
            tmpl = '/'.join(segs[:k])
            if tmpl in idx:
                if tmpl not in seen:
                    seen.add(tmpl)
                    out.append((tmpl, m.group(0)))
                    if len(out) >= cap:
                        return out
                break
    return out
```

**analyze() change** — always include `'dictionary'` key; populate it when `_index` is non-empty:

```python
    def analyze(self, js_text, source=None):
        """Analyse js_text and return a result dict with all 6 keys."""
        result = {
            'endpoints': [],
            'urls': [],
            'secrets': [],
            'emails': [],
            'files': [],
            'dictionary': [],
        }

        if not js_text:
            return result

        # --- existing endpoint / url / secret / email / file extraction ---
        # (Phase 0 code remains here unchanged)
        # ...

        # --- §2.3 dictionary matching ---
        if self._index:
            result['dictionary'] = _match_dict(js_text, self._index, cap=500)

        return result
```

- [ ] **Step 2: Run to verify GREEN**

```
python3 -m unittest tests.test_engine.TestDictionaryMatching -v
```

Expected:
```
test_alpha_segment_not_promoted ... ok
test_analyze_always_has_dictionary_key ... ok
test_build_index_dedup ... ok
test_cap_enforced ... ok
test_exact_match_lowercased ... ok
test_long_hex_wordlist_entry ... ok
test_no_match_returns_empty ... ok
test_numeric_id_matches_template ... ok
test_prefix_match_extra_trailing_segment ... ok
test_two_concrete_ids_one_template ... ok
test_uuid_segment_matches ... ok
----------------------------------------------------------------------
Ran 11 tests in 0.XXXs

OK
```

Also run the full suite to confirm no regressions:

```
python3 -m unittest discover tests -v
```

Expected: all normalization + engine tests pass, zero failures.

- [ ] **Step 3: Perf sanity (optional, not a hard test)**

Run from the project root to verify index build time is within the §8 budget:

```
python3 -c "
import time, js_analyzer_engine
lines = open('api.txt').readlines()
t0 = time.time()
idx = js_analyzer_engine.JSAnalyzerEngine._build_index(lines)
elapsed = (time.time() - t0) * 1000
print('entries=%d  build=%.1f ms' % (len(idx), elapsed))
"
```

Expected (CPython3 reference numbers from spec §2.2):
```
entries=47905  build=NNN ms   (target < 300 ms)
```

- [ ] **Step 4: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main
git add js_analyzer_engine.py tests/test_engine.py
git commit -m "$(cat <<'EOF'
P1.3-1.4: _build_index/_match_dict + TestDictionaryMatching (GREEN)

Implements §2.2-2.3: frozenset index (O(1) lookup), DICT_CAND regex,
longest-prefix walk, cap=500, per-response dedup via seen set.
11 dictionary tests GREEN; full test suite no regressions.
EOF
)"
```

---

### Task P1.5: Adapter — read api.txt and wire dictionary findings

**Files:**
- `js_analyzer.py` — Modify

---

- [ ] **Step 1: Write minimal implementation**

**registerExtenderCallbacks** — read `api.txt` and build the engine with the wordlist.

Replace the current `registerExtenderCallbacks` body in `js_analyzer.py`.

Current code (lines 217–236):
```python
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("JS Analyzer")
        
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Results storage
        self.all_findings = []
        self.seen_values = set()
        
        # Initialize UI
        self.panel = ResultsPanel(callbacks, self)
        
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        
        self._log("JS Analyzer loaded - Right-click JS responses to analyze")
```

Replace with:

```python
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("JS Analyzer")

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # Results storage
        self.all_findings = []
        self.seen_values = set()

        # Load wordlist (api.txt next to this file) for dictionary matching.
        # Uses codecs.open for explicit UTF-8 decoding under both Py2 and Py3.
        # Missing or unreadable file is non-fatal: engine runs with empty index.
        wordlist_lines = []
        try:
            import codecs as _codecs
            _wl_path = os.path.join(ext_dir, 'api.txt')
            with _codecs.open(_wl_path, 'r', 'utf-8') as _wl_fh:
                wordlist_lines = _wl_fh.readlines()
            self._log('Loaded wordlist: %d lines from api.txt' % len(wordlist_lines))
        except IOError:
            self._log('api.txt not found — dictionary matching disabled')
        except Exception as _wl_err:
            self._log('api.txt load error: %s' % str(_wl_err))

        # Build pure engine (zero Burp deps)
        from js_analyzer_engine import JSAnalyzerEngine
        self._engine = JSAnalyzerEngine(wordlist=wordlist_lines if wordlist_lines else None)

        # Initialize UI
        self.panel = ResultsPanel(callbacks, self)

        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

        self._log('JS Analyzer loaded - Right-click JS responses to analyze')
```

**analyze_response** — after the existing findings loop, add dictionary matching.

Locate the end of `analyze_response`, just before the `# Update UI` comment (around line 363 in the original). Add:

```python
        # 6. Dictionary matching (wordlist-based path template detection)
        try:
            dict_hits = self._engine.analyze(body).get('dictionary', [])
            for tmpl, evidence in dict_hits:
                key = 'dictionary:' + tmpl
                finding = self._add_finding('dictionary', tmpl, source_name)
                if finding:
                    new_findings.append(finding)
        except Exception as e:
            self._log('Error in dictionary matching: ' + str(e))
```

Note: `_add_finding` already uses `category + ':' + value` as the dedup key (line 371 in original), so the key will be `'dictionary:' + tmpl` automatically — the explicit `key` variable above is just for clarity; the actual dedup happens inside `_add_finding`. (Spec-gap G2: dedup key is `'dictionary:' + template` — `_add_finding` builds `category + ':' + value`, so passing `value=template` gives the spec §2.4 key.)

- [ ] **Step 2: Manual verification in Burp**

This code runs under Jython 2.7 and cannot be covered by python3 unit tests. Verify manually:

1. Load the extension in Burp Suite (Extender → Extensions → Add → Python, select `js_analyzer.py`).
2. Check the **Output** tab for the extension. You must see:
   ```
   [JS Analyzer] Loaded wordlist: 49675 lines from api.txt
   [JS Analyzer] JS Analyzer loaded - Right-click JS responses to analyze
   ```
3. If `api.txt` is absent, you must see `api.txt not found — dictionary matching disabled` (not an error/stack trace).
4. In Burp's Proxy History, find a JS response that contains paths like `api/v1/users/42` or similar. Right-click → "Analyze JS with JS Analyzer".
5. In the **JS Analyzer** tab, the **Dictionary** tab (6th tab) must appear and show at least one row with template `api/v1/users/{id}` and the source JS filename.
6. Run the same JS response a second time. The Dictionary tab count must NOT increase (dedup working).

---

### Task P1.6: UI — add Dictionary tab and fix all hardcoded category sites

**Files:**
- `ui/results_panel.py` — Modify

The grep audit above found every hardcoded category site. There are **7 sites** to update:

| Line | Site | Change needed |
|------|------|---------------|
| 27–33 | `self.findings` dict initializer | Add `"dictionary": []` |
| 52 | `stats_label` initial string | Change to `"| E:0 | U:0 | S:0 | M:0 | F:0 | D:0"` |
| 102–108 | `categories` list in `_init_ui` | Append `("Dictionary", "dictionary")` with columns Template/Source |
| 156–157 | `titles` / `keys` lists in `_refresh_tables` | Append `"Dictionary"` / `"dictionary"` |
| 192 | `_update_stats` format string | Add `D` counter |
| 197–199 | `_get_current_table` `keys` list | Append `"dictionary"` |
| 205–207 | `_get_current_key` `keys` list | Append `"dictionary"` |
| 268–274 | `export_all` export dict | Add `"dictionary"` key |

- [ ] **Step 1: Enumerate every hardcoded category site (mandatory verification step)**

Run this command first and confirm the output matches the table above before editing:

```bash
grep -n 'endpoints\|emails\|files\|urls\|secrets\|categories\|titles\b\|keys\b\|stats_label\|_update_stats\|export' /Users/gg/Downloads/JSAnalyzer-main/ui/results_panel.py
```

- [ ] **Step 2: Write minimal implementation**

Apply the following 8 targeted edits to `/Users/gg/Downloads/JSAnalyzer-main/ui/results_panel.py`:

**Edit 1 — findings dict (line 27):**

```python
# OLD
        self.findings = {
            "endpoints": [],
            "urls": [],
            "secrets": [],
            "emails": [],
            "files": [],
        }
```
```python
# NEW
        self.findings = {
            "endpoints": [],
            "urls": [],
            "secrets": [],
            "emails": [],
            "files": [],
            "dictionary": [],
        }
```

**Edit 2 — stats_label initial string (line 52):**

```python
# OLD
        self.stats_label = JLabel("| E:0 | U:0 | S:0 | M:0")
```
```python
# NEW
        self.stats_label = JLabel("| E:0 | U:0 | S:0 | M:0 | F:0 | D:0")
```

**Edit 3 — categories list in _init_ui (lines 102–108):**

The existing `categories` list uses generic `["Value", "Source"]` columns for all tabs. The Dictionary tab uses `["Template", "Source"]` columns. Since all other tabs have exactly 2 columns and the column width assignments reference index 0 and 1, extend the loop to accept an optional third element for column names:

```python
# OLD
        categories = [
            ("Endpoints", "endpoints"),
            ("URLs", "urls"),
            ("Secrets", "secrets"),
            ("Emails", "emails"),
            ("Files", "files"),
        ]
        
        for title, key in categories:
            panel = JPanel(BorderLayout())
            
            # 2 columns: Value, Source
            columns = ["Value", "Source"]
```

```python
# NEW
        categories = [
            ("Endpoints", "endpoints", ["Value", "Source"]),
            ("URLs", "urls", ["Value", "Source"]),
            ("Secrets", "secrets", ["Value", "Source"]),
            ("Emails", "emails", ["Value", "Source"]),
            ("Files", "files", ["Value", "Source"]),
            ("Dictionary", "dictionary", ["Template", "Source"]),
        ]

        for title, key, columns in categories:
            panel = JPanel(BorderLayout())
```

**Edit 4 — titles/keys lists in _refresh_tables (lines 156–157):**

```python
# OLD
        titles = ["Endpoints", "URLs", "Secrets", "Emails", "Files"]
        keys = ["endpoints", "urls", "secrets", "emails", "files"]
```
```python
# NEW
        titles = ["Endpoints", "URLs", "Secrets", "Emails", "Files", "Dictionary"]
        keys = ["endpoints", "urls", "secrets", "emails", "files", "dictionary"]
```

**Edit 5 — _update_stats (line 192):**

```python
# OLD
        self.stats_label.setText("| E:%d | U:%d | S:%d | M:%d | F:%d" % (e, u, s, m, f))
```
```python
# NEW
        d = len(self.findings.get("dictionary", []))
        self.stats_label.setText("| E:%d | U:%d | S:%d | M:%d | F:%d | D:%d" % (e, u, s, m, f, d))
```

**Edit 6 — _get_current_table keys list (line 197):**

```python
# OLD
        keys = ["endpoints", "urls", "secrets", "emails", "files"]
        if 0 <= idx < len(keys):
            return self.tables.get(keys[idx])
        return None
```
```python
# NEW
        keys = ["endpoints", "urls", "secrets", "emails", "files", "dictionary"]
        if 0 <= idx < len(keys):
            return self.tables.get(keys[idx])
        return None
```

**Edit 7 — _get_current_key keys list (line 205):**

```python
# OLD
        keys = ["endpoints", "urls", "secrets", "emails", "files"]
        if 0 <= idx < len(keys):
            return keys[idx]
        return None
```
```python
# NEW
        keys = ["endpoints", "urls", "secrets", "emails", "files", "dictionary"]
        if 0 <= idx < len(keys):
            return keys[idx]
        return None
```

**Edit 8 — export_all dict (lines 268–274):**

```python
# OLD
            export = {
                "endpoints": [f["value"] for f in self.findings.get("endpoints", [])],
                "urls": [f["value"] for f in self.findings.get("urls", [])],
                "secrets": [f["value"] for f in self.findings.get("secrets", [])],
                "emails": [f["value"] for f in self.findings.get("emails", [])],
                "files": [f["value"] for f in self.findings.get("files", [])],
            }
```
```python
# NEW
            export = {
                "endpoints": [f["value"] for f in self.findings.get("endpoints", [])],
                "urls": [f["value"] for f in self.findings.get("urls", [])],
                "secrets": [f["value"] for f in self.findings.get("secrets", [])],
                "emails": [f["value"] for f in self.findings.get("emails", [])],
                "files": [f["value"] for f in self.findings.get("files", [])],
                "dictionary": [f["value"] for f in self.findings.get("dictionary", [])],
            }
```

- [ ] **Step 3: Manual verification in Burp**

This file imports `javax.swing` and cannot run under python3 tests. Verify manually:

1. Reload the extension (Extender → Extensions → select JS Analyzer → Reload).
2. The extension must load without errors (Output tab clean).
3. In the **JS Analyzer** tab, verify there are now **6 tabs**: Endpoints, URLs, Secrets, Emails, Files, **Dictionary**.
4. The stats label in the header must read `| E:0 | U:0 | S:0 | M:0 | F:0 | D:0` on fresh load.
5. Right-click a JS response containing paths like `api/v1/users/42`. After analysis:
   - The **Dictionary (N)** tab title shows a count > 0.
   - The stats label shows `D:N` with the correct count.
   - The Dictionary tab table shows two columns: **Template** and **Source**.
   - The Template column shows the normalized template (e.g. `api/v1/users/{id}`).
6. Click **Export**. Open the saved JSON. Confirm the key `"dictionary"` is present and contains the matched templates as strings.
7. Click the Dictionary tab, then click **Copy All**. The clipboard must contain one template per line.

- [ ] **Step 4: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main
git add ui/results_panel.py js_analyzer.py
git commit -m "$(cat <<'EOF'
P1.5-1.6: wire dictionary findings in adapter + 6th Dictionary UI tab

js_analyzer.py: reads api.txt via codecs.open (UTF-8, missing-file safe),
builds JSAnalyzerEngine(wordlist=lines), loops result['dictionary'] into
_add_finding('dictionary', template, source).

ui/results_panel.py: adds 'dictionary' to findings dict, categories list
(Template|Source columns), titles/keys in _refresh_tables, _get_current_table
/_get_current_key, _update_stats (D: counter), stats_label initial string,
and export_all JSON map. 7 category sites updated per grep audit.
EOF
)"
```

**Risks for executor (this phase):**
- Phase 0 must exist: js_analyzer_engine.py must already have the class stub with analyze() returning a dict and the existing import re / import math lines. If Phase 0 is not complete, Step 1.2 will fail to find the module. Verify with `python3 -c 'from js_analyzer_engine import JSAnalyzerEngine'` before starting P1.2.
- Jython 2.7 string encoding: api.txt may contain non-ASCII characters. The codecs.open(..., 'utf-8') call with errors='replace' should be used if IOError occurs on malformed lines under Jython. Adjust if load errors appear in Burp Output tab.
- _match_dict called twice in P1.5: the adapter calls self._engine.analyze(body) which internally runs all extraction including endpoints/urls/secrets. If Phase 0 already calls engine.analyze() for those, do NOT call it a second time for dictionary — instead call engine.analyze() once and read all keys from the single result dict to avoid double-processing.
- categories list iteration change in P1.6 Edit 3: the loop unpacking changes from `for title, key in categories` to `for title, key, columns in categories`. If any other method in results_panel.py also iterates the categories list by reference (e.g. a stored self.categories attribute), that code must be updated too. Grep for 'self.categories' before committing.
- Column width assignment in _init_ui: after Edit 3 the loop body references `columns` from the tuple instead of a hardcoded list. The `table.getColumnModel().getColumn(0).setPreferredWidth(500)` line remains valid for both 2-column layouts (Value/Source and Template/Source) since both have column 0.
- Dedup key collision: _add_finding uses `category + ':' + value` as the key. For dictionary findings the value is the template string (e.g. 'api/v1/users/{id}'). If by coincidence an endpoint or url finding has an identical value string, the dedup key will differ because the category prefix differs — this is correct behavior but worth confirming no cross-category collisions cause silent drops.
- Memory: _build_index on 49,675 lines allocates ~5-6 MB. Under Jython this runs once at load time synchronously on the EDT (in registerExtenderCallbacks). For a wordlist of this size the ~150-200 ms Jython build time is acceptable, but if Burp's load timeout is shorter, move the build to a background java.lang.Thread and gate analyze_response until the index is ready (set self._index = None initially, check before calling _match_dict).


## Phase 2 — WS3 Improvements

### Task P2.1: Secret FP tests — RED

**Files:**
- `tests/__init__.py` Create (empty, if not already present from Phase 0)
- `tests/test_engine.py` Create/Modify — add `TestSecretFalsePositives`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_engine.py  (full file — create if not present, otherwise append class)
import unittest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# --- Phase 0 contract tests (kept here for regression) ---
class TestEngineContract(unittest.TestCase):
    def setUp(self):
        from js_analyzer_engine import JSAnalyzerEngine
        self.engine = JSAnalyzerEngine()

    def test_import_no_burp(self):
        import js_analyzer_engine  # must not raise

    def test_analyze_empty_returns_all_keys(self):
        r = self.engine.analyze('')
        for k in ('endpoints','urls','secrets','emails','files','dictionary'):
            self.assertIn(k, r)
            self.assertEqual(r[k], [])

    def test_stateless(self):
        from js_analyzer_engine import JSAnalyzerEngine
        e1 = JSAnalyzerEngine()
        e2 = JSAnalyzerEngine()
        r1 = e1.analyze('AKIA1234567890ABCDEF')
        r2 = e2.analyze('')
        self.assertEqual(r2['secrets'], [])

    def test_secret_dict_shape(self):
        from js_analyzer_engine import JSAnalyzerEngine
        r = JSAnalyzerEngine().analyze('AKIA1234567890ABCDEF')
        if r['secrets']:
            s = r['secrets'][0]
            self.assertIn('type', s)
            self.assertIn('value', s)
            self.assertIn('masked', s)


# --- Phase 2: Secret FP gate tests ---
class TestSecretFalsePositives(unittest.TestCase):
    def setUp(self):
        from js_analyzer_engine import JSAnalyzerEngine
        self.engine = JSAnalyzerEngine()

    def _secrets(self, text):
        return self.engine.analyze(text)['secrets']

    # bare hex32 without context => 0 secrets
    def test_bare_hex32_no_context_rejected(self):
        vals = self._secrets('var x = "deadbeefdeadbeefdeadbeefdeadbeef";')
        types = [s['type'] for s in vals]
        self.assertNotIn('Bugsnag API Key', types,
            'bare hex32 without "bugsnag" context must NOT be reported as Bugsnag')

    # bugsnag context + high entropy => reported
    def test_bugsnag_with_context_accepted(self):
        # 32-char hex with high entropy
        key = 'a3f1e29c7b84d56f0e91c2a748b3d5e6'
        text = 'bugsnag.apiKey = "%s"' % key
        vals = self._secrets(text)
        types = [s['type'] for s in vals]
        self.assertIn('Bugsnag API Key', types,
            'hex32 with "bugsnag" context and high entropy MUST be reported')

    # low entropy hex with bugsnag context => rejected
    def test_bugsnag_low_entropy_rejected(self):
        key = 'aaaabbbbccccddddaaaabbbbccccdddd'   # entropy ~2.0
        text = 'bugsnag.apiKey = "%s"' % key
        vals = self._secrets(text)
        types = [s['type'] for s in vals]
        self.assertNotIn('Bugsnag API Key', types,
            'low-entropy hex32 must be rejected even with bugsnag context')

    # bare [a-z0-9]{32} without context => 0 Datadog findings
    def test_bare_alnum32_no_context_rejected(self):
        vals = self._secrets('var token = "abcdef1234567890abcdef1234567890";')
        types = [s['type'] for s in vals]
        self.assertNotIn('Datadog API Key', types,
            'bare alnum32 without "datadog" context must NOT be reported')

    # datadog context + high entropy => reported
    def test_datadog_with_context_accepted(self):
        key = 'a3f1e29c7b84d56f0e91c2a748b3d5e7'
        text = 'datadog_api_key = "%s"' % key
        vals = self._secrets(text)
        types = [s['type'] for s in vals]
        self.assertIn('Datadog API Key', types)

    # AKIA (fixed-prefix KEEP) still reported — bypass entropy floor
    def test_akia_still_reported(self):
        vals = self._secrets('aws_key = "AKIA1234567890ABCDEF"')
        types = [s['type'] for s in vals]
        self.assertIn('AWS Key', types)

    # JWT still reported
    def test_jwt_reported(self):
        text = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"'
        vals = self._secrets(text)
        types = [s['type'] for s in vals]
        self.assertIn('JWT', types)

    # all-same-char value => rejected
    def test_all_same_char_rejected(self):
        from js_analyzer_engine import _is_valid_secret
        self.assertFalse(_is_valid_secret('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))

    # UUID shape => rejected
    def test_uuid_shape_rejected(self):
        from js_analyzer_engine import _is_valid_secret
        self.assertFalse(_is_valid_secret('550e8400-e29b-41d4-a716-446655440000'))

    # Telegram without context => not reported
    def test_telegram_without_context_rejected(self):
        # bare pattern: 9 digits : 35 alnum
        text = 'var x = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";'
        vals = self._secrets(text)
        types = [s['type'] for s in vals]
        self.assertNotIn('Telegram Bot Token', types,
            'Telegram token without telegram/tg/bot context must not be reported')

    def test_telegram_with_context_accepted(self):
        text = 'telegram_bot_token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"'
        vals = self._secrets(text)
        types = [s['type'] for s in vals]
        self.assertIn('Telegram Bot Token', types)

    # Twilio SK without context => not reported
    def test_twilio_without_context_rejected(self):
        text = 'var k = "SK' + 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" + '"'
        vals = self._secrets(text)
        types = [s['type'] for s in vals]
        self.assertNotIn('Twilio API Key', types)

    def test_twilio_with_context_accepted(self):
        text = 'twilio_key = "SK' + 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4' + '"'
        vals = self._secrets(text)
        types = [s['type'] for s in vals]
        self.assertIn('Twilio API Key', types)

    # Dropbox without context => not reported
    def test_dropbox_without_context_rejected(self):
        text = 'var t = "sl.ABcDeFgHiJkLmNoPqRsTuVwXyZabcdefghijklmnopqr";'
        vals = self._secrets(text)
        types = [s['type'] for s in vals]
        self.assertNotIn('Dropbox Access Token', types)

    def test_dropbox_with_context_accepted(self):
        text = 'dropbox_token = "sl.ABcDeFgHiJkLmNoPqRsTuVwXyZabcdefghijklmnopqr"'
        vals = self._secrets(text)
        types = [s['type'] for s in vals]
        self.assertIn('Dropbox Access Token', types)

    # min-length floor raised from 10 to 12 in Phase 2
    def test_length_11_below_new_floor_rejected(self):
        from js_analyzer_engine import _is_valid_secret
        self.assertFalse(_is_valid_secret('AKIA1234567'))  # len=11, below new floor of 12
        # Raised from 10 to 12 in Phase 2 to exclude very short ambiguous patterns

    # example/placeholder tokens => rejected
    def test_example_token_rejected(self):
        from js_analyzer_engine import _is_valid_secret
        self.assertFalse(_is_valid_secret('your_api_key_here_example'))
        self.assertFalse(_is_valid_secret('xxxxxxxxxxxxxxxxxxxxxxxxxxxx'))
        self.assertFalse(_is_valid_secret('changeme_placeholder_value_1'))

    # per-response span dedup: same value matched by two patterns => 1 finding
    def test_span_dedup_one_finding_per_value(self):
        # AKIA key appears once in body
        text = 'AKIA1234567890ABCDEF'
        vals = self._secrets(text)
        akia_vals = [s for s in vals if s['type'] == 'AWS Key']
        self.assertEqual(len(akia_vals), 1, 'same span must not produce duplicate findings')

    # masked field present and non-empty
    def test_masked_field_present(self):
        vals = self._secrets('bugsnag.key = "a3f1e29c7b84d56f0e91c2a748b3d5e6"')
        for s in vals:
            self.assertIn('masked', s)
            self.assertTrue(len(s['masked']) > 0)

    # raw value stored (for dedup key in adapter)
    def test_value_field_is_raw(self):
        vals = self._secrets('bugsnag.key = "a3f1e29c7b84d56f0e91c2a748b3d5e6"')
        for s in vals:
            # value should equal the captured group, not masked
            self.assertEqual(s['value'], s['value'].strip())
            self.assertNotIn('...', s['value'],
                'secret value field must be raw (unmasked)')


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify RED**

```
python3 -m unittest tests.test_engine.TestSecretFalsePositives -v
```

Expected failure (engine does not exist yet or lacks the gated patterns):
```
ModuleNotFoundError: No module named 'js_analyzer_engine'
```
(or, if Phase 0 stub exists: `AssertionError: bare hex32 without "bugsnag" context must NOT be reported as Bugsnag`)

- [ ] **Step 3: Write minimal implementation — entropy helpers and rewritten SECRET_PATTERNS in `js_analyzer_engine.py`**

> **Spec-gap note (G1):** Spec §4.3's `_is_valid_secret(value)` is pseudocode; the real signature is `_is_valid_secret(value, label=None)` where label lets the 19 fixed-prefix KEEP patterns bypass the entropy floor.

This step assumes Phase 0 created the engine stub with the basic structure. Add/replace the following sections (shown as the complete relevant additions to `js_analyzer_engine.py`):

```python
# js_analyzer_engine.py  — additions/replacements for Phase 2
# Add at module level AFTER existing imports (re, math):

import math

# ==================== SECRET FP REDUCTION ====================

_ENTROPY_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE)
_HEX64_RE = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)
_COLOR_RE = re.compile(r'^#?[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?$')

_COMMON_WORDS = frozenset([
    'undefined', 'function', 'prototype', 'constructor', 'arguments',
    'document', 'window', 'object', 'string', 'boolean', 'number',
    'return', 'import', 'export', 'default', 'module', 'require',
])

# Labels whose prefix IS the precision — bypass entropy floor entirely
_SECRET_KEEP_LABELS = frozenset([
    'AWS Key',
    'Google API',
    'Stripe Live',
    'GitHub PAT',
    'Slack Token',
    'JWT',
    'Private Key',
    'MongoDB',
    'PostgreSQL',
    'MySQL URI with Credentials',
    'Segment Public API Token',
    'Segment API Key',
    'Facebook App ID',
    'Facebook Secret Key',
    'Facebook Access Token',
    'Google OAuth2 Access Token',
    'Linear API Key',
    'Heroku API Key',
    'DigitalOcean Token',
    'SendGrid API Key',
    'GitLab Token',
    'Shopify Access Token',
    'New Relic Key',
])

# Most-specific first; context-gated patterns replace bare ones
SECRET_PATTERNS = [
    # Fixed-prefix KEEP patterns (bypass entropy)
    (re.compile(r'(AKIA[0-9A-Z]{16})'), 'AWS Key'),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), 'Google API'),
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'), 'Stripe Live'),
    (re.compile(r'(ghp_[0-9a-zA-Z]{36})'), 'GitHub PAT'),
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'), 'Slack Token'),
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'), 'JWT'),
    (re.compile(r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)'), 'Private Key'),
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]+)'), 'MongoDB'),
    (re.compile(r'(postgres(?:ql)?://[^\s"\'<>]+)'), 'PostgreSQL'),
    (re.compile(r'(mysql://[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:/[^\s"\'?:]+)?(?:\?[^\s"\']*)?)'), 'MySQL URI with Credentials'),
    (re.compile(r'\b(sgp_[A-Z0-9_-]{60,70})\b'), 'Segment Public API Token'),
    (re.compile(r'(?i)(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}([A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})'), 'Segment API Key'),
    (re.compile(r'(?i)(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})\b'), 'Facebook App ID'),
    (re.compile(r'(?i)(?:facebook|fb).{0,32}(?:api|app|application|client|consumer|secret|key).{0,32}([a-z0-9]{32})\b'), 'Facebook Secret Key'),
    (re.compile(r'(EAACEdEose0cBA[A-Z0-9]{20,})\b'), 'Facebook Access Token'),
    (re.compile(r'\b(ya29\.[a-z0-9_-]{30,})\b'), 'Google OAuth2 Access Token'),
    (re.compile(r'\b(lin_api_[a-zA-Z0-9]{40})\b'), 'Linear API Key'),
    (re.compile(r'[hH]eroku[\'"][0-9a-f]{32}[\'"]'), 'Heroku API Key'),
    (re.compile(r'\b(dop_v1_[a-z0-9]{64})\b'), 'DigitalOcean Token'),
    (re.compile(r'(SG\.[\w\d\-_]{22}\.[\w\d\-_]{43})'), 'SendGrid API Key'),
    (re.compile(r'\b(glpat-[0-9a-zA-Z\-_]{20})\b'), 'GitLab Token'),
    (re.compile(r'\b(shpat_[0-9a-fA-F]{32})\b'), 'Shopify Access Token'),
    (re.compile(r'\b(NRII-[a-zA-Z0-9]{20,})\b'), 'New Relic Key'),
    # Already context-gated
    (re.compile(r'(?i)algolia.{0,32}([a-z0-9]{32})\b'), 'Algolia Admin API Key'),
    (re.compile(r'(?i)algolia.{0,16}([A-Z0-9]{10})\b'), 'Algolia Application ID'),
    (re.compile(r'(?i)cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b'), 'Cloudflare API Token'),
    (re.compile(r'(?i)(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b'), 'Cloudflare Service Key'),
    # GATED replacements (context required)
    (re.compile(r'(?i)bugsnag.{0,40}([a-f0-9]{32})\b'), 'Bugsnag API Key'),
    (re.compile(r'(?i)datadog.{0,40}([a-z0-9]{32})\b'), 'Datadog API Key'),
    (re.compile(r'(?i)(?:telegram|tg|bot)\D{0,16}(\d{9}:[a-zA-Z0-9_-]{35})\b'), 'Telegram Bot Token'),
    (re.compile(r'(?i)twilio.{0,40}(SK[0-9a-fA-F]{32})\b'), 'Twilio API Key'),
    (re.compile(r'(?i)dropbox.{0,40}(sl\.[A-Za-z0-9_-]{43,})\b'), 'Dropbox Access Token'),
]


def _entropy(s):
    """Shannon entropy (bits). Py2/Py3 compatible."""
    if not s:
        return 0.0
    n = len(s)
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    h = 0.0
    for c in freq.values():
        p = float(c) / n
        h -= p * (math.log(p) / math.log(2))
    return h


def _is_valid_secret(value, label=''):
    """
    Return True if value looks like a real secret.
    Fixed-prefix KEEP patterns bypass the entropy floor (label in _SECRET_KEEP_LABELS).

    Spec §4.3 note (spec-gap G1): spec uses _is_valid_secret(value) pseudocode;
    the real signature is _is_valid_secret(value, label=None) where label lets
    the 19 fixed-prefix KEEP patterns bypass the entropy floor.
    """
    if not value or len(value) < 12:  # Raised from 10 to 12 in Phase 2 to exclude very short ambiguous patterns
        return False
    v = value.strip()
    vl = v.lower()
    for x in ('example', 'placeholder', 'your', 'xxxx', 'test',
              'sample', 'dummy', 'changeme', '0000', '1234'):
        if x in vl:
            return False
    if len(set(v)) <= 2:
        return False
    if vl.isalpha() and vl in _COMMON_WORDS:
        return False
    if _UUID_RE.match(v) or _HEX64_RE.match(v) or _COLOR_RE.match(v):
        return False
    # Entropy floor — bypassed for known fixed-prefix patterns
    if label not in _SECRET_KEEP_LABELS:
        threshold = 3.0 if _ENTROPY_HEX_RE.match(v) else 4.0
        if _entropy(v) < threshold:
            return False
    return True
```

Then replace the `analyze` method's secrets section to pass `label`, implement span dedup, and return the correct dict shape:

```python
# Inside JSAnalyzerEngine.analyze() — secrets extraction block
# (replaces the secrets loop)

    def analyze(self, js_text, source=None):
        result = {
            'endpoints': [],
            'urls': [],
            'secrets': [],
            'emails': [],
            'files': [],
            'dictionary': [],
        }
        if not js_text:
            return result

        body = js_text

        # --- Endpoints ---
        seen_ep = set()
        for pattern, label in ENDPOINT_PATTERNS:
            for m in pattern.finditer(body):
                try:
                    value = m.group(1).strip()
                except IndexError:
                    continue
                if _is_valid_endpoint(value, label):
                    if value not in seen_ep:
                        seen_ep.add(value)
                        result['endpoints'].append(value)

        # --- URLs ---
        seen_url = set()
        for pattern in URL_PATTERNS:
            for m in pattern.finditer(body):
                try:
                    value = (m.group(1) if m.lastindex else m.group(0)).strip()
                except IndexError:
                    value = m.group(0).strip()
                if _is_valid_url(value) and value not in seen_url:
                    seen_url.add(value)
                    result['urls'].append(value)

        # --- Secrets: span dedup (most-specific-first order) ---
        used_spans = []   # list of (start, end) already claimed

        def _overlaps(start, end):
            for s, e in used_spans:
                if start < e and end > s:
                    return True
            return False

        for pattern, label in SECRET_PATTERNS:
            for m in pattern.finditer(body):
                start, end = m.start(), m.end()
                if _overlaps(start, end):
                    continue
                try:
                    value = m.group(1).strip()
                except IndexError:
                    value = m.group(0).strip()  # patterns without capture group (e.g. Heroku) fall back to full match
                if not _is_valid_secret(value, label):
                    continue
                used_spans.append((start, end))
                masked = (value[:10] + '...' + value[-4:]
                          if len(value) > 20 else value)
                result['secrets'].append({
                    'type': label,
                    'value': value,
                    'masked': masked,
                })

        # --- Emails ---
        seen_em = set()
        for m in EMAIL_PATTERN.finditer(body):
            try:
                value = m.group(1).strip()
            except IndexError:
                continue
            if _is_valid_email(value) and value not in seen_em:
                seen_em.add(value)
                result['emails'].append(value)

        # --- Files ---
        seen_fi = set()
        for m in FILE_PATTERNS.finditer(body):
            try:
                value = m.group(1).strip()
            except IndexError:
                continue
            if _is_valid_file(value) and value not in seen_fi:
                seen_fi.add(value)
                result['files'].append(value)

        # --- Dictionary (from Phase 1; safe no-op if index empty) ---
        if self._index:
            result['dictionary'] = _match_dict(js_text, self._index, cap=500)

        return result
```

Also update `_is_valid_endpoint` signature to accept optional `label` for the relative-path bypass (covered in P2.2):

```python
def _is_valid_endpoint(value, label=''):
    """Strict endpoint validation. Leading-slash check skipped for relative-path categories."""
    if not value or len(value) < 3:
        return False
    if value in NOISE_STRINGS:
        return False
    for pattern in NOISE_PATTERNS:
        if pattern.search(value):
            return False
    # Only require leading slash for absolute endpoint patterns
    if label != 'Relative API Path' and not value.startswith('/'):
        return False
    parts = value.split('/')
    if len(parts) < 2 or all(len(p) < 2 for p in parts if p):
        return False
    return True
```

- [ ] **Step 4: Run to verify GREEN**

```
python3 -m unittest tests.test_engine.TestSecretFalsePositives -v
```

Expected output (all pass):
```
test_all_same_char_rejected ... ok
test_akia_still_reported ... ok
test_bare_alnum32_no_context_rejected ... ok
test_bare_hex32_no_context_rejected ... ok
test_bugsnag_low_entropy_rejected ... ok
test_bugsnag_with_context_accepted ... ok
test_datadog_with_context_accepted ... ok
test_dropbox_with_context_accepted ... ok
test_dropbox_without_context_rejected ... ok
test_example_token_rejected ... ok
test_jwt_reported ... ok
test_masked_field_present ... ok
test_span_dedup_one_finding_per_value ... ok
test_telegram_with_context_accepted ... ok
test_telegram_without_context_rejected ... ok
test_twilio_with_context_accepted ... ok
test_twilio_without_context_rejected ... ok
test_uuid_shape_rejected ... ok
test_value_field_is_raw ... ok

Ran 19 tests in 0.XXXs
OK
```

- [ ] **Step 5: Commit**

```bash
git add tests/__init__.py tests/test_engine.py js_analyzer_engine.py
git commit -m "$(cat <<'EOF'
feat(P2.1): secret FP reduction — entropy gate, context-gated patterns, span dedup

- Add _entropy, _ENTROPY_HEX_RE/_UUID_RE/_HEX64_RE/_COLOR_RE/_COMMON_WORDS
- Drop bare Bugsnag/Datadog/Telegram/Twilio/Dropbox patterns; add context-gated replacements
- _SECRET_KEEP_LABELS frozenset bypasses entropy floor for fixed-prefix patterns
- Per-response span dedup (most-specific-first); secrets now carry type/value/masked
- _is_valid_secret(value, label='') signature; analyze() spans list
- 19 new RED->GREEN tests

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P2.2: Relative path detection — RED then GREEN

**Files:**
- `tests/test_engine.py` Modify — add `TestRelativePaths`
- `js_analyzer_engine.py` Modify — add `Relative API Path` endpoint pattern; update `_is_valid_endpoint`

- [ ] **Step 1: Write the failing tests**

Append this class to `tests/test_engine.py`:

```python
class TestRelativePaths(unittest.TestCase):
    def setUp(self):
        from js_analyzer_engine import JSAnalyzerEngine
        self.engine = JSAnalyzerEngine()

    def _endpoints(self, text):
        return self.engine.analyze(text)['endpoints']

    def test_relative_api_path_detected(self):
        text = 'fetch("api/v1/users")'
        eps = self._endpoints(text)
        self.assertTrue(
            any('api/v1/users' in ep for ep in eps),
            'relative api/v1/users must be detected; got: %r' % eps)

    def test_relative_graphql_path_detected(self):
        text = 'url = "graphql/query"'
        eps = self._endpoints(text)
        self.assertTrue(
            any('graphql/query' in ep for ep in eps),
            'relative graphql/query must be detected')

    def test_relative_v2_path_detected(self):
        text = 'endpoint = "v2/products/list"'
        eps = self._endpoints(text)
        self.assertTrue(
            any('v2/products/list' in ep for ep in eps),
            'relative v2/products/list must be detected')

    def test_absolute_path_still_works(self):
        text = 'path = "/api/v1/login"'
        eps = self._endpoints(text)
        self.assertTrue(
            any('/api/v1/login' in ep for ep in eps),
            'absolute /api/v1/login must still be detected')

    def test_relative_too_short_rejected(self):
        # "api/x" — path segment after prefix is only 1 char (< 3 total after prefix)
        text = 'url = "api/x"'
        eps = self._endpoints(text)
        self.assertFalse(
            any(ep == 'api/x' for ep in eps),
            'api/x is too short and must be rejected')

    def test_plain_filename_not_relative_endpoint(self):
        text = 'src = "utils/helper.js"'
        eps = self._endpoints(text)
        # helper.js ends with .js -> noise pattern rejects it
        self.assertFalse(
            any('utils/helper.js' in ep for ep in eps),
            'JS file path must not be reported as relative endpoint')
```

- [ ] **Step 2: Run to verify RED**

```
python3 -m unittest tests.test_engine.TestRelativePaths -v
```

Expected failure for the first relative test:
```
FAIL: test_relative_api_path_detected
AssertionError: relative api/v1/users must be detected; got: []
```

- [ ] **Step 3: Convert `ENDPOINT_PATTERNS` to `(compiled_re, label)` tuples and add `Relative API Path` in `js_analyzer_engine.py`**

Phase 0 defined `ENDPOINT_PATTERNS` as a plain list of `re.compile()` objects. Convert it to the `(compiled_re, label)` tuple form here and append the new pattern. Replace the entire `ENDPOINT_PATTERNS` block:

```python
# ==================== ENDPOINT PATTERNS ====================
# (compiled_re, label) tuple form — fix [1]: converted from plain list in P2.2

ENDPOINT_PATTERNS = [
    # API endpoints
    (re.compile(r'["\']((?:https?:)?//[^"\']+/api/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE), 'API Endpoint'),
    (re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE), 'API Endpoint'),
    (re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE), 'API Endpoint'),
    (re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE), 'API Endpoint'),
    (re.compile(r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'API Endpoint'),

    # OAuth/Auth endpoints
    (re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE), 'OAuth/Auth'),
    (re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'OAuth/Auth'),
    (re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'OAuth/Auth'),
    (re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'OAuth/Auth'),
    (re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'OAuth/Auth'),

    # Sensitive paths
    (re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'Sensitive Path'),
    (re.compile(r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'Sensitive Path'),
    (re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'Sensitive Path'),
    (re.compile(r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'Sensitive Path'),
    (re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'Sensitive Path'),
    (re.compile(r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'Sensitive Path'),
    (re.compile(r'["\'](/private[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'Sensitive Path'),
    (re.compile(r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'Sensitive Path'),
    (re.compile(r'["\'](/download[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE), 'Sensitive Path'),

    # Well-known paths
    (re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE), 'Well-known'),
    (re.compile(r'["\'](/idp/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE), 'Well-known'),

    # Relative API paths (no leading slash) — added in P2.2
    (re.compile(r'["\']((api|graphql|rest|v\d+)/[a-zA-Z0-9_/.-]{3,100})["\']'),
     'Relative API Path'),
]
```

Update the `analyze()` endpoint loop to unpack the tuple (if not already done in P2.1):

```python
# --- Endpoints ---
seen_ep = set()
for pattern, label in ENDPOINT_PATTERNS:
    for m in pattern.finditer(body):
        try:
            value = m.group(1).strip()
        except IndexError:
            continue
        if _is_valid_endpoint(value, label):
            if value not in seen_ep:
                seen_ep.add(value)
                result['endpoints'].append(value)
```

> **Schema note:** `label` is only used internally by `_is_valid_endpoint` for the leading-slash bypass. The `result['endpoints']` list remains a `list[str]` — the label is NOT stored in the result dict. The adapter's `_add_finding` receives `value` (the path string) as before.

The `_is_valid_endpoint(value, label='')` function introduced in P2.1 already handles the conditional leading-slash check:

```python
def _is_valid_endpoint(value, label=''):
    if not value or len(value) < 3:
        return False
    if value in NOISE_STRINGS:
        return False
    for pattern in NOISE_PATTERNS:
        if pattern.search(value):
            return False
    # Relative API Path patterns do not start with /
    if label != 'Relative API Path' and not value.startswith('/'):
        return False
    parts = value.split('/')
    if len(parts) < 2 or all(len(p) < 2 for p in parts if p):
        return False
    return True
```

- [ ] **Step 4: Run to verify GREEN**

```
python3 -m unittest tests.test_engine.TestRelativePaths -v
```

Expected:
```
test_absolute_path_still_works ... ok
test_plain_filename_not_relative_endpoint ... ok
test_relative_api_path_detected ... ok
test_relative_graphql_path_detected ... ok
test_relative_too_short_rejected ... ok
test_relative_v2_path_detected ... ok

Ran 6 tests in 0.XXXs
OK
```

Also run the full suite to confirm no regressions:
```
python3 -m unittest discover tests -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add tests/test_engine.py js_analyzer_engine.py
git commit -m "$(cat <<'EOF'
feat(P2.2): relative API path detection

- Add 'Relative API Path' pattern matching api/*/rest/*/graphql/*/vN/* without leading slash
- _is_valid_endpoint(value, label) makes leading-slash check conditional on label
- 6 new tests GREEN

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P2.3: Settings cast helper — RED then GREEN

**Files:**
- `js_analyzer_engine.py` Modify — add `SETTING_KEYS` and `cast_setting` module-level helper
- `tests/test_engine.py` Modify — add `TestSettingCasts`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_engine.py`:

```python
class TestSettingCasts(unittest.TestCase):
    def setUp(self):
        from js_analyzer_engine import cast_setting, SETTING_KEYS
        self.cast = cast_setting
        self.keys = SETTING_KEYS

    def test_threads_int_cast(self):
        self.assertEqual(self.cast('threads', '15'), 15)

    def test_threads_clamp_max(self):
        self.assertEqual(self.cast('threads', '999'), 50)

    def test_threads_clamp_min(self):
        self.assertEqual(self.cast('threads', '0'), 1)

    def test_rate_float_cast(self):
        self.assertAlmostEqual(self.cast('rate', '20.5'), 20.5)

    def test_rate_clamp_max(self):
        self.assertAlmostEqual(self.cast('rate', '200'), 100.0)

    def test_timeout_int_cast(self):
        self.assertEqual(self.cast('timeout', '30'), 30)

    def test_method_string_upper(self):
        self.assertEqual(self.cast('method', 'get'), 'GET')

    def test_method_invalid_fallback(self):
        self.assertEqual(self.cast('method', 'DELETE'), 'GET')

    def test_destructive_true_strings(self):
        self.assertTrue(self.cast('destructive', 'true'))
        self.assertTrue(self.cast('destructive', '1'))
        self.assertTrue(self.cast('destructive', 'yes'))

    def test_destructive_false_strings(self):
        self.assertFalse(self.cast('destructive', 'false'))
        self.assertFalse(self.cast('destructive', '0'))
        self.assertFalse(self.cast('destructive', 'no'))

    def test_inscope_bool_cast(self):
        self.assertTrue(self.cast('inscope', 'true'))
        self.assertFalse(self.cast('inscope', 'false'))

    def test_wordlist_string_passthrough(self):
        self.assertEqual(self.cast('wordlist', '/tmp/api.txt'), '/tmp/api.txt')

    def test_unknown_key_returns_raw(self):
        self.assertEqual(self.cast('unknown_key', 'hello'), 'hello')

    def test_setting_keys_contains_expected(self):
        for k in ('threads', 'rate', 'timeout', 'method', 'destructive', 'inscope', 'wordlist'):
            self.assertIn(k, self.keys)
```

- [ ] **Step 2: Run to verify RED**

```
python3 -m unittest tests.test_engine.TestSettingCasts -v
```

Expected:
```
ImportError: cannot import name 'cast_setting' from 'js_analyzer_engine'
```

- [ ] **Step 3: Add `SETTING_KEYS` and `cast_setting` to `js_analyzer_engine.py`**

```python
# js_analyzer_engine.py — add at module level (no burp/java imports)

# Settings persistence helpers (pure — actual saveExtensionSetting is Burp-side)
SETTING_KEYS = ('threads', 'rate', 'timeout', 'method', 'destructive', 'inscope', 'wordlist')

_SETTING_DEFAULTS = {
    'threads': 10,
    'rate': 20.0,
    'timeout': 10,
    'method': 'GET',
    'destructive': False,
    'inscope': True,
    'wordlist': '',
}

_ALLOWED_METHODS = frozenset(['GET', 'HEAD'])


def cast_setting(key, raw_value):
    """
    Cast a raw string (from Burp loadExtensionSetting) to the correct Python type.
    Clamps numeric values. Returns raw_value unchanged for unknown keys.
    Pure function — no Burp/Java imports.
    """
    if key == 'threads':
        try:
            v = int(raw_value)
        except (ValueError, TypeError):
            v = _SETTING_DEFAULTS['threads']
        return max(1, min(50, v))
    if key == 'rate':
        try:
            v = float(raw_value)
        except (ValueError, TypeError):
            v = _SETTING_DEFAULTS['rate']
        return max(0.5, min(100.0, v))
    if key == 'timeout':
        try:
            v = int(raw_value)
        except (ValueError, TypeError):
            v = _SETTING_DEFAULTS['timeout']
        return max(1, min(120, v))
    if key == 'method':
        s = str(raw_value).upper()
        return s if s in _ALLOWED_METHODS else 'GET'
    if key in ('destructive', 'inscope'):
        return str(raw_value).lower() in ('true', '1', 'yes')
    if key == 'wordlist':
        return str(raw_value)
    return raw_value
```

- [ ] **Step 4: Run to verify GREEN**

```
python3 -m unittest tests.test_engine.TestSettingCasts -v
```

Expected:
```
test_destructive_false_strings ... ok
test_destructive_true_strings ... ok
test_inscope_bool_cast ... ok
test_method_invalid_fallback ... ok
test_method_string_upper ... ok
test_rate_clamp_max ... ok
test_rate_float_cast ... ok
test_setting_keys_contains_expected ... ok
test_threads_clamp_max ... ok
test_threads_clamp_min ... ok
test_threads_int_cast ... ok
test_timeout_int_cast ... ok
test_unknown_key_returns_raw ... ok
test_wordlist_string_passthrough ... ok

Ran 14 tests in 0.XXXs
OK
```

Run full suite:
```
python3 -m unittest discover tests -v
```

- [ ] **Step 5: Commit**

```bash
git add tests/test_engine.py js_analyzer_engine.py
git commit -m "$(cat <<'EOF'
feat(P2.3): pure settings cast helper

- Add SETTING_KEYS tuple and cast_setting(key, raw_value) to engine
- Clamps threads 1-50, rate 0.5-100, timeout 1-120; method whitelist GET/HEAD
- bool cast for destructive/inscope; wordlist passthrough
- 14 unit tests GREEN

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P2.4: CSV format helper — RED then GREEN

**Files:**
- `tests/test_csv_format.py` Create — pure CSV row formatting tests
- `ui/csv_utils.py` **Create** — pure module (zero javax imports) with `_csv_field` and `format_csv_row`
- `ui/results_panel.py` Modify — `from csv_utils import format_csv_row` (sys.path-relative import)

> **Fix [4]:** `format_csv_row` and `_csv_field` live in a NEW pure module `ui/csv_utils.py`
> (zero javax imports). `results_panel.py` imports them via `from csv_utils import format_csv_row`.
> This allows CPython3 to import and test the CSV logic without triggering the javax.swing
> module-level import in `results_panel.py`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_csv_format.py
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
```

- [ ] **Step 2: Run to verify RED**

```
python3 -m unittest tests.test_csv_format -v
```

Expected:
```
ModuleNotFoundError: No module named 'csv_utils'
```

- [ ] **Step 3: Create `ui/csv_utils.py` (pure — zero javax imports)**

Create `/Users/gg/Downloads/JSAnalyzer-main/ui/csv_utils.py`:

```python
# -*- coding: utf-8 -*-
"""
ui/csv_utils.py — Pure CSV helpers (zero javax/burp imports).

Safe to import under CPython3 for unit testing.
Used by results_panel.py and active_scan_panel.py.
"""


def _csv_field(value):
    """
    RFC 4180 field quoting.
    Quote if value contains comma, double-quote, or newline.
    Double any embedded double-quotes.
    Pure Python — no Swing/Java imports.
    """
    s = str(value) if not isinstance(value, str) else value
    if ',' in s or '"' in s or '\n' in s or '\r' in s:
        return '"' + s.replace('"', '""') + '"'
    return s


def format_csv_row(category, value, source, label):
    """
    Format one CSV row as a string (no trailing newline).
    Columns: category, value, source, label.
    Pure function — safe to unit-test under CPython3.
    """
    return ','.join([
        _csv_field(category),
        _csv_field(value),
        _csv_field(source),
        _csv_field(label),
    ])
```

Then update `ui/results_panel.py` to import from `csv_utils` (sys.path-relative). Add the following import near the top of `results_panel.py`, AFTER the `# -*- coding: utf-8 -*-` line and module docstring, BEFORE the `from javax.swing import ...` block:

```python
# Pure CSV helpers (importable under CPython3 without javax)
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from csv_utils import format_csv_row, _csv_field
```

- [ ] **Step 4: Run to verify GREEN**

```
python3 -m unittest tests.test_csv_format -v
```

Expected:
```
test_empty_label_allowed ... ok
test_label_with_comma_gets_quoted ... ok
test_no_special_chars_no_quotes ... ok
test_returns_string ... ok
test_simple_row ... ok
test_source_with_comma_quoted ... ok
test_unicode_value ... ok
test_value_with_comma_gets_quoted ... ok
test_value_with_double_quote_escaped ... ok
test_value_with_newline_gets_quoted ... ok

Ran 10 tests in 0.XXXs
OK
```

Run full suite:
```
python3 -m unittest discover tests -v
```

- [ ] **Step 5: Commit**

```bash
git add tests/test_csv_format.py ui/csv_utils.py ui/results_panel.py
git commit -m "$(cat <<'EOF'
feat(P2.4): pure CSV row formatter in ui/csv_utils.py with RFC 4180 quote-escaping

- Create ui/csv_utils.py (zero javax imports): _csv_field + format_csv_row
- results_panel.py imports from csv_utils (sys.path-relative)
- tests/test_csv_format.py imports from csv_utils via ui/ sys.path insert
- Enables CPython3 unit testing of CSV formatting without Swing
- 10 unit tests GREEN

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P2.5: Adapter — label threading, dedup key fix, DEDUP_CAP, settings persistence

**Files:**
- `js_analyzer.py` Modify — `_add_finding` gains `label=None`; dedup key on raw secret `value`; `DEDUP_CAP = 50000`; `_load_setting`/`_save_setting`; load settings in `registerExtenderCallbacks`

This task is purely Burp-side. No CPython3-testable unit tests; follow "Manual verification in Burp" steps.

- [ ] **Step 1: Update `_add_finding` in `js_analyzer.py`**

Current `_add_finding` (line 369–382):
```python
def _add_finding(self, category, value, source):
    """Add a finding if not duplicate."""
    key = category + ":" + value
    if key in self.seen_values:
        return None
    self.seen_values.add(key)
    finding = {
        "category": category,
        "value": value,
        "source": source,
    }
    self.all_findings.append(finding)
    return finding
```

Replace with:
```python
DEDUP_CAP = 50000

def _add_finding(self, category, value, source, label=None):
    """
    Add a finding if not duplicate.
    Dedup key: category + raw value (never masked).
    label: pattern label string (e.g. 'AWS Key'), stored for display.
    DEDUP_CAP guard: once seen_values reaches 50000, log once and drop.
    """
    if len(self.seen_values) >= DEDUP_CAP:
        if not getattr(self, '_dedup_cap_logged', False):
            self._log("DEDUP_CAP reached (%d); dropping further findings." % DEDUP_CAP)
            self._dedup_cap_logged = True
        return None
    key = category + ':' + value   # raw value, never masked
    if key in self.seen_values:
        return None
    self.seen_values.add(key)
    finding = {
        'category': category,
        'value': value,
        'source': source,
        'label': label or '',
    }
    self.all_findings.append(finding)
    return finding
```

- [ ] **Step 2: Update the secrets loop in `analyze_response` to pass raw value and label**

Current secrets loop (lines 319–331 of `js_analyzer.py`):
```python
for pattern, _ in SECRET_PATTERNS:
    for match in pattern.finditer(body):
        try:
            value = match.group(1).strip()
            if self._is_valid_secret(value):
                masked = value[:10] + "..." + value[-4:] if len(value) > 20 else value
                finding = self._add_finding("secrets", masked, source_name)
```

After Phase 2 the engine handles analysis; `analyze_response` calls `self._engine.analyze(body, source_name)` and consumes the result. The adapter's secrets handling becomes:

```python
for sec in results.get('secrets', []):
    # dedup key on raw value; store masked for display
    raw_value = sec['value']
    masked = sec['masked']
    label = sec['type']
    finding = self._add_finding('secrets', raw_value, source_name, label=label)
    if finding:
        # Override the stored display value with masked form
        finding['value'] = masked
        new_findings.append(finding)
```

Note: `_add_finding` uses raw `value` as the dedup key. We then replace `finding['value']` with `masked` so the UI displays the masked form. This keeps `seen_values` keyed on raw values while showing masked in the panel.

- [ ] **Step 3: Add `_load_setting`/`_save_setting` and load in `registerExtenderCallbacks`**

Add to `js_analyzer.py` (before `registerExtenderCallbacks` or as methods of `BurpExtender`):

```python
from js_analyzer_engine import cast_setting, SETTING_KEYS

# Prefix for Burp extension settings (global across projects — documented)
_SETTINGS_PREFIX = 'jsa_'

# Burp-side default values (strings, as stored by saveExtensionSetting)
_SETTINGS_DEFAULTS_STR = {
    'threads': '10',
    'rate': '20',
    'timeout': '10',
    'method': 'GET',
    'destructive': 'false',
    'inscope': 'true',
    'wordlist': '',
}
```

Inside `BurpExtender`:

```python
def _load_setting(self, key):
    """
    Load setting from Burp persistent store.
    Falls back to default string then casts via engine helper.
    NOTE: saveExtensionSetting is global across all Burp projects.
    """
    raw = self._callbacks.loadExtensionSetting(_SETTINGS_PREFIX + key)
    if raw is None:
        raw = _SETTINGS_DEFAULTS_STR.get(key, '')
    return cast_setting(key, raw)

def _save_setting(self, key, value):
    """Persist a setting. value is Python-typed; stored as string."""
    self._callbacks.saveExtensionSetting(_SETTINGS_PREFIX + key, str(value))
```

In `registerExtenderCallbacks`, after `self.panel = ResultsPanel(callbacks, self)`:

```python
# Load persisted settings (falls back to defaults if first run)
self._settings = {}
for k in SETTING_KEYS:
    self._settings[k] = self._load_setting(k)
self._log("Settings loaded: threads=%s rate=%s timeout=%s method=%s" % (
    self._settings['threads'], self._settings['rate'],
    self._settings['timeout'], self._settings['method']))
```

- [ ] **Step 4: Manual verification in Burp**

Load the extension in Burp Suite. Open the Extender tab → Extensions → Add → select `js_analyzer.py`.

1. **DEDUP_CAP guard:** Right-click a large JS response and analyze it 3 times rapidly. The Extender output pane must show identical "Found N new items" counts on 2nd and 3rd analysis (dedup works). Count never exceeds 50000 in `seen_values`.

2. **Label threading:** After analyzing a response that contains a secret (e.g. an AWS key in a test JS file containing `AKIA1234567890ABCDEF`), switch to the Secrets tab. The "Type" column (see P2.6) must show "AWS Key".

3. **Settings persistence:** Restart Burp. Reload the extension. Check the Extender output for the "Settings loaded:" log line. Values must match what was saved previously (defaults on first run).

4. **No double-reporting of masked value:** If the same raw secret appears twice in the JS body, only 1 row appears in the Secrets tab (raw value is the dedup key, not the masked string).

- [ ] **Step 5: Commit**

```bash
git add js_analyzer.py
git commit -m "$(cat <<'EOF'
feat(P2.5): adapter — label threading, raw-value dedup, DEDUP_CAP, settings persistence

- _add_finding(category, value, source, label=None): dedup key on raw secret value
- DEDUP_CAP=50000: log once and drop after cap; _dedup_cap_logged guard
- secrets loop: pass raw value + label to _add_finding, override display with masked
- _load_setting/_save_setting using engine cast_setting; prefix jsa_
- registerExtenderCallbacks loads all SETTING_KEYS on startup

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P2.6: Off-EDT dispatch + 2 MB body cap

**Files:**
- `js_analyzer.py` Modify — `AnalyzeAction.actionPerformed` dispatches to worker thread; `analyze_response` applies 2 MB body cap before dict matching; `add_findings` marshalled via `SwingUtilities.invokeLater`

This is Burp/Swing-side — manual verification only.

- [ ] **Step 1: Rewrite `AnalyzeAction` to use explicit `Runnable` on a `java.lang.Thread`**

Current `AnalyzeAction` (lines 495–510):
```python
class AnalyzeAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        try:
            messages = self.invocation.getSelectedMessages()
            for msg in messages:
                try:
                    self.extender.analyze_response(msg)
                except Exception as e:
                    self.extender._log("Error analyzing response: " + str(e))
        except Exception as e:
            if self.extender:
                self.extender._log("Action error: " + str(e))
```

Replace with:

```python
from java.lang import Runnable as JRunnable, Thread as JThread
from javax.swing import SwingUtilities


class _AnalyzeRunnable(JRunnable):
    """Worker-thread body for one analysis run. Never runs on EDT."""
    def __init__(self, extender, messages):
        self.extender = extender
        self.messages = messages

    def run(self):
        for msg in self.messages:
            try:
                self.extender.analyze_response(msg)
            except Exception as e:
                self.extender._log("Error analyzing response: " + str(e))


class AnalyzeAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        """Called on EDT — immediately hand off to a worker thread."""
        try:
            messages = list(self.invocation.getSelectedMessages())
            t = JThread(_AnalyzeRunnable(self.extender, messages))
            t.setDaemon(True)
            t.setName("JSAnalyzer-worker")
            t.start()
        except Exception as e:
            if self.extender:
                self.extender._log("Action error: " + str(e))
```

- [ ] **Step 2: Apply 2 MB body cap in `analyze_response` and marshal UI updates via `SwingUtilities.invokeLater`**

In `analyze_response`, after `body = self._helpers.bytesToString(response[body_offset:])`:

```python
_BODY_CAP = 2 * 1024 * 1024   # 2 MB

# ... after body = ...
if len(body) > _BODY_CAP:
    self._log("Body truncated to 2 MB for analysis (was %d bytes)" % len(body))
    body = body[:_BODY_CAP]
```

The UI update at the end of `analyze_response` must use `invokeLater` because we are now on a worker thread:

```python
# Replace the current "if new_findings: ... self.panel.add_findings(...)" block:
if new_findings:
    self._log("Found %d new items" % len(new_findings))
    # Marshal to EDT
    panel = self.panel
    findings_snapshot = list(new_findings)
    source_snapshot = source_name

    class _AddFindingsRunnable(JRunnable):
        def run(self):
            panel.add_findings(findings_snapshot, source_snapshot)

    SwingUtilities.invokeLater(_AddFindingsRunnable())
else:
    self._log("No new findings")
```

- [ ] **Step 3: Manual verification in Burp**

1. **UI does not freeze on large body:** Find or craft an HTTP response with a JS body > 500 KB. Right-click → "Analyze JS with JS Analyzer". The Burp UI must remain responsive (scroll, click tabs) while analysis runs. The Extender output must show "Analyzing: ..." after a short delay.

2. **Body cap logged:** For a response > 2 MB, the Extender output must show "Body truncated to 2 MB for analysis (was XXXXXX bytes)".

3. **Re-analyze gives identical counts:** Right-click the same message and analyze 3 times. Each time "Found 0 new items" after the first run (dedup works). Total counts in the stats label do not change.

4. **Findings appear in UI:** After analysis completes, switch to the JS Analyzer tab. New findings appear in the appropriate tabs.

- [ ] **Step 4: Commit**

```bash
git add js_analyzer.py
git commit -m "$(cat <<'EOF'
feat(P2.6): off-EDT analysis dispatch and 2 MB body cap

- AnalyzeAction.actionPerformed: spawn _AnalyzeRunnable on daemon java.lang.Thread
- _BODY_CAP = 2MB; body truncated before analysis; logged when hit
- panel.add_findings marshalled via SwingUtilities.invokeLater(_AddFindingsRunnable)
- Prevents UI freeze on large JS responses

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P2.7: UI — Type column, stats dup counters, search debounce

**Files:**
- `ui/results_panel.py` Modify — Secrets table gains "Type" column; stats label gains dup counters; `SearchKeyListener` replaced by debounce via `javax.swing.Timer(150ms)`

This is Swing-side — manual verification only.

- [ ] **Step 1: Add "Type" column to the Secrets JTable**

In `ResultsPanel._init_ui`, the `categories` list (line 102) and per-table column setup (lines 110–128) currently builds each table with two columns (`["Value", "Source"]`).

Change the secrets table to three columns:

```python
categories = [
    ("Endpoints", "endpoints", ["Value", "Source"]),
    ("URLs", "urls", ["Value", "Source"]),
    ("Secrets", "secrets", ["Value", "Type", "Source"]),
    ("Emails", "emails", ["Value", "Source"]),
    ("Files", "files", ["Value", "Source"]),
    ("Dictionary", "dictionary", ["Template", "Source"]),
]

for title, key, columns in categories:
    panel = JPanel(BorderLayout())
    model = NonEditableTableModel(columns, 0)
    self.models[key] = model

    table = JTable(model)
    table.setAutoCreateRowSorter(True)
    table.setFont(Font("Monospaced", Font.PLAIN, 12))

    if key == "secrets":
        table.getColumnModel().getColumn(0).setPreferredWidth(130)  # Type
        table.getColumnModel().getColumn(1).setPreferredWidth(400)  # Value
        table.getColumnModel().getColumn(2).setPreferredWidth(150)  # Source
    else:
        table.getColumnModel().getColumn(0).setPreferredWidth(500)
        table.getColumnModel().getColumn(1).setPreferredWidth(150)

    self.tables[key] = table
    scroll = JScrollPane(table)
    panel.add(scroll, BorderLayout.CENTER)
    self.tabs.addTab(title + " (0)", panel)
```

Update `add_findings` to store `label` in the secrets dict:

```python
def add_findings(self, new_findings, source_name):
    if source_name and source_name not in self.sources:
        self.sources.add(source_name)
        self.source_filter.addItem(source_name)

    for finding in new_findings:
        category = finding.get('category', '')
        if category in self.findings:
            entry = {
                'value': finding.get('value', ''),
                'source': finding.get('source', source_name),
                'label': finding.get('label', ''),
            }
            self.findings[category].append(entry)

    self._refresh_tables()
```

Update `_refresh_tables` secrets rows to include type:

```python
for i, (title, key, _cols) in enumerate(zip(titles, keys, [None]*5)):
    model = self.models[key]
    model.setRowCount(0)
    count = 0
    for item in self.findings.get(key, []):
        if selected_source != 'All' and item.get('source') != selected_source:
            continue
        if search_text:
            value_lower = item.get('value', '').lower()
            if search_text not in value_lower:
                continue
        if key == 'secrets':
            model.addRow([
                item.get('label', ''),
                item.get('value', ''),
                item.get('source', ''),
            ])
        else:
            model.addRow([
                item.get('value', ''),
                item.get('source', ''),
            ])
        count += 1
    self.tabs.setTitleAt(i, '%s (%d)' % (title, count))
```

Also update `_get_current_key` and `copy_selected` — `copy_selected` reads column 0 for all tabs; for secrets, column 0 is now "Type". Change to read column 1 (Value) for secrets:

```python
def copy_selected(self):
    table = self._get_current_table()
    if not table:
        return
    row = table.getSelectedRow()
    if row >= 0:
        model_row = table.convertRowIndexToModel(row)
        key = self._get_current_key()
        col = 1 if key == 'secrets' else 0
        value = table.getModel().getValueAt(model_row, col)
        self._copy_to_clipboard(str(value))
```

- [ ] **Step 2: Stats label with dup counters**

The current stats label (line 192 of `results_panel.py`) shows total counts. Add dup counters. Track a separate `dup_counts` dict in `__init__`:

```python
# In ResultsPanel.__init__, after self.findings = {...}:
self.dup_counts = {k: 0 for k in ('endpoints','urls','secrets','emails','files')}
```

In `add_findings`, before appending to `self.findings[category]`, check for duplicates and increment:

```python
# Note: dedup is the adapter's job; panel tracks dup for display only
# If the adapter already deduped, dup_count stays 0 unless panel itself
# receives same value twice (e.g. from two calls with same findings list).
# For display, dup_count = total attempts - total unique stored.
```

Simpler approach: count duplicates at the panel level too by checking a per-category value set:

```python
# In __init__:
self._panel_seen = {k: set() for k in ('endpoints','urls','secrets','emails','files')}

# In add_findings loop:
v_key = finding.get('value', '')
if v_key in self._panel_seen.get(category, set()):
    self.dup_counts[category] = self.dup_counts.get(category, 0) + 1
    continue
self._panel_seen[category].add(v_key)
entry = { 'value': ..., 'source': ..., 'label': ... }
self.findings[category].append(entry)
```

Update `_update_stats`:

```python
def _update_stats(self):
    e = len(self.findings.get('endpoints', []))
    u = len(self.findings.get('urls', []))
    s = len(self.findings.get('secrets', []))
    sd = self.dup_counts.get('secrets', 0)
    m = len(self.findings.get('emails', []))
    f = len(self.findings.get('files', []))
    d = len(self.findings.get('dictionary', []))
    self.stats_label.setText(
        '| E:%d | U:%d | S:%d (%d dup) | M:%d | F:%d | D:%d' % (e, u, s, sd, m, f, d))
```

Fix the initial stats string to match the new format (line 52 of `results_panel.py`):

```python
self.stats_label = JLabel("| E:0 | U:0 | S:0 (0 dup) | M:0 | F:0 | D:0")
```

- [ ] **Step 3: Search debounce via `javax.swing.Timer`**

Replace `SearchKeyListener` (currently fires `_refresh_tables` on every keystroke) with a debounce approach using `javax.swing.Timer`:

```python
from javax.swing import Timer as SwingTimer
from java.awt.event import ActionListener as AwtActionListener


class _DebounceTimerAction(AwtActionListener):
    """Fires _refresh_tables once after 150 ms of typing silence."""
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel._refresh_tables()
        # Timer is setRepeats(False) so it fires exactly once


class SearchKeyListener(KeyListener):
    """Starts/restarts a 150 ms debounce timer on each keystroke."""
    def __init__(self, panel):
        self.panel = panel
        self._timer = SwingTimer(150, _DebounceTimerAction(panel))
        self._timer.setRepeats(False)

    def keyPressed(self, event):
        pass

    def keyReleased(self, event):
        if self._timer.isRunning():
            self._timer.restart()
        else:
            self._timer.start()

    def keyTyped(self, event):
        pass
```

- [ ] **Step 4: Manual verification in Burp**

1. **Type column:** Analyze a JS response containing `AKIA1234567890ABCDEF`. Go to Secrets tab. The first column header must read "Type" and the cell must read "AWS Key".

2. **Stats dup counters:** After two separate analyses of different JS files both containing the same secret, the stats label must show `S:1 (1 dup)` (one unique, one duplicate).

3. **Search debounce:** Open the JS Analyzer tab. Type quickly in the search box "api". The table must NOT flicker/refresh on every keystroke — it should refresh once after ~150 ms of pause.

4. **Initial stats string:** On fresh load (no findings), the stats label reads `| E:0 | U:0 | S:0 (0 dup) | M:0 | F:0 | D:0`.

- [ ] **Step 5: Commit**

```bash
git add ui/results_panel.py
git commit -m "$(cat <<'EOF'
feat(P2.7): UI improvements — Type column, dup stats, search debounce

- Secrets tab: 3-column table (Type | Value | Source); copy_selected reads Value col
- Stats label: S:N (N dup) format; initial label matches; D: counter included
- Search debounce: javax.swing.Timer(150ms, setRepeats=false) replaces immediate refresh
- Panel-level dup tracking in _panel_seen / dup_counts dicts

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P2.8: CSV export — full export button + per-tab JPopupMenu

**Files:**
- `ui/results_panel.py` Modify — replace current JSON-only `export_all` with `_export_csv`; add "Export CSV" button; add per-tab `JPopupMenu` "Export this tab as CSV"

This is Swing-side — manual verification only.

- [ ] **Step 1: Add `_export_csv` method and wire the "Export CSV" button**

The `format_csv_row` function lives in `ui/csv_utils.py` (added in P2.4) and is already imported into `results_panel.py` via `from csv_utils import format_csv_row`. Use it here directly.

Replace the existing `export_all` method and the existing `ExportAction` class, and add a new `ExportCsvAction`:

```python
def _export_csv(self, category=None):
    """
    Export findings to CSV (codecs.open, utf-8).
    If category is None, export all categories.
    Columns: category, value, source, label
    """
    import codecs
    from javax.swing import JFileChooser, JOptionPane
    from java.io import File

    chooser = JFileChooser()
    default_name = (category or 'all') + '_findings.csv'
    chooser.setSelectedFile(File(default_name))
    if chooser.showSaveDialog(self) != JFileChooser.APPROVE_OPTION:
        return

    path = chooser.getSelectedFile().getAbsolutePath()

    cats = [category] if category else list(self.findings.keys())

    try:
        with codecs.open(path, 'w', 'utf-8') as fp:
            fp.write('category,value,source,label\n')
            for cat in cats:
                for item in self.findings.get(cat, []):
                    row = format_csv_row(
                        cat,
                        item.get('value', ''),
                        item.get('source', ''),
                        item.get('label', ''),
                    )
                    fp.write(row + '\n')
    except Exception as ex:
        JOptionPane.showMessageDialog(self,
            'CSV export failed: ' + str(ex),
            'Export Error',
            JOptionPane.ERROR_MESSAGE)
        return

    JOptionPane.showMessageDialog(self,
        'Exported to ' + path,
        'Export Complete',
        JOptionPane.INFORMATION_MESSAGE)


def export_all(self):
    """Export all findings to JSON (legacy) + CSV."""
    # Keep existing JSON export
    import json
    from javax.swing import JFileChooser
    from java.io import File

    chooser = JFileChooser()
    chooser.setSelectedFile(File('js_findings.json'))
    if chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
        path = chooser.getSelectedFile().getAbsolutePath()
        export = {
            'endpoints': [f['value'] for f in self.findings.get('endpoints', [])],
            'urls': [f['value'] for f in self.findings.get('urls', [])],
            'secrets': [f['value'] for f in self.findings.get('secrets', [])],
            'emails': [f['value'] for f in self.findings.get('emails', [])],
            'files': [f['value'] for f in self.findings.get('files', [])],
            'dictionary': [{'template': t, 'evidence': e}
                           for t, e in self.findings.get('dictionary', [])],
        }
        fp = open(path, 'w')
        try:
            json.dump(export, fp, indent=2)
        finally:
            fp.close()
```

In `_init_ui`, replace the existing "Export" button with two buttons:

```python
# Replace existing export_btn lines:
export_json_btn = JButton("Export JSON")
export_json_btn.addActionListener(ExportAction(self))
controls.add(export_json_btn)

export_csv_btn = JButton("Export CSV")
export_csv_btn.addActionListener(ExportCsvAction(self))
controls.add(export_csv_btn)
```

Add the new action class:

```python
class ExportCsvAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel._export_csv(category=None)
```

- [ ] **Step 2: Add per-tab CSV export via JPopupMenu**

In `_init_ui`, after creating each table and scroll pane, attach a right-click popup:

```python
# After scroll = JScrollPane(table) inside the categories loop:
popup = JPopupMenu()
tab_csv_item = JMenuItem('Export this tab as CSV')
tab_csv_item_action = _TabCsvAction(self, key)
tab_csv_item.addActionListener(tab_csv_item_action)
popup.add(tab_csv_item)
table.setComponentPopupMenu(popup)
```

Add the action class:

```python
class _TabCsvAction(ActionListener):
    def __init__(self, panel, category):
        self.panel = panel
        self.category = category

    def actionPerformed(self, event):
        self.panel._export_csv(category=self.category)
```

- [ ] **Step 3: Manual verification in Burp**

1. **"Export CSV" button:** After analyzing a JS response with findings, click "Export CSV". A file save dialog appears. Save as `test.csv`. Open the file in a text editor: first line is `category,value,source,label`; each data line has 4 comma-separated fields; fields containing commas are double-quoted; file is valid UTF-8.

2. **Per-tab CSV:** Right-click any row in the Secrets tab. A context menu appears with "Export this tab as CSV". Clicking it opens a save dialog. The saved CSV contains only secrets rows (not endpoints/urls/etc.).

3. **JSON export unchanged:** "Export JSON" button still works; the saved JSON contains the `dictionary` key in addition to the original 5 keys.

4. **Unicode in CSV:** If any finding contains non-ASCII characters (e.g. a URL with encoded characters), the CSV file opens correctly in UTF-8 capable editors without garbled characters.

- [ ] **Step 4: Commit**

```bash
git add ui/results_panel.py
git commit -m "$(cat <<'EOF'
feat(P2.8): CSV export — full export button and per-tab JPopupMenu

- _export_csv(category=None) uses codecs.open utf-8 + format_csv_row (from ui/csv_utils.py)
- 'Export CSV' button alongside existing 'Export JSON'
- Per-tab right-click JPopupMenu 'Export this tab as CSV' via setComponentPopupMenu
- JSON export gains 'dictionary' key
- ExportCsvAction + _TabCsvAction listener classes

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P2.9: Full regression — all tests GREEN + full suite

**Files:**
- `tests/test_engine.py` — no new tests; run existing suite
- `tests/test_csv_format.py` — no new tests; run existing suite

- [ ] **Step 1: Run full test suite**

```
python3 -m unittest discover tests -v
```

Expected output (all tests from P2.1 through P2.4 plus any Phase 0/1 tests):
```
test_all_same_char_rejected (tests.test_engine.TestSecretFalsePositives) ... ok
test_akia_still_reported (tests.test_engine.TestSecretFalsePositives) ... ok
test_bare_alnum32_no_context_rejected (tests.test_engine.TestSecretFalsePositives) ... ok
test_bare_hex32_no_context_rejected (tests.test_engine.TestSecretFalsePositives) ... ok
test_bugsnag_low_entropy_rejected (tests.test_engine.TestSecretFalsePositives) ... ok
test_bugsnag_with_context_accepted (tests.test_engine.TestSecretFalsePositives) ... ok
test_datadog_with_context_accepted (tests.test_engine.TestSecretFalsePositives) ... ok
test_dropbox_with_context_accepted (tests.test_engine.TestSecretFalsePositives) ... ok
test_dropbox_without_context_rejected (tests.test_engine.TestSecretFalsePositives) ... ok
test_example_token_rejected (tests.test_engine.TestSecretFalsePositives) ... ok
test_jwt_reported (tests.test_engine.TestSecretFalsePositives) ... ok
test_masked_field_present (tests.test_engine.TestSecretFalsePositives) ... ok
test_span_dedup_one_finding_per_value (tests.test_engine.TestSecretFalsePositives) ... ok
test_telegram_with_context_accepted (tests.test_engine.TestSecretFalsePositives) ... ok
test_telegram_without_context_rejected (tests.test_engine.TestSecretFalsePositives) ... ok
test_twilio_with_context_accepted (tests.test_engine.TestSecretFalsePositives) ... ok
test_twilio_without_context_rejected (tests.test_engine.TestSecretFalsePositives) ... ok
test_uuid_shape_rejected (tests.test_engine.TestSecretFalsePositives) ... ok
test_value_field_is_raw (tests.test_engine.TestSecretFalsePositives) ... ok
test_absolute_path_still_works (tests.test_engine.TestRelativePaths) ... ok
test_plain_filename_not_relative_endpoint (tests.test_engine.TestRelativePaths) ... ok
test_relative_api_path_detected (tests.test_engine.TestRelativePaths) ... ok
test_relative_graphql_path_detected (tests.test_engine.TestRelativePaths) ... ok
test_relative_too_short_rejected (tests.test_engine.TestRelativePaths) ... ok
test_relative_v2_path_detected (tests.test_engine.TestRelativePaths) ... ok
test_destructive_false_strings (tests.test_engine.TestSettingCasts) ... ok
test_destructive_true_strings (tests.test_engine.TestSettingCasts) ... ok
test_inscope_bool_cast (tests.test_engine.TestSettingCasts) ... ok
test_method_invalid_fallback (tests.test_engine.TestSettingCasts) ... ok
test_method_string_upper (tests.test_engine.TestSettingCasts) ... ok
test_rate_clamp_max (tests.test_engine.TestSettingCasts) ... ok
test_rate_float_cast (tests.test_engine.TestSettingCasts) ... ok
test_setting_keys_contains_expected (tests.test_engine.TestSettingCasts) ... ok
test_threads_clamp_max (tests.test_engine.TestSettingCasts) ... ok
test_threads_clamp_min (tests.test_engine.TestSettingCasts) ... ok
test_threads_int_cast (tests.test_engine.TestSettingCasts) ... ok
test_timeout_int_cast (tests.test_engine.TestSettingCasts) ... ok
test_unknown_key_returns_raw (tests.test_engine.TestSettingCasts) ... ok
test_wordlist_string_passthrough (tests.test_engine.TestSettingCasts) ... ok
test_empty_label_allowed (tests.test_csv_format.TestCsvFormatRow) ... ok
test_label_with_comma_gets_quoted (tests.test_csv_format.TestCsvFormatRow) ... ok
test_no_special_chars_no_quotes (tests.test_csv_format.TestCsvFormatRow) ... ok
test_returns_string (tests.test_csv_format.TestCsvFormatRow) ... ok
test_simple_row (tests.test_csv_format.TestCsvFormatRow) ... ok
test_source_with_comma_quoted (tests.test_csv_format.TestCsvFormatRow) ... ok
test_unicode_value (tests.test_csv_format.TestCsvFormatRow) ... ok
test_value_with_comma_gets_quoted (tests.test_csv_format.TestCsvFormatRow) ... ok
test_value_with_double_quote_escaped (tests.test_csv_format.TestCsvFormatRow) ... ok
test_value_with_newline_gets_quoted (tests.test_csv_format.TestCsvFormatRow) ... ok

Ran 49 tests in 0.XXXs
OK
```

- [ ] **Step 2: Commit final phase tag**

```bash
git add -A
git commit -m "$(cat <<'EOF'
chore(P2): Phase 2 WS3 complete — all 49 tests GREEN

Summary:
- P2.1: entropy gate, context-gated secret patterns, span dedup (19 tests)
- P2.2: relative API path detection (6 tests)
- P2.3: pure settings cast_setting helper (14 tests)
- P2.4: CSV format_csv_row RFC 4180 (10 tests)
- P2.5: adapter label threading, raw-value dedup key, DEDUP_CAP=50000
- P2.6: off-EDT dispatch (java.lang.Thread + invokeLater), 2 MB body cap
- P2.7: Type column in Secrets tab, dup stats, search debounce 150 ms
- P2.8: Export CSV button + per-tab JPopupMenu

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

**Risks for executor (this phase):**
- ENDPOINT_PATTERNS must be a list of (compiled_re, label_str) tuples in the engine — Phase 0 may have left it as a flat list of compiled regexes. If so, convert all entries to (re, label) pairs in P2.1 before adding the new pattern in P2.2; the analyze() endpoints loop must unpack both.
- _is_valid_endpoint is currently a method on BurpExtender (js_analyzer.py lines 384-407). Phase 0 moves it to a module-level function in js_analyzer_engine.py. Confirm it is at module-level (not a method) before writing P2.1/P2.2 tests that import it directly via `from js_analyzer_engine import _is_valid_endpoint`.
- The per-response span dedup list in P2.1 uses Python list.append and a linear overlap scan. For bodies with hundreds of secret matches this is O(n^2). Cap SECRET_PATTERNS at ~30 entries; the spec lists exactly 30 patterns so this is acceptable. If Jython exhibits slowness, switch to a sorted list and bisect.
- results_panel.py imports javax.swing at module level (line 7). The P2.4 plan inserts format_csv_row BEFORE those imports so CPython3 can import the function without Swing. Verify the exact byte position after edit: the coding declaration and module docstring must remain the very first two items in the file, then the pure functions, then the javax imports.
- _add_finding in P2.5 overrides finding['value'] with masked after insertion. This means all_findings stores masked display value, not raw. The dedup key in seen_values remains raw (correct). If any downstream code (e.g. JSON export) needs the raw secret value it will get the masked form — document this trade-off and confirm it is acceptable per spec §4.3.
- javax.swing.Timer constructor in Jython requires an int delay and an ActionListener. The _DebounceTimerAction must implement java.awt.event.ActionListener (import as AwtActionListener to avoid name collision with ActionListener already imported from the same package). Ensure the import alias is consistent throughout results_panel.py.
- cast_setting('method', value) returns 'GET' for any non-whitelisted method. When the WS2 panel (Phase 3) adds 'HEAD' support it will need to update _ALLOWED_METHODS in the engine. Note this in a comment next to _ALLOWED_METHODS.
- The DEDUP_CAP guard uses getattr(self, '_dedup_cap_logged', False) to avoid re-importing state. This attribute is set on the BurpExtender instance; if the extension is reloaded without a full Burp restart, clear_results() must also reset _dedup_cap_logged to False.
- _export_csv uses codecs.open which is available in both Jython 2.7 and CPython 3. However on Jython the 'utf-8' codec name must be lowercase 'utf-8' not 'UTF-8'. Use lowercase consistently.


## Phase 3 — WS2 Active Scanner


### Task P3.1: Create `discovery_logic.py` with `_sanitize` and write failing tests

**Files:**
- `discovery_logic.py` — **Create**
- `tests/test_discovery_logic.py` — **Create** (partial: sanitize tests only)

---

- [ ] **Step 1: Write the failing tests for `_sanitize`**

Create `/Users/gg/Downloads/JSAnalyzer-main/tests/test_discovery_logic.py`:

```python
# -*- coding: utf-8 -*-
"""Tests for discovery_logic pure helpers (CPython3, no burp/java)."""
import unittest


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
        # Only lines whose first non-space char is '#' are comments.
        # '/api/v1  # note' is kept (cut before '#').
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
        # '/api/v1' and 'api/v1' both normalise to '/api/v1' -> one entry
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
        # '?only-query' -> after cut = '' -> excluded
        result = self._sanitize(['?only-query'])
        self.assertEqual(result, [])

    def test_whitespace_stripped_from_path(self):
        result = self._sanitize(['  /api/v1/users  '])
        self.assertEqual(result, ['/api/v1/users'])

    def test_sanitize_preserves_literal_braces(self):
        # G3 / decision #6: wordlist containing {id} is passed through as-is
        # (not normalized) — proving WS2 fuzzes concrete paths per spec decision #6.
        out = self._sanitize(['api/v1/users/{id}'])
        self.assertEqual(out, ['/api/v1/users/{id}'])


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify RED**

```
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest tests.test_discovery_logic.TestSanitize -v 2>&1 | head -30
```

Expected failure:
```
ModuleNotFoundError: No module named 'discovery_logic'
```

- [ ] **Step 3: Write minimal implementation — create `discovery_logic.py`**

Create `/Users/gg/Downloads/JSAnalyzer-main/discovery_logic.py`:

```python
# -*- coding: utf-8 -*-
"""
discovery_logic.py — Pure Python helpers for WS2 Active Scanner.

Zero burp/java/javax imports. Runs under CPython3 and Jython 2.7.
"""
import re
import math

# ---------------------------------------------------------------------------
# §3.2 Destructive path filter
# ---------------------------------------------------------------------------
_DESTRUCTIVE = re.compile(
    r'(?i)(?:^|[/_.-])(?:del|delete|remove|destroy|drop|deactivate|disable|'
    r'revoke|purge|wipe|reset|logout|signout|signoff|terminate|cancel|'
    r'expire|kill|unsubscribe)(?:$|[/_.-])'
)


def is_destructive(path):
    """Return True if path matches a destructive-operation pattern."""
    return bool(_DESTRUCTIVE.search(path))


# ---------------------------------------------------------------------------
# §3.3 Wordlist sanitisation
# ---------------------------------------------------------------------------
def _sanitize(lines):
    """Strip blanks/#comments, cut at ?,#,|, enforce single leading /,
    dedup preserving order. Returns a list of str.

    Py2/Py3 compatible; no java imports.
    """
    seen = set()
    out = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        # Cut at first separator
        for sep in ('?', '#', '|'):
            idx = line.find(sep)
            if idx != -1:
                line = line[:idx]
        line = line.strip()
        if not line:
            continue
        # Enforce single leading slash
        line = '/' + line.lstrip('/')
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


# ---------------------------------------------------------------------------
# §3.6 Triage — which status codes are interesting?
# ---------------------------------------------------------------------------
_REPORTED_SIMPLE = frozenset([200, 201, 204, 401, 403, 405, 500, 502, 503])
_REDIRECT_CODES  = frozenset([301, 302, 307, 308])


def is_interesting(status, has_location=False):
    """Return True if the response should be reported.

    Reported: 200, 201, 204, 301/302/307/308 only with Location header,
              401, 403, 405, 500, 502, 503.
    Dropped:  404, 400, and any code not listed above.
    """
    if status in _REPORTED_SIMPLE:
        return True
    if status in _REDIRECT_CODES and has_location:
        return True
    return False


# ---------------------------------------------------------------------------
# §3.5 Soft-404 fingerprint
# ---------------------------------------------------------------------------
def _word_bucket(body_text):
    """Return the count-of-words in the first 8 KB, bucketed to nearest 10."""
    chunk = body_text[:8192]
    words = len(chunk.split())
    return (words // 10) * 10


def soft404_fingerprint(status, body_len, body):
    """Return (status, len_bucket, word_bucket) fingerprint.

    len_bucket = body_len // 64 * 64  (64-byte granularity)
    word_bucket = word count of first 8 KB bucketed to nearest 10
    """
    len_bucket = (body_len // 64) * 64
    wb = _word_bucket(body)
    return (status, len_bucket, wb)
```

- [ ] **Step 4: Run to verify GREEN**

```
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest tests.test_discovery_logic.TestSanitize -v 2>&1
```

Expected:
```
test_after_cut_becomes_empty_string_excluded ... ok
test_already_has_slash_unchanged ... ok
test_blank_lines_removed ... ok
test_comment_lines_removed ... ok
...
Ran 17 tests in 0.00Xs

OK
```

- [ ] **Step 5: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && git add discovery_logic.py tests/test_discovery_logic.py && git commit -m "$(cat <<'EOF'
P3.1: add pure discovery_logic.py with _sanitize; tests GREEN

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P3.2: Add `is_destructive` tests and `is_interesting` tests

**Files:**
- `tests/test_discovery_logic.py` — **Modify** (append two new test classes)

---

- [ ] **Step 1: Write the failing tests**

Append to `/Users/gg/Downloads/JSAnalyzer-main/tests/test_discovery_logic.py` (after the `TestSanitize` class, before `if __name__ == '__main__'`):

```python
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

    def test_benign_delegated(self):
        # 'del' only as substring within a larger word is OK
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

    # reported unconditionally
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

    # redirects: only with Location
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

    # dropped
    def test_404_dropped(self):
        self.assertFalse(self._fn(404))

    def test_400_dropped(self):
        self.assertFalse(self._fn(400))

    def test_429_dropped(self):
        self.assertFalse(self._fn(429))

    def test_200_default_no_location_arg(self):
        # has_location defaults to False; 200 is still reported
        self.assertTrue(self._fn(200))


class TestSoft404Fingerprint(unittest.TestCase):
    """soft404_fingerprint(status, body_len, body) — §3.5"""

    def setUp(self):
        from discovery_logic import soft404_fingerprint
        self._fn = soft404_fingerprint

    def test_len_bucket_64_granularity(self):
        status, lb, wb = self._fn(200, 128, 'hello world')
        self.assertEqual(lb, 128)  # 128 // 64 * 64 == 128

    def test_len_bucket_rounds_down(self):
        status, lb, wb = self._fn(200, 130, 'hello world')
        self.assertEqual(lb, 128)  # 130 // 64 * 64 == 128

    def test_len_bucket_zero(self):
        status, lb, wb = self._fn(404, 0, '')
        self.assertEqual(lb, 0)

    def test_status_preserved(self):
        status, lb, wb = self._fn(404, 0, '')
        self.assertEqual(status, 404)

    def test_word_bucket_granularity_10(self):
        # 15 words -> bucket 10
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
        # Body longer than 8192 chars; only first 8 KB counted
        body = ('word ' * 2000)  # 10000 chars, 2000 words
        # First 8192 chars ~ 1638 words (8192/5)
        status, lb, wb = self._fn(200, len(body), body)
        # 2000 words would bucket to 2000; 1638 words bucket to 1630
        self.assertLess(wb, 2000)
```

- [ ] **Step 2: Run to verify RED**

```
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest tests.test_discovery_logic.TestIsDestructive tests.test_discovery_logic.TestIsInteresting tests.test_discovery_logic.TestSoft404Fingerprint -v 2>&1 | tail -20
```

Expected: tests fail with `ImportError` or attribute errors because `discovery_logic` is not yet complete (actually it is already — verify they pass in step 4).

Note: since `discovery_logic.py` was already written in P3.1, all three new classes should already pass. Run to confirm GREEN immediately.

- [ ] **Step 3: Verify all three new classes GREEN**

```
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest tests.test_discovery_logic -v 2>&1
```

Expected:
```
Ran 60 tests in 0.00Xs

OK
```

If `test_benign_resets_not_matching` or `test_benign_deltas` fail (the destructive regex hits substrings), patch `_DESTRUCTIVE` in `discovery_logic.py` to tighten the right-hand word boundary — replace `(?:$|[/_.-])` with `(?=$|[/_.-])` (lookahead) and re-run. The regex as written uses non-overlapping anchors so check carefully. The key is that `/api/v1/deltas` must NOT match because `del` is followed by `t`, not a boundary character. The pattern already requires `(?:$|[/_.-])` after the verb, so `deltas` is safe since after `del` comes `t`.

- [ ] **Step 4: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && git add tests/test_discovery_logic.py && git commit -m "$(cat <<'EOF'
P3.2: add is_destructive, is_interesting, soft404_fingerprint tests

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P3.3: Create `ui/active_scan_panel.py` skeleton (DiscoveryConfig, WordlistLoader, DiscoveryPanel shell)

**Files:**
- `ui/active_scan_panel.py` — **Create**

This file imports `javax.swing` and `java.*` — it cannot run under CPython3. All pure logic (`_sanitize`, `is_destructive`) lives in `discovery_logic.py` and is already tested. This task wires the Burp/Swing shell.

---

- [ ] **Step 1: Write `ui/active_scan_panel.py`**

Create `/Users/gg/Downloads/JSAnalyzer-main/ui/active_scan_panel.py`:

```python
# -*- coding: utf-8 -*-
"""
ui/active_scan_panel.py — WS2 Active Scanner panel for JS Analyzer.

DiscoveryConfig  — settings with defaults and ceiling enforcement.
WordlistLoader   — loads and sanitises api.txt using pure _sanitize().
DiscoveryPanel   — JPanel: table / progressbar / start-stop / filter / export.
DiscoveryEngine  — ThreadPoolExecutor dispatcher (wired in Task P3.4).
ProbeTask        — per-path Runnable (wired in Task P3.4).

Burp/Swing only: no python3 unit tests possible for this file.
Manual verification steps are listed at the bottom of each section.
"""

# --- Java/Swing imports (Jython 2.7 only) ---
from javax.swing import (
    JPanel, JScrollPane, JButton, JLabel, JTable, JComboBox,
    JProgressBar, JTextField, JSplitPane, JOptionPane,
    BorderFactory, SwingUtilities, Timer as SwingTimer
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Dimension, Color
from java.awt.event import ActionListener
from java.io import PrintWriter
import sys
import os

# Pure helper — zero java imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from discovery_logic import _sanitize, is_destructive, is_interesting, soft404_fingerprint, build_request_line


# ---------------------------------------------------------------------------
# DiscoveryConfig — §3.2 defaults and ceilings
# ---------------------------------------------------------------------------
class DiscoveryConfig(object):
    """Holds active-scan settings. Ceilings enforced in setters."""

    THREAD_CEILING = 50
    RATE_CEILING   = 100

    def __init__(self):
        self.threads     = 10
        self.rate        = 20        # req/s
        self.timeout     = 10        # seconds per request
        self.method      = 'GET'
        self.destructive = False
        self.in_scope    = True
        self.wordlist    = ''        # path to wordlist file; '' = use bundled api.txt

    def set_threads(self, v):
        self.threads = max(1, min(int(v), self.THREAD_CEILING))

    def set_rate(self, v):
        self.rate = max(1, min(int(v), self.RATE_CEILING))

    def set_timeout(self, v):
        self.timeout = max(1, int(v))

    def apply_from_settings(self, load_fn):
        """Load persisted values via load_fn(key, default)."""
        self.set_threads(load_fn('jsa_threads', 10))
        self.set_rate(load_fn('jsa_rate', 20))
        self.set_timeout(load_fn('jsa_timeout', 10))
        self.method      = str(load_fn('jsa_method', 'GET'))
        self.destructive = str(load_fn('jsa_destructive', 'false')) == 'true'
        self.in_scope    = str(load_fn('jsa_inscope', 'true')) == 'true'
        self.wordlist    = str(load_fn('jsa_wordlist', ''))

    def persist(self, save_fn):
        """Persist current values via save_fn(key, value)."""
        save_fn('jsa_threads',     str(self.threads))
        save_fn('jsa_rate',        str(self.rate))
        save_fn('jsa_timeout',     str(self.timeout))
        save_fn('jsa_method',      self.method)
        save_fn('jsa_destructive', 'true' if self.destructive else 'false')
        save_fn('jsa_inscope',     'true' if self.in_scope else 'false')
        save_fn('jsa_wordlist',    self.wordlist)


# ---------------------------------------------------------------------------
# WordlistLoader — §3.3
# ---------------------------------------------------------------------------
class WordlistLoader(object):
    """Loads a file and returns sanitised paths via _sanitize()."""

    def load(self, filepath):
        """Read *filepath* and return list of sanitised paths.

        Raises IOError if the file cannot be read.
        """
        fp = open(filepath, 'r')
        try:
            lines = fp.read().splitlines()
        finally:
            fp.close()
        return _sanitize(lines)

    def filter_destructive(self, paths):
        """Return paths with destructive entries removed."""
        return [p for p in paths if not is_destructive(p)]


# ---------------------------------------------------------------------------
# Non-editable table model helper
# ---------------------------------------------------------------------------
class _NonEditableModel(DefaultTableModel):
    def __init__(self, cols, rows):
        DefaultTableModel.__init__(self, cols, rows)

    def isCellEditable(self, row, col):
        return False


# ---------------------------------------------------------------------------
# DiscoveryPanel — JPanel shell
# ---------------------------------------------------------------------------
class DiscoveryPanel(JPanel):
    """Active scan results panel.

    Columns: Path | Status | Length | Content-Type | Redirect
    Controls: Start / Stop / status-class filter / Export CSV / JProgressBar
    """

    _COLUMNS = ['Path', 'Status', 'Length', 'Content-Type', 'Redirect']

    def __init__(self, callbacks, extender, config):
        JPanel.__init__(self)
        self._callbacks = callbacks
        self._extender  = extender
        self._helpers   = callbacks.getHelpers()
        self.config     = config
        self._engine    = None    # set in P3.4

        self._init_ui()

    # --- UI construction ---

    def _init_ui(self):
        self.setLayout(BorderLayout(5, 5))

        # --- top controls ---
        top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))

        self._start_btn = JButton('Start')
        self._start_btn.addActionListener(_StartAction(self))
        top.add(self._start_btn)

        self._stop_btn = JButton('Stop')
        self._stop_btn.setEnabled(False)
        self._stop_btn.addActionListener(_StopAction(self))
        top.add(self._stop_btn)

        top.add(JLabel('Status filter:'))
        self._status_filter = JComboBox(['All', '2xx', '3xx', '4xx', '5xx'])
        self._status_filter.addActionListener(_FilterAction(self))
        top.add(self._status_filter)

        self._export_btn = JButton('Export CSV')
        self._export_btn.addActionListener(_ExportCSVAction(self))
        top.add(self._export_btn)

        self._status_lbl = JLabel('Idle')
        top.add(self._status_lbl)

        self.add(top, BorderLayout.NORTH)

        # --- progress bar ---
        self._progress = JProgressBar(0, 100)
        self._progress.setStringPainted(True)
        self._progress.setString('0 / 0')
        self.add(self._progress, BorderLayout.SOUTH)

        # --- table ---
        self._model = _NonEditableModel(self._COLUMNS, 0)
        self._table = JTable(self._model)
        self._table.setAutoCreateRowSorter(True)
        self._table.getColumnModel().getColumn(0).setPreferredWidth(350)
        self._table.getColumnModel().getColumn(1).setPreferredWidth(60)
        self._table.getColumnModel().getColumn(2).setPreferredWidth(70)
        self._table.getColumnModel().getColumn(3).setPreferredWidth(130)
        self._table.getColumnModel().getColumn(4).setPreferredWidth(200)
        scroll = JScrollPane(self._table)
        self.add(scroll, BorderLayout.CENTER)

        # All rows storage (unfiltered)
        self._all_rows = []

    # --- public API used by DiscoveryEngine (P3.4) ---

    def set_engine(self, engine):
        self._engine = engine

    def set_status(self, text):
        """Update status label from EDT."""
        self._status_lbl.setText(text)

    def set_progress(self, done, total):
        """Update progress bar from EDT."""
        if total > 0:
            pct = int(float(done) / float(total) * 100)
            self._progress.setValue(pct)
            self._progress.setString('%d / %d' % (done, total))
        else:
            self._progress.setValue(0)
            self._progress.setString('0 / 0')

    def append_rows(self, rows):
        """Add rows (list of 5-tuples) to table from EDT."""
        filter_val = str(self._status_filter.getSelectedItem())
        for row in rows:
            self._all_rows.append(row)
            if self._matches_filter(row, filter_val):
                self._model.addRow(list(row))

    def _matches_filter(self, row, filter_val):
        if filter_val == 'All':
            return True
        try:
            st = int(row[1])
        except (TypeError, ValueError):
            return False
        if filter_val == '2xx' and 200 <= st < 300:
            return True
        if filter_val == '3xx' and 300 <= st < 400:
            return True
        if filter_val == '4xx' and 400 <= st < 500:
            return True
        if filter_val == '5xx' and 500 <= st < 600:
            return True
        return False

    def _reapply_filter(self):
        filter_val = str(self._status_filter.getSelectedItem())
        self._model.setRowCount(0)
        for row in self._all_rows:
            if self._matches_filter(row, filter_val):
                self._model.addRow(list(row))

    def on_scan_started(self, total):
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self.set_progress(0, total)
        self.set_status('Running...')
        self._all_rows = []
        self._model.setRowCount(0)

    def on_scan_finished(self):
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self.set_status('Done. %d results.' % len(self._all_rows))

    def export_csv(self):
        """Export current table rows to a CSV file chosen via JFileChooser."""
        from javax.swing import JFileChooser
        from java.io import File
        import codecs
        chooser = JFileChooser()
        chooser.setSelectedFile(File('discovery_results.csv'))
        if chooser.showSaveDialog(self) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        fp = codecs.open(path, 'w', 'utf-8')
        try:
            fp.write('Path,Status,Length,Content-Type,Redirect\n')
            for row in self._all_rows:
                escaped = ['"%s"' % str(c).replace('"', '""') for c in row]
                fp.write(','.join(escaped) + '\n')
        finally:
            fp.close()


# ---------------------------------------------------------------------------
# Inner action listeners (EDT-safe, no blocking calls)
# ---------------------------------------------------------------------------
class _StartAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        if self._panel._engine:
            self._panel._engine.start()

class _StopAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        if self._panel._engine:
            self._panel._engine.stop()

class _FilterAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        self._panel._reapply_filter()

class _ExportCSVAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        self._panel.export_csv()
```

- [ ] **Step 2: Manual verification in Burp (no python3 test possible)**

Load the extension in Burp Suite:
1. Open Burp -> Extender -> Extensions -> Add -> Python -> select `js_analyzer.py`.
2. In the Output tab, confirm no errors (ignore "No module named active_scan_panel" — it is not yet imported).
3. This task does not import `active_scan_panel` yet (wired in P3.5). The file must simply parse without syntax errors under Jython. If Burp throws a SyntaxError, fix it before proceeding.

Success criterion: extension loads, "JS Analyzer loaded" appears in output.

- [ ] **Step 3: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && git add ui/active_scan_panel.py && git commit -m "$(cat <<'EOF'
P3.3: add DiscoveryConfig, WordlistLoader, DiscoveryPanel skeleton

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P3.4: Implement `DiscoveryEngine` and `ProbeTask` (Burp-side, with pure-logic helpers)

**Files:**
- `ui/active_scan_panel.py` — **Modify** (append DiscoveryEngine and ProbeTask at bottom of file)
- `discovery_logic.py` — **Modify** (add `build_request_line` pure helper so it can be tested)
- `tests/test_discovery_logic.py` — **Modify** (add TestBuildRequestLine)

---

- [ ] **Step 1: Write failing test for pure request-line builder**

Append to `/Users/gg/Downloads/JSAnalyzer-main/tests/test_discovery_logic.py` (before `if __name__ == '__main__'`):

```python
class TestBuildRequestLine(unittest.TestCase):
    """build_request_line(original_line, path) — pure string helper."""

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
```

- [ ] **Step 2: Run to verify RED**

```
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest tests.test_discovery_logic.TestBuildRequestLine -v 2>&1
```

Expected:
```
AttributeError: module 'discovery_logic' has no attribute 'build_request_line'
```

- [ ] **Step 3: Add `build_request_line` to `discovery_logic.py`**

Append to `/Users/gg/Downloads/JSAnalyzer-main/discovery_logic.py`:

```python
# ---------------------------------------------------------------------------
# Pure request-line builder (testable without Burp)
# ---------------------------------------------------------------------------
def build_request_line(original_line, path):
    """Rebuild an HTTP request line with a new path.

    original_line: e.g. 'GET /old/path HTTP/1.1'
    path:          e.g. '/api/v1/users'
    Returns: 'GET /api/v1/users HTTP/1.1'
    Raises ValueError if path is empty.
    """
    if not path:
        raise ValueError('path must be non-empty')
    parts = original_line.split(' ')
    method   = parts[0]
    protocol = parts[-1]
    return '%s %s %s' % (method, path, protocol)
```

- [ ] **Step 4: Run to verify GREEN**

```
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest tests.test_discovery_logic.TestBuildRequestLine -v 2>&1
```

Expected:
```
Ran 6 tests in 0.00Xs

OK
```

- [ ] **Step 5: Append `DiscoveryEngine` and `ProbeTask` to `ui/active_scan_panel.py`**

Read the current end of the file to get exact indentation context, then append:

```python
# ---------------------------------------------------------------------------
# DiscoveryEngine — §3.4 ThreadPoolExecutor + token-bucket dispatcher
# ---------------------------------------------------------------------------
# Java concurrency imports (Jython 2.7)
from java.util.concurrent import (
    ThreadPoolExecutor, TimeUnit, ArrayBlockingQueue,
    ThreadPoolExecutor as _TPE, Executors, Callable, Future
)
from java.util.concurrent.atomic import AtomicBoolean, AtomicInteger
from java.util.concurrent import ConcurrentLinkedQueue
from java.lang import Thread as JThread, Runnable, System
from java.util import UUID


class DiscoveryEngine(object):
    """Dispatcher + thread pool for active endpoint probing.

    Usage:
        engine = DiscoveryEngine(callbacks, helpers, msg, paths, config, panel)
        panel.set_engine(engine)
        engine.start()   # non-blocking; spawns dispatcher thread
        engine.stop()    # sets stop flag; pool drains within ~1 request cycle
    """

    def __init__(self, callbacks, helpers, msg, paths, config, panel):
        self._callbacks = callbacks
        self._helpers   = helpers
        self._msg       = msg           # IHttpRequestResponse template
        self._paths     = paths         # list[str] sanitised paths
        self._config    = config
        self._panel     = panel

        n = config.threads
        queue_cap = max(n * 4, 1)
        self._pool = ThreadPoolExecutor(
            n, n, 0, TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(queue_cap),
            ThreadPoolExecutor.CallerRunsPolicy()
        )
        # Separate single-thread pool for per-request timeout wrapping
        self._timeout_pool = Executors.newCachedThreadPool()

        self._stop         = AtomicBoolean(False)
        self._error_streak = AtomicInteger(0)
        self._queue        = ConcurrentLinkedQueue()  # metadata dicts -> Timer drains
        self._done         = AtomicInteger(0)
        self._total        = len(paths)

        # Soft-404 baselines: list of fingerprint tuples
        self._baselines    = []

        # javax.swing.Timer (EDT) drains queue -> table
        self._drain_timer  = SwingTimer(250, _DrainAction(self._queue, panel, self))
        self._drain_timer.setRepeats(True)

    def start(self):
        """Spawn dispatcher thread; non-blocking."""
        self._stop.set(False)
        SwingUtilities.invokeLater(_PanelStartRunnable(self._panel, self._total))
        self._drain_timer.start()
        t = JThread(_DispatcherRunnable(self))
        t.setDaemon(True)
        t.setName('jsa-discovery-dispatcher')
        t.start()

    def stop(self):
        """Signal stop; drain pool."""
        self._stop.set(True)
        self._pool.shutdownNow()
        self._drain_timer.stop()
        SwingUtilities.invokeLater(_PanelFinishRunnable(self._panel))

    def shutdown(self):
        """Called from extensionUnloaded — hard stop."""
        self._stop.set(True)
        self._pool.shutdownNow()
        self._timeout_pool.shutdownNow()
        try:
            self._pool.awaitTermination(5, TimeUnit.SECONDS)
        except Exception:
            pass
        self._drain_timer.stop()

    def _calibrate(self):
        """Probe 2 random paths to build soft-404 baselines."""
        for _ in range(2):
            rand_path = '/' + str(UUID.randomUUID()).replace('-', '')
            try:
                rr = self._probe(rand_path)
                if rr is None:
                    continue
                resp    = rr.getResponse()
                ri      = self._helpers.analyzeResponse(resp)
                status  = ri.getStatusCode()
                offset  = ri.getBodyOffset()
                body    = self._helpers.bytesToString(resp[offset:])
                fp      = soft404_fingerprint(status, len(body), body)
                self._baselines.append(fp)
                if status == 200:
                    SwingUtilities.invokeLater(
                        _StatusRunnable(self._panel,
                                        'Warning: server returns 200 for random paths (soft-404)'))
            except Exception:
                pass

    def _probe(self, path):
        """Build and fire a single GET request; returns IHttpRequestResponse or None."""
        try:
            req_info = self._helpers.analyzeRequest(self._msg)
            headers  = list(req_info.getHeaders())   # MUST copy — unmodifiable
            # Rewrite request line (headers[0])
            headers[0] = build_request_line(headers[0], path)
            # Strip body-related headers
            to_remove = [h for h in headers
                         if h.lower().startswith(
                             ('content-type:', 'content-length:', 'transfer-encoding:'))]
            for h in to_remove:
                headers.remove(h)
            req_bytes = self._helpers.buildHttpMessage(headers, None)
            # Use IHttpService overload (returns IHttpRequestResponse)
            rr = self._callbacks.makeHttpRequest(self._msg.getHttpService(), req_bytes)
            return rr
        except Exception:
            return None

    def _is_soft404(self, fingerprint):
        return fingerprint in self._baselines

    def record_result(self, meta):
        """Called from ProbeTask worker thread — push to queue."""
        self._queue.add(meta)
        self._done.incrementAndGet()

    def record_error(self):
        streak = self._error_streak.incrementAndGet()
        if streak >= 20:
            self._error_streak.set(0)
            SwingUtilities.invokeLater(
                _StatusRunnable(self._panel,
                                'Auto-paused: 20 consecutive errors. Retrying in 5s.'))
            try:
                JThread.sleep(5000)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Dispatcher Runnable — runs on dedicated non-EDT thread
# ---------------------------------------------------------------------------
class _DispatcherRunnable(Runnable):
    def __init__(self, engine):
        self._engine = engine

    def run(self):
        e  = self._engine
        ns_per_token = int(1e9 / float(e._config.rate))  # nanoseconds per token

        # Soft-404 calibration before dispatching
        e._calibrate()

        last_send_ns = 0
        for path in e._paths:
            if e._stop.get():
                break
            # Token-bucket: sleep until next allowed send time
            while True:
                now = System.nanoTime()  # System imported at top-level (fix [10])
                elapsed = now - last_send_ns
                if elapsed >= ns_per_token:
                    break
                sleep_ms = (ns_per_token - elapsed) // 1000000
                if sleep_ms > 0:
                    try:
                        JThread.sleep(sleep_ms)
                    except Exception:
                        pass
            last_send_ns = System.nanoTime()
            task = ProbeTask(e, path)
            try:
                e._pool.submit(task)
            except Exception:
                pass

        # Wait for pool to drain then signal UI
        e._pool.shutdown()
        try:
            e._pool.awaitTermination(60, TimeUnit.SECONDS)
        except Exception:
            pass
        e._drain_timer.stop()
        SwingUtilities.invokeLater(_PanelFinishRunnable(e._panel))


# ---------------------------------------------------------------------------
# ProbeTask — per-path Runnable submitted to thread pool
# ---------------------------------------------------------------------------
class ProbeTask(Runnable):
    """One GET probe. Stop flag checked first line."""

    def __init__(self, engine, path):
        self._engine = engine
        self._path   = path

    def run(self):
        e = self._engine
        if e._stop.get():
            return
        try:
            # Wrap blocking makeHttpRequest in Callable for timeout
            call = _ProbeCallable(e, self._path)
            future = e._timeout_pool.submit(call)
            try:
                rr = future.get(e._config.timeout, TimeUnit.SECONDS)
            except Exception:
                future.cancel(True)
                e.record_error()
                return

            if rr is None:
                e.record_error()
                return

            resp   = rr.getResponse()
            ri     = e._helpers.analyzeResponse(resp)
            status = int(ri.getStatusCode())
            offset = ri.getBodyOffset()
            body   = e._helpers.bytesToString(resp[offset:])
            ctype  = str(ri.getInferredMimeType())
            length = len(resp) - offset

            # Location header check
            headers_list = list(ri.getHeaders())
            location = ''
            for h in headers_list:
                if h.lower().startswith('location:'):
                    location = h[9:].strip()
                    break
            has_loc = bool(location)

            fp = soft404_fingerprint(status, length, body)

            if e._is_soft404(fp):
                return

            if not is_interesting(status, has_loc):
                return

            meta = {
                'path':     self._path,
                'status':   status,
                'length':   length,
                'ctype':    ctype,
                'redirect': location,
            }
            e.record_result(meta)
            e._error_streak.set(0)

        except Exception:
            e.record_error()


# ---------------------------------------------------------------------------
# Callable wrapper for timeout (submitted to cached pool)
# ---------------------------------------------------------------------------
class _ProbeCallable(Callable):
    def __init__(self, engine, path):
        self._engine = engine
        self._path   = path

    def call(self):
        return self._engine._probe(self._path)


# ---------------------------------------------------------------------------
# Swing Timer drain action (EDT)
# ---------------------------------------------------------------------------
class _DrainAction(ActionListener):
    def __init__(self, queue, panel, engine):
        self._queue  = queue
        self._panel  = panel
        self._engine = engine

    def actionPerformed(self, event):
        rows = []
        count = 0
        while count < 500:
            item = self._queue.poll()
            if item is None:
                break
            rows.append((
                item.get('path', ''),
                item.get('status', ''),
                item.get('length', ''),
                item.get('ctype', ''),
                item.get('redirect', ''),
            ))
            count += 1
        if rows:
            self._panel.append_rows(rows)
        done  = self._engine._done.get()
        total = self._engine._total
        self._panel.set_progress(done, total)


# ---------------------------------------------------------------------------
# Small EDT Runnables
# ---------------------------------------------------------------------------
class _PanelStartRunnable(Runnable):
    def __init__(self, panel, total):
        self._panel = panel
        self._total = total

    def run(self):
        self._panel.on_scan_started(self._total)


class _PanelFinishRunnable(Runnable):
    def __init__(self, panel):
        self._panel = panel

    def run(self):
        self._panel.on_scan_finished()


class _StatusRunnable(Runnable):
    def __init__(self, panel, text):
        self._panel = panel
        self._text  = text

    def run(self):
        self._panel.set_status(self._text)
```

- [ ] **Step 6: Run full pure test suite to confirm nothing broken**

```
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest discover tests -v 2>&1
```

Expected:
```
Ran <N> tests in 0.0Xs

OK
```
(N = accumulated total of all test methods up to P3.4.)

- [ ] **Step 7: Manual verification in Burp**

Load extension. In Burp, right-click any HTTP response in Proxy history -> click "Probe endpoints with wordlist" (added in P3.5 — skip for now; just confirm no import errors).

Success criterion: extension loads without errors. `active_scan_panel` is not imported yet so no Swing errors at this stage.

- [ ] **Step 8: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && git add discovery_logic.py ui/active_scan_panel.py tests/test_discovery_logic.py && git commit -m "$(cat <<'EOF'
P3.4: add DiscoveryEngine, ProbeTask, build_request_line; tests GREEN

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P3.5: Wire trigger + consent into `js_analyzer.py` (context menu, scope check, dialog)

**Files:**
- `js_analyzer.py` — **Modify**

This is Burp/Swing-only. All pure logic already tested. Manual verification steps listed.

---

- [ ] **Step 1: Add `_load_setting` / `_save_setting` stubs and `IExtensionStateListener` to `js_analyzer.py`**

Read lines 1-15 of `js_analyzer.py` (already done above). Modify the import block and class declaration:

Replace:
```python
from burp import IBurpExtender, IContextMenuFactory, ITab
```
with:
```python
from burp import IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener
```

Replace the class declaration:
```python
class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    """JS Analyzer with noise-reduced endpoint detection."""
```
with:
```python
class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):
    """JS Analyzer with noise-reduced endpoint detection."""
```

- [ ] **Step 2: Add `_load_setting`, `_save_setting`, and `_discovery_engine` to `registerExtenderCallbacks`**

In `registerExtenderCallbacks`, after the line `self.seen_values = set()`, add:

```python
        # Discovery engine reference (set when a scan starts)
        self._discovery_engine = None

        # Load persisted discovery config
        from ui.active_scan_panel import DiscoveryConfig, WordlistLoader
        self._discovery_config = DiscoveryConfig()
        self._discovery_config.apply_from_settings(self._load_setting)

        # Resolve bundled wordlist path
        self._api_txt = os.path.join(ext_dir, 'api.txt')
```

Also add these two methods to `BurpExtender` (after `_log`):

```python
    def _load_setting(self, key, default):
        """Load a persisted setting; returns default if absent.
        NOTE: saveExtensionSetting is global across all Burp projects.
        """
        try:
            val = self._callbacks.loadExtensionSetting(key)
            if val is None:
                return default
            # Cast to same type as default
            if isinstance(default, bool):
                return val == 'true'
            if isinstance(default, int):
                return int(val)
            return val
        except Exception:
            return default

    def _save_setting(self, key, value):
        """Persist a setting globally (all Burp projects share this store)."""
        try:
            self._callbacks.saveExtensionSetting(key, str(value))
        except Exception:
            pass
```

- [ ] **Step 3: Add `extensionUnloaded` shutdown method to `BurpExtender`**

Add after `get_all_findings`:

```python
    def extensionUnloaded(self):
        """IExtensionStateListener — shut down active scan thread pool on unload."""
        if self._discovery_engine is not None:
            try:
                self._discovery_engine.shutdown()
            except Exception:
                pass
        self._log("JS Analyzer unloaded.")
```

Also register the listener in `registerExtenderCallbacks`, after `callbacks.addSuiteTab(self)`:

```python
        callbacks.registerExtensionStateListener(self)
```

- [ ] **Step 4: Add the "Probe endpoints with wordlist" menu item and `ProbeAction` to `js_analyzer.py`**

In `createMenuItems`, after the existing `item.addActionListener(...)` block, add:

```python
            if len(messages) == 1:
                probe_item = JMenuItem("Probe endpoints with wordlist")
                probe_item.addActionListener(ProbeAction(self, invocation))
                menu.add(probe_item)
```

Add `ProbeAction` class at the bottom of `js_analyzer.py`:

```python
class ProbeAction(ActionListener):
    """Context menu action: Probe endpoints with wordlist (WS2)."""

    def __init__(self, extender, invocation):
        self._extender    = extender
        self._invocation  = invocation

    def actionPerformed(self, event):
        from javax.swing import JOptionPane
        from java.net import URL

        ext = self._extender
        try:
            messages = self._invocation.getSelectedMessages()
            if not messages or len(messages) != 1:
                return
            msg = messages[0]

            # --- 1. Derive base URL ---
            req_info = ext._helpers.analyzeRequest(msg)
            url_obj  = req_info.getUrl()
            scheme   = url_obj.getProtocol()
            host     = url_obj.getHost()
            port     = url_obj.getPort()
            if port == -1:
                base_url_str = '%s://%s' % (scheme, host)
            else:
                base_url_str = '%s://%s:%d' % (scheme, host, port)

            try:
                base_java_url = URL(base_url_str)
            except Exception as e:
                JOptionPane.showMessageDialog(None,
                    'Invalid base URL: ' + base_url_str, 'JS Analyzer', JOptionPane.ERROR_MESSAGE)
                return

            # --- 2. Scope check BEFORE dialog ---
            if ext._discovery_config.in_scope:
                if not ext._callbacks.isInScope(base_java_url):
                    JOptionPane.showMessageDialog(None,
                        'Target %s is NOT in scope.\n'
                        'Add it to scope or disable "in-scope only" in Discovery config.' % base_url_str,
                        'JS Analyzer — Out of Scope', JOptionPane.WARNING_MESSAGE)
                    return

            # --- 3. Load + filter wordlist ---
            from ui.active_scan_panel import WordlistLoader, DiscoveryEngine, DiscoveryPanel
            loader = WordlistLoader()
            wl_path = ext._discovery_config.wordlist or ext._api_txt
            try:
                paths = loader.load(wl_path)
            except IOError as e:
                JOptionPane.showMessageDialog(None,
                    'Cannot read wordlist: ' + str(e), 'JS Analyzer', JOptionPane.ERROR_MESSAGE)
                return

            if not ext._discovery_config.destructive:
                paths = loader.filter_destructive(paths)

            if not paths:
                JOptionPane.showMessageDialog(None,
                    'No paths remain after filtering.',
                    'JS Analyzer', JOptionPane.INFORMATION_MESSAGE)
                return

            cfg = ext._discovery_config
            destructive_label = 'YES (destructive paths INCLUDED)' if cfg.destructive else 'no'

            # --- 4. Consent dialog ---
            msg_text = (
                'JS Analyzer — Active Endpoint Probe\n\n'
                'Host:        %s\n'
                'Paths:       %d (post-filter)\n'
                'Method:      %s\n'
                'Threads:     %d\n'
                'Rate:        %d req/s\n'
                'Timeout:     %d s\n'
                'Destructive: %s\n'
                'In-scope:    %s\n\n'
                'WARNING: This sends real HTTP %s requests to the target.\n'
                'GET requests can still have side effects (caching, logging, etc.).\n\n'
                'Proceed?'
            ) % (
                base_url_str, len(paths), cfg.method,
                cfg.threads, cfg.rate, cfg.timeout,
                destructive_label,
                'yes' if cfg.in_scope else 'no (all hosts)',
                cfg.method,
            )

            choice = JOptionPane.showConfirmDialog(
                None, msg_text,
                'JS Analyzer — Confirm Probe',
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            )
            if choice != JOptionPane.YES_OPTION:
                return

            # --- 5. Build DiscoveryPanel + DiscoveryEngine and start ---
            # Get or create the panel tab
            if not hasattr(ext, '_discovery_panel') or ext._discovery_panel is None:
                panel = DiscoveryPanel(ext._callbacks, ext, cfg)
                ext._discovery_panel = panel
                # Add as a sub-tab or standalone tab
                ext._callbacks.addSuiteTab(_DiscoveryTab(panel))

            engine = DiscoveryEngine(
                ext._callbacks, ext._helpers, msg, paths, cfg, ext._discovery_panel
            )
            ext._discovery_engine = engine
            ext._discovery_panel.set_engine(engine)
            engine.start()

        except Exception as e:
            ext._log("ProbeAction error: " + str(e))
            import traceback
            ext._log(traceback.format_exc())


class _DiscoveryTab(object):
    """Minimal ITab wrapper for the DiscoveryPanel."""
    from burp import ITab as _ITab

    def __init__(self, panel):
        self._panel = panel

    def getTabCaption(self):
        return "JS Probe"

    def getUiComponent(self):
        return self._panel
```

- [ ] **Step 5: Manual verification in Burp — Trigger and consent (spec §8 WS2)**

Load extension. Perform each check:

1. **Single-message gate:** Right-click with zero messages selected — "Probe endpoints with wordlist" must NOT appear in the menu.
2. **Single-message gate:** Right-click with two messages selected — item must NOT appear.
3. **Scope check:** Right-click a response whose host is NOT in scope. Expected: Warning dialog "Target ... is NOT in scope" appears immediately. No confirm dialog follows.
4. **Consent dialog content:** Right-click an in-scope JS response. Confirm dialog appears showing host, post-filter count, method=GET, threads=10, rate=20, timeout=10, destructive=no, in-scope=yes, and the sentence "GET requests can still have side effects".
5. **Cancel aborts:** Click No/Cancel in the dialog. No requests are sent (verify in Proxy history — no new GET requests to the target).
6. **Proceed fires scan:** Click Yes. The "JS Probe" tab appears. Progress bar advances. Proxy history shows GET requests to the target host.
7. **Stop halts within 1 cycle:** Click Stop. Verify in Proxy history that the number of requests stops incrementing within ~1 second.
8. **Destructive paths skipped:** With destructive=false (default), paths matching the `_DESTRUCTIVE` pattern (e.g. `/delete`, `/logout`) must not appear in Proxy history. Confirm by searching Proxy history for those paths.
9. **Extension unload:** Unload the extension while a scan is running. Verify Burp does not hang and the thread pool shuts down (no "JS Probe" activity after 5 s).

Success criteria match spec §8 WS2: "no request without explicit YES confirmation", "dialog shows post-filter count/host/method/threads/rate/destructive", "all requests GET", "destructive paths skipped by default", "isInScope checked before dialog", "Stop halts within ~1 request cycle", "extensionUnloaded shuts pool".

- [ ] **Step 6: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && git add js_analyzer.py && git commit -m "$(cat <<'EOF'
P3.5: wire ProbeAction, extensionUnloaded, scope check, consent dialog

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P3.6: Persist `DiscoveryConfig` settings and verify survival across Burp restart

**Files:**
- `ui/active_scan_panel.py` — **Modify** (add settings UI to DiscoveryPanel)
- `js_analyzer.py` — **Modify** (save config on change; already has `_load_setting`/`_save_setting`)

---

- [ ] **Step 1: Add config-editing controls to `DiscoveryPanel._init_ui`**

In `ui/active_scan_panel.py`, inside `DiscoveryPanel._init_ui`, after the `top.add(self._status_lbl)` line, append a second row of controls for configuration:

```python
        # --- config row ---
        cfg_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        cfg_row.add(JLabel('Threads:'))
        self._threads_field = JTextField(str(config.threads), 4)
        cfg_row.add(self._threads_field)

        cfg_row.add(JLabel('Rate/s:'))
        self._rate_field = JTextField(str(config.rate), 4)
        cfg_row.add(self._rate_field)

        cfg_row.add(JLabel('Timeout(s):'))
        self._timeout_field = JTextField(str(config.timeout), 4)
        cfg_row.add(self._timeout_field)

        self._destructive_cb = JCheckBox('Allow destructive', config.destructive)
        cfg_row.add(self._destructive_cb)

        self._inscope_cb = JCheckBox('In-scope only', config.in_scope)
        cfg_row.add(self._inscope_cb)

        save_cfg_btn = JButton('Save config')
        save_cfg_btn.addActionListener(_SaveConfigAction(self))
        cfg_row.add(save_cfg_btn)

        # Wrap top + cfg_row in a single north panel
        north = JPanel(BorderLayout())
        north.add(top, BorderLayout.NORTH)
        north.add(cfg_row, BorderLayout.SOUTH)
        self.add(north, BorderLayout.NORTH)
```

Note: remove the earlier `self.add(top, BorderLayout.NORTH)` line and replace with the `north` wrapper above.

Add the `_SaveConfigAction` class at the bottom of `ui/active_scan_panel.py`:

```python
class _SaveConfigAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        p   = self._panel
        cfg = p.config
        try:
            cfg.set_threads(p._threads_field.getText().strip())
        except (ValueError, Exception):
            pass
        try:
            cfg.set_rate(p._rate_field.getText().strip())
        except (ValueError, Exception):
            pass
        try:
            cfg.set_timeout(p._timeout_field.getText().strip())
        except (ValueError, Exception):
            pass
        cfg.destructive = p._destructive_cb.isSelected()
        cfg.in_scope    = p._inscope_cb.isSelected()
        # Persist via extender's _save_setting
        extender = p._extender
        cfg.persist(extender._save_setting)
        p.set_status('Config saved.')
```

- [ ] **Step 2: Manual verification in Burp — settings persistence (spec §4.6)**

1. Load extension in Burp.
2. Navigate to "JS Probe" tab (trigger a probe or add the tab manually).
3. Change Threads to 25, Rate to 50, check "Allow destructive".
4. Click "Save config".
5. Close and reopen Burp (or reload the extension via Extender -> Reload).
6. Observe the "JS Probe" tab config fields: Threads must show 25, Rate 50, "Allow destructive" must be checked.
7. Verify ceiling enforcement: enter 999 in Threads field, click Save; observe it clamps to 50. Enter 999 in Rate, observe clamps to 100.
8. In consent dialog (trigger probe): verify the dialog shows the updated values (threads=25, rate=50).

Success: settings survive reload; ceilings enforced.

- [ ] **Step 3: Commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && git add ui/active_scan_panel.py && git commit -m "$(cat <<'EOF'
P3.6: add config-editing UI and settings persistence to DiscoveryPanel

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task P3.7: End-to-end manual verification against all WS2 acceptance criteria (spec §8)

**Files:** no code changes — verification only

---

- [ ] **Step 1: Full acceptance checklist**

Load the extension in Burp with a live target in scope. Verify each criterion from spec §8 WS2 in order:

**AC1 — No request without YES:** Trigger probe, click No. Open Proxy history, filter by target host, confirm zero new requests. PASS if count unchanged.

**AC2 — Dialog content:** Trigger probe on `https://example.com` (in scope). Confirm dialog text contains: host (`https://example.com`), count (e.g. "44,000+ paths"), method=GET, threads=10, rate=20, destructive=no, in-scope=yes, warning sentence.

**AC3 — GET only:** Start a scan. In Proxy history, select 20 random requests to the target. Confirm every request line starts with `GET `. Zero POST/PUT/DELETE.

**AC4 — Destructive skipped:** With destructive=false (default), search Proxy history for paths matching `/delete`, `/logout`, `/reset`, `/purge`. Confirm zero such requests appear.

**AC5 — isInScope before dialog:** Add `https://evil.example.com` to context menu without it being in scope. Confirm out-of-scope warning appears immediately, before any consent dialog.

**AC6 — Stop within 1 cycle:** Start scan (20 threads). After 5 seconds, click Stop. Count requests in Proxy history before and 2 seconds after clicking Stop. Delta must be ≤ 20 (one per thread at most).

**AC7 — extensionUnloaded shuts pool:** Start scan. Unload extension (Extender -> Remove). Wait 10 s. Confirm no new requests appear in Proxy history. Confirm Burp is not hanging (UI responsive).

**AC8 — Soft-404 suppression:** Point scan at a server that returns 200 for all paths (nginx with a catch-all). Confirm "Warning: server returns 200 for random paths" appears in DiscoveryPanel status. Confirm no rows are added to table for paths that match the 200-baseline fingerprint.

**AC9 — Table columns:** Confirm table shows Path, Status, Length, Content-Type, Redirect for each result row. For a 302 response, Redirect column shows the Location header value.

**AC10 — Memory < 20 MB:** Start a scan against a target that returns 200 for many paths. After 50,000 rows, note Burp heap usage via Help -> Diagnostics. Confirm increase is < 20 MB vs baseline.

**AC11 — Rate ≤ 25/s at default 20/s:** Use Proxy -> HTTP History, filter by target host, note timestamps on 100 consecutive requests. Compute rate = 100 / (last_ts - first_ts). Must be ≤ 25 req/s (allowing ±25% for token-bucket jitter).

- [ ] **Step 2: File any failures as GitHub issues with reproduction steps; do not merge until all AC pass.**

- [ ] **Step 3: Run full python3 test suite one final time**

```
cd /Users/gg/Downloads/JSAnalyzer-main && python3 -m unittest discover tests -v 2>&1
```

Expected:
```
Ran <N> tests in 0.0Xs

OK
```
(N = the accumulated total of all prior test methods across all phases; do not treat a count below 66 as a failure — run the suite and observe the actual number.)

- [ ] **Step 4: Final commit**

```bash
cd /Users/gg/Downloads/JSAnalyzer-main && git add -A && git commit -m "$(cat <<'EOF'
P3.7: all WS2 AC verified; phase 3 complete

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```


**Risks for executor (this phase):**
- _DESTRUCTIVE regex uses non-capturing alternation anchors: verify '/api/v1/deltas' does NOT match (del followed by 't', not a boundary char). If test_benign_deltas fails, the right-hand boundary in the regex must be a true word boundary, not just (?:$|[/_.-]) — consider (?=$|[/_.-]|$) or adding 't' check. Run python3 -m unittest tests.test_discovery_logic.TestIsDestructive -v immediately after P3.1 to catch this.
- getHeaders() returns an UNMODIFIABLE java.util.List — ProbeTask._probe MUST call headers = list(req_info.getHeaders()) before any mutation. A missing list() call causes UnsupportedOperationException that is silently swallowed in the except block, producing zero requests. Verify by adding a stdout print inside _probe during development.
- makeHttpRequest has two overloads with different return types: makeHttpRequest(IHttpService, byte[]) returns IHttpRequestResponse (correct); makeHttpRequest(String, int, bool, byte[]) returns byte[]. Using the wrong overload means rr.getResponse() will throw AttributeError on a byte[]. The DiscoveryEngine._probe code uses msg.getHttpService() — confirm msg is the original IHttpRequestResponse template, not a reconstructed one.
- AtomicBoolean stop flag must be java.util.concurrent.atomic.AtomicBoolean, not Python bool. A plain Python bool has no JVM cross-thread visibility guarantee. The import 'from java.util.concurrent.atomic import AtomicBoolean' must appear in ui/active_scan_panel.py. Verify by running a 2-thread scan and clicking Stop — threads must halt within one iteration.
- SwingTimer._DrainAction.actionPerformed runs on the EDT; ProbeTask.run() runs on pool threads. All ConcurrentLinkedQueue accesses are safe, but panel._model.addRow must only be called from EDT (inside DrainAction). Any accidental model mutation inside ProbeTask.run() will cause non-deterministic Swing corruption. Code as written is correct; do not refactor to call append_rows from worker threads.
- The _DiscoveryTab inner class at the bottom of ProbeAction references 'from burp import ITab as _ITab' at class-body scope — in Jython this works but the import must succeed before the class is defined. If loading order causes an ImportError, move the import to module level at the top of js_analyzer.py.
- DiscoveryPanel._init_ui adds 'top' to BorderLayout.NORTH and later wraps it in a 'north' panel — the original self.add(top, BorderLayout.NORTH) call must be REMOVED, otherwise two components compete for BorderLayout.NORTH and one will be invisible. In Task P3.6 the instruction says to replace; verify by inspecting the panel visually in Burp after P3.6.
- TokenPool CallerRunsPolicy means if the ArrayBlockingQueue(n*4) fills up, the dispatcher thread itself executes the task — which would block the dispatcher (no more submits) and tie up the rate-limiter. At 10 threads and 20 req/s this is unlikely but at maximum (50 threads, 100 req/s) monitor for dispatcher stalls. If observed, increase queue_cap to n*10.
- soft404_fingerprint word-bucket uses body.split() on a Python string; in Jython body is already a Python str (via bytesToString). If bytesToString returns a java.lang.String instead, .split() returns a java.util.List and len() will still work, but the first-8KB slice body[:8192] may behave differently. Test with a response > 8 KB in Burp to confirm truncation works.

