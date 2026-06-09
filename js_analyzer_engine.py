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


# ---------------------------------------------------------------------------
# §2.1  Normalization helpers — module-level constants (ONE definition each)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# §2.3  Candidate extraction & match
# ---------------------------------------------------------------------------
_DICT_CAND = re.compile(r'[A-Za-z0-9_.~-]+(?:/[A-Za-z0-9_.~-]+)+')


def _match_dict(body, idx, cap=500):
    """Extract path-like candidates from body and match against the index.

    Single pass over the body; for each candidate, normalise its segments and
    walk longest-prefix-first, returning the first (longest) prefix present in
    the index. Returns a list of (template, evidence) tuples capped at `cap`.
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


# ==================== ENDPOINT PATTERNS ====================
# Copied verbatim from js_analyzer.py lines 38-67

# (compiled_re, label) tuples. Label is used internally for validation
# (the 'Relative API Path' label bypasses the leading-slash requirement);
# result['endpoints'] stays a list of plain strings.
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

# ==================== SECRET FP REDUCTION (§4.3) ====================

_ENTROPY_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE)
_HEX64_RE = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)          # sha256 hex
_COLOR_RE = re.compile(r'^#?[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?$')  # css color

_COMMON_WORDS = frozenset([
    'undefined', 'function', 'prototype', 'constructor', 'arguments',
    'document', 'window', 'object', 'string', 'boolean', 'number',
    'return', 'import', 'export', 'default', 'module', 'require',
])

# Labels whose fixed prefix IS the precision -> bypass entropy + trivial-seq gates
_SECRET_KEEP_LABELS = frozenset([
    'AWS Key', 'Google API', 'Stripe Live', 'GitHub PAT', 'Slack Token',
    'JWT', 'Private Key', 'MongoDB', 'PostgreSQL', 'MySQL URI with Credentials',
    'Segment Public API Token', 'Segment API Key', 'Facebook App ID',
    'Facebook Secret Key', 'Facebook Access Token', 'Google OAuth2 Access Token',
    'Linear API Key', 'Heroku API Key', 'DigitalOcean Token', 'SendGrid API Key',
    'GitLab Token', 'Shopify Access Token', 'New Relic Key',
])

# ==================== SECRET PATTERNS ====================
# Most-specific first (span dedup short-circuits on first match per span).
# Bare/dangerous patterns (Bugsnag/Datadog/Telegram/Twilio/Dropbox) are
# context-gated; the catastrophic bare [a-f0-9]{32} / [a-z0-9]{32} are gone.

SECRET_PATTERNS = [
    # --- Fixed-prefix KEEP patterns (bypass entropy floor) ---
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
    (re.compile(r'[hH]eroku[\'"]([0-9a-f]{32})[\'"]'), 'Heroku API Key'),
    (re.compile(r'\b(dop_v1_[a-z0-9]{64})\b'), 'DigitalOcean Token'),
    (re.compile(r'(SG\.[\w\d\-_]{22}\.[\w\d\-_]{43})'), 'SendGrid API Key'),
    (re.compile(r'\b(glpat-[0-9a-zA-Z\-_]{20})\b'), 'GitLab Token'),
    (re.compile(r'\b(shpat_[0-9a-fA-F]{32})\b'), 'Shopify Access Token'),
    (re.compile(r'\b(NRII-[a-zA-Z0-9]{20,})\b'), 'New Relic Key'),
    # --- Already context-gated ---
    (re.compile(r'(?i)algolia.{0,32}([a-z0-9]{32})\b'), 'Algolia Admin API Key'),
    (re.compile(r'(?i)algolia.{0,16}([A-Z0-9]{10})\b'), 'Algolia Application ID'),
    (re.compile(r'(?i)cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b'), 'Cloudflare API Token'),
    (re.compile(r'(?i)(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b'), 'Cloudflare Service Key'),
    # --- GATED replacements (context required; were catastrophic bare patterns) ---
    (re.compile(r'(?i)bugsnag.{0,40}([a-f0-9]{32})\b'), 'Bugsnag API Key'),
    (re.compile(r'(?i)datadog.{0,40}([a-z0-9]{32})\b'), 'Datadog API Key'),
    (re.compile(r'(?i)(?:telegram|tg|bot)\D{0,16}(\d{9}:[a-zA-Z0-9_-]{35})\b'), 'Telegram Bot Token'),
    (re.compile(r'(?i)twilio.{0,40}(SK[0-9a-fA-F]{32})\b'), 'Twilio API Key'),
    (re.compile(r'(?i)dropbox.{0,40}(sl\.[A-Za-z0-9_-]{43,})\b'), 'Dropbox Access Token'),
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

def _is_valid_endpoint(value, label=''):
    """Return True if value is a real API endpoint path worth reporting.

    The leading-slash requirement is skipped for the 'Relative API Path'
    category (§4.5), which intentionally matches no-leading-slash paths.
    """
    if not value or len(value) < 3:
        return False
    if value in NOISE_STRINGS:
        return False
    for pattern in NOISE_PATTERNS:
        if pattern.search(value):
            return False
    if label != 'Relative API Path' and not value.startswith('/'):
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


def _entropy(s):
    """Shannon entropy of string s in bits/char. Py2/Py3 compatible."""
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
    """Return True if value looks like a real secret (§4.3).

    Fixed-prefix KEEP patterns (label in _SECRET_KEEP_LABELS) bypass the weak
    heuristics (trivial sequences + entropy floor) -- the prefix is the precision.

    Spec-gap G1: spec §4.3 writes _is_valid_secret(value) as pseudocode; the
    real signature carries an optional label to drive the KEEP bypass.
    """
    if not value or len(value) < 12:  # Raised from 10 to 12 in Phase 2
        return False
    v = value.strip()
    vl = v.lower()
    # Hard placeholder/word rejects (always applied)
    for x in ('example', 'placeholder', 'your', 'xxxx', 'test',
              'sample', 'dummy', 'changeme'):
        if x in vl:
            return False
    if len(set(v)) <= 2:               # all-same / trivially repeating
        return False
    if vl.isalpha() and vl in _COMMON_WORDS:
        return False
    if _UUID_RE.match(v) or _HEX64_RE.match(v) or _COLOR_RE.match(v):
        return False
    # Entropy floor -- bypassed for fixed-prefix KEEP labels (decision #5).
    # (Note: a trivial-sequence substring check like '1234'/'0000' was considered
    # but rejected -- it kills legitimate keys, e.g. a Telegram id '123456789...'.)
    if label not in _SECRET_KEEP_LABELS:
        threshold = 3.0 if _ENTROPY_HEX_RE.match(v) else 3.5
        if _entropy(v) < threshold:
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
        # Build the normalized path index once (read-only thereafter).
        # No wordlist -> empty frozenset -> dictionary matching disabled.
        if wordlist is not None:
            self._index = JSAnalyzerEngine._build_index(wordlist)
        else:
            self._index = frozenset()

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

        # 1. Endpoints (ENDPOINT_PATTERNS are (regex, label) tuples)
        seen_ep = set()
        for pattern, label in ENDPOINT_PATTERNS:
            for match in pattern.finditer(body):
                try:
                    value = match.group(1).strip()
                except IndexError:
                    continue
                if _is_valid_endpoint(value, label) and value not in seen_ep:
                    seen_ep.add(value)
                    result['endpoints'].append(value)

        # 2. URLs
        seen_url = set()
        for pattern in URL_PATTERNS:
            for match in pattern.finditer(body):
                try:
                    value = (match.group(1) if match.lastindex else match.group(0)).strip()
                except IndexError:
                    value = match.group(0).strip()
                if _is_valid_url(value) and value not in seen_url:
                    seen_url.add(value)
                    result['urls'].append(value)

        # 3. Secrets -- per-response span dedup, most-specific-first (§4.3)
        used_spans = []

        def _overlaps(start, end):
            for s, e in used_spans:
                if start < e and end > s:
                    return True
            return False

        for pattern, label in SECRET_PATTERNS:
            for match in pattern.finditer(body):
                start, end = match.start(), match.end()
                if _overlaps(start, end):
                    continue
                try:
                    value = match.group(1).strip()
                except IndexError:
                    value = match.group(0).strip()   # no capture group -> full match
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

        # 4. Emails
        seen_em = set()
        for match in EMAIL_PATTERN.finditer(body):
            try:
                value = match.group(1).strip()
            except IndexError:
                continue
            if _is_valid_email(value) and value not in seen_em:
                seen_em.add(value)
                result['emails'].append(value)

        # 5. Files
        seen_fi = set()
        for match in FILE_PATTERNS.finditer(body):
            try:
                value = match.group(1).strip()
            except IndexError:
                continue
            if _is_valid_file(value) and value not in seen_fi:
                seen_fi.add(value)
                result['files'].append(value)

        # 6. Dictionary -- §2.3 passive matching (only when a wordlist is loaded)
        if self._index:
            result['dictionary'] = _match_dict(js_text, self._index, cap=500)

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
    # staticmethods simply delegate -- they do NOT inline re.compile().
    # The module-level definitions are the single source of truth.

    @staticmethod
    def _entropy(s):
        """Delegate to module-level _entropy (single source of truth)."""
        return _entropy(s)
