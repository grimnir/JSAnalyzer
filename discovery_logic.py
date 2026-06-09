# -*- coding: utf-8 -*-
"""
discovery_logic.py -- Pure Python helpers for WS2 Active Scanner.

Zero burp/java/javax imports. Runs under CPython3 and Jython 2.7.
The threading/HTTP/Swing parts live in ui/active_scan_panel.py; everything
that can be unit-tested lives here.
"""
import re

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
    dedup preserving order. Returns a list of str. Py2/Py3 compatible.
    """
    seen = set()
    out = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        # Cut at first of ?, #, | (sequential cuts converge to earliest separator)
        for sep in ('?', '#', '|'):
            idx = line.find(sep)
            if idx != -1:
                line = line[:idx]
        line = line.strip()
        if not line:
            continue
        # Enforce a single leading slash
        line = '/' + line.lstrip('/')
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


# ---------------------------------------------------------------------------
# §3.6 Triage -- which status codes are interesting?
# ---------------------------------------------------------------------------
_REPORTED_SIMPLE = frozenset([200, 201, 204, 401, 403, 405, 500, 502, 503])
_REDIRECT_CODES = frozenset([301, 302, 307, 308])


def is_interesting(status, has_location=False):
    """Return True if the response should be reported.

    Reported: 200, 201, 204, 301/302/307/308 only with a Location header,
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
    """Count words in the first 8 KB, bucketed to the nearest 10."""
    chunk = body_text[:8192]
    words = len(chunk.split())
    return (words // 10) * 10


def soft404_fingerprint(status, body_len, body):
    """Return (status, len_bucket, word_bucket).

    len_bucket = body_len // 64 * 64  (64-byte granularity tolerates jitter)
    word_bucket = word count of first 8 KB bucketed to nearest 10
    """
    len_bucket = (body_len // 64) * 64
    return (status, len_bucket, _word_bucket(body))


# ---------------------------------------------------------------------------
# Passive->active bridge: convert a passive finding to a concrete probe path
# ---------------------------------------------------------------------------
def to_probe_path(value):
    """Convert a passive finding (endpoint/url/dictionary template) to a concrete
    probe path. Strips scheme+host from full URLs, replaces '{id}' templates with a
    sample '1', strips query/fragment, ensures a single leading '/'. Returns '' if
    nothing usable remains."""
    if not value:
        return ''
    v = value.strip()
    # strip scheme://host
    if '://' in v:
        rest = v.split('://', 1)[1]
        slash = rest.find('/')
        v = rest[slash:] if slash != -1 else '/'
    # cut query/fragment
    v = v.split('?', 1)[0].split('#', 1)[0]
    # template id -> sample
    v = v.replace('{id}', '1')
    v = v.strip()
    if not v:
        return ''
    if not v.startswith('/'):
        v = '/' + v
    # collapse leading duplicate slashes
    while v.startswith('//'):
        v = v[1:]
    return v


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
