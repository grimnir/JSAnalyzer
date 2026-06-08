# JS Analyzer — Dictionary Matching (Passive + Active) + Improvement Package

**Date:** 2026-06-08
**Status:** Approved (design)
**Beads epic:** JSAnalyzer-main-d4k
**Runtime:** Jython 2.7 inside Burp Suite (Python 2 syntax, no pip; Java stdlib + legacy Burp Extender API available). CPython3 used only to unit-test the pure engine.

This design was produced by a multi-agent research workflow (6 parallel researchers + adversarial verification + architect synthesis). Three Burp-API facts were corrected by verification and are applied throughout — see **§0 Verified corrections**.

---

## 0. Verified corrections (applied in this spec)

1. **`IRequestInfo.getHeaders()` returns an UNMODIFIABLE list.** Calling `.set()/.add()` on it throws `UnsupportedOperationException` (silent inside `except` blocks). Always copy first: `headers = list(req_info.getHeaders())`, then mutate the copy.
2. **`makeHttpRequest` overload return types differ.** `makeHttpRequest(IHttpService, byte[])` returns `IHttpRequestResponse`; the `makeHttpRequest(String host, int port, boolean useHttps, byte[])` overload returns **`byte[]`**. Use the **`IHttpService`** overload for WS2. `makeHttpRequest` is on `IBurpExtenderCallbacks` (the callbacks object), not on `IExtensionHelpers`. It is **synchronous/blocking** — call only from a worker thread, never the EDT.
3. **Stop flag must be `java.util.concurrent.atomic.AtomicBoolean`**, not a plain Python bool (no cross-thread visibility guarantee on the JVM otherwise).

(Non-load-bearing: Montoya API boundary is Burp 2022.9.5, not 2022.8.1 — legacy `burp` package remains the correct choice for Jython.)

---

## Resolved decisions (the 6 open questions)

| # | Question | Decision (v1) |
|---|----------|---------------|
| 1 | WS2 HTTP method | **GET-only**; HEAD checkbox is a future toggle |
| 2 | Results in Burp Site Map | Leave Burp's automatic proxy-history; **no explicit `addToSiteMap`** |
| 3 | Destructive-path skip list | **Fixed regex** in v1 (user-editable list is future work) |
| 4 | WS2 UI ceilings | threads ≤ 50, rate ≤ 100 req/s |
| 5 | 19 fixed-prefix secret patterns | **Bypass** the entropy floor (the prefix *is* the precision) |
| 6 | api.txt for WS2 fuzzing | Fuzz **concrete sanitized paths**, not `{id}` templates |

**Consequences the user accepted:** active scan sends real HTTP traffic and results land in Burp proxy history; legacy `saveExtensionSetting` is **global** (shared across all Burp projects).

---

## 1. Overview & component map

```
JSAnalyzer-main/
├── js_analyzer.py              # Thin Burp adapter: IBurpExtender, IContextMenuFactory, ITab,
│                               # IExtensionStateListener. Owns: seen_values dedup set, dedup cap,
│                               # settings load/save, file I/O (api.txt), Swing wiring,
│                               # off-EDT analysis dispatch.
├── js_analyzer_engine.py       # NEW. Pure Python (no burp/java imports).
│                               # All regex tables, noise tables, validators, entropy helpers,
│                               # dict index build+match. JSAnalyzerEngine.analyze() -> result dict.
├── ui/
│   ├── results_panel.py        # 6-tab Swing panel (endpoints/urls/secrets/emails/files/dictionary).
│   │                           # Live search (debounced), source filter, Copy/Export(JSON+CSV), stats.
│   └── active_scan_panel.py    # NEW. DiscoveryPanel JPanel: table+progressbar+start/stop+config.
│                               # DiscoveryEngine, ProbeTask(Runnable), WordlistLoader, DiscoveryConfig.
├── tests/
│   ├── __init__.py             # empty
│   ├── test_engine.py          # RED->GREEN unit tests (CPython3, stdlib only)
│   └── test_normalization.py   # Segment/path normalization corner cases
└── api.txt                     # 49,675 relative path fragments (wordlist, unmodified)
```

**Responsibility boundary:** anything touching `burp.*`, `javax.swing`, `java.*`, file I/O, or Burp callbacks stays in `js_analyzer.py` / `ui/`. Anything touching regex, text analysis, normalization, or entropy stays in `js_analyzer_engine.py` (pure, dual-runtime, stateless per call).

---

## 2. WS1 — Passive dictionary matching

### 2.1 Normalization scheme

Split each path on `/`; normalize each segment independently (first match wins → token `{id}`):

```python
import re
_SEG_NUM  = re.compile(r'^\d+$')
_SEG_VER  = re.compile(r'^\d+([._-]\d+)+$')        # 1.0, 24_8_0, 85-88-31
_SEG_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
_SEG_HEX  = re.compile(r'^[0-9a-f]{16,}$', re.I)    # >= 16 hex chars

def _norm_seg(s):
    if _SEG_NUM.match(s) or _SEG_UUID.match(s) or _SEG_HEX.match(s) or _SEG_VER.match(s):
        return '{id}'
    return s

def _norm_path(p):
    return '/'.join(_norm_seg(s) for s in p.split('/'))
```

**NOT normalized:** `v1`, `v2`, camelCase method names, any letter+digit mixed segment. The "base64-ish / long mixed-alnum" rule is **dropped** — on this dictionary it false-collapses 39 readable method names for ~2 genuine opaque tokens.

### 2.2 Index structure

Single `frozenset` of normalized lowercase strings, built once in `__init__`:

```python
def _build_index(lines):
    idx = set()
    for ln in lines:
        p = ln.strip().lower()
        if p:
            idx.add(_norm_path(p))
    return frozenset(idx)
```

- 49,675 lines → ~47,905 unique normalized entries
- Memory ~5–6 MB; build ~70 ms CPython / ~150–200 ms Jython (one-time at load)
- Lookup O(1). No trie / Aho-Corasick / second literal set.

### 2.3 Candidate extraction & match (one pass)

```python
_DICT_CAND = re.compile(r'[A-Za-z0-9_.~-]+(?:/[A-Za-z0-9_.~-]+)+')

def _match_dict(body, idx, cap=500):
    out, seen = [], set()
    for m in _DICT_CAND.finditer(body):
        c = m.group(0).lower().lstrip('/')
        if len(c) > 512 or c.count('/') > 12:
            continue
        segs = [_norm_seg(s) for s in c.split('/')]
        if len(segs) < 2:
            continue
        for k in range(len(segs), 1, -1):          # longest-prefix walk
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

**Prefix matching enabled** (+~65% hits at ~0 ms: JS paths routinely carry extra trailing segments). Both dict and candidates lowercased → case-insensitive without per-lookup variants.

### 2.4 Dedup, cap, UI

- Dedup key `'dictionary:' + template` in `seen_values`; finding `value = template`, `source = JS filename`.
- Cap 500 matches/response; global dedup cap (§4.4) applies.
- Sixth **Dictionary** tab (columns Template | Source); stats label gains `| D:0`; JSON export gains `"dictionary"`; CSV included. `_is_valid_endpoint` is NOT called for dictionary findings.
- **Note:** the category list is hardcoded in several sites in `results_panel.py` (the `findings` dict, the `categories`/titles/keys lists, `_update_stats`, export map). Enumerate them via `grep -n 'endpoints\|emails\|files' ui/results_panel.py` during Phase 1 and update every one — do not trust a fixed count.

---

## 3. WS2 — Active scanner (`ui/active_scan_panel.py`)

`js_analyzer.py` gains one attribute (`self._discovery_engine`) and one menu item; `analyze_response()` is untouched.

### 3.1 Trigger & consent

Context menu item **"Probe endpoints with wordlist"** shown only when exactly one message is selected. On click (EDT):
1. Base = `scheme + host + port` from `helpers.analyzeRequest(msg).getUrl()`.
2. `callbacks.isInScope(base_url)` — if false, warn and abort **before** confirmation.
3. Build filtered wordlist (destructive + scope) → final count.
4. Mandatory `JOptionPane.showConfirmDialog` (OK_CANCEL, WARNING icon) showing host, post-filter count, method, threads, rate, timeout, destructive/in-scope state, and "This sends real HTTP requests. GET can have side effects."
5. Proceed only on `YES_OPTION`.

### 3.2 Safety gates (default safe profile)

| Setting | Default | Notes |
|---|---|---|
| Method | GET | never POST/PUT/PATCH/DELETE |
| In-scope only | true | per-task `isInScope` |
| Allow destructive | false | skipped at load time |
| Threads | 10 (≤50) | bounded pool |
| Rate | 20/s (≤100) | token-bucket |
| Timeout | 10 s | `Future.get` |

```python
_DESTRUCTIVE = re.compile(
    r'(?i)(?:^|[/_.-])(?:del|delete|remove|destroy|drop|deactivate|disable|'
    r'revoke|purge|wipe|reset|logout|signout|signoff|terminate|cancel|'
    r'expire|kill|unsubscribe)(?:$|[/_.-])')
```

Applied at load time (~557 entries in api.txt).

### 3.3 Wordlist sanitization (once at load)

Strip blanks/comments; cut at `?`, `#`, `|`; ensure single leading `/`; dedup. (Concrete paths, per decision #6 — not `{id}` templates.)

### 3.4 Concurrency model

- `ThreadPoolExecutor(n, n, 0, MILLISECONDS, ArrayBlockingQueue(n*4), CallerRunsPolicy)`.
- Dispatcher on a dedicated non-EDT `java.lang.Thread`; token-bucket rate limit in the dispatcher (sleep between submits).
- Per-request timeout: wrap the blocking `makeHttpRequest` in a `Callable` submitted to a cached pool; `future.get(timeout, SECONDS)`; `future.cancel(True)` on `TimeoutException`.
- Request built from the selected request as **template** (auth carries over) — **copy headers first** (correction §0.1):

```python
req_info = self._helpers.analyzeRequest(msg)
headers = list(req_info.getHeaders())            # MUST copy (unmodifiable)
parts = headers[0].split(' ')
headers[0] = parts[0] + ' ' + path + ' ' + parts[-1]
for h in [h for h in headers if h.lower().startswith(
        ('content-type:', 'content-length:', 'transfer-encoding:'))]:
    headers.remove(h)
req_bytes = self._helpers.buildHttpMessage(headers, None)
rr = self._callbacks.makeHttpRequest(msg.getHttpService(), req_bytes)   # IHttpService overload
```

- **Stop / unload:** `AtomicBoolean stop` checked first line of each `ProbeTask.run()`; Stop button and `IExtensionStateListener.extensionUnloaded()` both call `shutdownNow()` (+ `awaitTermination(5, SECONDS)`).
- **Auto-pause:** `AtomicInteger error_streak`; on ≥20 consecutive errors/timeouts pause 5 s and warn in UI.

### 3.5 Soft-404 calibration

Before dispatch, probe 2–3 random non-existent paths (`UUID.randomUUID()`); fingerprint `(status, len//64*64, word_count_bucket_first_8KB)`; suppress probes matching any baseline. If a baseline returns 200, show a persistent warning.

### 3.6 Triage, streaming, memory

- Report: 200, 201, 204, 301/302/307/308 (only with `Location`), 401, 403, 405, 500, 502, 503. Drop 404/400 and soft-404 matches.
- Result dict (metadata only, never body): `{path, status, length, ctype, redirect}`.
- `ProbeTask` → `ConcurrentLinkedQueue`; a `javax.swing.Timer` (250 ms, EDT) drains ≤500 rows/tick into the JTable and updates `JProgressBar`. ~300–400 B/row; realistic < 2 MB, worst case (all 50k interesting) ~20 MB.
- Columns: Path | Status | Length | Content-Type | Redirect; status-class filter; CSV export. Active results are NOT added to `seen_values`.

---

## 4. WS3 — Improvements

### 4.1 Engine extraction & adapter wiring

```python
class JSAnalyzerEngine(object):
    def __init__(self, wordlist=None): ...   # builds frozenset index once
    def analyze(self, js_text, source=None):
        # always returns all 6 keys (lists may be empty):
        # {'endpoints':[str], 'urls':[str],
        #  'secrets':[{'type','value','masked'}], 'emails':[str],
        #  'files':[str], 'dictionary':[(template, evidence)]}
    @staticmethod
    def _build_index(lines): ...
    @staticmethod
    def _norm_path(p): ...
    @staticmethod
    def _norm_seg(s): ...
    @staticmethod
    def _entropy(s): ...
# module-level for tests: _is_valid_endpoint/_url/_secret/_email/_file
```

Engine is **stateless per call**; dedup, caps, persistence live in `BurpExtender`. File I/O (reading api.txt) lives in the adapter; engine takes an iterable of lines.

**Off-EDT dispatch** (fixes current freeze): `AnalyzeAction.actionPerformed` runs `analyze_response` in an explicit `Runnable` subclass on a `java.lang.Thread`; `panel.add_findings` is marshalled back via `SwingUtilities.invokeLater`. Apply a 2 MB body cap **before** dictionary matching.

### 4.2 Py2/Py3 compatibility rules (enforced in engine)

`range` (no `xrange`); `.items()/.values()` (no `iter*`); `'%s' % v` (no f-strings); no `print`; `float(c)/n`; `math.log(p)/math.log(2)` (no `math.log2`); `except E as e`; ASCII literals; `frozenset(list(gen))` if a Jython generator edge case appears.

### 4.3 Secret false-positive reduction

**DROP + REBIRTH** the two catastrophic patterns:
- `[a-f0-9]{32}` "Bugsnag" → `(?i)bugsnag.{0,40}?([a-f0-9]{32})\b`
- `[a-z0-9]{32}` "Datadog" → `(?i)datadog.{0,40}?([a-z0-9]{32})\b`

**GATE** (add context): Telegram `(?i)(?:telegram|tg|bot)\D{0,16}(\d{9}:[a-zA-Z0-9_-]{35})\b`; Twilio `(?i)twilio.{0,40}?(SK[0-9a-fA-F]{32})\b`; Dropbox `(?i)dropbox.{0,40}?(sl\.[A-Za-z0-9_-]{43,})\b`.

**KEEP as-is:** the 19 fixed-prefix patterns (AKIA, AIza, ghp_, sk_live_, xox*, JWT, PRIVATE KEY, DB URIs, sgp_, ya29., lin_api_, dop_v1_, SG.*, glpat-, shpat_, NRII-) and the already-context-gated ones (Algolia/Cloudflare/Facebook/Segment). Per decision #5 these **bypass** the entropy floor.

```python
def _entropy(s):
    if not s: return 0.0
    n = len(s); freq = {}
    for ch in s: freq[ch] = freq.get(ch, 0) + 1
    h = 0.0
    for c in freq.values():
        p = float(c)/n
        h -= p * (math.log(p)/math.log(2))
    return h

def _is_valid_secret(value):
    if not value or len(value) < 12: return False
    v = value.strip(); vl = v.lower()
    for x in ('example','placeholder','your','xxxx','test','sample','dummy','changeme','0000','1234'):
        if x in vl: return False
    if len(set(v)) <= 2: return False
    if vl.isalpha() and vl in _COMMON_WORDS: return False
    if _UUID_RE.match(v) or _HEX64_RE.match(v) or _COLOR_RE.match(v): return False
    threshold = 3.0 if _ENTROPY_HEX_RE.match(v) else 4.0
    if _entropy(v) < threshold: return False
    return True
```

**Per-response span dedup** (most-specific patterns first; skip overlapping spans) eliminates one-token-many-labels. Dedup key fix: key `seen_values` on the **raw** secret value, store masked form for display.

### 4.4 Memory bounding

`DEDUP_CAP = 50000` guard at top of `_add_finding`; once reached, log once and drop further findings.

### 4.5 Relative path detection

`_DICT_CAND` already catches no-leading-slash paths. Add one endpoint pattern:
`(re.compile(r'["\']((api|graphql|rest|v\d+)/[a-zA-Z0-9_/.-]{3,100})["\']'), 'Relative API Path')`.
Make `_is_valid_endpoint`'s leading-slash check conditional (not applied to dictionary / relative-API category).

### 4.6 Settings persistence

Prefix `jsa_`; keys: threads(10), rate(20), timeout(10), method(GET), destructive(false), inscope(true), wordlist(''). `_load_setting`/`_save_setting` cast via a table; loaded in `registerExtenderCallbacks`, saved on change. **Global across projects** — document in source.

### 4.7 UI

`JProgressBar` in header; "Type" column for secrets (from `finding['label']`); stats label `| E:.. | U:.. | S:.. (N dup) | M:.. | F:.. | D:.. |` and fixed initial string; search debounced via `javax.swing.Timer` (150 ms).

### 4.8 CSV export

"Export CSV" button (alongside JSON) writing `category,value,source,label` via `codecs.open(path,'w','utf-8')` with quote-escaping; per-tab CSV via `JPopupMenu` "Export this tab as CSV".

---

## 5. Initial RED tests (`tests/`, `python3 -m unittest discover tests`)

Cover (≈30 tests): engine imports without Burp; `analyze('')` returns all 6 keys empty; statelessness; secret has type/value/masked. **FP gates:** bare hex32 without context NOT reported; with `bugsnag` keyword + high entropy reported; low-entropy rejected; datadog without context not reported; AKIA still reported; JWT reported; all-same-char rejected; UUID rejected. **Dictionary:** numeric id → template; UUID segment → template; alpha segment NOT promoted; exact match; no-match empty; index dedup; prefix match on extra trailing segment; cap enforced. **Normalization:** numeric/version/uuid/long-hex collapse; `v1`/camelCase don't; full path. **Validators:** endpoint no-leading-slash rejected; noise string/domain/data-uri rejected; example email rejected, real accepted; package.json rejected, backup.sql accepted.

---

## 6. Implementation phasing (→ beads sub-tasks)

**Phase 0 — Foundation** (blocks everything): git init + .gitignore; `tests/` with all tests (verify RED); create `js_analyzer_engine.py` (constants + validators copied verbatim, class stub); contract tests GREEN; wire adapter (`from js_analyzer_engine import JSAnalyzerEngine`, replace inline detection, **delete** module tables from `js_analyzer.py`); load in Burp → regression check.

**Phase 1 — WS1** (depends 0): `_norm_seg/_norm_path/_build_index` → normalization tests GREEN; `_match_dict` → dictionary tests GREEN; adapter reads api.txt → engine; Dictionary tab + every hardcoded category site (enumerate via grep) + stats fix; wire findings; integration check.

**Phase 2 — WS3** (depends 0; parallel-friendly with 1): secret FP gate + entropy + span dedup → secret tests GREEN; Type column; dedup key fix + memory cap; off-EDT dispatch + 2 MB cap; settings persistence; search debounce; CSV export; stats/dup counters.

**Phase 3 — WS2** (depends 0; 2 recommended first): `active_scan_panel.py` skeleton (DiscoveryConfig, `_sanitize`, panel shell); DiscoveryEngine (pool, stop, dispatcher); ProbeTask (copy-headers build, send, parse, queue); soft-404 calibration; streaming drain Timer; `extensionUnloaded` → shutdown; context menu + consent + scope; settings; auto-pause.

---

## 7. Risks (residual)

- **Critical:** header copy (§0.1), `makeHttpRequest` overload (§0.2), `AtomicBoolean` stop (§0.3) — all applied above.
- **Medium:** entropy 3.2 may pass some webpack hashes (context gate handles); 200 ms budget tight on >2 MB bodies (2 MB cap mitigates, applied before matching); global settings bleed across projects (documented).
- **Low:** legacy API has no native per-request timeout — `Future` wrapper is the only mitigation; a slow-loris target can still pin a thread until OS timeout.

---

## 8. Acceptance criteria

**WS1:** index build < 300 ms (Jython, 50k); index memory < 15 MB (Runtime before/after); 1 MB body match < 200 ms; `api/v1/users/99999` → template `api/v1/users/{id}`; `api/v1/users/42/settings` → `api/v1/users/{id}` (prefix); `api/v1/users/abc` does NOT match; Dictionary tab populates; two differing concrete IDs → exactly 1 finding; `v1`/`v2` not collapsed.

**WS2:** no request without explicit YES confirmation; dialog shows post-filter count/host/method/threads/rate/destructive; all requests GET (or HEAD if enabled), never POST/PUT/DELETE; destructive paths skipped by default (require checkbox + re-confirm); `isInScope` checked before dialog; Stop halts within ~1 request cycle; `extensionUnloaded` shuts pool (no thread leak); soft-404 suppresses uniform 404s (+ warning on 200-for-random); table shows Path/Status/Length/Content-Type/Redirect; memory for 50k interesting < 20 MB; measured rate ≤ 25/s at default 20/s.

**WS3:** `python3 -m unittest discover tests` runs with zero Burp deps; all tests GREEN; engine imports under CPython3 and Jython 2.7; bare hex32 without context → 0 secrets; AKIA still reported (no regression); bugsnag-context+high-entropy reported; secret Type column present; same large body analyzed 3× → identical finding counts; `seen_values` ≤ 50,001; CSV is valid UTF-8 with category/value/source/label; settings survive Burp restart; 500 KB body does not freeze UI (off-EDT).
