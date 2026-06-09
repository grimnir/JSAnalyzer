# JS Analyzer - Burp Suite Extension

> **Original project** by **Jenish Sojitra ([@_jensec](https://x.com/_jensec))**.
> **This fork adds dictionary-based endpoint discovery (passive + active) and an accuracy/UX package — enhancements by Grimnir Skog.** Original credits preserved below.

A powerful Burp Suite extension for JavaScript static analysis. Extracts API endpoints, URLs, secrets, and email addresses from JavaScript files with intelligent noise filtering. The goal is to reduce noise as much as possible to ensure accuracy.

![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Extension-orange)
![Python](https://img.shields.io/badge/Python-Jython%202.7-blue)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ What's new in this fork (Grimnir Skog)

This fork keeps the original passive JS analysis intact and adds three workstreams on top:

### 1. Dictionary endpoint matching — **passive** (the headline feature)
A wordlist (`api.txt`, ~49.7k relative API paths) is now used during analysis. When you analyze a JS response, the extension also reports any **known endpoint templates** that appear in the code:

- **ID normalization** — numeric, version (`1.0`, `24_8_0`), UUID, and long-hex path segments collapse to `{id}`, so `api/users/777` and `api/users/999` both match the single template **`api/users/{id}`** (one finding, not two).
- **Fast & low-memory** — the wordlist is compiled once into a normalized index (~48k templates, ~5–6 MB). Candidate paths are extracted from the JS in a single pass and matched with O(1) hash lookups (no 50k substring scans). Measured: index build ~64 ms, match of a 1 MB body well under the 200 ms budget.
- **Longest-prefix matching** — a JS path with extra trailing segments still matches the shorter dictionary template.
- Results appear in a new **Dictionary** tab (Template | Source).

### 2. Endpoint discovery — **active** (opt-in, safe by default)
Right-click a request → **"Probe endpoints with wordlist"** to probe the target host with the wordlist. Safety is the whole design:

- **GET only** (the method is taken from your selected request, so auth/cookies carry over) — never POST/PUT/PATCH/DELETE.
- **Destructive paths skipped** by default (`del`, `delete`, `remove`, `drop`, `reset`, `logout`, …) unless explicitly enabled.
- **Scope-enforced** — out-of-scope targets are refused (`isInScope`) *before* a mandatory confirmation dialog showing host + request count + settings.
- **Bounded & polite** — fixed thread pool, token-bucket rate limit, per-request timeout, **Stop** button, auto-pause on error bursts, and soft-404 calibration (filters wildcard "everything-200" pages).
- **Memory-safe** — only response metadata is stored (status / length / content-type / redirect), never bodies.

### 3. Accuracy & UX improvements
- **Far fewer false-positive secrets** — the dangerous catch-all patterns (bare `[a-f0-9]{32}` "Bugsnag", `[a-z0-9]{32}` "Datadog") are replaced with **context-gated** forms, plus a **Shannon-entropy** floor and shape rejection (UUID/sha256/CSS-color). Fixed-prefix keys (AWS, Stripe, GitHub, …) are kept as-is.
- **Relative API path detection** (`api/...`, `v2/...` without a leading slash).
- **CSV export** (RFC 4180) in addition to JSON, plus a per-tab right-click export.
- **Secrets "Type" column**, duplicate counters, and a debounced search box.
- **No UI freeze** — analysis runs off the Swing EDT; large bodies are capped at 2 MB.
- **Bounded memory** — session dedup is capped.
- **Settings persist** across Burp restarts (threads, rate, timeout, method, toggles).
- **Testable core** — all detection logic now lives in a pure, Burp-independent `js_analyzer_engine.py` (plus `discovery_logic.py`), covered by **210 unit tests** runnable under CPython 3.

---

## Features

- **Endpoint Detection** - API paths, REST endpoints, OAuth URLs, admin routes (now incl. relative paths)
- **Dictionary Matching** - finds known API endpoint templates from a wordlist *(fork)*
- **Active Discovery** - safe, opt-in wordlist probing of the target *(fork)*
- **URL Extraction** - full URLs including cloud storage (AWS S3, Azure, GCP)
- **Secret Scanning** - API keys, tokens, credentials (AWS, Stripe, GitHub, Slack, JWT, etc.) with entropy + context gating *(fork)*
- **Email Extraction** - email addresses in JS code
- **File Detection** - references to sensitive files (`.sql`, `.csv`, `.bak`, `.env`, `.pdf`, etc.)
- **Smart Filtering** - removes noise from XML namespaces, module imports, build artifacts
- **Source Tracking** - shows which JS file each finding came from
- **Live Search** - filter results in real time (debounced)
- **Copy / Export** - copy findings, export to JSON or CSV *(CSV is fork)*

## Installation

1. Download the [Jython standalone JAR](https://www.jython.org/download)
2. In Burp Suite: `Extensions > Extensions Settings > Python Environment`
3. Set the Jython JAR path
4. `Extensions > Installed > Add`
5. Select `Python` and browse to `js_analyzer.py`

Keep `api.txt` next to `js_analyzer.py` — it is loaded at startup as the default wordlist (the extension also works without it; dictionary matching is simply disabled). On load you should see `Loaded wordlist: 49675 lines from api.txt` in the extension Output tab.

## Usage

### Passive analysis (incl. dictionary matching)
1. **Browse** websites with your browser proxied through Burp Suite
2. **Right-click** a response containing JS in any of: Proxy > HTTP history, Target > Site map, Repeater
3. Select **"Analyze JS with JS Analyzer"**
4. Check the **JS Analyzer** tab — including the **Dictionary** tab for wordlist matches

You can select multiple requests from HTTP history or the dashboard and send them all to JS Analyzer at once.

### Active discovery *(fork)*
1. Select **exactly one** request whose host you want to probe
2. Right-click → **"Probe endpoints with wordlist"**
3. Review the confirmation dialog (host, request count, method, threads, rate, safety toggles) and confirm
4. Watch live results in the discovery table; press **Stop** anytime

> ⚠️ Active discovery sends real HTTP requests. Only run it against targets you are authorized to test. Defaults are conservative (GET-only, in-scope-only, destructive paths skipped).

## What It Detects

### Endpoints
| Pattern | Example |
|---------|---------|
| API paths | `/api/v1/users`, `/api/v2/auth` |
| Relative API paths *(fork)* | `api/v1/users`, `v2/products/list` |
| REST endpoints | `/rest/data`, `/graphql` |
| OAuth/Auth | `/oauth2/token`, `/auth/login`, `/callback` |
| Admin routes | `/admin`, `/dashboard`, `/internal` |
| Well-known | `/.well-known/openid-configuration` |
| Dictionary templates *(fork)* | `api/v1/business/{id}`, `api/orders/{id}` |

### Secrets
High-precision fixed-prefix patterns (AWS `AKIA…`, Google `AIza…`, Stripe `sk_live_…`, GitHub `ghp_…`, Slack, JWT, private keys, DB URIs, etc.) are reported directly. Ambiguous/short-charset patterns (Bugsnag, Datadog, Telegram, Twilio, Dropbox) now require a **nearby context keyword** and must pass a **Shannon-entropy** floor — drastically cutting false positives versus the original bare-regex approach.

### Noise Filtering
Automatically filters XML namespaces (`schemas.openxmlformats.org`, `www.w3.org`), module imports (`./`, `../`, `@angular/`), PDF/Excel internal paths, locale files, and crypto-library internals.

### Files
Detects references to sensitive file types: data (`.sql`, `.csv`, `.xlsx`, `.json`, `.xml`, `.yaml`), config (`.env`, `.conf`, `.ini`, `.cfg`), backups (`.bak`, `.old`, `.orig`), certs (`.key`, `.pem`, `.crt`, `.p12`), docs (`.pdf`, `.docx`), archives (`.zip`, `.tar`, `.gz`), scripts (`.sh`, `.bat`, `.ps1`, `.py`).

## Architecture *(fork)*

Detection logic is split out of the Burp glue so it can be tested without Burp:

```
JSAnalyzer/
├── js_analyzer.py          # Thin Burp adapter (IBurpExtender / IContextMenuFactory / ITab / IExtensionStateListener)
├── js_analyzer_engine.py   # Pure engine: regex tables, validators, entropy, dictionary index + match (no Burp deps)
├── discovery_logic.py      # Pure active-scan logic: wordlist sanitize, destructive filter, triage, soft-404
├── ui/
│   ├── results_panel.py    # Swing results panel (6 tabs, search, copy, JSON/CSV export)
│   ├── active_scan_panel.py# Swing discovery panel + threaded scan engine
│   └── csv_utils.py        # Pure RFC-4180 CSV helpers
├── tests/                  # 210 unit tests (run under CPython 3)
└── api.txt                 # Default wordlist (49,675 relative API paths)
```

### Standalone Engine
The pure engine is usable outside Burp:

```python
from js_analyzer_engine import JSAnalyzerEngine

engine = JSAnalyzerEngine(wordlist=open('api.txt').readlines())  # wordlist optional
results = engine.analyze(javascript_content)

print(results["endpoints"])   # ['/api/v1/users', ...]
print(results["urls"])        # ['https://api.example.com', ...]
print(results["secrets"])     # [{'type': 'AWS Key', 'value': '...', 'masked': '...'}, ...]
print(results["emails"])      # ['admin@company.com', ...]
print(results["files"])       # ['backup.sql', ...]
print(results["dictionary"])  # [('api/v1/users/{id}', 'api/v1/users/42'), ...]
```

## Running the tests

The pure engine and discovery logic are CPython 3 compatible:

```bash
python3 -m unittest discover tests -v
```

(The Burp-facing files require Jython 2.7 inside Burp and are not exercised by these tests.)

## Contributing

Contributions are welcome — add secret patterns, improve noise filtering, add endpoint patterns, or report bugs.

## License

MIT License - see [LICENSE](LICENSE) file.

## Credits

Inspired by:
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) — endpoint detection regex
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) — secret patterns

Secret-detection false-positive gating (entropy thresholds, context keywords) informed by [gitleaks](https://github.com/gitleaks/gitleaks) and TruffleHog defaults.

## Authors

- **Original author:** Jenish Sojitra — https://x.com/_jensec
- **Fork enhancements (dictionary matching, active discovery, accuracy/UX package):** Grimnir Skog

Created with ❤️ for the InfoSec and Tech community.
