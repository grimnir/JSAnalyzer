# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Burp Suite extension (loaded under **Jython 2.7 / Python 2** inside Burp) that statically analyzes JavaScript responses to extract API endpoints, URLs, secrets, emails, and sensitive file references — with aggressive noise filtering to keep findings accurate. A fork adds **dictionary-based endpoint matching** (passive) and **safe, opt-in active endpoint discovery**.

The detection logic has been split out of the Burp glue into pure, dependency-free Python modules so it can be unit-tested without Burp.

## Runtime constraints (read before editing)

The extension runs inside Burp Suite under **Jython 2.7**, not CPython 3. This dictates how the Burp-facing code must be written:

- **Python 2 syntax only** in the Burp-facing files: `print` statements, `%`-formatting (no f-strings). String formatting uses `"... %d ..." % (...)`.
- **No `pip` packages.** Only the Python stdlib available in Jython plus the Java standard library are usable. UI is built on **Java Swing** (`javax.swing`, `java.awt`), imported directly as if they were Python modules.
- **Burp APIs** come from the `burp` package (`IBurpExtender`, `IContextMenuFactory`, `ITab`, `IExtensionStateListener`). These exist only when loaded inside Burp — the Burp-facing files cannot be run from a normal `python`/`python3` invocation.

The pure engine modules (`js_analyzer_engine.py`, `discovery_logic.py`, `ui/csv_utils.py`) are written to be **py2/py3 compatible** and have **no Burp/Swing imports**, so they run under CPython 3 and are covered by the unit suite:

```bash
python3 -m unittest discover tests
```

There are **210 tests** in `tests/`. The Burp-facing files (`js_analyzer.py`, `ui/results_panel.py`, `ui/active_scan_panel.py`) require Jython inside Burp and are **not** in the test suite; verify them with `python -m py_compile <file>` for syntax and by loading the extension in Burp (`Extensions > Installed > Add`, Python/Jython) and reading the Output tab (`self._log(...)` writes there).

## Architecture

The codebase is split into a thin Burp adapter, pure logic modules, and Swing UI:

- **`js_analyzer.py`** — thin Burp adapter. `BurpExtender` implements `IBurpExtender`, `IContextMenuFactory`, `ITab`, and `IExtensionStateListener`. It owns session dedup (`seen_values`), persisted settings, default wordlist load (`api.txt`), and dispatches analysis **off the Swing EDT** (via `_AnalyzeRunnable` / `_AddFindingsRunnable` on background threads, results marshaled back with `SwingUtilities.invokeLater`). `AnalyzeAction` wires the passive right-click menu item; `ProbeAction` wires the active-discovery menu item; `_DiscoveryTab` is the `ITab` wrapper. The actual detection is delegated to `js_analyzer_engine`.
- **`js_analyzer_engine.py`** — pure engine, no Burp deps. Holds the regex tables and noise tables, the per-category validators (`_is_valid_endpoint`, `_is_valid_url`, `_is_valid_secret`, `_is_valid_email`, `_is_valid_file`), Shannon `_entropy`, the dictionary normalization + index + match (`_norm_seg` / `_norm_path` / `_match_dict`), `cast_setting` for settings coercion, and the `JSAnalyzerEngine` class used by both Burp and the tests.
- **`discovery_logic.py`** — pure active-scan logic, no Burp deps. `_sanitize` (wordlist cleanup), `is_destructive` (skip `del`/`delete`/`remove`/`drop`/`reset`/`logout`/…), `is_interesting` (result triage), `soft404_fingerprint` (wildcard "everything-200" calibration), and `build_request_line`.
- **`ui/results_panel.py`** — `ResultsPanel` (a `JPanel`): the passive results UI as **6 tabbed tables** (Endpoints, URLs, Secrets, Emails, Files, **Dictionary**), with live search, source filtering, copy, clear, and **JSON + CSV export** (whole-panel buttons plus a per-tab right-click CSV export).
- **`ui/active_scan_panel.py`** — the active-discovery UI and threaded engine: `DiscoveryConfig` (settings), `WordlistLoader`, `DiscoveryPanel` (Swing panel), `DiscoveryEngine` (bounded thread pool, token-bucket rate limit, per-request timeout, Stop, auto-pause on error bursts), and `ProbeTask` (one probe). Only response metadata is stored — never bodies.
- **`ui/csv_utils.py`** — pure RFC-4180 CSV helpers (`_csv_field`, `format_csv_row`).
- **`tests/`** — 210 unit tests (`test_engine.py`, `test_normalization.py`, `test_discovery_logic.py`, `test_csv_format.py`) run under CPython 3.
- **`api.txt`** — default wordlist (~49.7k relative API paths), loaded at startup if present next to the extension.

**Detection vs. filtering is the core design.** A regex match is never trusted on its own — it must pass the category's `_is_valid_*` validator in `js_analyzer_engine.py`. When adding a pattern, that validator is where false positives get suppressed. The stated goal is "reduce noise as much as possible to ensure accuracy," so prefer tightening validators over loosening them.

**Secrets are entropy + context gated.** The dangerous catch-all secret patterns (bare `[a-f0-9]{32}` "Bugsnag", `[a-z0-9]{32}` "Datadog") have been replaced with context-gated forms that require a nearby context keyword and must clear a Shannon-entropy floor (with shape rejection for UUID/sha256/CSS-color). Fixed-prefix keys (AWS `AKIA…`, Google `AIza…`, Stripe `sk_live_…`, GitHub `ghp_…`, …) are reported directly. Keep this gating in mind before loosening `_is_valid_secret`.

## Adding detections

To add a new secret type, append a `(re.compile(...), "Label")` tuple to the secret table in `js_analyzer_engine.py`. Capture the secret in **group 1** — the pipeline reads `match.group(1)` for secrets/endpoints/emails/files (URLs fall back to `group(0)` when there's no capture group). Then make sure `_is_valid_secret` (length / entropy / context / shape checks) won't wrongly reject it, and add or extend a test in `tests/test_engine.py`.

## Notes

- The dictionary index normalizes ID-like path segments (numeric, version, UUID, long-hex) to `{id}` so `api/users/777` and `api/users/999` both collapse to the single template `api/users/{id}`. Longest-prefix matching lets a JS path with extra trailing segments match a shorter template.
- `api.txt` is data, not code; the extension works without it (dictionary matching is simply disabled).
- The pure modules are py2/py3 compatible and unit-tested; the Burp-facing files are verified via `py_compile` plus a manual load in Burp.
