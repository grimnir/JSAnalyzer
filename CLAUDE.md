# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Burp Suite extension (written for **Jython 2.7 / Python 2**) that statically analyzes JavaScript responses to extract API endpoints, URLs, secrets, emails, and sensitive file references — with aggressive noise filtering to keep findings accurate. There is no build step and no test suite.

## Runtime constraints (read before editing)

This runs inside Burp Suite under **Jython 2.7**, not CPython 3. This dictates how all code must be written:

- **Python 2 syntax only**: `print` statements, `%`-formatting (no f-strings), `except Exception as e` is fine but no `print()` chaining tricks. String formatting throughout uses `"... %d ..." % (...)`.
- **No `pip` packages.** Only the Python stdlib available in Jython plus the Java standard library are usable. UI is built on **Java Swing** (`javax.swing`, `java.awt`), imported directly as if they were Python modules.
- **Burp APIs** come from the `burp` package (`IBurpExtender`, `IContextMenuFactory`, `ITab`). These exist only when loaded inside Burp — the code cannot be run standalone from a normal `python`/`python3` invocation.

Because of the above, there is no way to lint or unit-test locally with standard tooling. Verification means loading the updated `js_analyzer.py` into Burp via `Extensions > Installed > Add` (Python/Jython) and reading the extension's stdout/stderr output panel (`self._log(...)` writes there).

## Architecture

Two files do all the work:

- **`js_analyzer.py`** — extension entry point and the entire detection engine.
  - Module-level regex tables define *what* is detected: `ENDPOINT_PATTERNS`, `URL_PATTERNS`, `SECRET_PATTERNS` (list of `(regex, label)`), `EMAIL_PATTERN`, `FILE_PATTERNS`.
  - Module-level noise tables define *what is rejected*: `NOISE_DOMAINS`, `MODULE_PREFIXES`, `NOISE_PATTERNS`, `NOISE_STRINGS`.
  - `BurpExtender.analyze_response()` is the pipeline: pull the response body, run each pattern category in its own try/except block, and gate every match through a per-category validator (`_is_valid_endpoint`, `_is_valid_url`, `_is_valid_secret`, `_is_valid_email`, `_is_valid_file`).
  - `_add_finding()` deduplicates across the whole session using `seen_values` (a `set` keyed by `"category:value"`); secrets are masked before storage.
  - `AnalyzeAction` is the Swing `ActionListener` wired to the right-click context menu item.
- **`ui/results_panel.py`** — `ResultsPanel` (a `JPanel`) renders findings in five tabbed `JTable`s (Endpoints, URLs, Secrets, Emails, Files) and handles live search, source filtering, copy, clear, and JSON export. It keeps its own copy of findings in `self.findings`; the extender holds the canonical list and dedup set.

**Detection vs. filtering is the core design.** A regex match is never trusted on its own — it must pass the category's validator. When adding a new pattern, the corresponding `_is_valid_*` method is where false positives get suppressed. The README's stated goal is "reduce noise as much as possible to ensure accuracy," so prefer tightening validators over loosening them.

### Two-layer data flow
1. `BurpExtender` (in `js_analyzer.py`) owns `all_findings` + `seen_values` — the authoritative, deduplicated set for the session.
2. `ResultsPanel` owns a parallel `self.findings` dict for display/filtering. When changing the finding schema (`category`/`value`/`source`), both layers must stay in sync, including the export map in `ResultsPanel.export_all()`.

## Adding detections

To add a new secret type, append a `(re.compile(...), "Label")` tuple to `SECRET_PATTERNS`. Capture the secret in **group 1** — the pipeline reads `match.group(1)` for secrets/endpoints/emails/files (URLs fall back to `group(0)` when there's no capture group). Then sanity-check `_is_valid_secret` won't wrongly reject it (it drops values shorter than 10 chars or containing `example`/`placeholder`/`your`/`xxxx`/`test`).

Note: some existing secret patterns are intentionally broad (e.g. bare `[a-f0-9]{32}` for "Bugsnag/Datadog API Key") and will produce false positives — this is a known tradeoff in the current ruleset.

## Notes / discrepancies

- The README documents a standalone `js_analyzer_engine.JSAnalyzerEngine` class and Flask usage. **That module does not exist in this repo** — only the Burp extension is implemented. Don't assume it's importable.
- `api.txt` is a large (~50k line) sample/scratch dataset of extracted endpoint-like strings, not code. It is not referenced by the extension.
- Not a git repository.


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:6cd5cc61 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->
