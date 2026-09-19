# Release readiness checklist (TACS)

Maintainer checklist before flipping
[`time_assurance_code_scanner`](https://github.com/y2038-com/time_assurance_code_scanner)
to public. **Do not** change GitHub visibility from automation — do that manually.

Out of scope for this cut: `mock` provider, PyPI publish, and the public
visibility flip itself. Deferred non-blocking ideas live in [backlog.md](backlog.md).

## Quality bar

- [x] `pip install -e ".[dev]"` on a clean venv
- [x] `pytest` green (unit suite; manual harnesses under `tests/manual/`)
- [x] Offline smoke (`--llm none`) on bundled patterns
- [x] Ollama Cloud smoke (`--llm ollama`, `gpt-oss:120b-cloud`)
- [x] Optional extra provider smoke (OpenAI) — completed; not a blocker
- [x] Scan leaves **tracked** files unchanged (discovery writes only under `results/scans/…`)
- [x] Light SPDX/copyright headers on every first-party source file under `src/`, `scripts/` and `tests/` (`.py`, `.sh`, `.c`, `.h`, `.cpp`), enforced by `tests/test_license_headers.py`
- [x] PyPI metadata prepared in `pyproject.toml` (not published)
- [x] GitHub Actions CI (`.github/workflows/ci.yml`): Python 3.12, `pytest`, and a
      blocking `ruff check --select E9,F63,F7`. The full `ruff check` runs as an
      informational step because the tree does not pass a complete lint yet.

## Smoke results (2026-09-14)

Command template (repo root, venv active):

```bash
tacs scan \
  --root tests/patterns \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --env-config configs/example.env_config.json \
  --include "test_arithmetic_patterns_mini.c" \
  --out findings_<tag>.json
```

| Run | Flags | Result |
|-----|--------|--------|
| Offline | `--llm none --out findings_mini.json` | **PASS** — 10 findings (0 yes / 0 no / 10 abstain); tracked tree clean |
| Ollama Cloud | `--llm ollama --model gpt-oss:120b-cloud --out findings_ollama.json` | **PASS** — 4 findings (4 yes); Cloud auth OK; tracked tree clean |
| OpenAI (optional) | `--llm openai --model gpt-4.1-mini --out findings_openai.json` | **PASS (pipeline)** — completed with 0 retained findings (model labeled all `no`; expected variance). Not a release blocker |

Post-scan check:

```bash
git status --porcelain --untracked-files=no
# should show only intentional local edits, not rules/source mutations
```

## Suggested GitHub metadata (apply manually)

**Description:**

> AI-assisted scanner (`tacs`) that supports long-horizon time assurance by identifying potential Y2038/Y2106-class risks in source code (related ABI/`time_t` assumptions). Findings are review candidates, not a certification of time safety.

**Topics (suggested):**

`y2038` `y2106` `time-t` `static-analysis` `security` `c` `cpp` `cli` `python` `ollama` `byollm`

**About links:**

- Homepage / docs: repository README
- Sibling: [`time_assurance_doc_scanner`](https://github.com/y2038-com/time_assurance_doc_scanner) (`tads`)

**Security:**

- Enable GitHub private vulnerability reporting
- Confirm [SECURITY.md](../SECURITY.md) link works from the Security tab

**Before flipping public:**

- [x] Confirm no secrets in git history — `gitleaks detect --source . --log-opts="--all"`
      (gitleaks 8.30.1, 2026-09-16): 49 commits, ~1.9 MB scanned, **no leaks found**.
      The only env file ever committed is the `.env.example` template, which holds
      empty placeholders. Re-run this after any further commits.
- [x] Confirm `findings*.json` / `results/` are not tracked — `git ls-files` shows
      only `results/README.md`; `.gitignore` also covers the ad-hoc `test_*_results.json`
      and `*_report.html` outputs the docs tell you to create
- [x] Confirm LICENSE is Apache-2.0 and copyright year is correct — Apache-2.0 with
      `Copyright (c) 2026 Y2038.com LLC`, matching the SPDX identifier in every header
      and the `license` field in `pyproject.toml`. No `NOTICE` file, and none is
      required: no vendored third-party source is redistributed here.
- [ ] Set description + topics above
- [ ] Link sibling `tads` in About / README (already in README)
- [ ] Flip visibility to Public when ready

## PyPI prep (do not publish yet)

Package name: `time-assurance-code-scanner`  
Console script: `tacs`  
Requires: Python >= 3.12  

Prepared in `pyproject.toml`: keywords, classifiers, Issues/Documentation URLs.  
Publish later with maintainer credentials (`twine` / Trusted Publishing) — **not** part of this checklist’s automation.

## Known gaps carried into the public release

None of these block the visibility flip, but a first outside reader may notice them.
Deferred non-blocking work beyond this cut is tracked in [backlog.md](backlog.md).

- **Lint debt.** `ruff check` reports ~1.3k findings under the rule set current ruff
  enables by default, ~148 of them under ruff's classic `E4,E7,E9,F` selection
  (unused imports, empty f-strings, unused variables). CI gates only on the
  breakage subset until that is paid down. The `dev` extra pins `ruff>=0.1.0`, so
  the informational number moves with the installed version.
- **Unused imports in `src/tacs/core/schema.py`.** `json`, `os`, `datetime`, `Union`
  and `validator` have no users. They predate the `LLMLogEntry` removal rather than
  resulting from it, so they are left with the rest of the lint debt above.

## Manual test harnesses

Longer pattern/LLM experiments live under [`tests/manual/`](../tests/manual/README.md) and are intentionally excluded from normal `pytest`.
