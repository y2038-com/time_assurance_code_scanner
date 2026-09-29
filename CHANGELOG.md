# Changelog

All notable changes to the public Time Assurance Code Scanner (`tacs`) are
documented here. Versions follow [PEP 440](https://peps.python.org/pep-0440/).
Git tags use a dotted pre-release form (for example `v0.2.0-rc.1`) while the
Python package version uses the PEP 440 form (`0.2.0rc1`).

The public JSON result shape is versioned separately as `schema_version` and is
currently **1.1**.

## 0.2.0rc1 — 2026-09-29

First release candidate after the v0.1.0 public cut. Focus: public result
structure, attribution integrity, prompt and provider-error hardening, and
packaging/CI validation.

### Added

- Public result **schema 1.1** with deterministic `candidates[]` evidence and
  separate `assessments[]` (execution status distinct from model verdict).
- Stable packaged-catalog **rule IDs** (`TACS-RULE-NNNN`) plus a retired-ID
  deny-list shipped in the wheel.
- Structured per-match **candidate attribution** (`matches[]`) for catalog
  discoveries.
- Improved bounded C/C++ **function recognition** and function linkage for
  candidate-bearing regions.
- Trusted-instruction versus untrusted-source **prompt channel separation**.
- Strict model-response parsing and **exact `function_id`** binding for model
  results (no aliases or positional inference).
- Provider-error and diagnostic-logging hardening (allowlisted transport errors;
  gated raw LLM artifacts).
- Expanded CI packaging checks (build, twine, clean-environment wheel smoke).

### Changed

- Compatibility findings and assessments use controlled operational reasons for
  protocol/transport failures; validated model issue text is unchanged.
- Generic config-detector `--debug` prints safe diagnostics only; raw dumps
  require `--debug-llm-raw`.
- Default session `*_output.json` stores safe summaries; full model-output
  persistence requires `--log-llm` and `--allow-raw-code-logging`.

### Compatibility / upgrade notes

- Noncanonical model-result aliases and positional function-ID inference are
  **no longer accepted**.
- Protocol and provider failures become `execution_status=analysis_error`, not
  genuine abstentions or negative verdicts.
- External legacy rule catalogs without IDs remain supported with **null**
  attribution; supplied IDs must meet validation rules.
- Candidate IDs remain **report-local** foreign keys and are not stable across
  source edits.
- Public schema remains **1.1** (unchanged in this RC relative to the merged
  feature work on `main`).

### Known limitations

- A fatal provider failure can still abort before a partial public report is
  written.
- Function recognition is a bounded lexical recognizer, not a complete C++
  parser.
- Stage 7 remains optional and has known architectural limitations.
- Findings and assessments remain **decision-support** output, not proof that
  code is time-safe or free of Y2038/Y2106 defects.
- This release does not claim coverage of all C/C++ syntax, all security risks,
  or all time-related defects.

## 0.1.0 — 2026-09

Initial public CLI-first release of the core scanning pipeline (`tacs scan`,
`tacs repos`, `tacs render`, experimental `tacs detect`).
