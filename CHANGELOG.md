# Changelog

All notable changes to the public Time Assurance Code Scanner (`tacs`) are
documented here. Versions follow [PEP 440](https://peps.python.org/pep-0440/).
Git tags use a dotted pre-release form (for example `v0.2.0-rc.2`) while the
Python package version uses the PEP 440 form (`0.2.0rc2`).

The public JSON result shape is versioned separately as `schema_version` and is
currently **1.2**.

## Unreleased

### Changed

- Default scan scope for ``tacs scan`` and ``tacs repos`` now includes common
  C and C++ sources and headers: ``**/*.c``, ``**/*.h``, ``**/*.cc``,
  ``**/*.cpp``, ``**/*.cxx``, ``**/*.hh``, ``**/*.hpp``, ``**/*.hxx``. Explicit
  ``--include`` and per-repository ``scan_overrides.include`` still replace
  those defaults. Default exclude remains ``**/tests/**``. Implementation
  fragments (``.ipp``, ``.tpp``, ``.inl``, ``.tcc``) and uncommon uppercase
  extensions stay out of the default globs and out of the catalog IR
  allowlist; explicit ``--include`` of those names does not catalog-scan them.
  Broader defaults can increase files scanned, candidates, runtime, LLM
  requests, tokens, and cost.

## 0.2.0rc2 — 2026-10-18

Second release candidate. Focus since RC1: translation-unit-aware typedef
scoping, opt-in OpenAI GPT-6 Luna, public schema **1.2** provenance fields, and
stricter staged LLM analysis / provider-response handling. Package version is
**0.2.0rc2**; the public report schema remains **1.2**.

### Added

- Translation-unit-aware **typedef alias scoping**: discovered aliases are
  scoped to their defining source file and that file’s project include
  closure. Catalog-colliding local aliases remain usable as type aliases while
  call sites continue to use the catalog function rule. I/O-boundary,
  migration, and LLM alias consumers use the scoped alias set.
- Opt-in OpenAI **GPT-6 Luna** (`gpt-6-luna`) via `--model gpt-6-luna` with
  `--reasoning-effort none|low` on `tacs scan` and `tacs repos`. Unset Luna
  effort defaults to effective `none` (temperature retained). Explicit `low`
  omits incompatible sampling fields. Unsupported models or providers reject an
  explicit effort **before any HTTP request**. Non-Luna OpenAI models and other
  providers keep their prior request shape.
- Public result **schema 1.2** optional provenance: `meta.llm_provider` and
  `meta.reasoning_effort`. Optional provider-reported `reasoning_tokens` usage
  is recorded when present and is not double-counted into completion totals.
  Schema **1.0** / **1.1** reports still load and render; loading does not
  invent provider or reasoning provenance.
- Narrow OpenAI model-policy layer (`tacs.llm.openai_models`) for reasoning
  effort. OpenAI completion-token budgets remain unset (same as pre-Luna OpenAI
  in TACS; Anthropic/Ollama still use their own caps). No provider-native
  structured output was added. TACS has no USD cost estimator.

### Changed

- OpenAI Chat Completions responses are fail-closed on refusal, truncation
  (`finish_reason=length`), `content_filter`, tool/function calls, non-string
  content, and unrecognized or missing/null `finish_reason` on the **official**
  API. Custom `OPENAI_BASE_URL` endpoints may omit `finish_reason` (compat path
  only). Deterministic shape/decode errors are non-retryable (one provider
  call); transport/HTTP retryables still use the existing three-attempt batch
  loop. Malformed JSON and `function_id` alignment failures remain local parse
  fallbacks (no HTTP retry).
- Pass F1/F2/F3 share one canonical model-response wire-contract prompt
  fragment (`canonical_wire_contract_prompt`) so F2/F3 no longer drift to
  incomplete “same schema as F1” instructions. Fail-closed validation and
  `extra=forbid` are unchanged; schema-invalid items still become
  `analysis_error` without an HTTP retry.
- Progress and final classification counters count completed yes/no/abstain
  from assessment `execution_status`, separately from `analysis_error`
  (compatibility findings may still carry abstain-shaped `y2038_issue`).
- Text and HTML reports label findings linked to `analysis_error` assessments
  as analysis errors rather than genuine model abstentions; legacy reports
  without assessments still render as before. Empty-result reports retain LLM
  provenance when present in meta.

### Notes

- Luna is opt-in; the default provider remains `--llm none` and the default
  model id remains `gpt-oss:120b-cloud` (for Ollama when LLM is enabled).
- `low` may increase latency and completion usage (reasoning tokens count
  toward the provider’s completion budget when the API enforces one). No claim
  is made that Luna improves TACS accuracy, that providers agree, or that a
  scan certifies time safety.
- Bounded offline smoke tests with Luna (`none` and `low`) completed
  successfully with zero analysis errors after the shared wire-contract
  correction. Live results remain model-dependent.

### Compatibility / upgrade notes

- Public schema remains **1.2** (introduced with the Luna / provenance work on
  this RC lineage). Older **1.0** / **1.1** documents continue to load.
- Canonical F1/F2/F3 wire validation remains strict; undocumented aliases and
  extra fields are still rejected.

### Known limitations

- Function recognition remains a bounded lexical recognizer, not a complete
  C++ parser.
- Findings and assessments remain **decision-support** output, not proof that
  code is time-safe or free of Y2038/Y2106 defects.
- This release does not claim coverage of all C/C++ syntax, all security risks,
  or all time-related defects.

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
