# TACS Backlog

This file tracks **known non-blocking work intentionally deferred beyond the
current release**. It is not a ship commitment and not a multi-year roadmap.

Release blockers, visibility-flip steps, and the quality bar for flipping the
repo public live in [release_checklist.md](release_checklist.md). Prefer that
checklist for “must be true before we call this cut done.” Prefer this backlog
for deferred polish and analysis depth.

When you pick up an item, remove or rewrite it here so the list stays accurate.

## Near-term

- [ ] Build a small manually reviewed ground-truth benchmark set for regression testing
- [ ] Improve distinction between absolute timestamps and relative durations in LLM classification
- [ ] Improve handling of guarded narrowing/casts and boundary-test/reference implementations
- [ ] Expand LLM/provider compatibility testing and compare model quality on a fixed fixture set
- [ ] Improve Windows hard-timeout cleanup for descendant processes (`tacs repos` scan child)
- [ ] Consider richer skipped-file metrics beyond the current oversized-file and external-symlink fields (e.g. extension or byte totals)
- [ ] Give candidates a stable rule/source identifier for identity and provenance (today `risk` is only severity; same-site/same-symbol/same-risk detector variants intentionally collapse — fine for the current ruleset, but insufficient if distinct rules must remain distinct)

## Analysis improvements

- [ ] Add AST/tree-sitter-based analysis (the `.[full]` extra installs tree-sitter, but structural filtering is still a no-op)
- [ ] Improve dataflow and type propagation for time-bearing values
- [ ] Improve macro and typedef resolution beyond the current prescan heuristics
- [ ] Improve cross-function tracking of time-bearing values
- [ ] Expand Y2106-specific analysis (optional `--detect-y2106` path)
- [ ] Improve automatic environment/libc/RTOS capability inference (`tacs detect` remains experimental)
- [ ] Better model mixed 32/64-bit ABI boundaries in classification and env-config guidance

## LLM and model support

- [ ] Support/evaluate additional LLM providers and models (beyond the current Ollama / OpenAI / Anthropic / Gemini adapters)
- [ ] Improve provider-specific structured-output reliability
- [ ] Improve retry/error handling where model responses are malformed or truncated
- [ ] Benchmark classification quality across supported models on a shared fixture set
- [ ] Add optional token/cost budgets or clearer cost reporting for large batch runs (per-run token counts already appear in `stage_stats.json`)
- [ ] Consider a clearly test-only mock LLM provider for CI/integration (not a public default; `--llm none` stays the offline path)

## Reporting and integrations

- [ ] Add SARIF export
- [ ] Improve machine-readable finding taxonomy
- [ ] Improve HTML report filtering/grouping
- [ ] Consider GitHub/CI scanning integration
- [ ] Clarify reporting distinctions among confirmed issue, candidate, abstain, and contextual concern

## Performance and batch operation

- [ ] Profile large repositories
- [ ] Consider parallel repository scanning in `tacs repos`
- [ ] Cache deterministic scan stages where safe
- [ ] Add resume/retry support for large batch runs
- [ ] Improve deterministic/byte-stable artifacts where practical

## Engineering / release hygiene

- [ ] Reduce existing Ruff debt incrementally (CI currently gates only on the breakage subset; see release checklist “Known gaps”)
- [ ] Tighten CI lint coverage as lint debt is reduced
- [ ] Modernize package metadata to current PEP 639 license conventions
- [ ] Expand typing coverage and consider shipping `py.typed` only when the public surface is ready
- [ ] Continue pruning obsolete manual/debug tooling under `tests/manual/` as it becomes unnecessary
- [ ] Improve default exclude patterns for common harness directories (`t/`, `test/`, `*_test.c`, etc.) without hiding real product code
- [ ] Fix remaining Stage 8/9 console grammar (`N functions` / `function(s)` → singular when N is 1)

## Longer-term

- [ ] Support additional source languages beyond C/C++
