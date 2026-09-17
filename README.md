# Time Assurance Code Scanner

Open-source, AI-assisted scanner (`tacs`) for long-horizon **time assurance** issues in source code — especially Y2038 / Y2106 class risks around 32-bit `time_t` and related ABI assumptions.

This repository is the open-source scanner engine and CLI. It is the code-scanning sibling of [`time_assurance_doc_scanner`](https://github.com/y2038-com/time_assurance_doc_scanner) (`tads`).

**New here?** Follow **[QUICK_START.md](QUICK_START.md)** — install through a first local scan (no LLM required).

## Status

**v0.1.0** — CLI-first release of the core scanning pipeline:

| Command | Purpose |
|---------|---------|
| `tacs scan` | Scan one local source tree |
| `tacs repos` | Batch-scan git repos from a JSONL list |
| `tacs render` | Render `findings.json` (or a batch run) to text/HTML |
| `tacs detect` | **Experimental** guess among the 8 ABI/`time_t` configs |

**Default LLM mode for a first run:** `--llm none` (deterministic candidate discovery on the bundled `tests/patterns` tree; no API key). External LLMs are **opt-in** via `--llm` or `TACS_LLM_PROVIDER`.

| Provider | Typical model | Notes |
|----------|---------------|--------|
| *(none)* | — | Default; discovery-only candidates |
| Ollama Cloud | `gpt-oss:120b-cloud` | Recommended optional path; `OLLAMA_API_KEY`, leave `OLLAMA_HOST` unset |
| Ollama local | e.g. `llama3.1` | Set `OLLAMA_HOST=http://127.0.0.1:11434` |
| OpenAI / Anthropic / Gemini | see `.env.example` | Requires the matching API key |

BYOLLM: bring your own provider; no vendor lock-in.

## Privacy (read this)

There is no hosted code vault, but “local” is not the same as “nothing is retained.”

- **Source code context may be sent to the LLM provider you configure** only when you opt in (`--llm` ≠ `none`, or `TACS_LLM_PROVIDER`). That can include complete function bodies and, in later analysis stages, file-level context and type/macro definitions.
- **`tacs scan` reads your tree in place; `tacs repos` clones repositories and keeps them** in `--cache-dir` (default `.repo_cache`, gitignored) so later runs can reuse them. Delete that directory when you are done.
- Reports are written only where you ask (`--out` / batch output dirs). Prefer `--llm none` or local Ollama for sensitive trees. For local runs, keep private inputs under `inputs/` and generated artifacts under `results/` (both gitignored except their READMEs).

Details: [docs/privacy.md](docs/privacy.md).

## Principles

- Open source first; model-independent (BYOLLM)
- Explicit environment configuration is the supported path (8 ABI/`time_t` configs)
- Evidence-oriented pipeline with optional multi-stage LLM analysis
- Human review is authoritative — scanner outputs are **candidates for review**
- Language surface today is C/C++; the project name and CLI are not limited to C forever

## Limitations

TACS is an AI-assisted review aid, not an authoritative compliance oracle. Treat outputs as **candidates for review**, not confirmed defects.

- False positives and false negatives are expected.
- With `--llm none`, findings are discovery locations (often `abstain`) — not LLM-validated issues.
- Results vary by model, provider, rules, and `--env-config` assumptions.
- Wrong or missing environment config can mis-rank risk (prefer an explicit ABI/`time_t` config).
- `tacs detect` is experimental and often low-confidence — not ground truth.
- Preprocessor-agnostic scanning means guarded/dead code may still appear as candidates.
- Structural filtering is heuristic today; tree-sitter AST analysis is **not** implemented in v0.1.0. The `.[full]` extra installs tree-sitter for that future work, but installing it changes nothing yet — the filter stays a no-op either way.
- No findings ≠ “no time-assurance risk.”
- Experts should review severity and remediation before changing production code or ABI choices.

## Environment configuration (important)

Scans are only as meaningful as the assumed ABI/`time_t` model. Prefer an explicit `--env-config` JSON (see `configs/` and `docs/env_config.md`).

`tacs detect` can *guess* among eight configs from Makefiles/CMake. That path is **experimental** and often low-confidence — use it for convenience, not as ground truth. Batch/`repos` may fall back when detection is unsure; set an explicit `config_override` in the JSONL when you know the target.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

tacs version

tacs scan \
  --root tests/patterns \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --env-config configs/example.env_config.json \
  --llm none \
  --out findings.json
```

Then open `findings.json`. For providers, troubleshooting, and batch/render, see **[QUICK_START.md](QUICK_START.md)**.

## Layout

| Path | Purpose |
|------|---------|
| `src/tacs/` | Core engine + CLI (`scan`, `repos`, `render`) |
| `src/config_detector/` | Experimental build-system config detection |
| `src/envui/` | Environment config schema + wizard helpers |
| `src/report_renderer/` | Text/HTML report rendering |
| `configs/` | Example rules / env configs |
| `tests/patterns/` | Bundled example C patterns for local smoke scans |
| `tests/` | Unit and pattern tests |
| `inputs/` | Optional local run inputs (contents gitignored) |
| `results/` | Generated scan/batch output (`scans/`, `batches/`, each with a `latest` symlink; contents gitignored) |

## Docs

**Start here:** [QUICK_START.md](QUICK_START.md)

| Doc | Status | Purpose |
|-----|--------|---------|
| [QUICK_START.md](QUICK_START.md) | Current | Install → offline scan → optional LLM |
| [docs/privacy.md](docs/privacy.md) | Current | Privacy and retention defaults |
| [docs/env_config.md](docs/env_config.md) | Current | Environment / ABI configuration |
| [docs/usage/RUNNING_FULL_PIPELINE.md](docs/usage/RUNNING_FULL_PIPELINE.md) | Current | Function-first vs legacy pipeline flags |
| [docs/usage/CONFIG_DETECTOR_USAGE.md](docs/usage/CONFIG_DETECTOR_USAGE.md) | Current | Experimental `tacs detect` |
| [docs/config_detector.md](docs/config_detector.md) | Current | Detector design notes |
| [docs/report_renderer.md](docs/report_renderer.md) | Current | Text/HTML rendering |
| [docs/prd/Scanning-Workflow.md](docs/prd/Scanning-Workflow.md) | Historical | Design-era workflow PRD (not CLI source of truth) |
| [docs/README.md](docs/README.md) | Current | Docs index |
| [docs/release_checklist.md](docs/release_checklist.md) | Current | Maintainer release / GitHub metadata checklist |

Sibling project: [time_assurance_doc_scanner](https://github.com/y2038-com/time_assurance_doc_scanner) (`tads`) — documentation / standards scanner.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, use [SECURITY.md](SECURITY.md) (not a public issue).

## License

Licensed under the Apache License, Version 2.0.

Copyright (c) 2026 Y2038.com LLC
