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

**Default LLM mode for a first run:** `--llm none` (deterministic candidate discovery; no API key).

BYOLLM also supports local Ollama, Ollama Cloud, OpenAI, Anthropic, and Gemini.

## Privacy (read this)

Processing is **ephemeral by default**: the tool does not keep a private code store. That does **not** mean “never leaves your machine.”

- **Source snippets may be sent to the LLM provider you configure** when `--llm` is not `none`.
- Reports are written only where you ask (`--out` / batch output dirs). Prefer `--llm none` or local Ollama for sensitive trees.

## Principles

- Open source first; model-independent (BYOLLM)
- Explicit environment configuration is the supported path (8 ABI/`time_t` configs)
- Evidence-oriented pipeline with optional multi-stage LLM analysis
- Human review is authoritative — scanner outputs are **candidates for review**
- Language surface today is C/C++; the project name and CLI are not limited to C forever

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
  --llm none \
  --out findings.json
```

Then open `findings.json`. For providers and batch/render, see **QUICK_START.md**.

## Layout

| Path | Purpose |
|------|---------|
| `src/tacs/` | Core engine + CLI (`scan`, `repos`, `render`) |
| `src/config_detector/` | Experimental build-system config detection |
| `src/envui/` | Environment config schema + wizard helpers |
| `src/report_renderer/` | Text/HTML report rendering |
| `configs/` | Example rules / env configs |
| `tests/` | Unit and pattern tests |

## Docs

| Doc | Purpose |
|-----|---------|
| [QUICK_START.md](QUICK_START.md) | Install → first scan |
| [docs/env_config.md](docs/env_config.md) | Environment configuration |
| [docs/usage/RUNNING_FULL_PIPELINE.md](docs/usage/RUNNING_FULL_PIPELINE.md) | Full pipeline notes |
| [docs/usage/CONFIG_DETECTOR_USAGE.md](docs/usage/CONFIG_DETECTOR_USAGE.md) | Experimental detector |
| [docs/prd/Scanning-Workflow.md](docs/prd/Scanning-Workflow.md) | Workflow specification |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, use [SECURITY.md](SECURITY.md) (not a public issue).

## License

Licensed under the Apache License, Version 2.0.

Copyright (c) 2026 Y2038.com LLC
