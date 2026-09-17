# Contributing

Thanks for your interest in the Time Assurance Code Scanner (`tacs`).

This CLI is the code-scanning sibling of
[`time_assurance_doc_scanner`](https://github.com/y2038-com/time_assurance_doc_scanner)
(`tads`). Prefer matching the sibling’s operator conventions for LLM keys and
`.env` layout where practical (`OLLAMA_API_KEY`, optional `TACS_*` knobs).

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env               # only if you will call a real LLM
tacs version
pytest
```

New-user workflow: **[QUICK_START.md](QUICK_START.md)**.

**Privacy:** leave `--llm none` (default) unless you intentionally opt in. Do not
commit `.env` or scan outputs.

## Before you open a PR

- Run `pytest` and keep changes focused.
- Do **not** commit secrets or workspace junk: `.env`, API keys, or scan output trees (`results/`, legacy `batch_runs/` / `results/batch_runs/`, `findings.json`, `inputs/*`).
- Prefer small PRs: code, docs, or tests — avoid mixing large refactors with unrelated doc edits.
- Match existing style (Python 3.12+, Click CLI).
- Keep public docs honest about **experimental** features (`tacs detect`) and about findings as **candidates for review**.

## What to work on

- Bugs and UX friction in the CLI / docs are always welcome.
- Improving **experimental** config auto-detect (`tacs detect` / `config_detector`) is welcome, but keep expectations honest in docs.
- Explicit env-config workflow and scan quality are higher priority than detection heuristics.
- Known deferred (non-blocking) work is listed in [docs/backlog.md](docs/backlog.md).

## Security

Report vulnerabilities privately — see **[SECURITY.md](SECURITY.md)**. Do not
file public issues for exploitable bugs.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License, Version 2.0](LICENSE).

New source files under `src/`, `scripts/` and `tests/` carry a two-line header,
below any shebang, using the comment syntax of the language:

```python
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0
```

`tests/test_license_headers.py` checks this for `.py`, `.sh`, `.c`, `.h` and
`.cpp`. Formats that cannot carry a comment, such as JSON, and prose files are
out of scope.
