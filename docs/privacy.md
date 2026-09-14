# Privacy and retention

Privacy is a first-order principle for this scanner. TACS may process proprietary
source trees — external LLM use is therefore **opt-in**.

## Defaults

| Setting | Default |
|---------|---------|
| Privacy posture | Ephemeral processing; no private code vault |
| LLM mode | `--llm none` (no external calls) |
| Persist source trees | No (scans read files in place) |
| Persist findings | Only to paths you pass (`--out`, batch dirs, optional session trees under `results/` when the pipeline writes them) |
| Log source bodies | No at default verbosity |
| Third-party sharing | Only the user-selected LLM provider receives snippets when LLM mode is enabled |

## Modes

### Discovery-only (`--llm none`)

- Deterministic candidate discovery (rules, typedef/macro IR, optional I/O heuristics)
- No provider API calls
- Findings are typically `abstain` locations for human or later LLM review

### Opt-in LLM review (`--llm ollama|openai|anthropic|gemini`)

- Source snippets and prompts are sent to that provider
- Also triggered if you set `TACS_LLM_PROVIDER` in `.env` (explicit env opt-in)
- Prefer local Ollama (`OLLAMA_HOST=http://127.0.0.1:11434`) for sensitive trees
- Prefer Ollama Cloud only when you accept sending snippets to that host (`OLLAMA_API_KEY`; leave `OLLAMA_HOST` unset)

### Optional LLM logging (`--log-llm`)

- Disabled by default
- When enabled, may write prompt/response artifacts under `--log-dir` (default `results/llm_logs`)
- Prefer `--redact-prompts` (default on) so paths/code spans are minimized in logs
- Treat log directories as sensitive if the scanned tree was

## What leaves the machine

Nothing leaves the machine for `--llm none`.

When LLM mode is enabled, snippets (and related prompt context) go to the configured
API endpoint. Treat provider choice as a data-handling decision.

## Operational hygiene

- Do not commit `.env`, API keys, or scan outputs that may contain proprietary source
- Prefer gitignored output paths (`findings.json`, `results/`, `batch_runs/` are ignored by default)
- Debug flags that dump raw prompts (`--debug-llm-raw`, etc.) may expose secrets in the scanned tree — use carefully
