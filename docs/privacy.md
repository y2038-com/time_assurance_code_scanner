# Privacy and retention

Privacy is a first-order principle for this scanner. TACS may process proprietary
source trees — external LLM use is therefore **opt-in**.

## Defaults

| Setting | Default |
|---------|---------|
| Privacy posture | No hosted code vault; nothing is uploaded except to the LLM provider you opt into |
| LLM mode | `--llm none` (no external calls) |
| Persist source trees | Depends on the command — see [Source tree retention](#source-tree-retention) below |
| Persist findings | Only to paths you pass (`--out`, batch dirs, optional session trees under `results/` when the pipeline writes them) |
| Log source bodies | No at default verbosity |
| Third-party sharing | Only the user-selected LLM provider receives source context when LLM mode is enabled |

## Source tree retention

Retention differs by command. This is local-disk behavior only; it is independent of
whether any code is sent to an LLM.

| Command | Source tree handling |
|---------|----------------------|
| `tacs scan` | Reads the tree you pass with `--root` **in place**. No copy of the source is made. |
| `tacs repos` | **Clones each repository to local disk and keeps it** in `--cache-dir` (default `.repo_cache`) so later runs can reuse it. Clones stay until you delete them. |
| `tacs render` | Reads existing findings JSON only. |

Notes for `tacs repos`:

- The cache holds a full git working tree per repository, including history.
- `.repo_cache/` is gitignored, so clones are not committed by accident. If you point
  `--cache-dir` somewhere else, make sure that path is also ignored or outside the repo.
- Private repositories are cached the same way as public ones. If that matters for your
  environment, put `--cache-dir` on appropriate storage and remove it when finished:

```bash
rm -rf .repo_cache          # or the path you passed to --cache-dir
```

## Modes

### Discovery-only (`--llm none`)

- Deterministic candidate discovery (rules, typedef/macro IR, optional I/O heuristics)
- No provider API calls
- Findings are typically `abstain` locations for human or later LLM review

### Opt-in LLM review (`--llm ollama|openai|anthropic|gemini`)

- Source code context, including complete function bodies and, in later analysis stages, file-level context and type/macro definitions, may be sent to the configured provider
- Also triggered if you set `TACS_LLM_PROVIDER` in `.env` (explicit env opt-in)
- Prefer local Ollama (`OLLAMA_HOST=http://127.0.0.1:11434`) for sensitive trees
- Prefer Ollama Cloud only when you accept sending that context to that host (`OLLAMA_API_KEY`; leave `OLLAMA_HOST` unset)

### Optional LLM logging (`--log-llm`)

- Disabled by default
- When enabled, may write prompt/response artifacts under `--log-dir` (default `results/llm_logs`)
- Prefer `--redact-prompts` (default on) so paths/code spans are minimized in logs
- Treat log directories as sensitive if the scanned tree was

## What leaves the machine

Nothing leaves the machine for `--llm none`.

When LLM mode is enabled, prompts that include source code context go to the configured
API endpoint — typically complete extracted function bodies, and in later stages file
preamble (for example leading lines) plus typedefs, structs, and macros gathered from
the file. Treat provider choice as a data-handling decision.

## Operational hygiene

- Do not commit `.env`, API keys, or scan outputs that may contain proprietary source
- Prefer gitignored output paths (`findings.json`, `results/` — including
  `results/scans/` and `results/batch_runs/` — are ignored by default; legacy
  top-level `batch_runs/` is also ignored if present)
- Remember that `tacs repos` leaves cloned repositories in `--cache-dir`
  (default `.repo_cache`, gitignored); delete it when you no longer need the clones
- Debug flags that dump raw prompts (`--debug-llm-raw`, etc.) may expose secrets in the scanned tree — use carefully
