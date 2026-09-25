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
| Log source bodies | No — see [LLM artifact retention](#optional-llm-logging---log-llm) |
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

### Repository credentials

A `repo_url` that embeds credentials — `https://user:TOKEN@host/org/repo.git`, or a
token supplied as the username — is rejected with a warning and the repository is
skipped. Such a URL would otherwise be printed in the repo header and stored in the
run's `meta.json`, `status.json`, and `summary.json`, and `git clone` would record it
in the cache clone's `.git/config`.

Authenticate outside the URL: a git credential helper, or an SSH remote such as
`ssh://git@host/org/repo.git`. Any credential URL that still reaches a log line or
error message is redacted to `https://***@host/...` before it is printed or written.

## Modes

### Discovery-only (`--llm none`)

- Deterministic candidate discovery (rules, typedef/macro IR, optional I/O heuristics)
- No provider API calls
- Findings are typically `abstain` locations for human or later LLM review

### Opt-in LLM review (`--llm ollama|openai|anthropic|gemini`)

- Source code context, including complete function bodies and, in later analysis
  stages, file-leading context (file preamble) plus extracted typedefs, structs,
  and macros, may be sent to the configured provider
- Also triggered if you set `TACS_LLM_PROVIDER` in the process environment or
  `.env` (explicit opt-in)
- Prefer local Ollama (`OLLAMA_HOST=http://127.0.0.1:11434`) for sensitive trees
- Prefer Ollama Cloud only when you accept sending that context to that host (`OLLAMA_API_KEY`; leave `OLLAMA_HOST` unset)

### Optional LLM logging (`--log-llm`)

- Disabled by default
- When enabled, adds prompt text to the per-batch artifacts described below, inside
  the scan session (`results/scans/<run-id>/llm/…`) or the batch repo directory —
  not in a separate log directory
- Prefer `--redact-prompts` (default on) so paths/code spans are minimized in logs
- Treat those directories as sensitive if the scanned tree was

#### Function-batch artifacts

Each LLM batch writes an artifact under `llm/<pass>/batches/` — inside the scan
session for `tacs scan`, and directly under `repos/<repo-key>/` for `tacs repos`.
What it contains depends on the flags above:

| Flags | Persisted |
|-------|-----------|
| default (no `--log-llm`) | Manifest only: batch/function ids, relative paths, line ranges, symbols, candidate line numbers, and the size and SHA-256 of each prompt channel. No prompt text, no function bodies. |
| `--log-llm` | Manifest plus both prompt channels redacted: function bodies are replaced by placeholders, source lines are removed, paths are hashed. |
| `--log-llm --allow-raw-code-logging` | Manifest plus both verbatim prompt channels and verbatim function bodies. |

A prompt has two channels, and they are sized, hashed and persisted separately
(`system_prompt_*` and `user_prompt_*`). A single digest over a concatenation
would describe a prompt that was never sent and would hide which channel a given
line travelled in.

`--allow-raw-code-logging` is the authoritative switch for verbatim source retention.
`--no-redact-prompts` on its own does not grant it, and `--allow-raw-code-logging`
without `--log-llm` persists nothing extra. Each artifact records the flags that
applied under a `privacy` key, so you can tell what a directory contains.

`tacs repos` runs with the private posture (no LLM logging, no raw code logging) and
does not expose flags to change it, so batch runs keep manifests only.

## What leaves the machine

Nothing leaves the machine for `--llm none`.

When LLM mode is enabled, prompts that include source code context go to the configured
API endpoint — typically complete extracted function bodies, and in later stages file
preamble (for example leading lines) plus typedefs, structs, and macros gathered from
the file. Treat provider choice as a data-handling decision.

That content is sent in the provider's untrusted user channel, labelled as
analysis data, while TACS's own auditor instructions go in the trusted channel:
a `system` message for OpenAI-compatible APIs, a top-level `system` for
Anthropic, `systemInstruction` for Gemini, and the `system` field alongside
`prompt` for the Ollama `/api/generate` endpoint. Environment and migration
facts travel with the code rather than with the instructions. The separation is
best-effort and not injection-proof: a model may still act on text it was told
to treat as data.

## Operational hygiene

- TACS can read provider credentials from the process environment or a local
  `.env`; process environment values take precedence. Treat `.env` as a
  plaintext secret file and never commit it.
- Do not commit `.env`, API keys, or scan outputs that may contain proprietary source
- Prefer gitignored output paths (`findings.json`, `results/` — including
  `results/scans/` and `results/batches/` — are ignored by default; legacy
  top-level `batch_runs/` and older `results/batch_runs/` trees are also
  ignored if present)
- Remember that `tacs repos` leaves cloned repositories in `--cache-dir`
  (default `.repo_cache`, gitignored); delete it when you no longer need the clones
- Debug flags that dump raw prompts (`--debug-llm-raw`, etc.) may expose secrets in the scanned tree — use carefully

## Paths in published artifacts

Finding and source identifiers are repository-relative. Scan metadata prefers
cwd-relative or package-relative forms for the scan root and rules path (cache
clones publish as `.`). Batch `summary.json` records `repos_file` / `cache_dir` /
`out_dir` in cwd-relative form when possible; absolute host prefixes are avoided
so shared result bundles do not needlessly disclose usernames or local layouts.
Local clone directories under `--cache-dir` are not written into per-repo `meta.json`.
