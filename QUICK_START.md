# Quick start — Time Assurance Code Scanner (`tacs`)

Goal: **clone → install → first candidate findings in about 15 minutes.**

1. Install the CLI  
2. Run a **local scan with `--llm none`** (no API key) on the bundled example tree  
3. Optionally enable a real LLM provider (explicit opt-in)

Copy secrets only into a local `.env` (never commit it). Template: [`.env.example`](.env.example).

**Privacy:** CLI default is `--llm none`. When `--llm` is not `none` (or you set
`TACS_LLM_PROVIDER`), source code context — including complete function bodies and,
in later stages, file-level context and type/macro definitions — may be sent to your
configured provider. See [docs/privacy.md](docs/privacy.md).

**Local workspace:** `inputs/` for run-specific manifests and configs you supply;
`results/` for everything TACS generates (`results/scans/`, `results/batch_runs/`).
Both are gitignored except their READMEs. Tracked fixtures under `src/tacs/fixtures/`
and `configs/` are unchanged. Override destinations anytime with `--out` / `--out-dir`.

---

## 1. Install

```bash
cd /path/to/time_assurance_code_scanner
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env               # optional until you use a real provider
tacs version
```

---

## 2. First success (offline — `--llm none`)

`tests/patterns/` is a **bundled example C codebase** with intentional Y2038-style
patterns. With `--llm none`, the scanner still runs **deterministic candidate
discovery** (rules, typedef/macro discovery, IR, optional I/O heuristics) and
writes those locations to `findings.json`. Classifications stay `abstain` until
you opt into an LLM.

```bash
tacs scan \
  --root tests/patterns \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --env-config configs/example.env_config.json \
  --llm none \
  --out findings.json
```

You should see a non-empty `findings` array (often hundreds of candidates on the
full patterns tree). Treat them as **candidates for review**, not confirmed defects.

Discovery artifacts (merged rules, discovery report) land under
`results/scans/<session>/prescan/` — the `--rules` file you pass is never modified.

Useful checks:

```bash
python3 -c "import json; d=json.load(open('findings.json')); print(len(d['findings']), 'candidates')"
```

### Smaller smoke (one file)

```bash
tacs scan \
  --root tests/patterns \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --env-config configs/example.env_config.json \
  --include "test_arithmetic_patterns_mini.c" \
  --llm none \
  --out findings_mini.json
```

---

## 3. Optional: Ollama Cloud (recommended when you want LLM review)

External LLM use is **opt-in**. Recommended optional path: Ollama Cloud.

1. Create an API key at [ollama.com/settings/keys](https://ollama.com/settings/keys).  
2. Put it in `.env`:

```bash
# Leave OLLAMA_HOST unset → https://ollama.com
OLLAMA_API_KEY=your_key_here
# Optional:
# TACS_MODEL=gpt-oss:120b-cloud
```

3. Run with an explicit `--llm ollama` (do not rely on a hidden default):

```bash
tacs scan \
  --root tests/patterns \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --env-config configs/example.env_config.json \
  --include "test_arithmetic_patterns_mini.c" \
  --llm ollama \
  --model gpt-oss:120b-cloud \
  --out findings_ollama.json
```

Finding counts and classifications vary by model. Keep treating results as candidates.

---

## 4. Other providers

Set keys in `.env`, then pass `--llm` / `--model`. Full copy-paste blocks: [`.env.example`](.env.example).

Setting `TACS_LLM_PROVIDER=ollama` (or another provider) in `.env` also opts in as
the CLI default for `--llm`; leave it unset to keep the privacy-safe `none` default.

### Ollama local

```bash
OLLAMA_HOST=http://127.0.0.1:11434
# TACS_MODEL=llama3.1
```

Then:

```bash
tacs scan ... --llm ollama --model llama3.1
```

Prefer the [official Ollama installer](https://ollama.com/download). Pull the model
first (`ollama pull …`). Small local models may truncate large function batches.

### Google Gemini

```bash
# TACS_LLM_PROVIDER=gemini
GOOGLE_API_KEY=...          # or GEMINI_API_KEY
# TACS_MODEL=gemini-3.6-flash
```

```bash
tacs scan ... --llm gemini --model gemini-3.6-flash
```

### OpenAI

```bash
# TACS_LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
# TACS_MODEL=gpt-4.1-mini
```

```bash
tacs scan ... --llm openai --model gpt-4.1-mini
```

### Anthropic

```bash
# TACS_LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=...
# TACS_MODEL=claude-sonnet-4-5
```

```bash
tacs scan ... --llm anthropic --model claude-sonnet-4-5
```

---

## 5. Batch repos and render

```bash
tacs repos --help

tacs repos --repos-file src/tacs/fixtures/repo_lists/test_repos.jsonl --dry-run

# LLM is opt-in for batch (same privacy default as tacs scan):
# tacs repos ... --enable-llm --llm-type ollama

# Note: tacs repos clones each repo into --cache-dir (default .repo_cache,
# gitignored) and keeps it for reuse. Delete that directory to discard the clones.

# Analysis defaults match tacs scan, so a batch result is comparable with a
# standalone one on the same source, env config, and model. Both default to
# Y2106 detection off and the Stage S1 pre-filter off; to change that, pass the
# same flag to either command:
#   --detect-y2106        also assess 32-bit unsigned time_t overflow in 2106
#   --no-disable-stage1   restore the line-level LLM pre-filter (drops candidates)

```

### Timeouts in `tacs repos`

Each repository's scan runs in its own process, so one repository cannot hang
the batch. Two separate limits apply:

| Option | Default | What it bounds |
| --- | --- | --- |
| `--scanner-timeout-sec` | 3600s | **Per-repository scan timeout.** The deadline after which that repository's scan process is terminated. |
| `--request-timeout-sec` | 300s | One LLM request inside a scan. Ollama Cloud gets twice this, and a failed request is retried up to 3 times. |

The deadline covers the scan phase only: the deterministic scanner, parsing and
function analysis, every LLM stage, and the artifact writes that finish the
scan. Cloning, ref resolution and config detection happen first and are not
counted against it; git commands there have their own 300-second limit.

The deadline is when termination begins, not the total elapsed time. The scan is
asked to stop, then killed if it has not exited within a 10-second grace period,
so a wedged repository can take up to `--scanner-timeout-sec` plus that grace.

A repository that outstays the deadline is recorded as `status: "timeout"` with
`error_code: "SCAN_TIMEOUT"` in its `status.json` and in the run's
`summary.json`; no `findings.json` is published for it, and `tacs render` skips
it. The batch continues unless `--fail-fast` or `--no-continue-on-error` is set,
and the run exits non-zero.

For reference, a ten-repository validation batch against Ollama Cloud
(`gpt-oss:120b-cloud`) spent 0.4-60s per repository, so the defaults leave
considerable headroom; lower them only if you know your corpus.

On Linux and macOS the scan runs in its own process group, so terminating it
also stops the scanner subprocess and anything else the scan started. On Windows
the fallback terminates the Python scan child only, and a scanner subprocess it
had already started may survive, so the descendant-process guarantee is weaker
there.

`tacs scan --timeout-sec` is the standalone equivalent of `--request-timeout-sec`
alone: it bounds one LLM request, not the scan, which runs as long as its work
takes.

### Render

```bash
tacs render --help

# Single findings JSON (e.g. from tacs scan --out):
# tacs render findings.json --format text
# tacs render findings.json --format html --out results/report.html

# Batch run directory (default repos out-dir is results/batch_runs;
# "latest" is a symlink to the newest run):
# tacs render results/batch_runs/latest --format text
# tacs render results/batch_runs/<run_id> --format html --out-dir results/reports
```

Prefer an explicit `config_override` / env config per repo when known. `tacs detect`
and batch auto-detect are **experimental**.

---

## 6. Troubleshooting

| Symptom | What to try |
|---------|-------------|
| `tacs: command not found` | Activate `.venv` and re-run `pip install -e ".[dev]"` |
| Empty or only `abstain` findings with `--llm none` | Expected for discovery-only mode; open `findings.json` and check `len(findings)`. Use a smaller `--include` if the tree is huge |
| Ollama Cloud 401/403 | Set `OLLAMA_API_KEY` (legacy: `OLLAMA_CLOUD_TOKEN`); leave `OLLAMA_HOST` unset for cloud |
| Local Ollama connection errors | Set `OLLAMA_HOST=http://127.0.0.1:11434` and confirm `ollama serve` / `ollama ps` |
| Cloud requests going to the wrong host | Unset `OLLAMA_HOST` for cloud; set it only for local |
| OpenAI / Gemini 429 | Check billing / prepaid credits before blaming TLS |
| “prompt too long” / truncated JSON | Reduce `--batch-size-func` / stage batch sizes; try a larger-context model |
| Odd risk rankings | Pass an accurate `--env-config` (see `docs/env_config.md`); do not trust experimental `tacs detect` alone |
| Want cheaper first LLM run | Keep `--include` narrow (one file) and a modest model |

---

## 7. Tests

```bash
pytest
```

Some files under `tests/` are manual scripts (not pytest modules). Prefer the
commands above and [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 8. More docs

| Doc | Purpose |
|-----|---------|
| [README.md](README.md) | Overview, limitations, privacy |
| [docs/privacy.md](docs/privacy.md) | Privacy defaults |
| [docs/env_config.md](docs/env_config.md) | ABI / `time_t` environment config |
| [docs/usage/RUNNING_FULL_PIPELINE.md](docs/usage/RUNNING_FULL_PIPELINE.md) | Pipeline modes and flags |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev setup and PRs |
| [SECURITY.md](SECURITY.md) | Private vulnerability reporting |
| `.env.example` | Provider env blocks |
