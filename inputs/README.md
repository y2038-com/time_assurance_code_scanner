# inputs/

Place **local, run-specific** scan inputs here (not committed by default):

- Repository JSONL lists for `tacs repos`
- Custom environment / ABI configs
- Benchmark manifests and similar one-off files

Tracked examples stay under source control (for example
`src/tacs/fixtures/repo_lists/*.jsonl` and `configs/`). Copy or adapt them into
`inputs/` when you want a private working copy.

Generated output belongs under `results/` (not here).

```bash
# Example: batch dry-run from a local list (default out-dir: results/batches)
tacs repos --repos-file inputs/my_repos.jsonl --dry-run
```

Contents of this folder are gitignored (except this README).

## Per-repository `scan_overrides`

Each JSONL entry takes `repo_url`, an optional `name` and `ref`, and an optional
`scan_overrides` object. An override applies to that repository only and beats
the batch-wide CLI default; anything the entry leaves out keeps the CLI value.
Unsupported keys are reported as a warning and ignored.

```jsonl
{"repo_url":"https://github.com/example/lib.git","scan_overrides":{"config_override":"ilp32_signed_32bit","llm_type":"anthropic","model":"claude-sonnet-4-5","max_file_size":5242880}}
```

| Key | Type | Meaning |
| --- | --- | --- |
| `config_override` | string | Environment config id, skipping auto-detect |
| `file_extensions` | list | Source extensions to scan, e.g. `[".c", ".h"]` |
| `exclude_patterns` | list | Glob patterns to skip |
| `max_file_size` | integer | Byte limit per source file; omit for no limit |
| `enable_llm` | bool | Whether LLM analysis runs for this repository |
| `llm_type` | string | `ollama`, `openai`, `anthropic`, or `gemini` |
| `model` | string | Model name for the selected provider |
| `disable_stage1` | bool | Skip the Stage S1 line-level pre-filter |
| `detect_y2106` | bool | Also assess 2106 overflow of unsigned 32-bit `time_t` |
| `confidence_floor` | float | Minimum confidence for a classification; the LLM prompts quote it |
| `confidence_threshold` | float | Alias for `confidence_floor`, which wins if both appear |
| `include_no_findings` | bool | Keep findings classified as safe |

`llm_type` and `model` are recorded either way, so a run stays reproducible, but
`enable_llm: false` still decides whether anything is sent to a provider. A
rejected value (an unknown provider, a `max_file_size` that is not a positive
integer) fails that one repository with `error_code: INVALID_SCAN_OVERRIDE` in
its `status.json` and leaves the rest of the batch running.

`max_file_size` is enforced while files are enumerated, so an oversized file is
never parsed or sent to a model. Each repository records the limit it applied and
what the limit cost, in `stage_stats.json`:

```json
{"files": {"max_file_size": 5242880, "files_skipped_too_large": 3}}
```

`metrics.json` additionally lists the skipped files by repo-relative path and
size, capped at 100 entries while `files_skipped_too_large` stays exact.

## Private repositories

Do not put credentials in a `repo_url`. An entry such as
`https://user:TOKEN@github.com/org/private.git` is skipped with a warning,
because the URL would otherwise be printed in the repo header, stored in the
run's `meta.json`, `status.json`, and `summary.json`, and written into the cache
clone's `.git/config`.

Authenticate outside the URL instead — a git credential helper, or an SSH remote
such as `ssh://git@github.com/org/private.git`. Both leave nothing for TACS to
record.
