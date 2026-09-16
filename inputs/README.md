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
# Example: batch dry-run from a local list (default out-dir: results/batch_runs)
tacs repos --repos-file inputs/my_repos.jsonl --dry-run
```

Contents of this folder are gitignored (except this README).

## Private repositories

Do not put credentials in a `repo_url`. An entry such as
`https://user:TOKEN@github.com/org/private.git` is skipped with a warning,
because the URL would otherwise be printed in the repo header, stored in the
run's `meta.json`, `status.json`, and `summary.json`, and written into the cache
clone's `.git/config`.

Authenticate outside the URL instead — a git credential helper, or an SSH remote
such as `ssh://git@github.com/org/private.git`. Both leave nothing for TACS to
record.
