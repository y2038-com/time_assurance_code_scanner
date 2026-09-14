# inputs/

Place **local, run-specific** scan inputs here (not committed by default):

- Repository JSONL lists for `tacs repos`
- Custom environment / ABI configs
- Benchmark manifests and similar one-off files

Tracked examples stay under source control (for example
`src/tacs/fixtures/repo_lists/*.jsonl` and `configs/`). Copy or adapt them into
`inputs/` when you want a private working copy.

```bash
# Example: batch dry-run from a local list
tacs repos --repos-file inputs/my_repos.jsonl --dry-run --out-dir outputs/batch
```

Contents of this folder are gitignored (except this README).
