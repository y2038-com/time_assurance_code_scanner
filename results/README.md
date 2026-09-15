# results/

Generated TACS output lives here (contents gitignored except this README).

```text
results/
├── scans/         # standalone tacs scan session trees
└── batch_runs/    # tacs repos multi-repo runs (default --out-dir)
```

**Rule of thumb**

- `inputs/` — things you supply (repo lists, local configs)
- `results/` — things TACS generates

Defaults:

- `tacs scan` sessions → `results/scans/<session>/`
- `tacs repos` → `results/batch_runs/<run_id>/` (override with `--out-dir`)
- `tacs scan --out` still writes the primary findings JSON to the path you pass
  (default `findings.json` in the current directory)

```bash
tacs repos --repos-file inputs/my_repos.jsonl
tacs render results/batch_runs/<run_id> --format text
```

Explicit `--out-dir` / `--out` paths are never rewritten under `results/`.
