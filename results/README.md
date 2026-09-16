# results/

Generated TACS output lives here (contents gitignored except this README).

```text
results/
├── scans/         # standalone tacs scan session trees
│   └── latest ->  # symlink to the newest session
└── batch_runs/    # tacs repos multi-repo runs (default --out-dir)
    └── latest ->  # symlink to the newest run
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
tacs render results/batch_runs/latest --format text
```

`latest` is created inside whatever `--out-dir` you use and is repointed when a
run starts, so it is usable while the run is in progress and still points at the
run that failed if one does. `--dry-run` leaves it alone. Older runs are kept;
delete them yourself when you no longer need them.

Explicit `--out-dir` / `--out` paths are never rewritten under `results/`.
