# results/

Generated TACS output lives here (contents gitignored except this README).

```text
results/
├── scans/         # standalone tacs scan session trees
│   └── latest ->  # symlink to the newest session
└── batches/       # tacs repos multi-repo runs (default --out-dir)
    └── latest ->  # symlink to the newest run
```

**Rule of thumb**

- `inputs/` — things you supply (repo lists, local configs)
- `results/` — things TACS generates

Defaults:

- `tacs scan` sessions → `results/scans/<session>/`
- `tacs repos` → `results/batches/<run_id>/` (override with `--out-dir`)
- `tacs scan --out` still writes the primary findings JSON to the path you pass
  (default `findings.json` in the current directory)

Session and run ids share one shape — a UTC timestamp and a short random
suffix, such as `20260916T151300Z_7c91ab`. The timestamp sorts listings
chronologically; the suffix keeps runs started in the same second apart.

```bash
tacs repos --repos-file inputs/my_repos.jsonl
tacs render results/batches/latest --format text
```

`latest` is created inside whatever `--out-dir` you use and is repointed when a
run starts, so it is usable while the run is in progress and still points at the
run that failed if one does. `--dry-run` leaves it alone. Older runs are kept;
delete them yourself when you no longer need them.

Explicit `--out-dir` / `--out` paths are never rewritten under `results/`.

## Batch run layout

A batch run identifies each scan by run id and repo key, so the per-repo
directory *is* that scan's artifact root — there is no session subtree inside it.

```text
results/batches/<run-id>/
├── summary.json                # run-wide counters, aggregates, per-repo results
├── reports/                    # created by tacs render
└── repos/<repo-key>/
    ├── findings.json           # canonical findings (meta + findings)
    ├── summary.txt             # human-readable scan summary
    ├── stage_stats.json        # per-stage counters and LLM token usage
    ├── meta.json               # repository identity, ref, resolved config
    ├── status.json             # outcome, timing, finding and verdict counts
    ├── scan_meta.json          # scanner metadata: scan id, versions, timing
    ├── config_detection.json   # environment auto-detection evidence
    ├── env_config.json         # environment config the scan actually used
    ├── config.snapshot.json    # resolved scanner options
    ├── metrics.json            # files, lines, characters scanned
    ├── ir/candidates.jsonl     # discovered candidates
    ├── llm/<pass>/batches/     # LLM batch manifests (only when LLM ran)
    ├── logs/run.log
    └── prescan/                # typedef and macro discovery output
```

Directories appear only when something was written to them, so a discovery-only
run has no `llm/`. A repository that failed before scanning still gets its
directory with `status.json` and whatever config metadata was resolved.

Standalone `tacs scan` keeps its own session history under
`results/scans/<session-id>/`, including `README.txt`, `findings/findings.json`,
and the `latest` link. That structure is unchanged.
