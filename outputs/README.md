# outputs/

Place **generated** scan artifacts here when you want a private working tree
(not committed by default): findings JSON, batch run dirs, rendered reports,
benchmark output, and similar.

TACS does **not** require this directory — defaults such as `--out findings.json`,
`results/`, and `batch_runs/` still work. Prefer `outputs/` when you want a
single gitignored place for local runs (same convention as `tads`).

```bash
tacs scan \
  --root /path/to/code \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --llm none \
  --out outputs/findings.json

tacs repos --repos-file inputs/my_repos.jsonl --out-dir outputs/batch_runs
tacs render outputs/findings.json --format text
tacs render outputs/batch_runs/<run_id> --format text --out-dir outputs/reports
```

Contents of this folder are gitignored (except this README).
