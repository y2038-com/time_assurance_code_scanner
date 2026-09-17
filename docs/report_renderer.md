# report_renderer

Renders scanner `findings.json` as terminal text or a standalone HTML report.

## Preferred CLI

```bash
tacs render --help

# Single findings file (from tacs scan --out, or a session findings.json):
tacs render path/to/findings.json --format text
tacs render path/to/findings.json --format html --out report.html

# Batch run directory (default tacs repos out-dir is results/batches;
# "latest" is a symlink to the newest run):
tacs render results/batches/latest --format text
tacs render results/batches/<run_id> --format html --out-dir results/reports/
```

`tacs render` auto-detects a findings JSON file vs a batch run directory
(with `repos/`). `--batch-run-dir` remains as a deprecated alias for batch input.

In batch mode each repository's canonical findings document is
`repos/<repo-key>/findings.json`. Runs produced before the per-repo layout was
flattened kept it at `repos/<repo-key>/scan/findings.json`; both still render.

## Source paths

Findings name each source file relative to the scanned repository root, so a
report reads `benchmark/timezone_gmt_time.c` whether the tree was scanned in
place by `tacs scan` or from a clone under the `tacs repos` cache. The absolute
root is recorded once per scan under `meta.root` in `findings.json`. A file
outside the scan root keeps its original path, since it is not part of the
repository.

## Module usage

Run from repository root (with the package installed editable):

```bash
python -m report_renderer <path-to-findings.json> --format text
python -m report_renderer <path-to-findings.json> --format html --out report.html
```

## Common options

- `--only yes|no|abstain`
- `--min-confidence 0.80`
- `--file-glob "src/*.c"` (repeatable; matched against repository-relative paths)
- `--rule TIME_T_TRUNCATION` (repeatable)
- `--sort file|line|risk|confidence`
- `--strict`

## Text mode options

- `--finding 12` (single-file mode)
- `--list`

## HTML mode options

- `--out report.html` (single-file; defaults beside the findings file if omitted)
- `--out-dir DIR` (batch mode)
- `--group-by file|rule|none`
- `--title "Time Assurance Scan Report"`
- `--open` (single-file HTML; best-effort)
