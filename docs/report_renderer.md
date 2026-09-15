# report_renderer

Renders scanner `findings.json` as terminal text or a standalone HTML report.

## Preferred CLI

```bash
tacs render --help

# Single findings file (from tacs scan --out, or a session findings.json):
tacs render path/to/findings.json --format text
tacs render path/to/findings.json --format html --out report.html

# Batch run directory (default tacs repos out-dir is results/batch_runs):
tacs render results/batch_runs/<run_id> --format text
tacs render results/batch_runs/<run_id> --format html --out-dir results/reports/
```

`tacs render` auto-detects a findings JSON file vs a batch run directory
(with `repos/`). `--batch-run-dir` remains as a deprecated alias for batch input.

## Module usage

Run from repository root (with the package installed editable):

```bash
python -m report_renderer <path-to-findings.json> --format text
python -m report_renderer <path-to-findings.json> --format html --out report.html
```

## Common options

- `--only yes|no|abstain`
- `--min-confidence 0.80`
- `--file-glob "src/**/*.c"` (repeatable)
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
