# report_renderer

Renders scanner `findings.json` as terminal text or a standalone HTML report.

## Preferred CLI

```bash
tacs render --help
```

`tacs render` forwards to the batch/report entrypoints used for single findings
files and batch run directories.

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

- `--finding 12`
- `--list`

## HTML mode options

- `--out report.html`
- `--group-by file|rule|none`
- `--title "Time Assurance Scan Report"`
- `--open` (best-effort)
