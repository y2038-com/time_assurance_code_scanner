# report_renderer

CLI utility to render scanner `findings.json` as either terminal text or a standalone HTML report.

## Usage

Run from repository root:

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
- `--title "Y2038 Scan Report"`
- `--open` (best-effort)
