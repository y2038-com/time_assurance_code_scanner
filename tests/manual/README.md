# Manual and historical test harnesses

These scripts are **not** part of the normal `pytest` suite. They are kept for
local experiments, long-running pattern corpus runs, or LLM integration checks
that need external services.

Run them explicitly, for example:

```bash
python tests/manual/manual_pattern_detection.py
python tests/manual/manual_io_quick.py
```

Normal CI / contributor verification:

```bash
pip install -e ".[dev]"
pytest
```

| Script | Notes |
|--------|--------|
| `manual_pattern_detection.py` | Pattern corpus IR checks |
| `manual_multi_config.py` | Multi env-config harness |
| `manual_io_quick.py` | Quick I/O-boundary smoke |
| `manual_llm_*.py` / `manual_pass2.py` | LLM integration experiments |
| `manual_env_integration.py` | Env-config wizard demos |
| `manual_improved_scanning.py` | Define-scan experiment |
| `manual_wizard_fix.py` | Wizard import smoke |
| `debug_*.py` / `analyze_*.py` / `inspect_*.py` / `show_abstains.py` | Ad-hoc debug helpers |
