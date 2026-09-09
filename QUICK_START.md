# Quick start — Time Assurance Code Scanner (`tacs`)

Goal: **clone → install → first findings in about 15 minutes.**

1. Install the CLI  
2. Run a **local scan with `--llm none`** (no API key)  
3. Optionally enable a real LLM provider

Copy secrets only into a local `.env` (never commit it). Template: [`.env.example`](.env.example).

**Privacy:** when `--llm` is not `none`, source snippets may be sent to your configured provider.

---

## 1. Install

```bash
cd /path/to/time_assurance_code_scanner
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
# Optional structural filtering:
# pip install -e ".[full]"
cp .env.example .env               # optional until you use a real provider
tacs version
```

---

## 2. First success (no LLM)

```bash
tacs scan \
  --root tests/patterns \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --llm none \
  --out findings.json
```

You should get a `findings.json` with candidate locations. Treat them as **candidates for review**, not confirmed defects.

### Explicit environment config (recommended)

```bash
tacs scan \
  --root /path/to/your/project \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --env-config configs/example.env_config.json \
  --llm none \
  --out findings.json
```

If you do not have an example env config yet, see `docs/env_config.md` and `tests/patterns/env_configs/`.

---

## 3. Optional: real LLM scan

Set the matching key in `.env`, then:

```bash
tacs scan \
  --root /path/to/your/project \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --env-config /path/to/env_config.json \
  --llm ollama \
  --model gpt-oss:120b-cloud \
  --out findings.json
```

Other `--llm` choices: `openai`, `anthropic`, `gemini` (each needs its API key).

---

## 4. Batch repos and render

```bash
# Full flag list:
tacs repos

tacs repos --repos-file src/tacs/fixtures/repo_lists/test_repos.jsonl --dry-run

# Render findings from a batch run directory or a single findings.json:
tacs render
```

Prefer an explicit `config_override` / env config per repo when known. `tacs detect` and batch auto-detect are **experimental**.

---

## 5. Tests

```bash
pytest
```
