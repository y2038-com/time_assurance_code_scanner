# Y2038 Repo Scanner – Scanning Workflow (preprocessor-agnostic, LLM-assisted)

> **Historical / design document.** This PRD describes the pipeline as designed during
> early implementation. It is **not** the CLI user guide and may disagree with the
> current `tacs` command surface, defaults, or stage naming.
>
> For public usage, start with [QUICK_START.md](../../QUICK_START.md) and
> [docs/usage/RUNNING_FULL_PIPELINE.md](../usage/RUNNING_FULL_PIPELINE.md).
> Planned items labeled “v0.4” below are **not** a ship commitment for the open-source CLI.

Version: 0.3
Status: Design-era record (implementation evolved; treat as historical)
Owners: John Lange; Contributors: GPT-5 Thinking

## 1. Goals and scope
- Deliver high precision and recall for Y2038 risk detection across C and C++ repositories.
- Scanner operates line-first and is preprocessor-agnostic by design. All code is examined regardless of `#ifdef` or related guards.
- Minimize false positives through structural filtering, a three-pass LLM review with strict output schema, and deterministic re-ranking.
- This document focuses only on the scanning pipeline. It plugs into separate Architecture and Workflow PRDs without changing other services.

## 2. Principles
- All uncommented lines matter: Do not exclude code by preprocessor state. The scanner evaluates every uncommented line with context.
- Scenario-aware, not scenario-filtered: Use environment knowledge to interpret risk, not to hide code paths.
- Cheap filters before expensive reasoning: IR with token inverted index and structural filters reduce the LLM load.
- Deterministic before probabilistic: Apply deterministic rules to rank and de-noise before and after LLM calls.
- Batch LLM payloads to minimize costs and optimize LLM efficiency

## 3. Inputs and outputs
### 3.1 Inputs
- Input is a treed folder containing code which can be local, git, or zip file
- Repo root path (local, cloned repo, or unpacked ZIP)
- Repo root path (local clone or unpacked ZIP)
- Rules JSON (symbols, categories, risk defaults; derived flags like `needs_paren`)
- Scenario facts (time_t bits, signedness, time64 APIs availability, mitigation path if ILP32 signed)
- Project config: include/exclude globs, min risk threshold, limits (file count, bytes, timeouts)

### 3.2 Outputs
- Findings JSON objects with fields:
  - `file`, `region` (start_line, end_line), `lines` (list), `symbol`, `category`, `severity`, `confidence`, `reason` (<= 25 words), `scenario`, `preprocessor_context` (captured as-is), `source_snippet` (trimmed)
- Optional abstentions with `y2038_issue = "abstain"` and `needs_more_context = true`

## 4. Pipeline stages (three-pass LLM, single-line first pass)

### Current Implementation (v0.3) - ✅ COMPLETE

### Stage 0. Environment Configuration ✅
- Environment wizard collects hardware architecture, time_t configuration, and toolchain details
- JSON schema validation with derived fields (scenario_hint, mitigation_path)
- Configuration passed to all LLM passes for context-aware analysis

### Stage 1. Code Metrics ✅
- Calculate total characters, words, lines, and files
- Calculate max/average line and file lengths
- Persist metrics in scan results and emit structured logs

### Stage 2. Typedef and Macro Discovery ✅
- Recursive typedef graph rooted at `time_t` (configurable depth, default 5 hops)
- Smart macro discovery with hardware filtering
- Integrated #define scanning with subchecks (time_type_alias, time_function_alias, time_constant, time_struct_alias)
- Hardware-related definitions filtered out (clocks, frequencies, registers)

### Stage 3. IR Candidate Discovery ✅
- Fast token inverted index scanner integration
- Integrated #define scanning with smart subchecks
- Comprehensive candidate discovery across all files
- Glob pattern support for include/exclude

### Stage 4. Structural Filter ✅
- Tree-sitter C/C++ parsing with safe fallback
- Symbol role tagging (call, declaration, variable, type, field, macro usage)
- Preprocessor directive filtering (#warning, #error, #pragma)
- Declaration-only and comment filtering

### Stage 5. LLM Pass 1: Single-line Triage ✅
- Batch processing (50-150 candidates per request)
- Strict JSON schema with environment context
- Confidence-based filtering
- Comprehensive logging with redaction controls

### Stage 6. LLM Pass 2: Widened Context ✅
- Triggered by abstain candidates from Pass 1
- 5-line context extraction around candidates
- Batch processing with intelligent grouping
- Same strict JSON schema

### Stage 7. LLM Pass 3: File-leading Context ✅
- Triggered by remaining abstain candidates from Pass 2
- Full file content with practical limits (200KB)
- Intelligent batching to avoid duplicate file sends
- File grouping for efficiency

### Stage 8. Output Assembly ✅
- Comprehensive JSON output with metadata
- Structured logging in `results/scans/<session-id>/`
- Human-readable summaries
- ID mapping and artifact preservation

### Next Phase (v0.4) - 🚧 PLANNED

### Stage 2.5. Second Quick Scan (Conditional) 🚧
- **Trigger:** If critical macros found (e.g., `#define MY_TIME_T time_t`)
- **Purpose:** Follow up on important macro discoveries
- **Implementation:** Additional scanning pass for macro derivative usage
- **Efficiency:** Only runs when high-value macros are discovered

### Stage 4.5. Local LLM Pre-filter 🚧
- **Purpose:** Intelligent pre-filtering before commercial LLM passes
- **Model:** Small local model (e.g., `llama3.2:3b`, `qwen2.5:3b`)
- **Risk Assessment:** Categorize candidates into high/medium/low risk
- **Pattern Detection:** Cast detection, printf usage, function calls
- **Cost Optimization:** Reduce commercial LLM API calls by 80-90%

### Stage 4.6. Risk-Based Processing 🚧
- **High Risk:** Suspicious casts, printf usage → Direct to commercial LLM
- **Medium Risk:** Function calls → Local LLM triage
- **Low Risk:** Declarations → Filter out
- **Learning System:** Corpus building for local model training

### Stage 4.7. Learning and Adaptation 🚧
- **Corpus Building:** Collect examples from commercial LLM decisions
- **Model Training:** Fine-tune local model on collected data
- **Iterative Improvement:** Continuous learning from scan results
- **Performance Tracking:** Monitor filtering accuracy and cost savings
## 5. LLM specification

### 5.1 System prompt ✅
"You are a C/C++ Y2038 auditor. Use the environment summary and the provided code inputs to decide if there is a Y2038 risk. Do not guess. If there is not enough information, answer abstain with a short reason."

### 5.2 Few-shot exemplars ✅
- One true positive unsafe cast to 32-bit.
- One benign time64 API usage.
- One unclear macro indirection that warrants abstention.

### 5.3 Strict JSON schema per item ✅
```json
{
  "id": "string",
  "y2038_issue": "yes" | "no" | "abstain",
  "severity": "low" | "medium" | "high" | "critical" | null,
  "confidence": 0.0,  // range 0.0 to 1.0
  "reason": "<= 25 words",
  "needs_more_context": true
}
```
- Pass 1 IDs correspond to single-line candidates; Pass 2 and 3 IDs correspond to regions formed in Stage 6.
  - Optional fields:
    - Pass 1: "line": int, "col_start": int, "col_end": int
    - Pass 2 and 3: "region": { "start_line": int, "end_line": int }

### 5.4 Batching and limits ✅
- Pass 1: 50 to 150 single lines per request.
- Pass 2: 20 regions per request (configurable).
- Pass 3: 5 unresolved regions per request (configurable).
- Timeout budget: ~3 seconds per region equivalent.
- Exponential backoff on 429/5xx.
- Hard token budget per scan and per request to cap cost. Abort or degrade gracefully when limits are hit.

## 6. Deterministic rule set (examples) ✅
- Cast narrowing: `time_t` or alias to 32-bit integral types
- Signedness mismatches around arithmetic and comparisons
- Use of 32-bit time APIs when 64-bit APIs exist (and are available)
- Storage and serialization of time fields in 32-bit slots

## 7. Evaluation and datasets 🚧
- Maintain a labeled gold set of 50 to 100 regions across Zephyr, FreeRTOS, Linux userland.
- Metrics: precision and recall by severity; accepted vs rejected rates; abstention rate.
- Run the evals on every rules or prompt change. Pin and record: model name, model version, prompt version, and few-shot set version. Use a fixed seed where supported.

## 8. Security and privacy ✅
- Only send minimal snippets and context; redact secrets or tokens if present in paths or comments.
- Disable verbose raw model logging in production by default.
- Log batch ids, token counts, and decision histograms for tuning (not raw code) unless LLM logging is explicitly enabled.
- Strip or hash repository paths that might include user names or sensitive directory names.

## 8A. LLM logging and dataset capture (opt in) ✅
- Purpose: create a corpus of prompts and responses for future fine-tuning and evaluation.
- Opt in: disabled by default; enable via CLI flag `--log-llm` (true/false). Respect project-level policy if present.
- Storage: plain files on disk, not a database, under a configurable directory `--log-dir` (default: `results/llm_logs`).
- Format: one file per request per pass in JSON Lines (`.jsonl`).
  - Filename template: `{UTC_ISO_TIMESTAMP}_pass{1|2|3}_batch{NN}.jsonl` (for example, `2025-10-11T16-42-08Z_pass1_batch03.jsonl`).
  - Each line is a JSON object with keys: `repo_id_hash`, `project_id` (optional), `model`, `model_version` (if available), `prompt_preamble_hash`, `items` (array of region IDs), `request_tokens`, `response_tokens`, `latency_ms`, `prompt` (redacted if `--redact-prompts`), `response` (full JSON), and `timestamp`.
- Redaction controls:
  - `--redact-prompts` replaces file paths with hashes and removes long code spans, keeping only line numbers and short context. Default: **enabled** when `--log-llm` is on.
  - A separate `mapping.json` with hash->original path is **not** written unless `--unsafe-allow-pathmap` is passed for strictly local research.
- Retention: do not retain logs longer than project-configured days (default 30). A `cleanup_logs.py` script prunes old files.
- Security: never write access tokens or credentials. Scrub environment variables from logged payloads.

## 9. Configuration knobs (per project) ✅
- include_globs, exclude_globs
- min_risk threshold for the IR stage
- LLM confidence floor (default 0.6)
- Batch sizes and timeouts per pass
- Max token budget per scan
- **LLM logging:** `--log-llm` flag, `--log-dir` path, `--redact-prompts` (default on)
- **Environment configuration:** `--env-config` file path
- **Debug options:** `--debug-candidates`, `--debug-pass2`

## 10. Integration points ✅
- Worker job consumes this pipeline and writes Findings to the DB.
- UI reads the Findings JSON and renders a sortable table with filters for severity, confidence, rule, file, and scenario.
- Feedback loop records user actions for future threshold tuning.

## 11. Non-goals ✅
- No compile-time path exploration or macro evaluation in v1.
- No automatic code rewriting in this workflow doc (patching is separate).

## 12. Open questions 🚧
- What is the optimal region size cap for best precision vs cost in driver-heavy codebases.
- Do we need per-language-tailored preambles for C vs C++.
- Confidence calibration curves per model family (Ollama cloud variants vs others).
- **Local LLM model selection:** Which small model provides best accuracy vs speed tradeoff?
- **Risk assessment thresholds:** What confidence levels should trigger different processing paths?
- **Learning system architecture:** How to efficiently collect and process training data?

## 13. Implementation Status Summary

### ✅ COMPLETED (v0.3)
- **Environment Configuration:** Complete CLI wizard with JSON schema validation
- **Typedef Discovery:** Recursive alias detection with configurable depth
- **Integrated #define Scanning:** Smart subchecks with hardware filtering
- **Three-Pass LLM Analysis:** All passes fully implemented with proper context
- **Structural Filtering:** Tree-sitter integration with preprocessor directive filtering
- **Comprehensive Logging:** Structured scan results with detailed metadata
- **Ollama Integration:** Local and cloud LLM support with proper error handling
- **JSON Schema Validation:** Strict output format enforcement

### 🚧 PLANNED (v0.4)
- **Local LLM Pre-filter:** Small local model for intelligent candidate filtering
- **Risk-Based Assessment:** Categorize candidates by risk level (high/medium/low)
- **Second Quick Scan:** Follow-up scanning for critical macro derivatives
- **Learning System:** Corpus building for local model training
- **Performance Optimization:** Advanced batch processing and rate limit handling

### 🎯 ARCHITECTURE GOALS (v0.4)
The next phase will implement the refined architecture:
```
Pre-scan typedefs → Quick scan (including macros) → Second quick scan (if important macro derivatives) → Structural filter → Local LLM filter → Commercial LLM Pass 1 → Commercial LLM Pass 2 → Commercial LLM Pass 3
```

This architecture will provide:
- **80-90% reduction** in commercial LLM API calls
- **Intelligent pre-filtering** with local models
- **Adaptive processing** based on macro discoveries
- **Learning capabilities** for continuous improvement
- **Cost optimization** while maintaining accuracy

