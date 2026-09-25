# TACS Theory of Operation

The Time Assurance Code Scanner (TACS) is an open-source, AI-assisted source-code
scanner that supports long-horizon time assurance by identifying potential
Y2038- and Y2106-class risks in C and C++ software.

TACS treats assurance as an evidence-building process rather than a binary
certification result. It attempts to expose relevant code, representations,
interfaces, and assumptions for review, but it cannot demonstrate that every
possible time-related failure has been discovered. TACS supports time assurance
by identifying and documenting potential time-related risks; it does not
guarantee that all such risks have been found.

TACS is designed around a simple principle:

> **Scan broadly first, then add context progressively before deciding whether a
> candidate represents a real time-assurance risk.**

A source line that mentions `time_t`, performs arithmetic on a timestamp, or
stores a time value in a 32-bit field is not automatically a defect. Whether it
is dangerous depends on the target environment, surrounding code, data
representation, interfaces, and sometimes definitions elsewhere in the file.

TACS therefore operates as a funnel:

1. establish the assumed time environment (when provided),
2. inventory and understand the source tree,
3. discover time-related type aliases and candidate locations,
4. add deterministic context and specialized analysis,
5. group candidate locations into complete functions,
6. optionally use an LLM to classify those functions,
7. give ambiguous cases progressively more context rather than forcing a guess,
8. preserve the resulting findings and supporting evidence for human review.

Human review remains authoritative. TACS findings are **candidates for review**,
not proof that a vulnerability or defect exists.

---

## How the top-level commands fit together

TACS exposes several top-level commands, but they do not represent separate
analysis engines.

| Command | Role | Relationship to the analysis pipeline |
|---|---|---|
| `tacs scan` | Scan one local source tree | Runs the core analysis pipeline directly on a local directory |
| `tacs repos` | Batch-scan repositories | Acquires and prepares repositories, then runs the same core scanner for each repository |
| `tacs detect` | Experimental environment inference | Helps determine the Phase 0 environment configuration; it is not the source-code scanner itself |
| `tacs render` | Report presentation | Reads completed findings and renders them as text or HTML; it does not scan source code |
| `tacs version` | Version information | Utility command; not part of analysis |

The relationship can be viewed as:

```text
                     ┌───────────────┐
                     │  tacs detect  │
                     │ experimental  │
                     │ env inference │
                     └───────┬───────┘
                             │
                             ▼
                     Environment config
                             │
                             ▼
┌──────────────┐      ┌─────────────────┐
│  tacs scan   │─────►│ Analysis pipeline│
│ local tree   │      │   Phases 0–9    │
└──────────────┘      └────────┬────────┘
                               │
┌──────────────┐               │
│  tacs repos  │───────────────┘
│ clone/batch  │
└──────────────┘
                               ▼
                         findings.json
                               │
                               ▼
                        ┌──────────────┐
                        │ tacs render  │
                        │ text / HTML  │
                        └──────────────┘
````

### `tacs scan`

`tacs scan` is the direct entry point to the scanner. It operates on a source
tree already present on local disk.

For example:

```bash
tacs scan \
  --root ./my_project \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --env-config configs/example.env_config.json \
  --llm none \
  --out findings.json
```

The source tree is read in place. TACS does not copy it into a separate source
vault.

`--env-config` is optional for `tacs scan`. When it is omitted, the scan still
runs, but later reasoning has less explicit ABI / `time_t` information and must
be more conservative. An explicit environment configuration remains preferred
when the target platform is known.

### `tacs repos`

`tacs repos` is a **batch orchestrator around the same scanner used by
`tacs scan`**.

It adds repository-management functions such as:

* cloning or reusing repositories,
* resolving refs,
* selecting or detecting an environment configuration,
* applying per-repository overrides,
* enforcing per-repository scan deadlines,
* continuing past individual repository failures when configured,
* aggregating results across a batch.

Once a repository has been prepared, its source is passed into the same core
analysis pipeline.

Unlike a bare `tacs scan`, `tacs repos` always materializes an environment
configuration for each repository: an explicit override when provided,
experimental detection when evidence is strong enough, or a configured fallback
otherwise.

### `tacs detect`

`tacs detect` attempts to infer which supported ABI / `time_t` environment best
matches a project by examining build-system evidence.

Its result can help supply the environment assumptions used by Phase 0.

Detection is experimental and should not be treated as authoritative. When the
target environment is known, an explicit environment configuration is
preferred.

`tacs repos` may also use this detection logic while preparing repositories and
fall back to a configured default when the evidence is insufficient.

### `tacs render`

`tacs render` operates **after scanning**.

It reads existing findings and produces a human-oriented text or HTML report.
It does not rediscover candidates, invoke the scanner, or reclassify code.

---

# Analysis pipeline at a glance

The default TACS pipeline is function-first: candidate locations are discovered
deterministically and then grouped into complete functions before optional LLM
classification.

| Phase                                        | Purpose                                           | In plain English                                                  |
| -------------------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------- |
| 0. Environment configuration                 | Establish the assumed ABI and time model          | “What does `time_t` mean on this target?”                         |
| 1. Code metrics                              | Inventory the source being analyzed               | “How much code are we examining?”                                 |
| 2. Typedef / time-type discovery             | Learn project-specific aliases of `time_t`        | “What does this project call its time values?”                    |
| 3. Candidate discovery                       | Find potentially time-sensitive code              | “Where might a rollover problem exist?”                           |
| 4. Structural filter                         | Optional heuristic / structural pruning           | “Can obvious non-use sites be skipped cheaply?”                   |
| 5. I/O boundary analysis                     | Examine time values crossing interfaces           | “Could a timestamp be truncated or misrepresented at a boundary?” |
| 6. Migration analysis                        | Optionally compare source and target environments | “Could an ABI/platform migration expose a time risk?”             |
| 7. Optional line-level LLM triage (legacy)   | Optionally reject obvious non-issues early        | “Can inexpensive line-level reasoning prune candidates?”          |
| Functionization                              | Group candidate sites into complete functions     | “What function contains this candidate?”                          |
| 8a. Function-level analysis                  | Analyze candidate-bearing functions               | “Does this function actually contain a rollover risk?”            |
| 8b. Targeted enrichment                      | Extract requested definitions from the same file  | “What specific information was missing?”                          |
| 9. File-level escalation                     | Give unresolved cases broader file context        | “Can surrounding file context resolve the ambiguity?”             |
| Output assembly                              | Preserve results and evidence                     | “What did TACS find, and how did it reach that point?”            |

Candidate identity normalization and de-duplication are applied more than once:
after IR discovery, and again after I/O / migration candidates are merged, so
that later stages see a stable set. Stage 4 is the structural-filter step; it is
not the only place where candidates are normalized.

The flow is approximately:

```text
Environment / config
        │
        ▼
Source inventory / metrics
        │
        ▼
Typedef / time-type discovery
        │
        ▼
IR candidate discovery
        │
        ▼
Normalize / dedupe candidates
        │
        ▼
Stage 4 structural filter
        │
        ▼
Stage 5 I/O boundary analysis
        │
        ▼
Stage 6 optional migration analysis
        │
        ▼
Merge + normalize / dedupe again
        │
        ▼
[optional legacy Stage 7 line triage]
        │
        ▼
Functionization
        │
        ▼
Stage 8a function analysis
        │
        ├── decided ───────────────► finding / safe classification
        │
        └── abstain
              │
              ▼
       Stage 8b targeted enrichment
              │
              ├── decided ─────────► finding / safe classification
              │
              └── abstain
                    │
                    ▼
              Stage 9 broader file context
                    │
                    ▼
                final result / output
```

LLM stages are optional. With `--llm none`, TACS still performs deterministic
candidate discovery and emits those candidates as findings with
`y2038_issue=abstain` for human (or later model) review. It does not attempt
LLM-based yes/no classification.

---

# Phase 0 — Environment configuration

## Purpose

Y2038 risk depends heavily on the execution environment.

The same C statement can be safe on one platform and unsafe on another.
When an environment configuration is available, TACS carries an explicit model
of the target ABI and `time_t` representation into later analysis.

Important properties include:

* ABI model,
* `time_t` width,
* `time_t` signedness,
* availability of time64 APIs,
* relevant toolchain capabilities,
* known or unknown migration capabilities.

How this phase is supplied differs by command:

* **`tacs scan`:** `--env-config` is optional. If omitted, the scan continues
  without a concrete ABI / time-model file; later reasoning must be more
  conservative across possible platforms. An explicit configuration is still
  preferred when the target is known.
* **`tacs repos`:** an environment configuration is always materialized for
  each repository — via explicit override, experimental detection, or fallback
  configuration.

## Example

Consider:

```c
time_t now = time(NULL);
```

This is not inherently a Y2038 bug.

If `time_t` is a signed 32-bit integer, the representation reaches its maximum
on January 19, 2038.

If `time_t` is 64-bit, the same statement does not have the classic Y2038
overflow problem.

Another example:

```c
uint32_t timestamp;
```

The type alone is not enough to determine whether this is a problem. TACS needs
to know:

* whether the value represents Unix epoch seconds,
* whether the system intentionally uses unsigned 32-bit time,
* whether Y2106 analysis is enabled,
* how the value crosses interfaces or is converted elsewhere.

Environment configuration gives later phases the context needed to make those
distinctions when it is present.

---

# Phase 1 — Code metrics

## Purpose

Before analyzing the source, TACS establishes what code is actually being
examined.

The scanner records metrics such as:

* number of source files,
* line count,
* character count,
* selected size statistics.

Source enumeration uses canonical in-repository file identity so that aliases
to the same underlying source do not count as separate files.

## Why this matters

Code metrics are primarily about provenance and reproducibility rather than
defect detection.

They help answer questions such as:

> Did TACS scan the source tree I expected?

> Was the same amount of source analyzed in two comparison runs?

> Why did one repository require substantially more processing than another?

For example:

```text
Files:      22
Lines:      2,378
Characters: 62,720
```

These numbers give context to the rest of the run.

---

# Phase 2 — Typedef / time-type discovery

## Purpose

Real codebases rarely use only the literal name `time_t`.

Projects introduce aliases and helper types. Phase 2 therefore learns
project-specific type aliases that ultimately relate to `time_t` (and a small
set of related time representation seeds such as `clock_t` / `timer_t`).

The goal is vocabulary for later deterministic discovery, not defect
classification and not macro inventory. In current `main`, Phase 2 does not
return a useful macro set; `#define` handling lives in candidate discovery
(Phase 3).

## Typedef example

```c
typedef time_t timestamp_t;
typedef timestamp_t event_time_t;
```

A scanner that only searched for the literal token `time_t` could miss later
code such as:

```c
event_time_t expiration;
```

TACS follows typedef relationships so later phases understand that
`event_time_t` is related to `time_t`. Discovered aliases are folded into the
rules used by IR candidate discovery so those names can become candidate
sites.

---

# Phase 3 — Candidate discovery

## Purpose

Candidate discovery deliberately favors **recall over final precision**.

The goal is to identify source locations that deserve further examination, not
to prove that every location is defective.

In current `main`, this phase combines several deterministic mechanisms:

* **IR / rule-based discovery** — matching rules and discovered type aliases
  against source tokens (including casts involving known time types),
* **arithmetic heuristics** — time-bearing arithmetic and related patterns,
* **integrated `#define` scanning** — when the ruleset includes a `#define`
  rule, a define scanner examines macro definitions for time-related shapes.

Discovering a macro definition as potentially time-related is not the same as
proving that it creates a rollover bug. A hit remains a candidate for later
analysis.

## Code-pattern examples

### Narrowing conversions

```c
int32_t stored = (int32_t)time(NULL);
```

### Time arithmetic

```c
expires = now + lifetime;
```

### Boundary comparisons

```c
if (timestamp > INT32_MAX)
    ...
```

### Potentially narrow storage

```c
struct record {
    int32_t created;
};
```

### Time-related APIs and types

```c
time_t now = time(NULL);
gmtime(&now);
```

The last example may be perfectly safe. Its presence as a candidate simply
means that it is part of the time-processing surface of the program.

## Macro-related examples

A project might define:

```c
#define CURRENT_TIME() time(NULL)
```

or:

```c
#define TIME_MAX INT32_MAX
```

Those definitions can change the meaning of later expressions and may be
recorded as candidates when they look time-related.

Not every symbol containing words such as `time`, `clock`, or `tick` is related
to epoch rollover. For example:

```c
#define CPU_CLOCK_HZ 100000000
```

is not automatically relevant to Y2038. The define scanner applies heuristics
intended to prefer time-representation macros and to skip many hardware clock
and register-style definitions.

A candidate should therefore be understood as:

> **“This location may be relevant to time assurance and deserves analysis.”**

It does not mean:

> **“TACS has confirmed a Y2038 defect here.”**

That distinction is fundamental to interpreting TACS output.

---

# Phase 4 — Structural filter

## Purpose

After IR discovery (and an initial normalize / dedupe of that candidate set),
TACS applies Stage 4 structural filtering.

Candidate path canonicalization, exact-duplicate collapse, and deterministic
ordering are handled by the shared candidate-identity helpers. Those steps run
around discovery and again after later stages merge additional candidates; they
are not exclusive to Stage 4.

## Current v0.1.0 behavior

Stage 4 itself depends on whether tree-sitter is importable:

* **Without tree-sitter available**, Stage 4 is effectively a **no-op**:
  candidates pass through unchanged.
* **With tree-sitter importable**, current behavior is still
  **heuristic / line-oriented** (simple role guesses and skips for comments,
  some declarations, and similar). It is not full AST analysis.

Full tree-sitter AST-based structural filtering is **not implemented** in
v0.1.0. Installing the optional tree-sitter dependency does not turn this phase
into a complete structural analysis pass. The default install therefore should
not be assumed to apply meaningful structural pruning here.

TACS remains intentionally conservative at this stage.

## Example

Suppose two repository paths ultimately refer to the same source file through
an in-repository symbolic link.

TACS should not analyze the same physical function twice merely because it can
be reached through two names. That identity collapse comes from canonical
source enumeration and candidate normalization, not from AST filtering.

---

# Phase 5 — I/O boundary analysis

## Purpose

Time-related failures often occur not where a timestamp is created, but where
it crosses a representation boundary.

A program may use a safe internal time representation and still truncate or
misinterpret time when it is:

* printed,
* parsed,
* written to a file,
* serialized,
* transmitted,
* copied into a fixed-width structure,
* passed through an external interface.

TACS performs specialized checks for these boundary conditions (enabled by
default; can be disabled on `tacs scan`).

## Formatted I/O example

```c
fprintf(fp, "%d", timestamp);
```

If `timestamp` is wider than the representation expected by `%d`, information
can be lost or misinterpreted.

## Raw I/O example

```c
write(fd, &timestamp, 4);
```

If the in-memory time representation is wider than four bytes, this may define
a 32-bit external representation even on a system with a safe 64-bit
`time_t`.

## Serialization example

```c
memcpy(buffer, &event_time, sizeof(uint32_t));
```

Again, the problem may not be the internal type. The risk is the representation
chosen at the boundary.

This phase is important because upgrading `time_t` alone does not necessarily
fix storage formats, network protocols, or persistent binary data.

---

# Phase 6 — Migration analysis

## Purpose

Migration analysis is optional.

It examines how code behaves when moving between two environment
configurations.

For example:

```text
32-bit signed time_t
        │
        │ migration
        ▼
64-bit time_t
```

The destination platform may be individually Y2038-safe while existing code
still contains assumptions tied to the old representation.

Potential migration risks include:

* casts that preserve an obsolete width,
* structures with fixed 32-bit time fields,
* binary file formats,
* network protocol fields,
* ABI boundaries,
* signedness assumptions,
* conversions between old and new representations.

The important question is therefore not simply:

> “Is the new platform safe?”

but also:

> “Does this code or its external data representation still assume the old
> platform?”

Migration mode is separate from ordinary candidate discovery and is disabled
unless requested.

After I/O and optional migration candidates are merged into the working set,
TACS normalizes and de-duplicates again before functionization (or before
legacy Stage 7, when that path is active).

---

# Phase 7 — Optional line-level LLM triage (legacy path)

## Purpose

TACS contains an optional early LLM pass that can classify individual
candidate lines before function-level analysis.

This can reduce the amount of later LLM work by rejecting obvious non-issues.

However, it is **disabled by default**, and in current `main` it is **only
reachable on the legacy pipeline**:

```bash
tacs scan ... --no-function-first --no-disable-stage1
```

Both flags are required. `--no-disable-stage1` alone does **not** restore Stage 7
on the default function-first path.

The default function-first path constructs a `FunctionLLMClient` for Stages 8
and 9. Stage 7 depends on the legacy `llm_client` used by the non-function-first
pipeline. Without that client, the Stage 7 gate never runs even if line triage
is notionally enabled.

## Example

Consider:

```c
time_t now = time(NULL);
```

On its own, this line may be completely safe.

A line-level model may be able to say that it is not evidence of a Y2038
problem.

But consider:

```c
return now + offset;
```

The safety of this expression may depend on:

* the type of `now`,
* the type and range of `offset`,
* checks earlier in the function,
* the target environment,
* how the return value is consumed.

Discarding the candidate based only on one line could lose a real issue.

For that reason, TACS defaults to the function-first approach, keeps Stage 7
off, and does not use line-level triage on the path most users run.

---

# Functionization — from candidate line to program behavior

## Purpose

Functionization is one of the central ideas in the current TACS architecture.

Candidate discovery operates on source locations, but meaningful reasoning
usually requires the containing function.

Suppose discovery identifies:

```c
return now + offset;
```

That line alone gives limited information.

The complete function might be:

```c
time_t expiration(time_t now, int offset)
{
    if (offset < 0)
        return now;

    return now + offset;
}
```

Now an analyzer can reason about:

* parameter types,
* guards,
* nearby assignments,
* return type,
* casts,
* arithmetic,
* related candidate locations in the same function.

TACS therefore groups candidate sites into their containing functions before
the primary LLM analysis.

Multiple candidate locations inside the same function are analyzed together
rather than sending the same function repeatedly.

This both reduces duplicate work and provides better context.

---

# Stage 8, Pass 2a — Initial function-level analysis

## Purpose

When an LLM is enabled, TACS asks the model to evaluate each candidate-bearing
function under the supplied environment assumptions.

On the function-first path, the model primarily receives:

* the complete function body,
* candidate locations within that function,
* environment configuration (when one was provided),
* migration context when migration mode is enabled.

Earlier deterministic discovery still matters: it decides which candidates and
functions reach this stage (including aliases folded into IR rules). It does
**not** mean that Phase 2 typedef aliases are automatically injected into the
function-level prompt as a global known-alias list.

The expected decision is conceptually:

```text
yes
no
abstain
```

### `yes`

The available evidence supports a time-assurance problem.

Example:

```c
int32_t seconds = (int32_t)time(NULL);
```

under an environment where `time_t` can exceed signed 32-bit range.

### `no`

The candidate appears safe in the supplied context.

Example:

```c
time_t now = time(NULL);
```

on a 64-bit `time_t` environment with no narrowing operation.

### `abstain`

There is not enough information to decide reliably.

For example:

```c
my_time_t deadline = get_deadline();
```

may be impossible to classify without knowing what `my_time_t` represents.

TACS deliberately supports abstention at this stage instead of forcing the
model to guess.

---

# Stage 8, Pass 2b — Targeted context enrichment

## Purpose

When the first function-level pass cannot decide, TACS attempts to supply the
specific additional context needed to resolve the ambiguity.

This is preferable to sending maximum repository context for every candidate.

When the first function-level pass requests more context, TACS re-examines that
function’s source file and extracts the requested definitions where available.
In current `main`, Pass 2b may extract file-local:

* typedefs,
* structs,
* macros,
* other requested context kinds (such as callees or headers) when asked.

It does **not** automatically supply a typedef that was discovered only in some
other header during Phase 2. Enrichment is scoped to the candidate function’s
own source file.

## Typedef example

Suppose a function contains:

```c
my_time_t deadline;
```

The initial analysis cannot determine whether `my_time_t` is 32 or 64 bits.

If the same source file contains:

```c
typedef int32_t my_time_t;
```

Pass 2b can extract that definition and give the model another chance to decide.

## Macro example

A function might contain:

```c
expires = now + DEFAULT_LIFETIME;
```

If `DEFAULT_LIFETIME` is defined in the same file, enrichment can supply that
macro text when macro context was requested.

## Structure example

A candidate may involve:

```c
record.created = now;
```

If the structure is defined in the same file, enrichment can reveal whether the
field is:

```c
time_t created;
```

or:

```c
int32_t created;
```

The principle is:

> **Escalate context selectively.**

Most functions should not require the entire source file or repository. Only
ambiguous cases receive additional file-local context.

---

# Stage 9 — File-level context

## Purpose

Some cases remain ambiguous even after targeted enrichment.

A function may depend on definitions, initialization logic, helper declarations,
or other information elsewhere in the same source file.

Stage 9 is the final escalation for unresolved findings. In current `main` it
does **not** send the whole source file. It provides:

* leading lines from the source file, and
* typedef / struct / macro definitions extracted from that file.

## Example

Consider:

```c
static timestamp_t epoch_offset;

time_t convert_time(time_t value)
{
    return value + epoch_offset;
}
```

The function alone may not explain the range, origin, or definition of
`timestamp_t` or `epoch_offset`. Leading lines and extracted definitions from
the same file may resolve the question.

## Decision policy

Because Stage 9 is the last LLM escalation, its prompt strongly encourages a
decisive `yes` or `no`. Abstain remains possible, but it is intended to be rare
at this point.

## Why not always send the whole file?

Sending complete file bodies for every candidate would:

* increase token use,
* increase processing time,
* send more source material to an external LLM when one is configured,
* potentially make model reasoning less focused.

TACS therefore starts with functions and expands to file-leading context plus
extracted definitions only when earlier passes abstain.

---

# Output assembly and audit trail

## Purpose

TACS preserves not only final findings but also information about how the scan
was performed.

Depending on command and options, scan artifacts can include:

* source metrics,
* environment configuration,
* discovered typedefs,
* candidate records,
* function identities,
* per-stage statistics,
* LLM request/token statistics,
* classifications,
* retained findings,
* scan timing and provenance,
* optional diagnostic artifacts.

The intent is to leave an auditable trail from broad deterministic discovery to
the final human-review candidate.

The value of TACS is therefore not only the findings it produces, but the
repeatable evidence it provides about what was examined, under which
assumptions, and which potential risks were identified.

The principal user-facing result is typically `findings.json`.

Starting with public result **schema_version `1.1`**, that document has the shape:

```json
{
  "schema_version": "1.1",
  "meta": {
    "candidate_summary": {},
    "analysis_status": "complete|partial|failed|not_requested",
    "assessment_summary": {}
  },
  "candidates": [],
  "assessments": [],
  "findings": []
}
```

* `candidates` is the canonical **deterministic discovery evidence** collection.
  Every prepared deterministic candidate appears here once, including candidates
  outside recognized functions and candidates later dropped from analysis by
  Stage 7 (when that opt-in filter is enabled). Presence in `candidates` does
  **not** mean the hit is a confirmed defect. Candidate evidence never carries
  model verdicts.
* `assessments` is the durable **model-analysis** record for function units
  (schema 1.1+). Each assessment links `candidate_ids` and separates
  `execution_status` (`completed` / `analysis_error`) from `verdict`
  (`yes` / `no` / `abstain` only when completed). A model conclusion does not
  validate or erase candidates. Parse/alignment/provider stubs are
  `analysis_error` with null verdict; compatibility `findings` may still use
  abstain-shaped rows for those stubs as a legacy exception. Public assessment
  `reason` text for operational stubs is a controlled message (not raw
  exception dumps, prompts, or function bodies).
* `findings` remains the existing **model-oriented compatibility projection**
  (filtering such as `--include-no-findings` unchanged). `--include-no-findings`
  affects only `findings[]`, not `candidates[]` or `assessments[]`.
* `--llm none` sets `meta.analysis_status=not_requested` with an empty
  `assessments[]` while retaining full `candidates[]` (and existing abstain
  compatibility findings).
* `meta.candidate_summary` / `meta.assessment_summary` are reconciled from the
  serialized arrays at write time.
* `rule_id` on candidate evidence is reserved for genuine catalog identifiers; it
  is currently null until a catalog ID migration (planned before a future 0.2.0).
  Detectors emit controlled `discovery_method` values at production time
  (`catalog_symbol_match`, `time_t_cast`, `define_scanner`, `arithmetic_scanner`,
  `io_boundary`, `migration`). Missing provenance becomes `unknown` rather than
  a fabricated catalog match.
* `analysis_coverage` is factual pipeline state: `grouped` when function
  association found an enclosing unit, `ungrouped` when association was attempted
  and none was found. Stage 7 filtering does not relabel an in-function candidate
  as ungrouped; linkage is derived from the full canonical set before Stage 7.
* Globally aborted scans (for example after repeated batch provider failures)
  still do not emit structured partial public reports; that remains deferred.
  Operational failure must not be silently represented as a negative model
  conclusion in assessments.

A retained finding can contain information such as:

* source file,
* line or region,
* symbol,
* issue classification,
* confidence,
* reason,
* source snippet,
* function identity,
* Y2038/Y2106 classification where applicable.

With `--llm none`, `meta.analysis_status` is `not_requested` and `assessments[]`
is empty. Compatibility `findings` still use `y2038_issue=abstain` for review.
Deterministic `candidates[]` are retained in full; the scanner does not invent
model assessments or yes/no verdicts without a model.

With an LLM enabled, later stages may classify candidates as `yes`, `no`, or
`abstain`. By default, findings classified as `y2038_issue=no` are **dropped**
from the retained finding set. Use `--include-no-findings` to keep them.
Classification totals can still reflect dropped safe results in scan
statistics. When `--detect-y2106` is enabled, a finding whose Y2106 issue is
`yes` is retained even if the Y2038 issue is `no`.

---

# Y2038 and Y2106

TACS primarily targets Y2038-class risks.

A signed 32-bit Unix-seconds representation reaches its maximum value on
January 19, 2038.

TACS can also optionally analyze Y2106-class risks with:

```bash
--detect-y2106
```

A 32-bit **unsigned** Unix-seconds representation wraps in February 2106.

This distinction matters because changing a representation from signed
32-bit to unsigned 32-bit can postpone the failure without eliminating the
underlying width limitation.

Y2106 analysis is therefore opt-in and uses the same general pipeline, with the
environment model and LLM context expanded to include unsigned-32-bit rollover
considerations.

---

# Deterministic analysis and LLM analysis

TACS intentionally combines two different kinds of analysis.

## Deterministic stages

These include activities such as:

* source enumeration,
* metrics,
* typedef / time-type discovery,
* rule matching,
* candidate discovery (including define and arithmetic scanners),
* candidate identity and de-duplication,
* I/O heuristics,
* function extraction.

They are intended to be reproducible for the same source and configuration.

## LLM stages

LLMs are used when broader semantic reasoning is useful, such as determining
whether:

```c
return base + delta;
```

represents dangerous epoch arithmetic or harmless relative-duration arithmetic.

LLM use is optional.

The default for `tacs scan`:

```text
--llm none
```

performs deterministic discovery without sending source code to an external
model.

When an LLM is enabled, source context may be sent to the configured provider.
See [privacy.md](privacy.md) for the data-handling implications.

---

# Why the pipeline is progressive

The pipeline deliberately does not begin by sending entire repositories to an
LLM.

Instead it moves through increasing levels of context:

```text
candidate site
     │
     ▼
complete function
     │
     ▼
targeted file-local typedef / macro / type context
     │
     ▼
file-leading lines + extracted definitions
```

TACS is designed to increase context progressively. In v0.1.0, the
function-first path starts with the complete function, then extracts requested
definitions and context from that function’s source file, and finally escalates
unresolved cases to file-leading context plus extracted definitions. That is
the current implementation of the progressive-context idea; it is not yet a
cross-header or whole-repository enrichment engine.

This design has several benefits:

* deterministic discovery remains available without an LLM,
* fewer tokens are required,
* external source disclosure is reduced,
* reasoning stays focused,
* ambiguous cases can abstain rather than being guessed (until the final
  escalation, which strongly prefers a decisive answer),
* the scanner retains a traceable connection between the original candidate
  and later conclusions.

The goal is therefore not:

> “Ask an LLM whether this repository has Y2038 bugs.”

It is closer to:

> “Systematically discover the code that can participate in time-representation
> risk, provide the environment and progressively necessary context, and ask
> for semantic judgment only where it adds value.”

---

# Current v0.1.0 boundaries

The current release should be understood within these limitations:

* C and C++ are the primary source languages.
* Full tree-sitter AST analysis is not implemented yet.
* Stage 4 structural filtering is a no-op without tree-sitter, and only
  heuristic even when tree-sitter is importable.
* Stage 7 line triage exists only on the legacy (`--no-function-first`) path.
* Scanning is preprocessor-agnostic; guarded or inactive code may still appear
  as candidates.
* Environment auto-detection is experimental; `tacs scan` may run without an
  `--env-config`.
* False positives and false negatives are expected.
* LLM results vary by model and provider.
* A `yes` result still requires human review.
* A `no` result is not proof that no rollover problem exists elsewhere.
* No findings does not prove that the system is time-safe.
* Y2106 analysis is disabled unless explicitly requested.

For deferred improvements, see [backlog.md](backlog.md).

For command-line usage, see
[usage/RUNNING_FULL_PIPELINE.md](usage/RUNNING_FULL_PIPELINE.md).

For installation and a first scan, see
[../QUICK_START.md](../QUICK_START.md).

For environment configuration, see [env_config.md](env_config.md).

For privacy and source-retention behavior, see [privacy.md](privacy.md).
