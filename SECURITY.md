# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest tagged release | Yes |
| `main` | Yes, as the development branch |
| Older tagged releases | No |

Security fixes are developed on `main`. A fix for a supported release may appear
as a new tagged release rather than a change to an existing artifact.

Reproducing against the latest tagged release or `main` is helpful. Do not delay
a report if you cannot do that.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Use one of these private channels, in order:

1. [GitHub private vulnerability reporting](https://github.com/y2038-com/time_assurance_code_scanner/security/advisories/new)
   (requires a GitHub sign-in)
2. Email fallback: [security@y2038.com](mailto:security@y2038.com)

Use email when you cannot use GitHub private reporting.

Do not send API keys, credentials, private source trees, proprietary code, or
other sensitive material unless it is necessary and arrangements have been made.

## What to include

Useful reports typically include:

- Affected release, commit, or branch
- Description of the issue and expected security impact
- Reproduction steps or a minimal proof of concept
- Platform, language, and relevant scanner configuration
- Whether the issue is already public
- Suggested mitigation, if known

Do not delay a report merely because every item is unavailable.

## What is in scope

Examples of issues we want reported privately:

- Credential or secret leakage through reports, logs, errors, or committed files
- Unsafe handling of local paths or output paths
- Unsafe repository cloning or checkout behavior
- Unsafe subprocess or command invocation
- Prompt injection or model-output handling that crosses a security boundary
  (for example writing outside intended output paths)
- Dependency vulnerabilities with a realistic exploit path in this project

Ordinary model mistakes (incorrect findings, missed issues, or poor wording)
are not security vulnerabilities. See [What is out of scope](#what-is-out-of-scope).

### Prompt role separation is best-effort

TACS sends its auditor instructions in the provider's trusted channel and sends
scanned repository content, environment facts and migration facts in the
untrusted user channel, labelled as data. Where a provider has no distinct
field, the nearest one is used: the Ollama `/api/generate` request carries the
instructions in `system` and the analysis data in `prompt`.

This is defence in depth, not an injection-proof boundary. A model may still
act on text it was told to treat as data, so a scanned repository can still
influence a verdict. Treat findings from an untrusted tree accordingly. A report
is in scope when the separation is not applied — for instance when repository
content reaches the trusted channel — rather than when a model simply follows
text that was correctly placed in the untrusted one.

## What is out of scope

Please use normal GitHub issues (not a security advisory) for:

- LLM **false positives / false negatives** or disagreement with a finding
- Weak or incorrect **experimental** ABI or configuration detection
- Model quality, cost, or provider availability
- Missing features, documentation typos, or general product feedback
- Expected transmission of source code to the configured LLM provider when
  `--llm` is not `none`. That is intended BYOLLM behavior.
  See [docs/privacy.md](docs/privacy.md).

With `--llm none`, TACS does not send source to an LLM provider.

## Disclosure and response

Maintainers will aim to:

- Acknowledge reports promptly
- Assess severity and affected versions
- Coordinate remediation and disclosure
- Credit reporters when requested and appropriate

Please allow reasonable time for investigation and remediation before public
disclosure. This project does not publish a response SLA, embargo period, bounty,
or legal safe-harbor statement.

## Operational notes

- Never commit `.env`, API keys, or private source trees used as scan inputs.
  Prefer keeping private inputs under `inputs/` and generated artifacts under
  `results/` (both gitignored except short READMEs).
- Treat scan reports as potentially sensitive if the source tree was.
- `tacs scan` reads the tree you pass with `--root` in place. `tacs repos`
  clones repositories into `--cache-dir` (default `.repo_cache`) and keeps them
  for reuse until you delete that directory. Put the cache on appropriate
  storage for private repositories and remove it when finished.
- A `repo_url` that embeds credentials is rejected and skipped. Prefer a git
  credential helper or an SSH remote. Credential-bearing URLs that still reach
  a log line or error message are redacted before printing or writing. Details:
  [docs/privacy.md](docs/privacy.md).
- Enabling debug logging in HTTP client or transport libraries may expose
  sensitive request data when an LLM provider is used. Prefer `--llm none` or
  local Ollama for sensitive trees.
