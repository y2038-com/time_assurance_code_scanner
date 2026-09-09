# Security Policy

## Supported versions

This project is under active development. Security fixes are applied on the
default branch (`main`) of
[time_assurance_code_scanner](https://github.com/y2038-com/time_assurance_code_scanner).
Please test against the latest `main` before reporting.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Prefer one of these private channels:

1. **GitHub private vulnerability reporting** (preferred when enabled):
   Repository → **Security** → **Advisories** → **Report a vulnerability**
   https://github.com/y2038-com/time_assurance_code_scanner/security/advisories/new
2. If private reporting is unavailable, contact the maintainers via a **private**
   GitHub channel and wait for acknowledgment before any public discussion.

Include enough detail to reproduce the issue (affected version/commit, steps,
impact). We will aim to acknowledge reports promptly and coordinate disclosure.

## What is in scope

Examples of issues we want reported privately:

- Secret or credential leakage (logs, reports, error messages, committed files)
- Unsafe handling of local paths, clones, or subprocess invocation
- Prompt-injection or output-handling bugs that could escalate beyond “bad
  finding text” (for example writing outside intended output paths)
- Dependency vulnerabilities with a realistic exploit path in this project

## What is out of scope

Please use normal issues (not a security advisory) for:

- LLM **false positives / false negatives** or disagreement with a finding
- Weak or incorrect **experimental** ABI/config auto-detection
- Model quality, cost, or provider availability
- Missing features, documentation typos, or general product feedback
- “The scanner sent my source to my configured LLM provider” — that is
  expected BYOLLM behavior when `--llm` is not `none`

## Operational notes

- Never commit `.env`, API keys, or private source trees used as scan inputs.
- Treat scan reports as potentially sensitive if the source tree was.
