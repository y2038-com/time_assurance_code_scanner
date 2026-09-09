# Privacy

`tacs` does not operate a hosted document/code store. Artifacts are written only
where you configure (`--out`, batch output directories, optional LLM logs).

When `--llm` is anything other than `none`, **source snippets and prompts are
sent to that provider** (Ollama Cloud, local Ollama, OpenAI, Anthropic, Gemini,
etc.). Use `--llm none` or a local Ollama daemon for sensitive codebases.

Do not commit `.env` files or scan outputs that may contain proprietary source.
