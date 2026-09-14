"""Time Assurance Code Scanner (`tacs`) — CLI entrypoint."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from tacs import __version__
from tacs.llm.env import DEFAULT_MODEL, default_llm_type, default_model_id, load_dotenv

# Load local `.env` before Click resolves option defaults / provider checks.
load_dotenv()


def _cli_default_llm() -> str:
    value = default_llm_type()
    allowed = {"none", "ollama", "openai", "anthropic", "gemini"}
    return value if value in allowed else "none"


def _cli_default_model() -> str:
    return default_model_id() or DEFAULT_MODEL


@click.group()
@click.version_option(__version__, prog_name="tacs")
def app() -> None:
    """Time Assurance Code Scanner — long-horizon time risks in source code."""


@app.command("version")
def version_cmd() -> None:
    """Print the package version."""
    click.echo(f"tacs {__version__}")


# Primary single-repo scan (Click command defined in scan_command.py)
from tacs.scan_command import main as scan_main  # noqa: E402

app.add_command(scan_main, name="scan")


@app.command(
    "repos",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.pass_context
def repos_cmd(ctx: click.Context) -> None:
    """Batch-scan git repositories from a JSONL list (see ``tacs repos --help`` via argparse)."""
    from tacs.batch_scan_repos import main as batch_main

    # Forward all remaining args to the argparse entrypoint.
    # Example: tacs repos --repos-file fixtures/repos.jsonl --dry-run
    argv = list(ctx.args)
    if not argv or argv[0] in {"-h", "--help"}:
        # Force argparse help when no args / help requested through click.
        raise SystemExit(batch_main(["--help"] if not argv else argv))
    raise SystemExit(batch_main(argv))


@app.command(
    "render",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.pass_context
def render_cmd(ctx: click.Context) -> None:
    """Render findings.json (or a batch run directory) to text/HTML."""
    from tacs.batch_render_reports import main as render_main

    argv = list(ctx.args)
    if not argv or argv[0] in {"-h", "--help"}:
        raise SystemExit(render_main(["--help"] if not argv else argv))
    raise SystemExit(render_main(argv))


@app.command("detect")
@click.argument("project_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--llm/--no-llm", default=False, help="Enable experimental LLM-assisted detection")
@click.option(
    "--model",
    default=_cli_default_model,
    show_default=True,
    help="LLM model when --llm is set",
)
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default="json", show_default=True)
@click.option("--out", type=click.Path(path_type=Path), default=None, help="Optional output file")
def detect_cmd(project_path: Path, llm: bool, model: str, fmt: str, out: Path | None) -> None:
    """Experimental: guess which of the 8 ABI/time_t configs a project uses.

    Prefer an explicit ``--env-config`` / config_id for production scans.
    Auto-detect is best-effort and often low-confidence.
    """
    from config_detector.likelihoods import ConfigDetectionError, detect_config_likelihoods

    click.echo(
        "NOTE: config auto-detect is experimental; prefer explicit env_config when known.",
        err=True,
    )
    try:
        result = detect_config_likelihoods(project_path, use_llm=llm, llm_model=model)
    except ConfigDetectionError as exc:
        click.echo(f"detect failed: {exc}", err=True)
        raise SystemExit(1) from exc

    if fmt == "json":
        payload = json.dumps(result, indent=2)
    else:
        lines = [
            f"overall_confidence={result.get('overall_confidence')}",
            f"recommended_config_id={result.get('recommended_config_id')}",
            "likelihoods:",
        ]
        for item in result.get("likelihoods", []):
            lines.append(
                f"  {item.get('config_id')}: {item.get('likelihood'):.3f} ({item.get('confidence')})"
            )
        payload = "\n".join(lines)

    if out:
        out.write_text(payload + ("\n" if not payload.endswith("\n") else ""), encoding="utf-8")
        click.echo(str(out))
    else:
        click.echo(payload)


def main(argv: list[str] | None = None) -> None:
    """Console-script entrypoint."""
    app.main(args=argv, prog_name="tacs")


if __name__ == "__main__":
    main(sys.argv[1:])
