from __future__ import annotations

import sys
import click
from pathlib import Path
from typing import List
from tacs.core.status_logger import StatusLogger
from tacs.core.pipeline import ScanningPipeline
from tacs.llm.env import (
    DEFAULT_LOCAL_HOST,
    default_llm_type,
    default_model_id,
    ollama_api_key,
    ollama_host,
    ollama_is_cloud_host,
)


def _default_llm() -> str:
    value = default_llm_type()
    allowed = {"none", "ollama", "openai", "anthropic", "gemini"}
    return value if value in allowed else "none"


def _default_model() -> str:
    return default_model_id()


@click.command("scan")
# Required options first
@click.option('--root', required=True, help='Root directory to scan (required)')
@click.option('--rules', required=True, help='Rules JSON file path (required)')
# Optional options in alphabetical order
@click.option('--allow-raw-code-logging', is_flag=True, default=False, help='Allow raw code snippets in logs (default: disabled)')
@click.option('--batch-size-func', type=int, default=15, help='Batch size for function analysis (default: 15)')
@click.option('--batch-size-stage1', type=int, default=100, help='Batch size for Stage S1 line-level analysis (default: 100)')
@click.option('--batch-size-stage2', type=int, default=40, help='Batch size for Stage S2 function-level widened context (default: 40)')
@click.option('--batch-size-stage3', type=int, default=20, help='Batch size for Stage S3 file-level context (default: 20)')
@click.option('--bypass-stage1', is_flag=True, default=False, help='Bypass Stage S1, send all candidates to Stage S2 (default: disabled)')
@click.option('--bypass-stage3', is_flag=True, default=False, help='Bypass Stage S3, stop after Stage S2 (default: disabled)')
@click.option('--confidence-floor', type=float, default=0.85, help='Confidence threshold/floor for decisions (default: 0.85)')
@click.option('--debug-candidates', is_flag=True, default=False, help='Show sample candidates sent to LLM (default: disabled)')
@click.option('--debug-llm-raw', is_flag=True, default=False, help='Show raw LLM input/output for debugging (default: disabled)')
@click.option('--debug-stage2', is_flag=True, default=False, help='Enable detailed Stage S2 debugging (default: disabled)')
@click.option('--debug-stage2-detailed', is_flag=True, default=False, help='Show ALL candidates and LLM responses for Stage S2 (default: disabled)')
@click.option('--debug-stage2-prompt', is_flag=True, default=False, help='Show complete LLM Stage S2 prompt for debugging (default: disabled)')
@click.option('--detect-y2106', is_flag=True, default=False, help='Enable Y2106 detection for 32-bit unsigned time_t overflow in 2106 (default: disabled)')
@click.option('--disable-stage1', is_flag=True, default=False, help='Disable Stage S1 line-level pre-filter (default: enabled)')
@click.option('--env-config', help='Environment configuration JSON file path (optional)')
@click.option('--exclude', multiple=True, default=['**/tests/**'], help='Exclude glob patterns (default: **/tests/**)')
@click.option('--include-no-findings', is_flag=True, default=False, help='Include findings classified as NO (safe) in output (default: disabled)')
@click.option('--function-first/--no-function-first', default=True, help='Use function-first pipeline (default: enabled)')
@click.option('--include', multiple=True, default=['**/*.c', '**/*.h'], help='Include glob patterns (default: **/*.c, **/*.h)')
@click.option('--io-analysis/--no-io-analysis', default=True, help='Enable I/O-boundary analysis (default: enabled)')
@click.option('--io-score-threshold', type=float, default=6.0, help='Minimum score for I/O-boundary candidates (default: 6.0)')
@click.option('--io-check-literal-widths/--no-io-check-literal-widths', default=True, help='Check for suspicious literal widths (4/8) in I/O operations (default: enabled)')
@click.option('--log-dir', default='results/llm_logs', help='LLM log directory (default: results/llm_logs)')
@click.option('--migration-mode', is_flag=True, default=False, help='Enable migration analysis mode (default: disabled)')
@click.option('--migration-from', help='Source config JSON file for migration (required if --migration-mode)')
@click.option('--migration-to', help='Target config JSON file for migration (required if --migration-mode)')
@click.option('--log-llm', is_flag=True, default=False, help='Enable LLM logging (default: disabled)')
@click.option(
    '--llm',
    type=click.Choice(['none', 'ollama', 'openai', 'anthropic', 'gemini']),
    default=_default_llm,
    show_default=True,
    help='LLM provider (default: none — set --llm or TACS_LLM_PROVIDER to opt in)',
)
@click.option('--max-aliases', type=int, default=64, help='Max typedef aliases to discover (default: 64)')
@click.option('--max-function-chars', type=int, default=20000, help='Maximum function characters before splitting (default: 20000)')
@click.option('--max-function-iters', type=int, default=2, help='Maximum iterations per function in Stage S2 Pass P2 (default: 2)')
@click.option('--max-function-lines', type=int, default=10000, help='Maximum function lines before splitting (default: 10000)')
@click.option('--max-macros', type=int, default=64, help='Max macros to discover (default: 64)')
@click.option('--max-typedef-hops', type=int, default=5, help='Max typedef chain hops (default: 5)')
@click.option('--min-risk', type=click.Choice(['low', 'medium', 'high']), default='medium', help='Minimum risk level (default: medium)')
@click.option(
    '--model',
    default=_default_model,
    show_default=True,
    help='Model name for selected provider (default: gpt-oss:120b-cloud or TACS_MODEL)',
)
@click.option('--no-enable-discovery', is_flag=True, default=False, help='Disable typedef/macro discovery (default: enabled)')
@click.option('--out', default='findings.json', help='Output file path (default: findings.json)')
@click.option('--redact-prompts/--no-redact-prompts', default=True, help='Redact prompts in logs (default: enabled)')
@click.option('--timeout-sec', type=int, default=300, help='Timeout in seconds (default: 300)')
@click.option('--token-budget', type=int, default=250000, help='Token budget per scan (default: 250000)')
def main(
    root: str,
    rules: str,
    include: List[str],
    exclude: List[str],
    include_no_findings: bool,
    min_risk: str,
    confidence_floor: float,
    llm: str,
    model: str,
    batch_size_stage1: int,
    timeout_sec: int,
    out: str,
    log_llm: bool,
    log_dir: str,
    redact_prompts: bool,
    no_enable_discovery: bool,
    max_typedef_hops: int,
    max_aliases: int,
    max_macros: int,
    allow_raw_code_logging: bool,
    batch_size_stage2: int,
    batch_size_stage3: int,
    token_budget: int,
    env_config: str,
    debug_stage2: bool,
    debug_candidates: bool,
    debug_stage2_detailed: bool,
    debug_llm_raw: bool,
    debug_stage2_prompt: bool,
    bypass_stage1: bool,
    bypass_stage3: bool,
    function_first: bool,
    disable_stage1: bool,
    detect_y2106: bool,
    max_function_iters: int,
    batch_size_func: int,
    max_function_lines: int,
    max_function_chars: int,
    io_analysis: bool,
    io_score_threshold: float,
    io_check_literal_widths: bool,
    migration_mode: bool,
    migration_from: str,
    migration_to: str
):
    """Time Assurance Code Scanner (single-repo scan) with LLM-assisted analysis."""
    
    # Validate inputs
    root_path = Path(root)
    if not root_path.exists():
        StatusLogger.timestamped_error(f"Root directory does not exist: {root}")
        sys.exit(1)
    
    rules_path = Path(rules)
    if not rules_path.exists():
        StatusLogger.timestamped_error(f"Rules file does not exist: {rules}")
        sys.exit(1)
    
    # Check LLM configuration
    if llm == "ollama":
        host = ollama_host()
        if ollama_is_cloud_host(host):
            if ollama_api_key():
                StatusLogger.timestamped_info(f"Using Ollama Cloud ({host}) with API key")
            else:
                StatusLogger.timestamped_warning(
                    "Ollama Cloud selected but OLLAMA_API_KEY is unset "
                    f"(legacy: OLLAMA_CLOUD_TOKEN). Local daemon: OLLAMA_HOST={DEFAULT_LOCAL_HOST}"
                )
        else:
            StatusLogger.timestamped_info(f"Using local Ollama at {host}")
    elif llm in {"openai", "anthropic", "gemini"}:
        StatusLogger.timestamped_info(f"Using {llm} provider")
    
    # Find the scanner script
    scanner_path = Path(__file__).parent / "python" / "y2038scan_fast_json_group.py"
    if not scanner_path.exists():
        StatusLogger.timestamped_error(f"Scanner script not found: {scanner_path}")
        sys.exit(1)
    
    try:
        # Initialize pipeline
        pipeline = ScanningPipeline(
            scanner_path=str(scanner_path),
            llm_type=llm,
            model=model,
            confidence_floor=confidence_floor,
            batch_size_pass1=batch_size_stage1,
            timeout_sec=timeout_sec,
            enable_discovery=not no_enable_discovery,
            max_typedef_hops=max_typedef_hops,
            max_aliases=max_aliases,
            max_macros=max_macros,
            enable_llm_logging=log_llm,
            redact_prompts=redact_prompts,
            allow_raw_code_logging=allow_raw_code_logging,
            batch_size_pass2=batch_size_stage2,
            batch_size_pass3=batch_size_stage3,
            token_budget=token_budget,
            environment_config_path=env_config,
            debug_pass2=debug_stage2,
            debug_candidates=debug_candidates,
            debug_pass2_detailed=debug_stage2_detailed,
            debug_llm_raw=debug_llm_raw,
            debug_pass2_prompt=debug_stage2_prompt,
            bypass_pass1=bypass_stage1,
            bypass_pass3=bypass_stage3,
            function_first=function_first,
            enable_pass1=not disable_stage1,  # Stage S1 enabled by default, can be disabled with --disable-stage1
            detect_y2106=detect_y2106,
            max_function_iters=max_function_iters,
            batch_size_func=batch_size_func,
            max_function_lines=max_function_lines,
            max_function_chars=max_function_chars,
            enable_io_analysis=io_analysis,
            io_score_threshold=io_score_threshold,
            io_check_literal_widths=io_check_literal_widths,
            migration_mode=migration_mode,
            migration_from_config_path=migration_from,
            migration_to_config_path=migration_to,
            include_no_findings=include_no_findings,
        )
        
        # Run scan
        results = pipeline.scan(
            root_path=str(root_path),
            rules_path=str(rules_path),
            include_patterns=list(include),
            exclude_patterns=list(exclude),
            min_risk=min_risk
        )
        
        # Save results
        pipeline.save_results(results, out)
        
        # Print summary
        total_findings = len(results.findings)
        yes_findings = len([f for f in results.findings if f.y2038_issue.value == "yes"])
        no_findings = len([f for f in results.findings if f.y2038_issue.value == "no"])
        abstain_findings = len([f for f in results.findings if f.y2038_issue.value == "abstain"])
        
        StatusLogger.timestamped_print(f"Scan complete: {total_findings} findings ({yes_findings} yes, {no_findings} no, {abstain_findings} abstain)")
        StatusLogger.timestamped_print(f"Results saved to: {out}")
        
        # Print intermediate results location
        if hasattr(pipeline, 'session') and pipeline.session:
            StatusLogger.timestamped_print(f"Intermediate results saved to: {pipeline.session.scan_folder}")
            StatusLogger.timestamped_print(f"  - Discovered rules: prescan/discovered_rules.json")
            StatusLogger.timestamped_print(f"  - All candidates: ir/candidates.jsonl")
            StatusLogger.timestamped_print(f"  - Function batches: llm/stage_8_pass_2a/batches/, llm/stage_8_pass_2b/batches/, llm/stage_9_pass_1/batches/")
        
    except Exception as e:
        StatusLogger.timestamped_error(f"Scan failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
