#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""CLI interface for the configuration detector."""

import argparse
import sys
import json
from pathlib import Path

# Handle both module and direct script execution
try:
    from .detector import ConfigDetector
    from .hybrid_detector import HybridConfigDetector
except ImportError:
    # If running as script directly, add parent to path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from config_detector.detector import ConfigDetector
    from config_detector.hybrid_detector import HybridConfigDetector


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Auto-detect environment configuration likelihoods from build systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (human-readable output, keyword-based only)
  python -m config_detector.cli /path/to/project

  # JSON output
  python -m config_detector.cli /path/to/project --format json

  # Enable LLM analysis (hybrid approach)
  python -m config_detector.cli /path/to/project --llm ollama --model qwen3-coder:480b-cloud

  # Force LLM analysis even if confidence is high
  python -m config_detector.cli /path/to/project --llm ollama --force-llm

  # Keyword-only (no LLM)
  python -m config_detector.cli /path/to/project --keyword-only

  # Non-interactive mode (auto-accept if high confidence)
  python -m config_detector.cli /path/to/project --llm ollama --non-interactive

  # Save to file
  python -m config_detector.cli /path/to/project --out results/config_likelihoods.json

  # Verbose output (show all evidence)
  python -m config_detector.cli /path/to/project --verbose
        """
    )
    
    parser.add_argument(
        'project_path',
        type=str,
        help='Path to the project root directory'
    )
    
    parser.add_argument(
        '--format',
        choices=['human', 'json'],
        default='human',
        help='Output format (default: human)'
    )
    
    parser.add_argument(
        '--out',
        type=str,
        help='Output file path (if not specified, prints to stdout)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed evidence and reasoning'
    )
    
    # LLM options
    parser.add_argument(
        '--llm',
        choices=['none', 'ollama'],
        default='none',
        help='LLM type to use for analysis (default: none, keyword-based only)'
    )
    
    parser.add_argument(
        '--model',
        type=str,
        default='gpt-oss:120b-cloud',
        help='LLM model name (default: gpt-oss:120b-cloud)'
    )
    
    parser.add_argument(
        '--llm-timeout',
        type=int,
        default=60,
        help='LLM request timeout in seconds (default: 60)'
    )
    
    parser.add_argument(
        '--confidence-threshold',
        type=float,
        default=0.7,
        help='Confidence threshold for triggering LLM analysis (default: 0.7)'
    )
    
    parser.add_argument(
        '--force-llm',
        action='store_true',
        help='Force LLM analysis even if confidence is high'
    )
    
    parser.add_argument(
        '--keyword-only',
        action='store_true',
        help='Only use keyword-based detection (no LLM)'
    )
    
    parser.add_argument(
        '--non-interactive',
        action='store_true',
        help='Non-interactive mode: auto-accept if high confidence, abort if low'
    )
    
    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable caching of LLM results'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output (show LLM prompts/responses)'
    )
    
    args = parser.parse_args()
    
    # Validate project path
    project_path = Path(args.project_path)
    if not project_path.exists():
        print(f"Error: Project path does not exist: {project_path}", file=sys.stderr)
        sys.exit(1)
    
    if not project_path.is_dir():
        print(f"Error: Project path is not a directory: {project_path}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Determine which detector to use
        use_hybrid = args.llm != 'none' and not args.keyword_only
        
        if use_hybrid:
            # Use hybrid detector
            detector = HybridConfigDetector(
                root_path=project_path,
                llm_type=args.llm,
                llm_model=args.model,
                llm_timeout=args.llm_timeout,
                confidence_threshold=args.confidence_threshold,
                use_cache=not args.no_cache,
                debug=args.debug or args.verbose
            )
            
            # Run hybrid detection
            results = detector.detect(
                force_llm=args.force_llm,
                keyword_only=args.keyword_only
            )
            
            # Handle user review if interactive
            if not args.non_interactive and results.get('llm_results'):
                results = _review_results(results, args)
            
            # Format output
            output = _format_hybrid_results(results, project_path, args.format, args.verbose)
        else:
            # Use keyword-based detector only
            detector = ConfigDetector(project_path)
            results = detector.detect()
            output = detector.format_results(results, format_type=args.format)
        
        # Output results
        if args.out:
            output_path = Path(args.out)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # If we have a final_config, save it as JSON (scanner expects pure JSON config)
            # Otherwise, save the formatted output
            final_config = results.get('final_config')
            if final_config:
                # Save the final_config as JSON (what the scanner expects)
                output_path.write_text(json.dumps(final_config, indent=2), encoding='utf-8')
                print(f"Configuration saved to: {output_path}")
            elif args.format == 'json':
                # Save full results as JSON
                output_path.write_text(output, encoding='utf-8')
                print(f"Results saved to: {output_path}")
            else:
                # Save human-readable format
                output_path.write_text(output, encoding='utf-8')
                print(f"Results saved to: {output_path}")
        else:
            print(output)
        
        # Exit code based on whether detection was successful
        if use_hybrid:
            build_files_found = len(detector._collect_build_files()) if hasattr(detector, '_collect_build_files') else 0
        else:
            build_files_found = results.get('extracted_info', {}).get('build_files_found', 0)
        
        if build_files_found == 0:
            print("\nWarning: No build files found. Detection may be inaccurate.", file=sys.stderr)
            sys.exit(1)
        
        sys.exit(0)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose or args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _review_results(results: dict, args: argparse.Namespace) -> dict:
    """Interactive review of detection results."""
    print("\n" + "="*70)
    print("PHASE 1: Keyword-Based Configuration Detection")
    print("="*70)
    
    keyword_results = results.get('keyword_results', {})
    confidence = results.get('confidence', {})
    
    # Display keyword-based results
    print("\nDetected Configuration (Keyword-Based):")
    _display_config_summary(keyword_results, confidence)
    
    # Check if LLM was used
    if results.get('llm_results'):
        print("\n" + "="*70)
        print("PHASE 2: LLM-Based Configuration Analysis")
        print("="*70)
        
        llm_results = results['llm_results']
        llm_config = llm_results.get('config', {})
        llm_confidence = llm_results.get('confidence', {})
        llm_reasoning = llm_results.get('reasoning', {})
        
        print("\nLLM-Detected Configuration:")
        _display_llm_config(llm_config, llm_confidence, llm_reasoning)
        
        # Show differences
        _show_differences(keyword_results, llm_config)
    
    # Final config
    final_config = results.get('final_config')
    if final_config:
        print("\n" + "="*70)
        print("FINAL CONFIGURATION (Combined)")
        print("="*70)
        _display_config_dict(final_config)
    
    # User options
    if not args.non_interactive:
        print("\nOptions:")
        print("  [a] Accept this configuration")
        print("  [s] Show full details")
        print("  [q] Quit without saving")
        
        choice = input("\nYour choice [a]: ").lower().strip() or 'a'
        
        if choice == 'q':
            print("Aborted by user.")
            sys.exit(0)
        elif choice == 's':
            print("\nFull Results:")
            print(json.dumps(results, indent=2, default=str))
    
    return results


def _display_config_summary(keyword_results: dict, confidence: dict):
    """Display summary of keyword-based detection."""
    arch = keyword_results.get('architecture', 'Unknown')
    arch_conf = confidence.get('hardware_model', 0.0)
    time_t_size = keyword_results.get('time_t_size', 'Unknown')
    time_t_conf = confidence.get('time_t_size_bits', 0.0)
    
    print(f"  Architecture: {arch} (confidence: {arch_conf:.2f})")
    print(f"  time_t size: {time_t_size} bits (confidence: {time_t_conf:.2f})")
    print(f"  Other fields: Low confidence (not detected by keyword-based)")


def _display_llm_config(config: dict, confidence: dict, reasoning: dict):
    """Display LLM-detected configuration."""
    for field, value in config.items():
        conf = confidence.get(field, 0.0)
        reason = reasoning.get(field, '')
        print(f"  {field}: {value} (confidence: {conf:.2f})")
        if reason:
            print(f"    Reasoning: {reason}")


def _show_differences(keyword_results: dict, llm_config: dict):
    """Show differences between keyword-based and LLM results."""
    differences = []
    
    if keyword_results.get('architecture') and llm_config.get('hardware_model'):
        if keyword_results['architecture'] != llm_config['hardware_model']:
            differences.append((
                'hardware_model',
                keyword_results['architecture'],
                llm_config['hardware_model']
            ))
    
    if keyword_results.get('time_t_size') and llm_config.get('time_t_size_bits'):
        if keyword_results['time_t_size'] != llm_config['time_t_size_bits']:
            differences.append((
                'time_t_size_bits',
                keyword_results['time_t_size'],
                llm_config['time_t_size_bits']
            ))
    
    if differences:
        print("\nDifferences from keyword-based detection:")
        for field, keyword_val, llm_val in differences:
            print(f"  {field}:")
            print(f"    Keyword-based: {keyword_val}")
            print(f"    LLM: {llm_val}")


def _display_config_dict(config: dict):
    """Display a configuration dictionary."""
    for key, value in config.items():
        print(f"  {key}: {value}")


def _format_hybrid_results(results: dict, project_path: Path, format_type: str, verbose: bool) -> str:
    """Format hybrid detection results for output."""
    if format_type == 'json':
        return json.dumps(results, indent=2, default=str)
    else:
        # Human-readable format
        lines = []
        lines.append("Configuration Detection Results")
        lines.append("=" * 50)
        lines.append("")
        lines.append(f"Project: {project_path}")
        lines.append(f"Method: {results.get('method', 'unknown')}")
        lines.append("")
        
        # Show likelihoods from keyword results
        keyword_results = results.get('keyword_results', {})
        if keyword_results.get('likelihoods'):
            lines.append("Likelihood Scores (from keyword-based detection):")
            for likelihood in keyword_results['likelihoods']:
                if hasattr(likelihood, 'name'):
                    # ConfigurationLikelihood object
                    symbol = "✓" if likelihood.likelihood > 0.7 else "⚠" if likelihood.likelihood > 0.3 else "○"
                    lines.append(f"  {symbol} {likelihood.name:25s} {int(likelihood.likelihood * 100):>3d}%")
                else:
                    # Dictionary
                    name = likelihood.get('name', 'unknown')
                    likelihood_val = likelihood.get('likelihood', 0.0)
                    symbol = "✓" if likelihood_val > 0.7 else "⚠" if likelihood_val > 0.3 else "○"
                    lines.append(f"  {symbol} {name:25s} {int(likelihood_val * 100):>3d}%")
            lines.append("")
        
        # Show LLM results if available
        llm_results = results.get('llm_results')
        if llm_results:
            lines.append("LLM Analysis Results:")
            llm_config = llm_results.get('config', {})
            for key, value in llm_config.items():
                lines.append(f"  {key}: {value}")
            lines.append("")
        
        # Show final config if available
        final_config = results.get('final_config')
        if final_config:
            lines.append("Final Configuration (Combined):")
            for key, value in final_config.items():
                lines.append(f"  {key}: {value}")
        
        return "\n".join(lines)


if __name__ == '__main__':
    main()
