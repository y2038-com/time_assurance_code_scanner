# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from tacs.core.schema import (
    Candidate, Finding, LLMResponse, ScanResults, ScanMetadata, Metrics,
    Y2038Issue, SeverityLevel, IOCandidate
)
from tacs.core.metrics import calculate_metrics
from tacs.core.path_utils import repo_relative_path
from tacs.core.discovery_manager import DiscoveryManager
from tacs.core.ir_adapter import IRAdapter
from tacs.core.struct_filter import StructuralFilter
from tacs.core.status_logger import StatusLogger
from tacs.core.scan_session import ScanSession
from tacs.core.function_schemas import FunctionBody, FunctionAnalysis
from tacs.llm.env import DEFAULT_MODEL
from tacs.llm.factory import create_llm_client
from tacs import __version__ as TACS_VERSION


def _format_count(n: int, singular: str, plural: str | None = None) -> str:
    """Return ``N noun`` with simple English singular/plural."""
    word = singular if n == 1 else (plural if plural is not None else f"{singular}s")
    return f"{n} {word}"


class ScanningPipeline:
    """Orchestrates the scanning pipeline from metrics to final findings."""
    
    def __init__(
        self,
        scanner_path: str,
        llm_type: str = "none",
        model: str = DEFAULT_MODEL,
        confidence_floor: float = 0.85,
        batch_size_pass1: int = 100,
        timeout_sec: int = 300,
        enable_discovery: bool = True,
        max_typedef_hops: int = 5,
        max_aliases: int = 64,
        max_macros: int = 64,
        enable_llm_logging: bool = False,
        redact_prompts: bool = True,
        allow_raw_code_logging: bool = False,
        batch_size_pass2: int = 40,
        batch_size_pass3: int = 20,
        token_budget: int = 250000,
        environment_config_path: Optional[str] = None,
        debug_pass2: bool = False,
        debug_candidates: bool = False,
        debug_pass2_detailed: bool = False,
        debug_llm_raw: bool = False,
        debug_pass2_prompt: bool = False,
        bypass_pass1: bool = False,
        bypass_pass3: bool = False,
        function_first: bool = True,
        enable_pass1: bool = True,
        detect_y2106: bool = False,
        max_function_iters: int = 2,
        batch_size_func: int = 15,
        max_function_lines: int = 10000,
        max_function_chars: int = 20000,
        enable_io_analysis: bool = True,
        io_score_threshold: float = 6.0,
        io_check_literal_widths: bool = True,
        migration_mode: bool = False,
        migration_from_config_path: Optional[str] = None,
        migration_to_config_path: Optional[str] = None,
        include_no_findings: bool = False,
    ):
        """
        Initialize the scanning pipeline.
        
        Args:
            scanner_path: Path to the fast scanner script
            llm_type: Type of LLM to use (none, ollama)
            model: Model name to use
            confidence_floor: Minimum confidence threshold
            batch_size_pass1: Batch size for Stage S1 (line-level analysis)
            timeout_sec: Timeout for operations
        """
        self.scanner_path = scanner_path
        self.llm_type = llm_type
        self.model = model
        self.confidence_floor = confidence_floor
        self.batch_size_pass1 = batch_size_pass1
        self.timeout_sec = timeout_sec
        self.enable_discovery = enable_discovery
        self.enable_llm_logging = enable_llm_logging
        self.redact_prompts = redact_prompts
        self.allow_raw_code_logging = allow_raw_code_logging
        self.batch_size_pass2 = batch_size_pass2
        self.batch_size_pass3 = batch_size_pass3
        self.token_budget = token_budget
        self.environment_config_path = environment_config_path
        self.debug_pass2 = debug_pass2
        self.debug_candidates = debug_candidates
        self.debug_pass2_detailed = debug_pass2_detailed
        self.debug_llm_raw = debug_llm_raw
        self.debug_pass2_prompt = debug_pass2_prompt
        self.bypass_pass1 = bypass_pass1
        self.bypass_pass3 = bypass_pass3
        self.function_first = function_first
        self.enable_pass1 = enable_pass1
        self.detect_y2106 = detect_y2106
        self.max_function_iters = max_function_iters
        self.batch_size_func = batch_size_func
        self.max_function_lines = max_function_lines
        self.max_function_chars = max_function_chars
        
        # I/O analysis options
        self.enable_io_analysis = enable_io_analysis
        self.io_score_threshold = io_score_threshold
        self.io_check_literal_widths = io_check_literal_widths
        self.io_score_weights = None  # Use defaults
        
        # Load environment configuration
        self.environment_config = self._load_environment_config()
        
        # Validate and normalize config
        if self.environment_config:
            from tacs.core.config_validator import ConfigValidator
            is_valid, config_id, error = ConfigValidator.validate_config(self.environment_config)
            if is_valid and config_id:
                self.environment_config['config_id'] = config_id
                StatusLogger.timestamped_print(f"Validated config: {config_id}")
            elif error:
                StatusLogger.timestamped_warning(f"Config validation warning: {error}")
        
        # Scan root, set by scan(). Persisted source identifiers and diagnostics are
        # named relative to it so they do not carry the host filesystem layout.
        self.root_path: Optional[str] = None

        # Migration mode
        self.migration_mode = migration_mode
        self.include_no_findings = include_no_findings
        # Y2038 classification counts from the last scan, taken before output
        # filtering drops safe ("no") findings. Summary lines and the batch runner
        # read this so a dropped "no" is not reported as a "no" verdict count.
        self.last_classification_counts: Optional[Dict[str, int]] = None
        self.migration_from_config = None
        self.migration_to_config = None
        
        if migration_mode:
            if not migration_from_config_path or not migration_to_config_path:
                StatusLogger.timestamped_warning("Migration mode enabled but --migration-from and --migration-to not provided")
            else:
                # Load migration configs
                try:
                    with open(migration_from_config_path, 'r', encoding='utf-8') as f:
                        from_config = json.load(f)
                    with open(migration_to_config_path, 'r', encoding='utf-8') as f:
                        to_config = json.load(f)
                    
                    # Validate and normalize
                    from tacs.core.config_validator import ConfigValidator
                    from_valid, from_id, from_error = ConfigValidator.validate_config(from_config)
                    to_valid, to_id, to_error = ConfigValidator.validate_config(to_config)
                    
                    if from_valid and to_valid:
                        self.migration_from_config = ConfigValidator.normalize_config(from_config)
                        self.migration_to_config = ConfigValidator.normalize_config(to_config)
                        StatusLogger.timestamped_print(f"Migration mode: {from_id} → {to_id}")
                    else:
                        StatusLogger.timestamped_error(f"Invalid migration configs: {from_error or to_error}")
                        self.migration_mode = False
                except Exception as e:
                    StatusLogger.timestamped_error(f"Failed to load migration configs: {e}")
                    self.migration_mode = False
        
        # Initialize components
        self.discovery_manager = DiscoveryManager(max_typedef_hops, max_aliases)
        self.ir_adapter = IRAdapter(scanner_path)
        self.struct_filter = StructuralFilter()
        
        # Initialize I/O boundary analyzer (will be updated with aliases after discovery)
        if self.enable_io_analysis:
            from tacs.core.io_boundary_analyzer import IOBoundaryAnalyzer
            self.io_analyzer = IOBoundaryAnalyzer(
                time_t_aliases={},
                time_bearing_symbols=set(),
                environment_config=self.environment_config,
                enable_io_analysis=self.enable_io_analysis,
                score_threshold=self.io_score_threshold,
                check_literal_widths=self.io_check_literal_widths,
                score_weights=self.io_score_weights
            )
        else:
            self.io_analyzer = None
        
        # Metadata mapping for I/O-boundary candidates
        self.io_metadata_map: Dict[str, Dict[str, Any]] = {}
        
        # Metadata mapping for migration risks
        self.migration_metadata: Dict[str, List[Dict[str, Any]]] = {}
        
        # Initialize LLM clients based on approach
        if self.function_first:
            from tacs.core.function_llm_client import FunctionLLMClient
            self.function_llm_client = FunctionLLMClient(
                llm_type, model, self.environment_config, timeout_sec, 
                batch_size_func, confidence_floor, debug_llm_raw
            )
            # Set migration mode configs if enabled
            if self.migration_mode:
                self.function_llm_client.migration_mode = True
                self.function_llm_client.migration_from_config = self.migration_from_config
                self.function_llm_client.migration_to_config = self.migration_to_config
            from tacs.core.function_analyzer import FunctionAnalyzer
            self.function_analyzer = FunctionAnalyzer(
                max_function_lines=max_function_lines,
                max_function_chars=max_function_chars
            )
        else:
            # Legacy pipeline - initialize LLM client for all stages
            self.llm_client = create_llm_client(
                llm_type,
                model,
                environment_config=self.environment_config,
                timeout_sec=timeout_sec,
                batch_size_pass2=batch_size_pass2,
                batch_size_pass3=batch_size_pass3,
                debug_llm_raw=debug_llm_raw,
                debug_pass2_prompt=debug_pass2_prompt,
                time_t_aliases={},
                io_metadata_map={},
                migration_mode=self.migration_mode,
                migration_from_config=self.migration_from_config,
                migration_to_config=self.migration_to_config,
            )
            # Store time_t aliases for Stage S1, Pass P1 (will be set when discovery runs)
            self._time_t_aliases = {}
    
    def _load_environment_config(self) -> Optional[Dict[str, Any]]:
        """Load environment configuration from file."""
        if not self.environment_config_path:
            return None
        
        try:
            with open(self.environment_config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            StatusLogger.timestamped_warning(f"Failed to load environment config from {self.environment_config_path}: {e}")
            return None
    
    def _collect_token_stats(self) -> Optional[Dict[str, Any]]:
        """Collect token usage statistics from LLM clients."""
        stats = {
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_requests": 0,
            "by_stage": {}
        }
        
        # Collect from legacy pipeline LLM client (Stage S1, S2, S3)
        if hasattr(self, 'llm_client') and self.llm_client:
            llm_stats = self.llm_client.get_token_stats()
            if llm_stats:
                stats["total_prompt_tokens"] += llm_stats.get("total_prompt_tokens", 0)
                stats["total_completion_tokens"] += llm_stats.get("total_completion_tokens", 0)
                stats["total_requests"] += llm_stats.get("total_requests", 0)
                
                # Merge by_stage statistics
                for stage_name, stage_stats in llm_stats.get("by_stage", {}).items():
                    if stage_name not in stats["by_stage"]:
                        stats["by_stage"][stage_name] = {
                            "prompt_tokens": 0,
                            "completion_tokens": 0,
                            "requests": 0
                        }
                    stats["by_stage"][stage_name]["prompt_tokens"] += stage_stats.get("prompt_tokens", 0)
                    stats["by_stage"][stage_name]["completion_tokens"] += stage_stats.get("completion_tokens", 0)
                    stats["by_stage"][stage_name]["requests"] += stage_stats.get("requests", 0)
        
        # Collect from function-first pipeline LLM client (Stage S2, S3)
        if hasattr(self, 'function_llm_client') and self.function_llm_client:
            if hasattr(self.function_llm_client, 'base_client') and self.function_llm_client.base_client:
                func_stats = self.function_llm_client.base_client.get_token_stats()
                if func_stats:
                    stats["total_prompt_tokens"] += func_stats.get("total_prompt_tokens", 0)
                    stats["total_completion_tokens"] += func_stats.get("total_completion_tokens", 0)
                    stats["total_requests"] += func_stats.get("total_requests", 0)
                    
                    # Merge by_stage statistics
                    for stage_name, stage_stats in func_stats.get("by_stage", {}).items():
                        if stage_name not in stats["by_stage"]:
                            stats["by_stage"][stage_name] = {
                                "prompt_tokens": 0,
                                "completion_tokens": 0,
                                "requests": 0
                            }
                        stats["by_stage"][stage_name]["prompt_tokens"] += stage_stats.get("prompt_tokens", 0)
                        stats["by_stage"][stage_name]["completion_tokens"] += stage_stats.get("completion_tokens", 0)
                        stats["by_stage"][stage_name]["requests"] += stage_stats.get("requests", 0)
        
        # Calculate total tokens
        stats["total_tokens"] = stats["total_prompt_tokens"] + stats["total_completion_tokens"]
        
        # Return None if no tokens were used
        if stats["total_tokens"] == 0:
            return None
        
        return stats
    
    @staticmethod
    def _build_stage_stats(
        session: ScanSession, token_stats: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Assemble the machine-readable per-stage counters persisted with a scan.

        ``io_boundary.candidates`` stays None when I/O boundary analysis did not
        run, so aggregation can tell "not measured" apart from "measured zero".
        """
        info = getattr(session, '_legacy_pipeline_info', None) or {}
        by_pass: Dict[str, Any] = {}
        for stage_name, stage in (token_stats or {}).get("by_stage", {}).items():
            prompt_tokens = int(stage.get("prompt_tokens", 0) or 0)
            completion_tokens = int(stage.get("completion_tokens", 0) or 0)
            by_pass[str(stage_name).upper()] = {
                "total_tokens": prompt_tokens + completion_tokens,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "requests": int(stage.get("requests", 0) or 0),
            }

        return {
            "prescan": {"time_t_aliases": session.stage_counts.get("time_t_aliases", 0)},
            "ir": {
                "candidates": session.stage_counts.get("ir_candidates", 0),
                "after_structural_filter": info.get('filtered_candidates_count'),
            },
            "io_boundary": {"candidates": info.get('io_boundary_candidates')},
            "llm": {
                "total_tokens": int((token_stats or {}).get("total_tokens", 0) or 0),
                "prompt_tokens": int((token_stats or {}).get("total_prompt_tokens", 0) or 0),
                "completion_tokens": int(
                    (token_stats or {}).get("total_completion_tokens", 0) or 0
                ),
                "requests": int((token_stats or {}).get("total_requests", 0) or 0),
                "by_pass": by_pass,
            },
        }
    
    def scan(
        self,
        root_path: str,
        rules_path: str,
        include_patterns: List[str],
        exclude_patterns: List[str],
        min_risk: str = "medium",
        check_cancelled: Optional[Callable[[], bool]] = None,
        output_base: Optional[str] = None,
        session_dir: Optional[str] = None,
    ) -> ScanResults:
        """
        Run the complete scanning pipeline.
        
        Args:
            root_path: Root directory to scan
            rules_path: Path to rules JSON file
            include_patterns: List of glob patterns to include
            exclude_patterns: List of glob patterns to exclude
            min_risk: Minimum risk level
            output_base: If set, session output (results/scans/...) is under this path (absolute).
                        Use when running under a job working dir so paths don't depend on cwd.
            session_dir: If set, this directory is the session artifact root itself,
                        with no results/scans/<session-id>/ nesting beneath it.
                        Used by ``tacs repos`` for its per-repo output directory.
            
        Returns:
            Complete scan results
        """
        # Name persisted source paths and diagnostics relative to this root.
        self.root_path = str(Path(root_path).resolve())
        if hasattr(self, 'function_analyzer'):
            self.function_analyzer.root_path = self.root_path

        # Initialize scan session
        session = ScanSession(
            root_path=root_path,
            enable_llm_logging=self.enable_llm_logging,
            redact_prompts=self.redact_prompts,
            allow_raw_code_logging=self.allow_raw_code_logging,
            output_base=output_base,
            session_dir=session_dir,
        )
        
        session.log_message("INFO", f"Starting scan {session.scan_id}")
        
        # Store session for later access
        self.session = session
        
        # Stage 1: Calculate metrics
        StatusLogger.timestamped_debug("Stage 1: Code metrics...")
        session.start_timing("metrics")
        metrics = calculate_metrics(root_path, include_patterns, exclude_patterns)
        StatusLogger.timestamped_print(f"Stage 1: Found {metrics.total_files} files, {metrics.total_lines} lines")
        session.end_timing("metrics")
        session.log_message("INFO", f"Metrics: {metrics.total_files} files, {metrics.total_lines} lines")
        
        # Stage 2: Typedef discovery (using iterative typedef scanner)
        if self.enable_discovery:
            session.start_timing("prescan")
            typedef_aliases, time_macros = self.discovery_manager.discover_time_aliases(
                root_path, include_patterns, exclude_patterns
            )
            
            # Log discoveries to session
            for alias_name, definitions in typedef_aliases.items():
                for definition in definitions:
                    # Extract info from definition string: "file:line: typedef ..."
                    parts = definition.split(':', 2)
                    if len(parts) >= 3:
                        file_path = parts[0]
                        line_num = int(parts[1]) if parts[1].isdigit() else 0
                        session.log_typedef(alias_name, "time_t", 1, file_path, line_num)
            
            session.end_timing("prescan")
            session.log_message("INFO", f"Prescan: {len(typedef_aliases)} typedefs discovered")
            
            # Update rules with discoveries (session/prescan only — never mutate --rules path)
            updated_rules_path = self.discovery_manager.update_rules_with_discoveries(
                rules_path,
                typedef_aliases,
                time_macros,
                output_dir=str(session.prescan_dir),
                root_path=root_path,
            )
            
            # Save discovery report beside other prescan artifacts
            self.discovery_manager.save_discovery_report(
                typedef_aliases,
                time_macros,
                str(session.prescan_dir / "discovery_report.json"),
                root_path=root_path,
            )
            
            # Extract and save new rules to scan session
            with open(updated_rules_path, 'r', encoding='utf-8') as f:
                updated_rules = json.load(f)
            with open(rules_path, 'r', encoding='utf-8') as f:
                original_rules = json.load(f)
            
            # Find new rules (those with "discovered": True)
            new_rules = [rule for rule in updated_rules if rule.get('discovered', False)]
            if new_rules:
                session.save_discovered_rules(new_rules, rules_path)
                StatusLogger.timestamped_debug(f"Saved {len(new_rules)} discovered rules to scan session")
            
            # Update LLM client with discovered time_t aliases (for Stage S1, Pass P1)
            # Store for use in function-first pipeline if Stage S1 is enabled
            if self.function_first:
                self._time_t_aliases = typedef_aliases
            if hasattr(self, 'llm_client'):
                self.llm_client.time_t_aliases = typedef_aliases
                StatusLogger.timestamped_debug(f"Passed {len(typedef_aliases)} time_t aliases to LLM client for Stage S1, Pass P1")
        else:
            StatusLogger.timestamped_debug("Skipping typedef discovery (disabled)")
            typedef_aliases, time_macros = {}, {}
            updated_rules_path = rules_path
            session.log_message("INFO", "Skipping typedef discovery (disabled)")
        
        # Stage 3: IR candidate discovery (using updated rules)
        StatusLogger.timestamped_print("Stage 3: IR candidate discovery...")
        session.start_timing("ir")
        
        # Extract time function names from rules for cast detection
        time_functions = []
        try:
            with open(updated_rules_path, 'r', encoding='utf-8') as f:
                rules = json.load(f)
            for rule in rules:
                if rule.get('category') == 'function' and rule.get('symbol'):
                    symbol = rule.get('symbol')
                    # Add common time functions
                    if symbol in ['time', 'mktime', 'gmtime', 'localtime', 'clock_gettime', 
                                  'gettimeofday', 'timespec_get', 'timespec_getres']:
                        time_functions.append(symbol)
        except Exception:
            pass
        
        candidates = self.ir_adapter.discover_candidates(
            root_path, updated_rules_path, min_risk, include_patterns, exclude_patterns,
            time_t_aliases=typedef_aliases if self.enable_discovery else {},
            time_functions=time_functions
        )
        StatusLogger.timestamped_print(f"Found {_format_count(len(candidates), 'candidate')}")
        session.end_timing("ir")
        session.log_message("INFO", f"IR: Found {_format_count(len(candidates), 'candidate')}")
        
        # Store original candidates count for summary
        if not hasattr(session, '_legacy_pipeline_info'):
            session._legacy_pipeline_info = {}
        session._legacy_pipeline_info['candidates_count'] = len(candidates)
        
        # Log candidates to session
        for candidate in candidates:
            candidate_id = f"{session.relative_path(candidate.file)}:{candidate.line}"
            session.log_candidate(
                candidate_id=candidate_id,
                file=candidate.file,
                line=candidate.line,
                col_start=candidate.col_start or 0,
                col_end=candidate.col_end or 0,
                symbol=candidate.symbol,
                rule=candidate.risk,
                snippet=candidate.one_line_snippet
            )
        
        # Stage 4: Structural filter
        StatusLogger.timestamped_debug("Stage 4: Structural filter...")
        filtered_candidates = self.struct_filter.filter_candidates(candidates)
        StatusLogger.timestamped_print(
            f"Stage 4: After filtering: {_format_count(len(filtered_candidates), 'candidate')}"
        )
        session.log_message(
            "INFO",
            f"Structural filter: {_format_count(len(filtered_candidates), 'candidate')}",
        )
        
        # Store filtered candidates count
        session._legacy_pipeline_info['filtered_candidates_count'] = len(filtered_candidates)
        
        # Stage 5: I/O Boundary Analysis
        StatusLogger.timestamped_debug("Stage 5: I/O boundary analysis...")
        if self.io_analyzer:
            session.start_timing("io_boundary_analysis")
            
            # Update analyzer with discovered aliases and enhanced time-bearing detection
            time_function_assignments = self._track_time_assignments(
                root_path, include_patterns, exclude_patterns
            )
            
            self.io_analyzer.update_time_context(
                time_t_aliases=typedef_aliases,
                time_bearing_symbols=set(typedef_aliases.keys()),
                time_function_assignments=time_function_assignments
            )
            
            # Analyze I/O boundaries (lazy file loading inside analyzer)
            io_candidates = self.io_analyzer.analyze_io_boundaries(
                candidates=filtered_candidates,
                root_path=root_path,
                include_patterns=include_patterns,
                exclude_patterns=exclude_patterns
            )
            
            StatusLogger.timestamped_debug(f"Found {len(io_candidates)} I/O-boundary candidates")
            session.end_timing("io_boundary_analysis")
            session.log_message("INFO", f"I/O boundary analysis: {len(io_candidates)} candidates")
            session._legacy_pipeline_info['io_boundary_candidates'] = len(io_candidates)
            
            # Merge I/O candidates with regular candidates
            # Convert IOCandidate to Candidate and store metadata in mapping
            for io_cand in io_candidates:
                candidate = self._convert_io_candidate_to_candidate(io_cand)
                filtered_candidates.append(candidate)
                # Store metadata in mapping (not as attribute)
                candidate_id = f"{candidate.file}:{candidate.line}"
                self.io_metadata_map[candidate_id] = {
                    'io_category': io_cand.io_category.value,
                    'io_function': io_cand.io_function,
                    'io_score': io_cand.io_score,
                    'io_confidence': io_cand.io_confidence,
                    'remediation_class': io_cand.remediation_class.value,
                    'affected_symbols': io_cand.affected_symbols,
                    'abi_assumptions': io_cand.abi_assumptions,
                    'reasoning': io_cand.reasoning
                }
                # Debug: Log I/O candidate metadata storage
                if self.debug_candidates:
                    StatusLogger.timestamped_debug(f"  I/O candidate stored: {candidate_id} (score={io_cand.io_score:.1f}, {io_cand.io_category.value})")
            
            # Update LLM client with I/O metadata map
            if hasattr(self, 'llm_client') and self.llm_client:
                self.llm_client.io_metadata_map = self.io_metadata_map
        else:
            StatusLogger.timestamped_debug("Stage 5: Skipped (I/O analysis disabled)")
        
        # Stage 6: Migration Analysis (if migration mode enabled)
        StatusLogger.timestamped_debug("Stage 6: Migration analysis...")
        if self.migration_mode and self.migration_from_config and self.migration_to_config:
            session.start_timing("migration_analysis")
            
            from tacs.core.migration_analyzer import MigrationAnalyzer
            
            migration_analyzer = MigrationAnalyzer(
                from_config=self.migration_from_config,
                to_config=self.migration_to_config,
                time_t_aliases=typedef_aliases,
                time_bearing_symbols=set(typedef_aliases.keys())
            )
            
            # Analyze migration risks
            migration_risks = migration_analyzer.analyze_migration_risks(
                candidates=filtered_candidates,
                root_path=root_path,
                include_patterns=include_patterns,
                exclude_patterns=exclude_patterns
            )
            
            # Also analyze I/O candidates for migration risks
            if self.io_analyzer and hasattr(self, 'io_metadata_map'):
                for candidate_id, io_metadata in self.io_metadata_map.items():
                    # Extract file and line from candidate_id
                    try:
                        file_path, line_str = candidate_id.rsplit(':', 1)
                        line_num = int(line_str)
                        
                        # Find the code snippet (would need to load file or get from candidate)
                        # For MVP, use the metadata we have
                        io_risks = migration_analyzer.analyze_io_migration_risks(
                            io_candidate={'file': file_path, 'line': line_num, **io_metadata},
                            io_function=io_metadata.get('io_function', 'unknown'),
                            code=io_metadata.get('reasoning', '')
                        )
                        migration_risks.extend(io_risks)
                    except (ValueError, AttributeError):
                        continue
            
            StatusLogger.timestamped_print(f"Found {len(migration_risks)} migration risks")
            session.end_timing("migration_analysis")
            session.log_message("INFO", f"Migration analysis: {len(migration_risks)} risks")
            
            # Convert migration risks to candidates and merge
            for risk in migration_risks:
                # Find original candidate if possible
                candidate = None
                for cand in filtered_candidates:
                    if cand.file == risk.get('file') and cand.line == risk.get('line'):
                        candidate = cand
                        break
                
                if not candidate:
                    # Create new candidate from risk
                    from tacs.core.schema import Candidate
                    candidate = Candidate(
                        file=risk.get('file', 'unknown'),
                        line=risk.get('line', 0),
                        symbol=risk.get('symbol', 'migration_risk'),
                        one_line_snippet=risk.get('code', ''),
                        risk='high',
                        description=f"Migration risk: {risk.get('type', 'unknown')}"
                    )
                    filtered_candidates.append(candidate)
                
                # Store migration metadata (similar to I/O metadata)
                candidate_id = f"{risk.get('file', 'unknown')}:{risk.get('line', 0)}"
                
                # Merge with existing migration metadata if any
                if candidate_id not in self.migration_metadata:
                    self.migration_metadata[candidate_id] = []
                self.migration_metadata[candidate_id].append({
                    'risk_type': risk.get('type'),
                    'severity': risk.get('severity'),
                    'description': risk.get('description'),
                    'remediation': risk.get('remediation')
                })
        else:
            if not self.migration_mode:
                StatusLogger.timestamped_debug("Stage 6: Skipped (migration mode disabled)")
            elif not self.migration_from_config or not self.migration_to_config:
                StatusLogger.timestamped_debug("Stage 6: Skipped (migration config files not provided)")
        
        # Debug: Show sample candidates
        if self.debug_candidates and filtered_candidates:
            StatusLogger.timestamped_print(f"Sample candidates being sent to Stage S1, Pass P1:")
            for i, candidate in enumerate(filtered_candidates[:5]):
                StatusLogger.timestamped_print(
                    f"  {i+1}. {self._display_path(candidate.file)}:{candidate.line} - {candidate.symbol}"
                )
                StatusLogger.timestamped_print(f"     Code: {candidate.one_line_snippet}")
                if candidate.symbol_role:
                    StatusLogger.timestamped_print(f"     Role: {candidate.symbol_role}")
            if len(filtered_candidates) > 5:
                StatusLogger.timestamped_print(f"  ... and {len(filtered_candidates) - 5} more candidates")
        
        # Route to appropriate analysis approach
        if self.function_first:
            findings = self._run_function_first_analysis(filtered_candidates, session, check_cancelled=check_cancelled)
        else:
            findings = self._run_legacy_analysis(filtered_candidates, session)

        # Record verdicts before filtering; "no" findings are dropped below.
        self.last_classification_counts = self._classification_counts(findings)
        
        # Default behavior: do not save "no"/safe findings unless explicitly requested.
        findings = self._filter_findings_for_output(findings)
        
        # Convert findings to scan results
        return self._create_scan_results(findings, metrics, session, root_path, rules_path)

    def _display_path(self, path: str) -> str:
        """Name a scanned file relative to the scan root for output and diagnostics."""
        return repo_relative_path(path, self.root_path)

    @staticmethod
    def _classification_counts(findings: List[Finding]) -> Dict[str, int]:
        """Count Y2038 verdicts across findings."""
        return {
            "yes": sum(1 for f in findings if f.y2038_issue == Y2038Issue.YES),
            "no": sum(1 for f in findings if f.y2038_issue == Y2038Issue.NO),
            "abstain": sum(1 for f in findings if f.y2038_issue == Y2038Issue.ABSTAIN),
            "total": len(findings),
        }

    def _filter_findings_for_output(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings before saving/output.

        By default, we exclude findings where Y2038 is classified as NO (safe),
        unless `include_no_findings` is enabled.

        When Y2106 detection is enabled, a finding is kept if its Y2106 issue is YES
        even if Y2038 is NO.
        """
        if self.include_no_findings:
            return findings

        filtered: list[Finding] = []
        for f in findings:
            if f.y2038_issue == Y2038Issue.NO:
                if self.detect_y2106 and getattr(f, "y2106_issue", None) == Y2038Issue.YES:
                    filtered.append(f)
                # else: drop safe (no issue)
                continue
            filtered.append(f)
        return filtered
    
    def _run_function_first_analysis(
        self,
        candidates: List[Candidate],
        session: ScanSession,
        check_cancelled: Optional[Callable[[], bool]] = None,
    ) -> List[Finding]:
        """Run function-first analysis pipeline."""
        StatusLogger.timestamped_debug("Running function-first analysis...")
        
        # Stage 7: LLM Pass 1 - Line-level analysis (single-line triage) - OPTIONAL PRE-FILTER
        StatusLogger.timestamped_debug("Stage 7: LLM Pass 1 (line-level analysis)...")
        if self.enable_pass1 and self.llm_type != "none" and hasattr(self, 'llm_client'):
            session.start_timing("stage_s1_pass_p1")
            
            # Run Stage 7, Pass P1 to filter candidates
            pass1_responses = self.llm_client.classify_candidates(
                candidates, self.batch_size_pass1
            )
            
            # Filter candidates based on Stage 7 results
            # Keep candidates that are YES (with sufficient confidence) or ABSTAIN
            filtered_candidates = []
            dropped_count = 0
            for response, candidate in zip(pass1_responses, candidates):
                if response.y2038_issue == Y2038Issue.YES and response.confidence >= self.confidence_floor:
                    # Keep YES findings with sufficient confidence
                    filtered_candidates.append(candidate)
                elif response.y2038_issue == Y2038Issue.ABSTAIN:
                    # Keep ABSTAIN findings for further analysis
                    filtered_candidates.append(candidate)
                elif response.y2038_issue == Y2038Issue.NO:
                    # Drop NO findings
                    dropped_count += 1
                elif response.y2038_issue == Y2038Issue.YES and response.confidence < self.confidence_floor:
                    # Drop YES findings with low confidence
                    dropped_count += 1
            
            StatusLogger.timestamped_print(f"Stage 7: {len(filtered_candidates)} candidates passed, {dropped_count} dropped")
            session.end_timing("stage_s1_pass_p1")
            session.log_message("INFO", f"Stage 7: {len(filtered_candidates)} candidates passed, {dropped_count} dropped")
            
            # Use filtered candidates for function-first analysis
            candidates = filtered_candidates
        else:
            if self.llm_type == "none":
                StatusLogger.timestamped_debug("Stage 7: Skipped (LLM disabled)")
            elif not self.enable_pass1:
                StatusLogger.timestamped_debug("Stage 7: Skipped (line-level analysis disabled)")
            else:
                StatusLogger.timestamped_debug("Stage 7: Skipped (line-level analysis disabled)")
        
        # Functionization (preparation for Stage S2)
        session.start_timing("functionization")
        StatusLogger.timestamped_debug("Functionization - extracting functions with candidates...")
        functions = self.function_analyzer.extract_functions_with_candidates(candidates)
        StatusLogger.timestamped_print(f"Extracted {len(functions)} functions containing candidates")
        session.end_timing("functionization")
        
        # Create mapping from function_id to FunctionBody for later passes
        function_map = {func.function_id: func for func in functions}
        
        # Stage 8: LLM Pass 2 - Function-level analysis, Pass 2a (initial function analysis)
        StatusLogger.timestamped_debug("Stage 8: LLM Pass 2 (function-level analysis), Pass 2a - initial analysis...")
        session.start_timing("stage_s2_pass_p1")
        findings = self._run_pass_f1(functions, session, check_cancelled=check_cancelled)
        session.end_timing("stage_s2_pass_p1")
        
        # Stage 8: LLM Pass 2 - Function-level analysis, Pass 2b (iterative enrichment)
        StatusLogger.timestamped_debug("Stage 8: LLM Pass 2 (function-level analysis), Pass 2b - iterative enrichment...")
        session.start_timing("stage_s2_pass_p2")
        findings = self._run_pass_f2(findings, function_map, session)
        session.end_timing("stage_s2_pass_p2")
        
        # Stage 9: LLM Pass 3 - File-level analysis, Pass 1 (file-leading context)
        StatusLogger.timestamped_debug("Stage 9: LLM Pass 3 (file-level analysis)...")
        session.start_timing("stage_s3_pass_p1")
        findings = self._run_pass_f3(findings, function_map, session)
        session.end_timing("stage_s3_pass_p1")
        
        # Summary: Count I/O findings
        io_findings_count = sum(1 for f in findings if f.io_category is not None)
        if hasattr(self, 'io_metadata_map') and self.io_metadata_map:
            total_io_candidates = len(self.io_metadata_map)
            StatusLogger.timestamped_debug(
                f"I/O metadata summary: {total_io_candidates} I/O candidates stored, "
                f"{io_findings_count} findings with I/O metadata attached"
            )
            if total_io_candidates > io_findings_count:
                missing = total_io_candidates - io_findings_count
                StatusLogger.timestamped_debug(
                    f"  Note: {missing} I/O candidates did not get metadata attached "
                    f"(may be in functions classified as NO, or path matching issue)"
                )
        
        return findings
    
    def _run_pass_f1(
        self,
        functions: List[FunctionBody],
        session: ScanSession,
        check_cancelled: Optional[Callable[[], bool]] = None,
    ) -> List[Finding]:
        """Run Pass F1 (function analysis)."""
        from tacs.core.function_schemas import FunctionBatch
        
        findings = []
        
        # Check if LLM is disabled
        llm_disabled = self.function_llm_client.llm_type == "none"
        
        if llm_disabled:
            StatusLogger.timestamped_debug("Stage 8, Pass 2a: Skipped (LLM disabled)")
            # Still create findings from functions with abstain status
            for func in functions:
                finding = Finding(
                    file=func.file_path,
                    region={"start_line": func.start_line, "end_line": func.end_line},
                    lines=[func.start_line, func.end_line],
                    symbol="",
                    y2038_issue=Y2038Issue.ABSTAIN,
                    confidence=0.0,
                    reason="LLM disabled (--llm none)",
                    source_snippet=func.body[:200] if func.body else "",
                    severity="medium"
                )
                # Check for I/O metadata for candidate lines in this function
                if func.candidate_lines:
                    for line in func.candidate_lines:
                        self._attach_io_metadata_to_finding(finding, func.file_path, line)
                        if finding.io_category:  # Stop after first match
                            break
                findings.append(finding)
            return findings
        
        # Process functions in batches
        batch_size = self.batch_size_func
        total_batches = (len(functions) + batch_size - 1) // batch_size
        
        for i in range(0, len(functions), batch_size):
            if check_cancelled and check_cancelled():
                raise InterruptedError("Job cancelled by user")
            batch_functions = functions[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            cand_total, cand_max, cand_zero = self._function_batch_candidate_stats(batch_functions)
            StatusLogger.timestamped_print(
                f"Stage 8: Processing batch {batch_num} of {total_batches} "
                f"({len(batch_functions)} functions, {cand_total} candidate lines in batch, "
                f"max {cand_max} lines in one function, {cand_zero} func(s) with no candidate_lines)..."
            )
            
            # Create function batch
            function_batch = FunctionBatch(
                batch_id=f"s2_p1_batch_{batch_num:04d}",
                functions=batch_functions,
                iteration=1
            )
            
            # Get prompt for saving (with error handling)
            try:
                prompt = self.function_llm_client._build_pass_f1_prompt(function_batch)
            except Exception as e:
                StatusLogger.timestamped_warning(f"Failed to build prompt for saving: {e}")
                prompt = None
            
            # Analyze functions
            analyses = self.function_llm_client.analyze_functions_pass_f1(function_batch)
            
            # Save batch to scan session
            response_data = None
            if analyses:
                try:
                    # Convert Pydantic models to dicts
                    response_data = [analysis.model_dump() if hasattr(analysis, 'model_dump') else analysis.dict() for analysis in analyses]
                except Exception as e:
                    # Fallback: convert manually
                    response_data = [
                        {
                            "function_id": a.function_id,
                            "y2038_summary": a.y2038_summary.value if hasattr(a.y2038_summary, 'value') else str(a.y2038_summary),
                            "confidence": a.confidence,
                            "issues": a.issues,
                            "needs_more_context": a.needs_more_context,
                            "needs": [n.value if hasattr(n, 'value') else str(n) for n in a.needs] if a.needs else []
                        }
                        for a in analyses
                    ]
            
            session.save_function_batch(
                pass_name="stage_8_pass_2a",
                batch_num=batch_num,
                function_batch=function_batch,
                prompt=prompt,
                response=response_data
            )
            
            # Convert analyses to findings
            batch_findings = self._convert_analyses_to_findings(analyses, batch_functions)
            findings.extend(batch_findings)
            
            # Log batch results
            batch_yes = sum(1 for f in batch_findings if f.y2038_issue == Y2038Issue.YES)
            batch_no = sum(1 for f in batch_findings if f.y2038_issue == Y2038Issue.NO)
            batch_abstain = sum(1 for f in batch_findings if f.y2038_issue == Y2038Issue.ABSTAIN)
            StatusLogger.timestamped_print(f"Stage 8, Pass 2a: Batch {batch_num} results: {batch_yes} yes, {batch_no} no, {batch_abstain} abstain")
        
        # Log Stage 8, Pass 2a summary
        yes_count = sum(1 for f in findings if f.y2038_issue == Y2038Issue.YES)
        no_count = sum(1 for f in findings if f.y2038_issue == Y2038Issue.NO)
        abstain_count = sum(1 for f in findings if f.y2038_issue == Y2038Issue.ABSTAIN)
        StatusLogger.timestamped_print(
            f"Stage 8, Pass 2a results: {yes_count} yes, {no_count} no, {abstain_count} abstain"
        )
        
        # Log abstain details
        if abstain_count > 0:
            StatusLogger.timestamped_debug(f"Stage 8, Pass 2a: {abstain_count} abstain(s) requiring additional passes:")
            for finding in findings[:10]:  # Log first 10 abstains
                if finding.y2038_issue == Y2038Issue.ABSTAIN:
                    needs_info = ""
                    if "needs more context:" in finding.reason:
                        needs_info = " (" + finding.reason.split("needs more context:")[-1].strip() + ")"
                    StatusLogger.timestamped_debug(f"  - {finding.function_id}: confidence={finding.confidence:.2f}{needs_info}")
            if abstain_count > 10:
                StatusLogger.timestamped_debug(f"  ... and {abstain_count - 10} more")
        
        return findings
    
    @staticmethod
    def _candidate_region(
        candidate_lines: list[int] | None,
        function: "FunctionBody",
    ) -> tuple[int, int]:
        """Prefer a region that spans actual candidate lines.

        Helps reviewers land on the focused line(s) rather than the function
        declaration when the LLM doesn't provide precise issue locations.
        """
        clean = [c for c in (candidate_lines or []) if isinstance(c, int) and c > 0]
        if clean:
            return min(clean), max(clean)

        start = function.start_line if function.start_line else 1
        end = function.end_line if function.end_line else start
        return start, end

    @staticmethod
    def _function_batch_candidate_stats(functions: List[Any]) -> tuple[int, int, int]:
        """Count absolute candidate lines across a batch of FunctionBody rows.

        Returns:
            (total_candidates, max_candidates_per_function, functions_with_zero_candidates)
        """
        total = 0
        max_per = 0
        zero = 0
        for f in functions:
            raw = getattr(f, "candidate_lines", None) or []
            lines = [c for c in raw if isinstance(c, int) and c > 0]
            n = len(lines)
            total += n
            if n > max_per:
                max_per = n
            if n == 0:
                zero += 1
        return total, max_per, zero

    @staticmethod
    def _resolve_llm_issue_line(issue_line_raw: Any, function: "FunctionBody") -> int | None:
        """Resolve LLM issue line into an absolute 1-based file line.

        The LLM may return:
        - an absolute file line number (preferred)
        - a 0-based or 1-based index relative to the provided function body
        - garbage / missing values

        We use `candidate_lines` (absolute) as an anchor whenever possible.
        """
        if issue_line_raw is None:
            return None

        try:
            issue_line_int = int(issue_line_raw)
        except (TypeError, ValueError):
            return None

        # 0 is a common "index" value; treat it as 0-based relative to the body.
        if issue_line_int == 0:
            if function.start_line:
                return function.start_line
            return None

        if issue_line_int <= 0:
            return None

        candidate_lines = [c for c in (function.candidate_lines or []) if isinstance(c, int) and c > 0]
        if candidate_lines and issue_line_int in candidate_lines:
            return issue_line_int

        # If it looks like an absolute file line within the function span, keep it.
        if function.start_line and function.end_line:
            if function.start_line <= issue_line_int <= function.end_line:
                return issue_line_int

        # Heuristic: interpret as index into function body (0-based or 1-based).
        if function.start_line:
            body_lines = function.body.splitlines() if function.body else []
            n = len(body_lines)
            if 0 <= issue_line_int < n:
                abs0 = function.start_line + issue_line_int  # 0-based index
                abs1 = function.start_line + issue_line_int - 1  # 1-based index
                if candidate_lines and abs0 in candidate_lines:
                    return abs0
                if candidate_lines and abs1 in candidate_lines:
                    return abs1
                # Prefer abs1 (1-based) when possible; otherwise abs0.
                if abs1 > 0:
                    return abs1
                return abs0 if abs0 > 0 else None

        return None

    def _convert_analyses_to_findings(self, analyses: List[FunctionAnalysis], functions: List[FunctionBody]) -> List[Finding]:
        """Convert function analyses to findings."""
        findings = []
        
        for analysis, function in zip(analyses, functions):
            # Convert Y2038Summary to Y2038Issue
            from tacs.core.schema import Y2038Issue, TimeIssueType
            if analysis.y2038_summary.value == "yes":
                y2038_issue = Y2038Issue.YES
            elif analysis.y2038_summary.value == "no":
                y2038_issue = Y2038Issue.NO
            else:
                y2038_issue = Y2038Issue.ABSTAIN
            
            # Determine Y2106 issue (when Y2106 detection enabled)
            y2106_issue = None
            if self.detect_y2106 and analysis.y2106_summary:
                if analysis.y2106_summary.value == "yes":
                    y2106_issue = Y2038Issue.YES
                elif analysis.y2106_summary.value == "no":
                    y2106_issue = Y2038Issue.NO
                else:
                    y2106_issue = Y2038Issue.ABSTAIN
            
            # Determine issue_type
            issue_type = None
            if self.detect_y2106:
                if analysis.issue_type:
                    issue_type = analysis.issue_type
                else:
                    # Infer from summaries
                    has_y2038 = y2038_issue == Y2038Issue.YES
                    has_y2106 = y2106_issue == Y2038Issue.YES if y2106_issue else False
                    
                    if has_y2038 and has_y2106:
                        issue_type = TimeIssueType.BOTH
                    elif has_y2038:
                        issue_type = TimeIssueType.Y2038
                    elif has_y2106:
                        issue_type = TimeIssueType.Y2106
                    elif y2038_issue == Y2038Issue.ABSTAIN:
                        issue_type = TimeIssueType.ABSTAIN
                    else:
                        issue_type = TimeIssueType.NONE
            
            # Create finding for each issue
            if analysis.issues:
                for issue in analysis.issues:
                    # LLM may provide either absolute file line numbers, or indexes
                    # relative to the provided function body. Resolve to an absolute
                    # 1-based file line so the UI can highlight the focus location.
                    issue_line_resolved = self._resolve_llm_issue_line(issue.get("line"), function)
                    candidate_lines = [c for c in (function.candidate_lines or []) if isinstance(c, int) and c > 0]
                    candidate_fallback = min(candidate_lines) if candidate_lines else None
                    focus_line = issue_line_resolved
                    if focus_line is None and candidate_lines:
                        # If we can't resolve LLM's line, choose the closest candidate line.
                        try:
                            issue_line_int = int(issue.get("line"))
                        except (TypeError, ValueError):
                            issue_line_int = None
                        if issue_line_int is not None:
                            focus_line = min(candidate_lines, key=lambda c: abs(c - issue_line_int))
                        else:
                            focus_line = candidate_fallback

                    if focus_line is None:
                        focus_line = function.start_line if function.start_line else None
                    if focus_line is None:
                        focus_line = 1
                    
                    finding = Finding(
                        file=function.file_path,
                        region={"start_line": focus_line, "end_line": focus_line},
                        lines=[focus_line],
                        symbol=issue.get('type', 'unknown'),
                        y2038_issue=y2038_issue,
                        y2106_issue=y2106_issue,
                        issue_type=issue_type,
                        issues=analysis.issues,
                        severity=issue.get('severity', 'medium'),
                        confidence=analysis.confidence,
                        reason=issue.get('description', f"Function analysis: {analysis.y2038_summary.value}"),
                        needs_more_context=analysis.needs_more_context,
                        source_snippet=function.body,
                        function_id=function.function_id,
                        iteration_count=1,
                        final_pass="S2_P1"
                    )
                    # Check for I/O metadata: try issue_line first, then all candidate_lines in function
                    # This handles cases where LLM reports issue at different line than I/O candidate
                    if not self._attach_io_metadata_to_finding(finding, function.file_path, focus_line):
                        # If not found at issue_line, check all candidate lines in the function
                        if candidate_lines:
                            for cand_line in candidate_lines:
                                if self._attach_io_metadata_to_finding(finding, function.file_path, cand_line):
                                    break  # Stop after first match
                    findings.append(finding)
            else:
                # Create finding for the function itself - only include candidate lines
                # Ensure we have valid line numbers
                if function.candidate_lines:
                    candidate_lines = [line for line in function.candidate_lines if line is not None]
                else:
                    candidate_lines = []
                
                # Fallback to function start/end lines if no candidate lines
                if not candidate_lines:
                    if function.start_line:
                        candidate_lines = [function.start_line]
                    elif function.end_line:
                        candidate_lines = [function.end_line]
                    else:
                        candidate_lines = [1]  # Absolute fallback
                
                # Ensure region is valid
                start_line, end_line = self._candidate_region(candidate_lines, function)
                
                # Create a more detailed reason based on the analysis
                if analysis.issues:
                    # Use the first issue description if available
                    first_issue = analysis.issues[0]
                    reason = first_issue.get('description', f"Function analysis: {analysis.y2038_summary.value}")
                elif analysis.y2038_summary.value == "abstain":
                    # For abstains, explain why more context is needed
                    if analysis.needs:
                        needs_str = ', '.join(analysis.needs)
                        reason = f"Function analysis: abstain (needs more context: {needs_str})"
                    elif analysis.needs_more_context:
                        reason = f"Function analysis: abstain (needs more context to determine Y2038 risk)"
                    else:
                        reason = f"Function analysis: abstain (ambiguous Y2038 risk, confidence: {analysis.confidence:.2f})"
                else:
                    # Fallback for cases where LLM didn't provide specific issues
                    reason = f"Function analysis: {analysis.y2038_summary.value} (confidence: {analysis.confidence:.2f})"
                
                finding = Finding(
                    file=function.file_path,
                    region={"start_line": start_line, "end_line": end_line},
                    lines=candidate_lines,  # Only include actual candidate lines
                    symbol=function.symbol,
                    y2038_issue=y2038_issue,
                    y2106_issue=y2106_issue,
                    issue_type=issue_type,
                    issues=analysis.issues,
                    severity=None,
                    confidence=analysis.confidence,
                    reason=reason,
                    needs_more_context=analysis.needs_more_context,
                    source_snippet=function.body,
                    function_id=function.function_id,
                    iteration_count=1,
                    final_pass="F1"
                )
                # Check for I/O metadata for candidate lines in this function
                # Try all candidate lines until we find a match
                for line in candidate_lines:
                    if self._attach_io_metadata_to_finding(finding, function.file_path, line):
                        break  # Stop after first successful match
                findings.append(finding)
        
        return findings
    
    def _run_pass_f2(self, findings: List[Finding], function_map: Dict[str, FunctionBody], session: ScanSession) -> List[Finding]:
        """Run Pass F2 (iterative enrichment) for functions that need more context."""
        from tacs.core.function_schemas import FunctionBatch, ContextNeed
        
        # Filter to abstain findings that need more context
        abstain_findings = [
            f for f in findings
            if f.y2038_issue == Y2038Issue.ABSTAIN and (f.needs_more_context or f.function_id)
        ]
        
        if not abstain_findings:
            StatusLogger.timestamped_debug("Stage 8, Pass 2b: Skipped (no abstain findings need iterative enrichment)")
            return findings
        
        StatusLogger.timestamped_debug(f"Stage 8, Pass 2b: Processing {len(abstain_findings)} abstain findings with iterative enrichment")
        
        # Log abstain details for debugging
        StatusLogger.timestamped_debug(f"Stage 8, Pass 2b: Abstain findings breakdown:")
        for finding in abstain_findings[:5]:  # Log first 5 for debugging
            StatusLogger.timestamped_debug(f"  - {finding.function_id}: {finding.reason[:80]}")
        if len(abstain_findings) > 5:
            StatusLogger.timestamped_debug(f"  ... and {len(abstain_findings) - 5} more")
        
        # Group findings by function_id to avoid duplicate processing
        function_findings_map = {}
        for finding in abstain_findings:
            if finding.function_id:
                if finding.function_id not in function_findings_map:
                    function_findings_map[finding.function_id] = []
                function_findings_map[finding.function_id].append(finding)
        
        # Process each function that needs more context
        enriched_functions = []
        function_to_findings = {}
        
        for function_id, func_findings in function_findings_map.items():
            original_function = function_map.get(function_id)
            if not original_function:
                continue
            
            # Collect all context needs from findings for this function
            all_needs = []
            for finding in func_findings:
                # Try to extract needs from the reason string
                # Format: "Function analysis: abstain (needs more context: typedef, struct)"
                if "needs more context:" in finding.reason:
                    needs_str = finding.reason.split("needs more context:")[-1].strip()
                    # Parse comma-separated needs
                    for need_str in needs_str.split(','):
                        need_str = need_str.strip().lower()
                        if need_str == "typedef":
                            all_needs.append(ContextNeed.TYPEDEF)
                        elif need_str == "struct":
                            all_needs.append(ContextNeed.STRUCT)
                        elif need_str == "macro":
                            all_needs.append(ContextNeed.MACRO)
                        elif need_str == "callee":
                            all_needs.append(ContextNeed.CALLEE)
                        elif need_str == "header":
                            all_needs.append(ContextNeed.HEADER)
                
                # Fallback: if needs_more_context is True but no specific needs found, request all
                if finding.needs_more_context and not all_needs:
                    all_needs.extend([ContextNeed.TYPEDEF, ContextNeed.STRUCT, ContextNeed.MACRO, ContextNeed.CALLEE, ContextNeed.HEADER])
            
            # Remove duplicates
            unique_needs = list(set(all_needs))
            
            # Log what context we're requesting
            if unique_needs:
                needs_str = ', '.join([n.value for n in unique_needs])
                StatusLogger.timestamped_debug(f"Stage 8, Pass 2b: Function {function_id} needs: {needs_str}")
            
            # Extract context additions
            context_additions = self.function_analyzer.extract_context_items(original_function, unique_needs)
            
            # Log what context was extracted
            if context_additions:
                for key, value in context_additions.items():
                    if value:
                        count = len(value) if isinstance(value, list) else 1
                        StatusLogger.timestamped_debug(f"Stage 8, Pass 2b: Extracted {count} {key} for {function_id}")
                        # Show first few items
                        if isinstance(value, list):
                            for item in value[:3]:
                                StatusLogger.timestamped_debug(f"  - {item[:80]}")
                            if len(value) > 3:
                                StatusLogger.timestamped_debug(f"  ... and {len(value) - 3} more")
            else:
                StatusLogger.timestamped_warning(f"Stage 8, Pass 2b: No context extracted for {function_id} (needs: {[n.value for n in unique_needs]})")
            
            # Create enriched function body
            enriched_function = FunctionBody(
                function_id=original_function.function_id,
                file_path=original_function.file_path,
                symbol=original_function.symbol,
                start_line=original_function.start_line,
                end_line=original_function.end_line,
                body=original_function.body,
                candidate_lines=original_function.candidate_lines,
                context_additions=context_additions if context_additions else None
            )
            enriched_functions.append(enriched_function)
            function_to_findings[function_id] = func_findings
        
        if not enriched_functions:
            StatusLogger.timestamped_debug("Stage 8, Pass 2b: No functions found for enrichment")
            return findings
        
        StatusLogger.timestamped_print(
            f"Stage 8, Pass 2b: enriching "
            f"{_format_count(len(enriched_functions), 'abstained function')}"
        )
        
        # Process in batches
        batch_size = self.batch_size_func
        new_findings = []
        iteration = 2  # Pass F2 is iteration 2
        
        for i in range(0, len(enriched_functions), batch_size):
            batch_functions = enriched_functions[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(enriched_functions) + batch_size - 1) // batch_size
            cand_total, cand_max, cand_zero = self._function_batch_candidate_stats(batch_functions)
            StatusLogger.timestamped_debug(
                f"Stage 8, Pass 2b: Processing batch {batch_num} of {total_batches}: "
                f"{len(batch_functions)} functions, {cand_total} candidate lines, "
                f"max {cand_max} per function, {cand_zero} func(s) with no candidate_lines"
            )
            
            # Create function batch
            function_batch = FunctionBatch(
                batch_id=f"f2_batch_{batch_num:04d}",
                functions=batch_functions,
                iteration=iteration
            )
            
            # Get prompt for saving
            prompt = self.function_llm_client._build_pass_f2_prompt(function_batch, iteration)
            
            # Analyze functions
            analyses = self.function_llm_client.analyze_functions_pass_f2(function_batch, iteration)
            
            # Save batch to scan session
            response_data = None
            if analyses:
                try:
                    response_data = [analysis.model_dump() if hasattr(analysis, 'model_dump') else analysis.dict() for analysis in analyses]
                except Exception as e:
                    response_data = [
                        {
                            "function_id": a.function_id,
                            "y2038_summary": a.y2038_summary.value if hasattr(a.y2038_summary, 'value') else str(a.y2038_summary),
                            "confidence": a.confidence,
                            "issues": a.issues,
                            "needs_more_context": a.needs_more_context,
                            "needs": [n.value if hasattr(n, 'value') else str(n) for n in a.needs] if a.needs else []
                        }
                        for a in analyses
                    ]
            
            session.save_function_batch(
                pass_name="stage_8_pass_2b",
                batch_num=batch_num,
                function_batch=function_batch,
                prompt=prompt,
                response=response_data
            )
            
            # Convert analyses to findings, replacing original abstain findings
            for analysis, function in zip(analyses, batch_functions):
                try:
                    # Remove old findings for this function
                    old_findings = function_to_findings.get(function.function_id, [])
                    
                    # Convert new analysis to findings
                    batch_findings = self._convert_analyses_to_findings([analysis], [function])
                    
                    # Update iteration count and final pass
                    for finding in batch_findings:
                        finding.iteration_count = iteration
                        finding.final_pass = "F2"
                    
                    new_findings.extend(batch_findings)
                except Exception as e:
                    StatusLogger.timestamped_error(f"Error converting analysis to findings for {function.function_id}: {e}")
                    StatusLogger.timestamped_error(f"Function body (first 200 chars): {function.body[:200] if function.body else 'N/A'}")
                    # Create a fallback abstain finding
                    # Note: Finding and Y2038Issue are already imported at the top of the file
                    fallback_finding = Finding(
                        file=function.file_path,
                        line=function.start_line if function.start_line else 1,
                        function=function.symbol if function.symbol else "unknown",
                        symbol=function.symbol if function.symbol else "unknown",
                        y2038_issue=Y2038Issue.ABSTAIN,
                        confidence=0.0,
                        reason=f"Error during analysis conversion: {str(e)[:200]}",
                        one_line_snippet=function.body.split('\n')[0] if function.body else "",
                        iteration_count=iteration,
                        final_pass="F2"
                    )
                    new_findings.append(fallback_finding)
        
        # Remove old abstain findings and add new findings
        final_findings = [f for f in findings if f not in abstain_findings]
        final_findings.extend(new_findings)
        
        # Log Pass F2 results with detailed abstain tracking
        yes_count = sum(1 for f in new_findings if f.y2038_issue == Y2038Issue.YES)
        no_count = sum(1 for f in new_findings if f.y2038_issue == Y2038Issue.NO)
        abstain_count = sum(1 for f in new_findings if f.y2038_issue == Y2038Issue.ABSTAIN)
        StatusLogger.timestamped_print(
            f"Stage 8, Pass 2b results: {yes_count} yes, {no_count} no, {abstain_count} abstain"
        )
        
        # Log abstain details if any remain
        if abstain_count > 0:
            StatusLogger.timestamped_debug(f"Stage 8, Pass 2b: {abstain_count} abstain(s) remaining after enrichment:")
            for finding in new_findings:
                if finding.y2038_issue == Y2038Issue.ABSTAIN:
                    StatusLogger.timestamped_debug(f"  - {finding.function_id}: confidence={finding.confidence:.2f}, reason={finding.reason[:80]}")
        
        return final_findings
    
    def _run_pass_f3(self, findings: List[Finding], function_map: Dict[str, FunctionBody], session: ScanSession) -> List[Finding]:
        """Run Pass F3 (file-leading context) for functions that still need more context."""
        from tacs.core.function_schemas import FunctionBatch
        
        # Filter to remaining abstain findings
        abstain_findings = [
            f for f in findings
            if f.y2038_issue == Y2038Issue.ABSTAIN and f.function_id
        ]
        
        if not abstain_findings:
            StatusLogger.timestamped_debug("Stage 9: Skipped (no abstain findings need file context)")
            return findings
        
        StatusLogger.timestamped_debug(f"Stage 9: Processing {len(abstain_findings)} abstain findings with file context")
        
        # Group findings by file to avoid reading the same file multiple times
        file_groups = {}
        for finding in abstain_findings:
            file_path = finding.file
            if file_path not in file_groups:
                file_groups[file_path] = []
            file_groups[file_path].append(finding)
        
        StatusLogger.timestamped_debug(f"Stage 9: Grouped into {len(file_groups)} unique files")
        
        # Process each file group
        new_findings = []
        
        for file_path, file_findings in file_groups.items():
            # Get functions for these findings
            functions_for_file = []
            finding_to_function = {}
            
            for finding in file_findings:
                if finding.function_id:
                    function = function_map.get(finding.function_id)
                    if function:
                        functions_for_file.append(function)
                        finding_to_function[finding.function_id] = finding
            
            if not functions_for_file:
                continue
            
            # Read file content (limited to first 50 lines for context)
            file_context = None
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    file_context = ''.join(lines[:50])
            except Exception as e:
                StatusLogger.timestamped_warning(f"Failed to read file {file_path} for Pass F3: {e}")
                continue
            
            # Process in batches
            batch_size = self.batch_size_func
            for i in range(0, len(functions_for_file), batch_size):
                batch_functions = functions_for_file[i:i + batch_size]
                batch_num = (i // batch_size) + 1
                total_batches = (len(functions_for_file) + batch_size - 1) // batch_size
                cand_total, cand_max, cand_zero = self._function_batch_candidate_stats(batch_functions)
                StatusLogger.timestamped_debug(
                    f"Stage 9: Processing batch {batch_num} of {total_batches} "
                    f"from {self._display_path(file_path)}: "
                    f"{len(batch_functions)} functions, {cand_total} candidate lines, "
                    f"max {cand_max} per function, {cand_zero} func(s) with no candidate_lines"
                )
                
                # Create function batch
                function_batch = FunctionBatch(
                    batch_id=f"f3_batch_{batch_num:04d}",
                    functions=batch_functions,
                    iteration=3
                )
                
                # Get prompt for saving
                prompt = self.function_llm_client._build_pass_f3_prompt(function_batch)
                
                # Analyze functions
                analyses = self.function_llm_client.analyze_functions_pass_f3(function_batch)
                
                # Save batch to scan session
                response_data = None
                if analyses:
                    try:
                        response_data = [analysis.model_dump() if hasattr(analysis, 'model_dump') else analysis.dict() for analysis in analyses]
                    except Exception as e:
                        response_data = [
                            {
                                "function_id": a.function_id,
                                "y2038_summary": a.y2038_summary.value if hasattr(a.y2038_summary, 'value') else str(a.y2038_summary),
                                "confidence": a.confidence,
                                "issues": a.issues,
                                "needs_more_context": a.needs_more_context,
                                "needs": [n.value if hasattr(n, 'value') else str(n) for n in a.needs] if a.needs else []
                            }
                            for a in analyses
                        ]
                
                session.save_function_batch(
                    pass_name="stage_9_pass_1",
                    batch_num=batch_num,
                    function_batch=function_batch,
                    prompt=prompt,
                    response=response_data
                )
                
                # Convert analyses to findings, replacing original abstain findings
                for analysis, function in zip(analyses, batch_functions):
                    # Convert new analysis to findings
                    batch_findings = self._convert_analyses_to_findings([analysis], [function])
                    
                    # Update iteration count and final pass
                    for finding in batch_findings:
                        finding.iteration_count = 3
                        finding.final_pass = "F3"
                    
                    new_findings.extend(batch_findings)
        
        # Remove old abstain findings and add new findings
        final_findings = [f for f in findings if f not in abstain_findings]
        final_findings.extend(new_findings)
        
        # Log Pass F3 results with detailed abstain tracking
        yes_count = sum(1 for f in new_findings if f.y2038_issue == Y2038Issue.YES)
        no_count = sum(1 for f in new_findings if f.y2038_issue == Y2038Issue.NO)
        abstain_count = sum(1 for f in new_findings if f.y2038_issue == Y2038Issue.ABSTAIN)
        StatusLogger.timestamped_print(
            f"Stage 9 results: {yes_count} yes, {no_count} no, {abstain_count} abstain"
        )
        
        # Log abstain details if any remain (these are final)
        if abstain_count > 0:
            StatusLogger.timestamped_debug(f"Stage 9: {abstain_count} final abstain(s) after file context:")
            for finding in new_findings:
                if finding.y2038_issue == Y2038Issue.ABSTAIN:
                    StatusLogger.timestamped_debug(f"  - {finding.function_id}: confidence={finding.confidence:.2f}, reason={finding.reason[:80]}")
        
        return final_findings
    
    def _create_scan_results(self, findings: List[Finding], metrics: Metrics, session: ScanSession, root_path: str, rules_path: str) -> ScanResults:
        """Create scan results from findings."""
        from tacs.core.schema import ScanResults
        
        # Findings are carried with absolute paths so earlier stages can read the
        # files; the ones we persist name the file as the repository does.
        for finding in findings:
            finding.file = repo_relative_path(finding.file, root_path)
        
        # Count findings by type
        from tacs.core.schema import TimeIssueType
        yes_count = sum(1 for f in findings if f.y2038_issue == Y2038Issue.YES)
        no_count = sum(1 for f in findings if f.y2038_issue == Y2038Issue.NO)
        abstain_count = sum(1 for f in findings if f.y2038_issue == Y2038Issue.ABSTAIN)
        
        # Verdict counts from before "no" findings were dropped from the output set.
        classified = self.last_classification_counts or self._classification_counts(findings)
        
        if self.detect_y2106:
            # Count Y2106 findings
            y2106_yes = sum(1 for f in findings if f.issue_type in [TimeIssueType.Y2106, TimeIssueType.BOTH])
            y2106_no = sum(1 for f in findings if f.issue_type == TimeIssueType.NONE)
            y2106_abstain = sum(1 for f in findings if f.issue_type == TimeIssueType.ABSTAIN)
            
            # Count total issues (Y2038 + Y2106, avoiding double-counting BOTH)
            total_issues = yes_count + y2106_yes - sum(1 for f in findings if f.issue_type == TimeIssueType.BOTH)
            
            StatusLogger.timestamped_print(f"Scan complete: {len(findings)} findings")
            StatusLogger.timestamped_debug(
                f"  Y2038: {classified['yes']} yes, {classified['no']} no, "
                f"{classified['abstain']} abstain"
            )
            StatusLogger.timestamped_debug(
                f"  Y2106: {y2106_yes} yes, {y2106_no} no, {y2106_abstain} abstain"
            )
            StatusLogger.timestamped_debug(
                f"  Total issues: {total_issues} ({yes_count} Y2038, {y2106_yes} Y2106)"
            )
        elif self.llm_type == "none":
            if len(findings) == 0:
                StatusLogger.timestamped_print("No Y2038 candidate findings detected")
            else:
                StatusLogger.timestamped_print(f"Scan complete: {len(findings)} findings")
                StatusLogger.timestamped_print(
                    f"{yes_count} confirmed Y2038 issues; "
                    f"{abstain_count} candidate findings remain unclassified (LLM disabled)"
                )
        else:
            # Report verdicts and retained records separately: safe ("no") findings
            # are dropped from the output set, so a "0 no" in the retained set would
            # otherwise read as "nothing was classified safe".
            StatusLogger.timestamped_print(
                f"Scan complete: {classified['yes']} yes, {classified['no']} no, "
                f"{classified['abstain']} abstain; "
                f"{_format_count(len(findings), 'finding')} retained"
            )
        
        # Log final abstain summary
        if abstain_count > 0 and self.llm_type != "none":
            StatusLogger.timestamped_print(f"Final abstain summary: {abstain_count} finding(s) could not be definitively classified")
            abstain_by_pass = {}
            for finding in findings:
                if finding.y2038_issue == Y2038Issue.ABSTAIN:
                    pass_name = finding.final_pass or "unknown"
                    abstain_by_pass[pass_name] = abstain_by_pass.get(pass_name, 0) + 1
            for pass_name, count in sorted(abstain_by_pass.items()):
                StatusLogger.timestamped_debug(f"  - {count} from {pass_name}")
        elif abstain_count > 0 and self.llm_type == "none":
            StatusLogger.timestamped_debug(
                f"Abstain breakdown (LLM disabled): {abstain_count} unclassified candidate(s)"
            )
        
        # Public findings JSON is written only by save_results(..., --out). A
        # standalone session also keeps a bare-array copy under findings/; batch
        # mode does not, since the published findings.json is a superset.
        
        # Save session metadata and findings (for function-first path)
        # Legacy path does this in _run_legacy_analysis, but function-first needs it here
        api_llm_type = (
            self.function_llm_client.llm_type
            if hasattr(self, "function_llm_client")
            else self.llm_type
        )
        api_model = (
            self.function_llm_client.model
            if hasattr(self, "function_llm_client")
            else self.model
        )
        # CLI still has a default --model for when LLM is enabled; do not
        # attribute that model to discovery-only (--llm none) provenance.
        reported_model = "none" if api_llm_type == "none" else api_model
        pipeline_mode = "function-first" if self.function_first else reported_model

        config = {
            "llm_type": api_llm_type,
            "llm_model": reported_model,
            "model": pipeline_mode,
            "model_version": "unknown",
            "confidence_floor": self.confidence_floor,
            "batch_size_pass1": self.batch_size_pass1,
            "batch_size_pass2": self.batch_size_pass2,
            "batch_size_pass3": self.batch_size_pass3,
            "token_budget": self.token_budget,
        }
        
        versions = {
            "scanner_cli": TACS_VERSION,
            "tii_script": "y2038scan_fast_json_group.py@unknown",
            "prompt_pack": "pp-v1",
            "rules": f"{Path(rules_path).name}@unknown"
        }
        
        session.save_metadata(config, metrics.dict(), versions)
        
        # Collect token statistics
        token_stats = self._collect_token_stats()
        
        # Create summary
        summary = f"""Y2038 Scan Summary
==================

Scan ID: {session.scan_id}
Created: {session.created_utc}
Root: {root_path}

Metrics:
- Files: {metrics.total_files}
- Lines: {metrics.total_lines}
- Characters: {metrics.total_chars}

Pipeline Results:
- Classified: {classified['yes']} yes, {classified['no']} no, {classified['abstain']} abstain
- Retained findings: {len(findings)}
  - Yes: {yes_count}
  - No: {no_count}
  - Abstain: {abstain_count}"""
        
        # Add token statistics to summary
        if token_stats:
            total_tokens = token_stats.get("total_tokens", 0)
            total_prompt = token_stats.get("total_prompt_tokens", 0)
            total_completion = token_stats.get("total_completion_tokens", 0)
            total_requests = token_stats.get("total_requests", 0)
            
            summary += f"""

Token Usage:
- Total tokens: {total_tokens:,}
  - Prompt tokens: {total_prompt:,}
  - Completion tokens: {total_completion:,}
- Total LLM requests: {total_requests}"""
            
            # Add per-stage breakdown
            by_stage = token_stats.get("by_stage", {})
            if by_stage:
                summary += "\n- Per stage/pass:"
                for stage_name, stage_stats in sorted(by_stage.items()):
                    stage_prompt = stage_stats.get("prompt_tokens", 0)
                    stage_completion = stage_stats.get("completion_tokens", 0)
                    stage_total = stage_prompt + stage_completion
                    stage_requests = stage_stats.get("requests", 0)
                    summary += f"\n  - {stage_name}: {stage_total:,} tokens ({stage_prompt:,} prompt + {stage_completion:,} completion) in {stage_requests} request(s)"
        
        # Add legacy-specific details if available
        if hasattr(session, '_legacy_pipeline_info') and session._legacy_pipeline_info:
            info = session._legacy_pipeline_info
            summary += f"""
- Candidates found: {info.get('candidates_count', 0)}
- After structural filter: {info.get('filtered_candidates_count', 0)}
- Stage S1, Pass P1 survivors: {info.get('stage_s1_pass_p1_survivors', 0)}
- Stage S1, Pass P1 dropped: {info.get('stage_s1_pass_p1_dropped', 0)}
"""
        
        summary += f"""
Timing (ms):
- Total: {session.timing.get('total_ms', 0)}
- Metrics: {session.timing.get('metrics_ms', 0)}
- Prescan: {session.timing.get('prescan_ms', 0)}
- IR: {session.timing.get('ir_ms', 0)}
"""
        if self.function_first:
            summary += f"- Functionization: {session.timing.get('functionization_ms', 0)}\n"
            summary += f"- Stage 8, Pass 2a: {session.timing.get('stage_s2_pass_p1_ms', 0)}\n"
            summary += f"- Stage 8, Pass 2b: {session.timing.get('stage_s2_pass_p2_ms', 0)}\n"
            summary += f"- Stage 9, Pass 1: {session.timing.get('stage_s3_pass_p1_ms', 0)}\n"
        else:
            summary += f"- Stage 7, Pass 1: {session.timing.get('stage_s1_pass_p1_ms', 0)}\n"
            summary += f"- Stage 8, Pass 2a: {session.timing.get('stage_s2_pass_p1_ms', 0)}\n"
            summary += f"- Stage 9, Pass 1: {session.timing.get('stage_s3_pass_p1_ms', 0)}\n"
        
        session.save_stage_stats(self._build_stage_stats(session, token_stats))
        session.save_findings([f.dict() for f in findings], summary)
        session.create_latest_symlink()
        session.update_index()
        
        session.log_message("INFO", f"Scan completed: {len(findings)} final findings")
        
        # Create scan metadata
        metadata = ScanMetadata(
            root=root_path,
            rules_path=rules_path,
            model=reported_model,
            confidence_floor=self.confidence_floor,
            metrics=metrics,
            timestamp=datetime.utcnow().isoformat() + "Z",
            environment_config=self.environment_config
        )
        
        return ScanResults(
            meta=metadata,
            findings=findings
        )
    
    def _run_legacy_analysis(self, candidates: List[Candidate], session: ScanSession) -> List[Finding]:
        """Run legacy analysis pipeline."""
        StatusLogger.timestamped_print("Running legacy analysis...")
        
        # Stage S1: Line-level analysis, Pass P1 (single-line triage) - BYPASSABLE
        session.start_timing("stage_s1_pass_p1")
        
        # Create a mapping from response ID to original candidate (needed for Stage S2)
        candidate_map = {}
        for candidate in candidates:
            candidate_id = f"{candidate.file}:{candidate.line}"
            candidate_map[candidate_id] = candidate
        
        if self.bypass_pass1:
            StatusLogger.timestamped_print("Bypassing Stage S1 (line-level), Pass P1 - sending all candidates to Stage S2")
            # Create mock responses for all candidates to send to Stage S2
            pass1_responses = []
            for candidate in candidates:
                mock_response = LLMResponse(
                    id=f"{candidate.file}:{candidate.line}",
                    y2038_issue=Y2038Issue.ABSTAIN,  # All go to Stage S2
                    severity=None,
                    confidence=0.0,
                    reason="Stage S1, Pass P1 bypassed - sent to Stage S2",
                    needs_more_context=True,
                    line=candidate.line,
                    col_start=candidate.col_start or 0,
                    col_end=candidate.col_end or 0
                )
                pass1_responses.append(mock_response)
            
            # All candidates are "survivors" when Stage S1 is bypassed
            survivors = pass1_responses
            dropped = []
        else:
            StatusLogger.timestamped_print("Running Stage S1 (line-level), Pass P1...")
            pass1_responses = self.llm_client.classify_candidates(
                candidates, self.batch_size_pass1
            )
            
            # Filter responses based on confidence floor
            survivors = []
            dropped = []
            for response in pass1_responses:
                if (response.y2038_issue == Y2038Issue.NO or 
                    (response.y2038_issue == Y2038Issue.YES and response.confidence < self.confidence_floor)):
                    dropped.append(response)
                else:
                    survivors.append(response)
        
        StatusLogger.timestamped_print(f"Stage S1, Pass P1: {len(survivors)} survivors, {len(dropped)} dropped")
        session.end_timing("stage_s1_pass_p1")
        session.log_message("INFO", f"Stage S1, Pass P1: {len(survivors)} survivors, {len(dropped)} dropped")
        
        # Stage S2: Function-level analysis, Pass P1 (widened region context)
        session.start_timing("stage_s2_pass_p1")
        StatusLogger.timestamped_print("Running Stage S2 (function-level), Pass P1 (widened context)...")
        pass2_findings = self.pass2_widened_region_context(survivors, candidate_map)
        session.end_timing("stage_s2_pass_p1")
        
        # Stage S3: File-level analysis, Pass P1 (file leading context) - BYPASSABLE
        session.start_timing("stage_s3_pass_p1")
        if self.bypass_pass3:
            StatusLogger.timestamped_print("Bypassing Stage S3 (file-level), Pass P1 - stopping after Stage S2")
            final_findings = pass2_findings
        else:
            StatusLogger.timestamped_print("Running Stage S3 (file-level), Pass P1 (file context)...")
            final_findings = self.pass3_file_leading_context(pass2_findings, candidate_map)
        session.end_timing("stage_s3_pass_p1")
        
        # Store legacy-specific data in session for summary generation
        # Note: Session cleanup (save_metadata, save_findings, create_latest_symlink, update_index)
        # is now handled in _create_scan_results() which is called after this method returns.
        # This ensures both function-first and legacy paths have consistent cleanup.
        
        # Store legacy pipeline info for summary
        if not hasattr(session, '_legacy_pipeline_info'):
            session._legacy_pipeline_info = {}
        session._legacy_pipeline_info.update({
            'candidates_count': len(candidates),
            'filtered_candidates_count': len(candidates),  # In legacy pipeline, candidates are already filtered
            'stage_s1_pass_p1_survivors': len(survivors),
            'stage_s1_pass_p1_dropped': len(dropped)
        })
        
        return final_findings
    
    def pass2_widened_region_context(self, survivors: List[LLMResponse], candidate_map: Dict[str, Candidate]) -> List[Finding]:
        """
        Stage S2, Pass P1: Widened region context - provides more context for abstain candidates.
        
        Args:
            survivors: Candidates that survived Stage S1, Pass P1
            candidate_map: Mapping from response ID to original candidate
            
        Returns:
            List of findings with improved context
        """
        # Filter to only abstain candidates that need more context
        abstain_candidates = []
        for response in survivors:
            if response.y2038_issue == Y2038Issue.ABSTAIN:
                candidate = candidate_map.get(response.id)
                if candidate is None:
                    # Try to find candidate with flexible matching
                    candidate = self._find_candidate_flexible(response.id, candidate_map)
                abstain_candidates.append((response, candidate))
        
        if not abstain_candidates:
            StatusLogger.timestamped_print("Stage S2, Pass P1: No abstain candidates need widened context")
            # Convert survivors to findings without additional processing
            return self._convert_responses_to_findings(survivors, candidate_map)
        
        StatusLogger.timestamped_print(f"Stage S2, Pass P1: Processing {len(abstain_candidates)} abstain candidates with widened context")
        
        # Debug: Show detailed candidate information
        if self.debug_pass2_detailed:
            StatusLogger.timestamped_print("=== DETAILED STAGE S2, PASS P1 DEBUG INFO ===")
            for i, (response, candidate) in enumerate(abstain_candidates):
                StatusLogger.timestamped_print(f"Candidate {i+1}/{len(abstain_candidates)}:")
                StatusLogger.timestamped_print(f"  ID: {response.id}")
                StatusLogger.timestamped_print(
                    f"  File: {self._display_path(candidate.file) if candidate else 'MISSING'}"
                )
                StatusLogger.timestamped_print(f"  Line: {candidate.line if candidate else 'MISSING'}")
                StatusLogger.timestamped_print(f"  Symbol: {candidate.symbol if candidate else 'MISSING'}")
                if candidate:
                    widened_context = self._extract_widened_context(candidate, context_lines=5)
                    StatusLogger.timestamped_print(f"  Full Context:")
                    # Show more context, not truncated
                    context_lines = widened_context.split('\n')
                    for line in context_lines:
                        StatusLogger.timestamped_print(f"    {line}")
                StatusLogger.timestamped_print("")
        
        # Debug: Check candidate map coverage
        missing_candidates = 0
        flexible_matches = 0
        for response, candidate in abstain_candidates:
            if candidate is None:
                missing_candidates += 1
            elif response.id not in candidate_map:
                flexible_matches += 1
        
        if missing_candidates > 0:
            StatusLogger.timestamped_warning(f"{missing_candidates} abstain candidates still missing from candidate_map")
            # Show sample missing IDs and available keys for debugging
            missing_ids = [r.id for r, c in abstain_candidates if c is None][:5]
            available_keys = list(candidate_map.keys())[:5]
            StatusLogger.timestamped_print(f"  Sample missing IDs: {missing_ids}")
            StatusLogger.timestamped_print(f"  Sample available keys: {available_keys}")
        if flexible_matches > 0:
            StatusLogger.timestamped_print(f"Info: {flexible_matches} candidates found using flexible matching")
        
        # Process abstain candidates with widened context
        findings = []
        
        # Process in batches for Stage S2, Pass P1
        batch_size = self.batch_size_pass2
        total_batches = (len(abstain_candidates) + batch_size - 1) // batch_size
        
        for i in range(0, len(abstain_candidates), batch_size):
            batch = abstain_candidates[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            StatusLogger.timestamped_print(f"Processing Stage S2, Pass P1 batch of {len(batch)} candidates with widened context (batch {batch_num} of {total_batches})...")
            batch_findings = self._process_pass2_batch(batch)
            findings.extend(batch_findings)
        
        # Log Stage S2, Pass P1 results
        yes_count = sum(1 for f in findings if f.y2038_issue == Y2038Issue.YES)
        no_count = sum(1 for f in findings if f.y2038_issue == Y2038Issue.NO)
        abstain_count = sum(1 for f in findings if f.y2038_issue == Y2038Issue.ABSTAIN)
        StatusLogger.timestamped_print(f"Stage S2, Pass P1: {yes_count} yes, {no_count} no, {abstain_count} abstain")
        
        # Add non-abstain survivors as findings
        non_abstain_findings = self._convert_responses_to_findings(
            [r for r in survivors if r.y2038_issue != Y2038Issue.ABSTAIN],
            candidate_map
        )
        findings.extend(non_abstain_findings)
        
        return findings
    
    def _find_candidate_flexible(self, response_id: str, candidate_map: dict) -> Optional[Candidate]:
        """Find candidate with flexible ID matching."""
        # Try exact match first
        if response_id in candidate_map:
            return candidate_map[response_id]
        
        # Try to extract file and line from response ID
        try:
            if ':' in response_id:
                file_part, line_part = response_id.rsplit(':', 1)
                line_num = int(line_part)
                
                # Try different path variations
                variations = [
                    file_part,
                    file_part.replace('\\', '/'),
                    file_part.replace('/', '\\'),
                    os.path.basename(file_part),
                    repo_relative_path(file_part, self.root_path),
                ]
                
                for variation in variations:
                    candidate_id = f"{variation}:{line_num}"
                    if candidate_id in candidate_map:
                        return candidate_map[candidate_id]
                
                # Try partial matching on filename and line
                filename = os.path.basename(file_part)
                for key in candidate_map.keys():
                    if filename in key and f":{line_num}" in key:
                        return candidate_map[key]
                        
        except (ValueError, AttributeError):
            pass
        
        return None
    
    def _process_pass2_batch(self, batch: List[tuple]) -> List[Finding]:
        """Process a batch of abstain candidates with widened context."""
        # Prepare candidates with widened context
        context_candidates = []
        missing_candidates = []
        
        for response, candidate in batch:
            if candidate:
                widened_context = self._extract_widened_context(candidate, context_lines=5)
                context_candidates.append((response, candidate, widened_context))
            else:
                missing_candidates.append(response.id)
        
        # Debug: Show which candidates are missing
        if missing_candidates and self.debug_pass2:
            StatusLogger.timestamped_print(f"  Batch: {len(missing_candidates)} candidates missing context (IDs: {missing_candidates[:3]}{'...' if len(missing_candidates) > 3 else ''})")
        
        if not context_candidates:
            StatusLogger.timestamped_print(f"  Batch: No valid candidates to process")
            return []
        
        # Use LLM to re-evaluate with widened context
        try:
            llm_responses = self.llm_client.classify_candidates_pass2(context_candidates)
            
            # Convert to findings
            findings = []
            for i, (original_response, candidate, context) in enumerate(context_candidates):
                if i < len(llm_responses):
                    llm_response = llm_responses[i]
                else:
                    # Fallback if we don't get enough responses
                    llm_response = original_response
                
                finding = self._create_finding_from_response(llm_response, candidate)
                findings.append(finding)
            
            return findings
            
        except Exception as e:
            StatusLogger.timestamped_error(f"Stage S2, Pass P1 LLM processing failed: {e}")
            # Fallback to original responses
            return [self._create_finding_from_response(response, candidate) 
                   for response, candidate, _ in context_candidates]
    
    def _extract_widened_context(self, candidate: Candidate, context_lines: int = 5) -> str:
        """
        Extract widened context around a candidate, preferring full functions.
        
        Args:
            candidate: The candidate to extract context for
            context_lines: Fallback number of lines if function detection fails
            
        Returns:
            Context string with line numbers
        """
        try:
            file_path = Path(candidate.file)
            if not file_path.exists():
                return candidate.one_line_snippet
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            if not lines:
                return f"Could not read file: {candidate.file}"
            
            # Try to find the function containing this line
            function_context = self._extract_function_context(lines, candidate.line)
            if function_context:
                return function_context
            
            # Fallback to line-based context
            return self._extract_line_context(lines, candidate.line, context_lines)
            
        except Exception as e:
            return f"Error reading file {candidate.file}: {e}"
    
    def _extract_function_context(self, lines: List[str], target_line: int) -> Optional[str]:
        """
        Extract the full function containing the target line.
        
        Args:
            lines: All lines from the file
            target_line: The line number we're interested in (1-indexed)
            
        Returns:
            Function context string or None if no function found
        """
        # Convert to 0-indexed
        target_idx = target_line - 1
        
        # Find function start (look backwards for function signature)
        function_start = None
        
        # Look backwards from target line for function start
        for i in range(target_idx, -1, -1):
            line = lines[i].strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('//') or line.startswith('/*') or line.startswith('*'):
                continue
            
            # Look for function signature patterns - more specific detection
            if (line.endswith('{') and 
                ('static' in line or 'extern' in line or 
                 any(keyword in line for keyword in ['int ', 'void ', 'char ', 'struct ', 'enum ', 'float ', 'double ', 'long ', 'short ', 'unsigned ', 'signed ']) and
                 '(' in line and ')' in line)):
                function_start = i
                break
        
        if function_start is None:
            return None
        
        # Find function end (look forwards for matching closing brace)
        function_end = None
        brace_count = 1  # We already found the opening brace
        
        for i in range(function_start + 1, len(lines)):
            line = lines[i]
            brace_count += line.count('{') - line.count('}')
            
            if brace_count == 0:
                function_end = i
                break
        
        if function_end is None:
            return None
        
        # Verify that the target line is within the function
        if target_line < function_start + 1 or target_line > function_end + 1:
            return None
        
        # Extract function (limit to 100 lines max)
        function_lines = lines[function_start:function_end + 1]
        if len(function_lines) > 100:
            # Take first 100 lines if function is too long
            function_lines = function_lines[:100]
            truncated = True
        else:
            truncated = False
        
        # Build context string
        context_parts = []
        for i, line in enumerate(function_lines):
            line_num = function_start + i + 1
            marker = ">>>" if line_num == target_line else "   "
            context_parts.append(f"{marker} {line_num:4d}: {line.rstrip()}")
        
        context = '\n'.join(context_parts)
        
        if truncated:
            context += "\n... [function truncated at 100 lines]"
        
        return context
    
    def _track_time_assignments(
        self,
        root_path: str,
        include_patterns: List[str],
        exclude_patterns: List[str]
    ) -> Dict[str, Set[str]]:
        """
        Track variables assigned from time functions (enhanced time-bearing detection).
        
        Patterns:
        - time_t t = time(NULL);
        - int64_t ts = (int64_t)time(NULL);
        - timestamp = get_time();
        
        Args:
            root_path: Root directory
            include_patterns: File include patterns
            exclude_patterns: File exclude patterns
        
        Returns:
            Dictionary mapping file_path -> set of time-bearing variable names
        """
        from fnmatch import fnmatch
        from pathlib import Path
        
        assignments: Dict[str, Set[str]] = {}
        root = Path(root_path)
        
        # Time function patterns
        time_function_pattern = re.compile(
            r'\b(time|gettimeofday|clock_gettime|localtime|gmtime)\s*\(',
            re.IGNORECASE
        )
        
        # Assignment pattern: type var = time_function(...);
        assignment_pattern = re.compile(
            r'(\w+(?:\s*\*)?)\s+(\w+)\s*=\s*(?:\([^)]+\)\s*)?(?:time|gettimeofday|clock_gettime|localtime|gmtime)\s*\(',
            re.IGNORECASE
        )
        
        # Get files
        all_files = []
        for pattern in include_patterns or ['**/*.c', '**/*.h']:
            for file_path in root.rglob(pattern.replace('**/', '')):
                if file_path.is_file():
                    all_files.append(file_path)
        
        # Filter by exclude patterns
        for file_path in all_files:
            rel_path = str(file_path.relative_to(root))
            if any(fnmatch(rel_path, pattern) for pattern in exclude_patterns or []):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                file_vars = set()
                for line in lines:
                    # Check for time function call
                    if time_function_pattern.search(line):
                        # Check for assignment
                        match = assignment_pattern.search(line)
                        if match:
                            var_name = match.group(2)
                            file_vars.add(var_name)
                
                if file_vars:
                    assignments[str(file_path)] = file_vars
            except Exception:
                continue
        
        return assignments
    
    def _attach_io_metadata_to_finding(self, finding: Finding, file_path: str, line_num: int) -> bool:
        """
        Attach I/O metadata to a finding if it exists for the given file:line.
        
        Args:
            finding: Finding to attach metadata to
            file_path: File path
            line_num: Line number
        
        Returns:
            True if metadata was attached, False otherwise
        """
        # Try different path formats
        import os
        candidate_ids = [
            f"{file_path}:{line_num}",
            f"{os.path.relpath(file_path)}:{line_num}",
            f"{os.path.basename(file_path)}:{line_num}",
        ]
        
        # Normalize paths (handle both / and \)
        normalized_ids = []
        for cid in candidate_ids:
            normalized_ids.append(cid)
            normalized_ids.append(cid.replace('\\', '/'))
            normalized_ids.append(cid.replace('/', '\\'))
        
        metadata = None
        matched_id = None
        for candidate_id in normalized_ids:
            if candidate_id in self.io_metadata_map:
                metadata = self.io_metadata_map[candidate_id]
                matched_id = candidate_id
                break
        
        if metadata:
            from tacs.core.schema import IOCandidateType, RemediationClass
            finding.io_category = IOCandidateType(metadata['io_category'])
            finding.io_function = metadata['io_function']
            finding.remediation_class = RemediationClass(metadata['remediation_class'])
            # Debug logging
            if self.debug_candidates:
                StatusLogger.timestamped_debug(f"  I/O metadata attached: {file_path}:{line_num} -> {matched_id} ({metadata['io_category']})")
            return True
        
        # Also check migration metadata
        if hasattr(self, 'migration_metadata') and self.migration_metadata:
            migration_key = f"{file_path}:{line_num}"
            # Try different path formats
            import os
            migration_keys = [
                migration_key,
                f"{os.path.relpath(file_path)}:{line_num}",
                f"{os.path.basename(file_path)}:{line_num}",
            ]
            for key in migration_keys:
                if key in self.migration_metadata:
                    migration_risks = self.migration_metadata[key]
                    # Attach first/most severe migration risk
                    if migration_risks:
                        risk = migration_risks[0]  # Take first for MVP
                        from tacs.core.schema import MigrationRiskType, MigrationSeverity
                        # Handle string values (from migration analyzer)
                        risk_type_val = risk.get('risk_type', '')
                        if isinstance(risk_type_val, str):
                            finding.migration_risk_type = MigrationRiskType(risk_type_val)
                        else:
                            finding.migration_risk_type = risk_type_val
                        
                        severity_val = risk.get('severity', '')
                        if isinstance(severity_val, str):
                            finding.migration_severity = MigrationSeverity(severity_val)
                        else:
                            finding.migration_severity = severity_val
                        
                        finding.migration_impact = risk.get('description')
                        finding.migration_remediation = risk.get('remediation')
                        if self.migration_from_config:
                            from tacs.core.config_validator import ConfigValidator
                            finding.from_config_id = ConfigValidator.get_config_id(self.migration_from_config)
                        if self.migration_to_config:
                            from tacs.core.config_validator import ConfigValidator
                            finding.to_config_id = ConfigValidator.get_config_id(self.migration_to_config)
                    break
        elif self.debug_candidates and line_num:  # Only log if we expected to find something
            # Check if any I/O metadata exists for this file (to see if it's a path mismatch)
            file_basename = os.path.basename(file_path)
            has_io_for_file = any(
                file_basename in key or file_path in key or os.path.basename(key.split(':')[0]) == file_basename
                for key in self.io_metadata_map.keys()
            )
            if has_io_for_file:
                StatusLogger.timestamped_debug(f"  I/O metadata NOT found for {file_path}:{line_num} (but I/O metadata exists for this file)")
                # Show what keys exist for this file
                matching_keys = [k for k in self.io_metadata_map.keys() if file_basename in k or file_path in k]
                if matching_keys:
                    StatusLogger.timestamped_debug(f"    Available keys for this file: {matching_keys[:3]}...")
        
        return False
    
    def _convert_io_candidate_to_candidate(self, io_cand: IOCandidate) -> Candidate:
        """
        Convert IOCandidate to Candidate for pipeline compatibility.
        
        Metadata is stored in separate mapping, not as candidate attribute,
        to ensure it survives serialization and pipeline transformations.
        """
        return Candidate(
            file=io_cand.file,
            line=io_cand.line,
            symbol=io_cand.symbol,
            one_line_snippet=io_cand.one_line_snippet,
            risk=io_cand.risk,
            description=io_cand.description,
            col_start=io_cand.col_start,
            col_end=io_cand.col_end,
            symbol_role=f"io_boundary_{io_cand.io_category.value}"
        )
    
    def _track_time_assignments(
        self,
        root_path: str,
        include_patterns: List[str],
        exclude_patterns: List[str]
    ) -> Dict[str, Set[str]]:
        """
        Track variables assigned from time functions (enhanced time-bearing detection).
        
        Patterns:
        - time_t t = time(NULL);
        - int64_t ts = (int64_t)time(NULL);
        - timestamp = get_time();
        
        Args:
            root_path: Root directory
            include_patterns: File include patterns
            exclude_patterns: File exclude patterns
        
        Returns:
            Dictionary mapping file_path -> set of time-bearing variable names
        """
        import re
        from fnmatch import fnmatch
        from pathlib import Path
        
        assignments: Dict[str, Set[str]] = {}
        root = Path(root_path)
        
        # Time function patterns
        time_function_pattern = re.compile(
            r'\b(time|gettimeofday|clock_gettime|localtime|gmtime)\s*\(',
            re.IGNORECASE
        )
        
        # Assignment pattern: type var = time_function(...);
        assignment_pattern = re.compile(
            r'(\w+(?:\s*\*)?)\s+(\w+)\s*=\s*(?:\([^)]+\)\s*)?(?:time|gettimeofday|clock_gettime|localtime|gmtime)\s*\(',
            re.IGNORECASE
        )
        
        # Get files
        all_files = []
        for pattern in include_patterns or ['**/*.c', '**/*.h']:
            for file_path in root.rglob(pattern.replace('**/', '')):
                if file_path.is_file():
                    all_files.append(file_path)
        
        # Filter by exclude patterns
        for file_path in all_files:
            rel_path = str(file_path.relative_to(root))
            if any(fnmatch(rel_path, pattern) for pattern in exclude_patterns or []):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                file_vars = set()
                for line in lines:
                    # Check for time function call
                    if time_function_pattern.search(line):
                        # Check for assignment
                        match = assignment_pattern.search(line)
                        if match:
                            var_name = match.group(2)
                            file_vars.add(var_name)
                
                if file_vars:
                    assignments[str(file_path)] = file_vars
            except Exception:
                continue
        
        return assignments
    
    def _extract_line_context(self, lines: List[str], target_line: int, context_lines: int) -> str:
        """
        Extract line-based context as fallback.
        
        Args:
            lines: All lines from the file
            target_line: The line number we're interested in (1-indexed)
            context_lines: Number of lines before/after to include
            
        Returns:
            Context string with line numbers
        """
        start_line = max(1, target_line - context_lines)
        end_line = min(len(lines), target_line + context_lines)
        
        context_parts = []
        for i in range(start_line - 1, end_line):
            line_num = i + 1
            marker = ">>>" if line_num == target_line else "   "
            context_parts.append(f"{marker} {line_num:4d}: {lines[i].rstrip()}")
        
        return '\n'.join(context_parts)
    
    def _convert_responses_to_findings(self, responses: List[LLMResponse], candidate_map: Dict[str, Candidate]) -> List[Finding]:
        """Convert LLM responses to findings."""
        findings = []
        for response in responses:
            candidate = candidate_map.get(response.id)
            finding = self._create_finding_from_response(response, candidate)
            findings.append(finding)
        return findings
    
    def _create_finding_from_response(self, response: LLMResponse, candidate: Optional[Candidate]) -> Finding:
        """Create a finding from an LLM response and candidate."""
        # Extract file and line from response ID
        try:
            file_path, line_str = response.id.split(':', 1)
            line_num = int(line_str)
        except (ValueError, IndexError):
            # Fallback for malformed IDs
            file_path = "unknown"
            line_num = 0
        
        finding = Finding(
            file=file_path,
            region={"start_line": line_num, "end_line": line_num},
            lines=[line_num],
            symbol=candidate.symbol if candidate else "unknown",
            severity=response.severity,
            confidence=response.confidence,
            reason=response.reason,
            scenario=None,
            preprocessor_context=[],
            source_snippet=candidate.one_line_snippet if candidate else "",
            y2038_issue=response.y2038_issue,
            needs_more_context=response.needs_more_context or response.y2038_issue == Y2038Issue.ABSTAIN
        )
        
        # Add I/O metadata if present (look up in mapping)
        # Try both candidate-based ID and response.id (which is the canonical identifier)
        candidate_id = None
        if candidate:
            candidate_id = f"{candidate.file}:{candidate.line}"
        
        # Also try response.id directly (canonical format)
        response_id = response.id if hasattr(response, 'id') else None
        
        # Check both IDs in the metadata map
        metadata = None
        if candidate_id and candidate_id in self.io_metadata_map:
            metadata = self.io_metadata_map[candidate_id]
        elif response_id and response_id in self.io_metadata_map:
            metadata = self.io_metadata_map[response_id]
        
        if metadata:
            from tacs.core.schema import IOCandidateType, RemediationClass
            finding.io_category = IOCandidateType(metadata['io_category'])
            finding.io_function = metadata['io_function']
            finding.remediation_class = RemediationClass(metadata['remediation_class'])
            # LLM may provide impact analysis in response.reason
            # Could parse or extract from reason field in future
        
        return finding
    
    def pass3_file_leading_context(self, unresolved: List[Finding], candidate_map: Dict[str, Candidate]) -> List[Finding]:
        """
        Stage S3, Pass P1: Analyze with full file context.
        
        Args:
            unresolved: Findings that need more context
            candidate_map: Mapping from response ID to original candidate
            
        Returns:
            List of findings with final decisions
        """
        # Filter to only abstain findings
        abstain_findings = [
            finding for finding in unresolved
            if finding.y2038_issue == Y2038Issue.ABSTAIN
        ]
        
        if not abstain_findings:
            StatusLogger.timestamped_print("Stage S3, Pass P1: No abstain findings need file context")
            return unresolved
        
        StatusLogger.timestamped_print(f"Stage S3, Pass P1: Processing {len(abstain_findings)} abstain findings with file context")
        
        # Group findings by file to avoid reading the same file multiple times
        file_groups = {}
        for finding in abstain_findings:
            # Use file path directly from finding
            file_path = finding.file
            if file_path not in file_groups:
                file_groups[file_path] = []
            file_groups[file_path].append(finding)
        
        StatusLogger.timestamped_print(f"Stage S3, Pass P1: Grouped into {len(file_groups)} unique files")
        
        # Process each file group
        all_findings = []
        for file_path, findings_in_file in file_groups.items():
            file_findings = self._process_file_group_pass3(file_path, findings_in_file, candidate_map)
            all_findings.extend(file_findings)
        
        # Add non-abstain findings unchanged
        non_abstain_findings = [
            finding for finding in unresolved
            if finding.y2038_issue != Y2038Issue.ABSTAIN
        ]
        all_findings.extend(non_abstain_findings)
        
        # Log Stage S3, Pass P1 results
        yes_count = sum(1 for f in all_findings if f.y2038_issue == Y2038Issue.YES)
        no_count = sum(1 for f in all_findings if f.y2038_issue == Y2038Issue.NO)
        abstain_count = sum(1 for f in all_findings if f.y2038_issue == Y2038Issue.ABSTAIN)
        StatusLogger.timestamped_print(f"Stage S3, Pass P1: {yes_count} yes, {no_count} no, {abstain_count} abstain")
        
        return all_findings
    
    def _process_file_group_pass3(self, file_path: str, findings_in_file: List[Finding], candidate_map: Dict[str, Candidate]) -> List[Finding]:
        """Process a group of findings from the same file with full file context."""
        try:
            # Read the full file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_content = f.read()
            
            # Limit file size to prevent token overflow (practical limit)
            max_file_size = 200000  # ~200KB (increased from 50KB)
            if len(file_content) > max_file_size:
                StatusLogger.timestamped_print(
                    f"  File {self._display_path(file_path)} too large "
                    f"({len(file_content)} chars), truncating to {max_file_size}"
                )
                file_content = file_content[:max_file_size] + "\n... [truncated]"
            
            # Prepare candidates with file content
            file_candidates = []
            for finding in findings_in_file:
                # Create ID from file and first line number
                finding_id = f"{finding.file}:{finding.lines[0]}" if finding.lines else f"{finding.file}:0"
                candidate = candidate_map.get(finding_id)
                if candidate:
                    # Create a mock response for the LLM client
                    mock_response = LLMResponse(
                        id=finding_id,
                        y2038_issue=finding.y2038_issue,
                        confidence=finding.confidence,
                        reason=finding.reason,
                        needs_more_context=finding.needs_more_context,
                        line=candidate.line,
                        col_start=candidate.col_start,
                        col_end=candidate.col_end
                    )
                    file_candidates.append((mock_response, candidate, file_content))
            
            if not file_candidates:
                StatusLogger.timestamped_print(
                    f"  No valid candidates found for file {self._display_path(file_path)}"
                )
                return findings_in_file
            
            # Use LLM to re-evaluate with full file context
            try:
                llm_responses = self.llm_client.classify_candidates_pass3(file_candidates)
                
                # Convert responses back to findings
                findings = []
                for i, (original_finding, candidate, file_content) in enumerate(file_candidates):
                    if i < len(llm_responses):
                        response = llm_responses[i]
                        finding = self._create_finding_from_response(response, candidate)
                        findings.append(finding)
                    else:
                        # Fallback if response count doesn't match
                        findings.append(original_finding)
                
                return findings
                
            except Exception as e:
                StatusLogger.timestamped_error(
                    f"  Stage S3, Pass P1 LLM processing failed for {self._display_path(file_path)}: {e}"
                )
                return findings_in_file
                
        except Exception as e:
            StatusLogger.timestamped_error(f"  Failed to read file {file_path}: {e}")
            return findings_in_file
    
    def save_results(self, results: ScanResults, output_path: str):
        """
        Save scan results to JSON file.
        
        Args:
            results: Scan results to save
            output_path: Path to output file
        """
        def _model_to_dict(obj):
            return obj.model_dump() if hasattr(obj, 'model_dump') else obj.dict()

        def _finding_to_dict(finding: Finding) -> Dict[str, Any]:
            """Serialize one finding to a JSON-safe dict; ensure function_id is always a string."""
            try:
                d = _model_to_dict(finding)
            except Exception:
                d = finding.__dict__ if hasattr(finding, '__dict__') else {}
            if isinstance(d, dict):
                fid = d.get('function_id')
                if fid is None or (isinstance(fid, str) and not fid.strip()):
                    d['function_id'] = 'unknown'
                elif not isinstance(fid, str):
                    d['function_id'] = str(fid)
            return d

        try:
            out = {
                'meta': _model_to_dict(results.meta),
                'findings': [_finding_to_dict(f) for f in results.findings],
            }
        except Exception:
            # Fallback: build manually so serialization never fails
            out = {
                'meta': _model_to_dict(results.meta),
                'findings': [],
            }
            for f in results.findings:
                try:
                    out['findings'].append(_finding_to_dict(f))
                except Exception:
                    out['findings'].append({
                        'file': getattr(f, 'file', ''),
                        'region': getattr(f, 'region', {}),
                        'function_id': str(getattr(f, 'function_id', None) or 'unknown'),
                        'y2038_issue': getattr(getattr(f, 'y2038_issue', None), 'value', 'abstain'),
                        'confidence': getattr(f, 'confidence', 0.0),
                        'reason': getattr(f, 'reason', ''),
                    })

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2)
