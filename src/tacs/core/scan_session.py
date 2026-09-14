# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import hashlib
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from collections import defaultdict


class ScanSession:
    """Manages a single scan session with structured logging."""
    
    def __init__(
        self,
        root_path: str,
        enable_llm_logging: bool = False,
        redact_prompts: bool = True,
        allow_raw_code_logging: bool = False,
        output_base: Optional[Union[str, Path]] = None,
    ):
        """
        Initialize a scan session.
        
        Args:
            root_path: Root directory being scanned
            enable_llm_logging: Whether to log LLM inputs/outputs
            redact_prompts: Whether to redact prompts in logs
            allow_raw_code_logging: Whether to allow raw code snippets
            output_base: If set, scan folder is created under this path (absolute).
                        Use this when running under a job working dir so paths don't depend on process cwd.
        """
        self.root_path = Path(root_path).resolve()
        self.enable_llm_logging = enable_llm_logging
        self.redact_prompts = redact_prompts
        self.allow_raw_code_logging = allow_raw_code_logging
        self._output_base = Path(output_base).resolve() if output_base else None
        
        # Generate scan ID and timestamp
        self.scan_id = self._generate_scan_id()
        self.created_utc = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
        
        # Create scan folder (absolute when output_base set, so concurrent jobs don't clash on cwd)
        rel_folder = f"results/scans/{self.created_utc}_scan-{self.scan_id}"
        if self._output_base is not None:
            self.scan_folder = (self._output_base / rel_folder).resolve()
        else:
            self.scan_folder = Path(rel_folder)
        self.scan_folder.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        self.prescan_dir = self.scan_folder / "prescan"
        self.ir_dir = self.scan_folder / "ir"
        self.llm_dir = self.scan_folder / "llm"
        self.findings_dir = self.scan_folder / "findings"
        self.artifacts_dir = self.scan_folder / "artifacts"
        self.logs_dir = self.scan_folder / "logs"
        
        for dir_path in [self.prescan_dir, self.ir_dir, self.llm_dir, self.findings_dir, 
                        self.artifacts_dir, self.logs_dir]:
            dir_path.mkdir(exist_ok=True)
        
        # Create LLM pass subdirectories
        if self.enable_llm_logging:
            for pass_num in [1, 2, 3]:
                pass_dir = self.llm_dir / f"pass{pass_num}"
                pass_dir.mkdir(exist_ok=True)
                (pass_dir / "batches").mkdir(exist_ok=True)
        
        # Initialize tracking
        self.timing = {}
        self.id_mappings = defaultdict(dict)
        self.batch_counters = {1: 0, 2: 0, 3: 0}
        
        # Start timing
        self.start_time = time.time()
        
        # Create README
        self._create_readme()
    
    def _generate_scan_id(self) -> str:
        """Generate a short unique scan ID."""
        timestamp = str(int(time.time()))
        return hashlib.md5(timestamp.encode()).hexdigest()[:6]
    
    def _create_readme(self):
        """Create README.txt for the scan folder."""
        readme_content = f"""Y2038 Scanner Session
====================

Scan ID: {self.scan_id}
Created: {self.created_utc}
Root: {self.root_path}

Folder Structure:
- meta.json: Scan metadata and timing
- config.snapshot.json: CLI args and resolved config
- metrics.json: Stage 1 code metrics
- ids.json: Stable ID mappings across passes
- prescan/: Typedef and macro discovery results
- ir/: Token inverted index results
- llm/: LLM pass inputs/outputs (if enabled)
- findings/: Final findings and summary
- artifacts/: Raw code snippets (if allowed)
- logs/: Execution logs

This scan session contains all data needed for debugging, review, and fine-tuning.
"""
        
        with open(self.scan_folder / "README.txt", 'w') as f:
            f.write(readme_content)
    
    def start_timing(self, stage: str):
        """Start timing a stage."""
        self.timing[f"{stage}_start"] = time.time()
    
    def end_timing(self, stage: str):
        """End timing a stage."""
        start_key = f"{stage}_start"
        if start_key in self.timing:
            duration_ms = int((time.time() - self.timing[start_key]) * 1000)
            self.timing[f"{stage}_ms"] = duration_ms
    
    def log_typedef(self, alias: str, resolves_to: str, depth: int, defined_in: str, line: int):
        """Log a typedef discovery."""
        entry = {
            "alias": alias,
            "resolves_to": resolves_to,
            "depth": depth,
            "defined_in": self._make_relative_path(defined_in),
            "line": line
        }
        
        typedef_file = self.prescan_dir / "typedefs.jsonl"
        try:
            with open(typedef_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
                f.flush()  # Ensure data is written immediately
        except Exception as e:
            # Log error but don't fail the scan
            import sys
            print(f"Warning: Failed to log typedef to {typedef_file}: {e}", file=sys.stderr)
    
    def log_macro(self, macro: str, value: str, defined_in: str, line: int):
        """Log a macro discovery."""
        entry = {
            "macro": macro,
            "value": value,
            "defined_in": self._make_relative_path(defined_in),
            "line": line
        }
        
        with open(self.prescan_dir / "defines.jsonl", 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def log_candidate(self, candidate_id: str, file: str, line: int, col_start: int, col_end: int, 
                     symbol: str, rule: str, snippet: str):
        """Log an IR candidate."""
        entry = {
            "id": candidate_id,
            "file": self._make_relative_path(file),
            "line": line,
            "col_start": col_start,
            "col_end": col_end,
            "symbol": symbol,
            "rule": rule,
            "one_line_snippet": snippet
        }
        
        with open(self.ir_dir / "candidates.jsonl", 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def log_llm_input(self, pass_num: int, batch_items: List[Dict[str, Any]], preamble_hash: str, model: str):
        """Log LLM input batch."""
        if not self.enable_llm_logging:
            return
        
        self.batch_counters[pass_num] += 1
        batch_num = f"{self.batch_counters[pass_num]:04d}"
        
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        for item in batch_items:
            entry = {
                "scan_id": self.scan_id,
                "batch": batch_num,
                "pass": pass_num,
                "model": model,
                "preamble_hash": preamble_hash,
                "item": item,
                "timestamp": timestamp
            }
            
            with open(self.llm_dir / f"pass{pass_num}" / "batches" / f"{batch_num}_input.jsonl", 'a') as f:
                f.write(json.dumps(entry) + '\n')
    
    def log_llm_output(self, pass_num: int, batch_results: List[Dict[str, Any]], model: str, 
                      request_tokens: int, response_tokens: int, latency_ms: int):
        """Log LLM output batch."""
        if not self.enable_llm_logging:
            return
        
        batch_num = f"{self.batch_counters[pass_num]:04d}"
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        for result in batch_results:
            entry = {
                "scan_id": self.scan_id,
                "batch": batch_num,
                "pass": pass_num,
                "model": model,
                "request_tokens": request_tokens,
                "response_tokens": response_tokens,
                "latency_ms": latency_ms,
                "timestamp": timestamp,
                **result
            }
            
            with open(self.llm_dir / f"pass{pass_num}" / "batches" / f"{batch_num}_output.jsonl", 'a') as f:
                f.write(json.dumps(entry) + '\n')
    
    def log_id_mapping(self, pass_from: str, pass_to: str, mappings: Dict[str, str]):
        """Log ID mappings between passes."""
        self.id_mappings[f"{pass_from}_to_{pass_to}"] = mappings
    
    def save_metadata(self, config: Dict[str, Any], metrics: Dict[str, Any], versions: Dict[str, str]):
        """Save scan metadata."""
        total_duration_ms = int((time.time() - self.start_time) * 1000)
        
        meta = {
            "scan_id": self.scan_id,
            "created_utc": self.created_utc,
            "root": str(self.root_path),
            "version": versions,
            "models": {
                "llm_type": config.get("llm_type"),
                "llm_model": (
                    "none"
                    if config.get("llm_type") == "none"
                    else (config.get("llm_model") or config.get("model", "none"))
                ),
                "llm_name": (
                    "none"
                    if config.get("llm_type") == "none"
                    else (config.get("llm_model") or config.get("model", "none"))
                ),
                "llm_version": config.get("model_version", "unknown"),
            },
            "limits": {
                "confidence_floor": config.get("confidence_floor", 0.6),
                "batch_pass1": config.get("batch_size_pass1", 100),
                "batch_pass2": config.get("batch_size_pass2", 40),
                "batch_pass3": config.get("batch_size_pass3", 20),
                "token_budget_scan": config.get("token_budget", 250000)
            },
            "flags": {
                "log_llm": self.enable_llm_logging,
                "redact_prompts": self.redact_prompts,
                "allow_raw_code_logging": self.allow_raw_code_logging
            },
            "timing_ms": {
                "total": total_duration_ms,
                **{k: v for k, v in self.timing.items() if k.endswith("_ms")}
            }
        }
        
        with open(self.scan_folder / "meta.json", 'w') as f:
            json.dump(meta, f, indent=2)
        
        # Save config snapshot
        with open(self.scan_folder / "config.snapshot.json", 'w') as f:
            json.dump(config, f, indent=2)
        
        # Save metrics
        with open(self.scan_folder / "metrics.json", 'w') as f:
            json.dump(metrics, f, indent=2)
        
        # Save ID mappings
        with open(self.scan_folder / "ids.json", 'w') as f:
            json.dump(dict(self.id_mappings), f, indent=2)
    
    def save_findings(self, findings: List[Dict[str, Any]], summary: str):
        """Save final findings and summary."""
        with open(self.findings_dir / "findings.json", 'w') as f:
            json.dump(findings, f, indent=2)
        
        with open(self.findings_dir / "summary.txt", 'w') as f:
            f.write(summary)
    
    def save_snippet(self, item_id: str, snippet: str):
        """Save raw code snippet if allowed."""
        if self.allow_raw_code_logging:
            snippet_file = self.artifacts_dir / "snippets" / f"{item_id}.txt"
            snippet_file.parent.mkdir(exist_ok=True)
            with open(snippet_file, 'w') as f:
                f.write(snippet)
    
    def log_message(self, level: str, message: str):
        """Log a message to the run log."""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] {level.upper()}: {message}\n"
        
        with open(self.logs_dir / "run.log", 'a') as f:
            f.write(log_entry)
    
    def _make_relative_path(self, path: str) -> str:
        """Convert absolute path to relative path."""
        try:
            abs_path = Path(path).resolve()
            rel_path = abs_path.relative_to(self.root_path)
            return str(rel_path)
        except ValueError:
            # Path is not under root, return as-is
            return path
    
    def create_latest_symlink(self):
        """Create symlink to latest scan."""
        if self._output_base is not None:
            latest_path = (self._output_base / "results" / "scans" / "latest").resolve()
        else:
            latest_path = Path("results/scans/latest")
        latest_path.parent.mkdir(parents=True, exist_ok=True)
        if latest_path.exists():
            latest_path.unlink()
        latest_path.symlink_to(self.scan_folder.name)
    
    def save_discovered_rules(self, new_rules: List[Dict[str, Any]], original_rules_path: str):
        """Save discovered rules to scan session folder."""
        rules_data = {
            "original_rules_path": original_rules_path,
            "new_rules_count": len(new_rules),
            "new_rules": new_rules,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        rules_file = self.prescan_dir / "discovered_rules.json"
        try:
            # Ensure directory exists
            self.prescan_dir.mkdir(parents=True, exist_ok=True)
            with open(rules_file, 'w', encoding='utf-8') as f:
                json.dump(rules_data, f, indent=2)
                f.flush()  # Ensure data is written immediately
        except Exception as e:
            # Log error but don't fail the scan
            import sys
            print(f"Warning: Failed to save discovered rules to {rules_file}: {e}", file=sys.stderr)
    
    def save_function_batch(self, pass_name: str, batch_num: int, function_batch: Any, prompt: str, 
                           response: Optional[List[Dict[str, Any]]] = None):
        """Save function batch with full prompt for review."""
        # Create pass directory if it doesn't exist
        # pass_name should be in format like "stage_8_pass_2a" or "stage_8_pass_2b" - use as-is without prefix
        pass_dir = self.llm_dir / pass_name.lower()
        pass_dir.mkdir(exist_ok=True)
        batches_dir = pass_dir / "batches"
        batches_dir.mkdir(exist_ok=True)
        
        # Save batch input (functions and prompt)
        batch_input = {
            "batch_id": f"{pass_name}_batch_{batch_num:04d}",
            "pass": pass_name,
            "batch_num": batch_num,
            "function_count": len(function_batch.functions) if hasattr(function_batch, 'functions') else 0,
            "functions": [
                {
                    "function_id": func.function_id,
                    "file_path": self._make_relative_path(func.file_path) if hasattr(func, 'file_path') else None,
                    "start_line": func.start_line if hasattr(func, 'start_line') else None,
                    "end_line": func.end_line if hasattr(func, 'end_line') else None,
                    "body": func.body if hasattr(func, 'body') else None,
                    "candidate_lines": func.candidate_lines if hasattr(func, 'candidate_lines') else None,
                    "symbol": func.symbol if hasattr(func, 'symbol') else None
                }
                for func in (function_batch.functions if hasattr(function_batch, 'functions') else [])
            ],
            "full_prompt": prompt,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        with open(batches_dir / f"{batch_num:04d}_input.json", 'w', encoding='utf-8') as f:
            json.dump(batch_input, f, indent=2)
        
        # Save batch output (LLM response) if provided
        if response:
            batch_output = {
                "batch_id": f"{pass_name}_batch_{batch_num:04d}",
                "pass": pass_name,
                "batch_num": batch_num,
                "response": response,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            
            with open(batches_dir / f"{batch_num:04d}_output.json", 'w', encoding='utf-8') as f:
                json.dump(batch_output, f, indent=2)
    
    def update_index(self):
        """Update the scans index."""
        index_path = Path("results/index.json")
        
        # Load existing index
        if index_path.exists():
            with open(index_path, 'r') as f:
                index = json.load(f)
        else:
            index = {"scans": []}
        
        # Add this scan
        scan_entry = {
            "scan_id": self.scan_id,
            "timestamp": self.created_utc,
            "root": str(self.root_path),
            "folder": str(self.scan_folder),
            "total_duration_ms": self.timing.get("total_ms", 0),
            "findings_count": 0  # Will be updated when findings are saved
        }
        
        index["scans"].insert(0, scan_entry)  # Add to beginning
        
        # Keep only last 50 scans
        index["scans"] = index["scans"][:50]
        
        with open(index_path, 'w') as f:
            json.dump(index, f, indent=2)
