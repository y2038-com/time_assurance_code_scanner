# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import hashlib
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from collections import defaultdict

from tacs.core.path_utils import repo_relative_path, update_latest_symlink
from tacs.core.run_ids import new_run_id


# Line-number prefixes used when source is embedded in prompts, e.g. "  12 | code"
# or "12: code"; stripped before matching so prefixed source lines still redact.
_SOURCE_LINE_PREFIX = re.compile(r"^\s*\d+\s*[:|]\s?")


class ScanSession:
    """Manages a single scan session with structured logging."""
    
    def __init__(
        self,
        root_path: str,
        enable_llm_logging: bool = False,
        redact_prompts: bool = True,
        allow_raw_code_logging: bool = False,
        output_base: Optional[Union[str, Path]] = None,
        session_dir: Optional[Union[str, Path]] = None,
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
            session_dir: If set, this directory *is* the artifact root; no
                        results/scans/<session-id>/ folder is created beneath it.
                        Used by ``tacs repos``, where the batch run id and repo key
                        already identify the scan.
        """
        if session_dir is not None and output_base is not None:
            raise ValueError("pass either session_dir or output_base, not both")

        self.root_path = Path(root_path).resolve()
        self.enable_llm_logging = enable_llm_logging
        self.redact_prompts = redact_prompts
        self.allow_raw_code_logging = allow_raw_code_logging
        self._output_base = Path(output_base).resolve() if output_base else None
        
        # Generate scan ID and timestamp
        self.scan_id = new_run_id()
        self.created_utc = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
        
        # A batch run already identifies each scan by run id and repo key, so the
        # supplied directory is the artifact root: no session-history folder, index,
        # or latest link belongs inside it.
        self.batch_mode = session_dir is not None
        if self.batch_mode:
            self.scan_folder = Path(session_dir).resolve()
        else:
            # Absolute when output_base is set, so concurrent jobs don't clash on cwd.
            rel_folder = f"results/scans/{self.scan_id}"
            if self._output_base is not None:
                self.scan_folder = (self._output_base / rel_folder).resolve()
            else:
                self.scan_folder = Path(rel_folder)
        self.scan_folder.mkdir(parents=True, exist_ok=True)
        
        # Batch output keeps the scanner's own metadata under a distinct name; the
        # per-repo meta.json written by tacs repos records repository identity.
        self.metadata_filename = "scan_meta.json" if self.batch_mode else "meta.json"
        
        # Subdirectory layout. These are created on first write rather than up
        # front, so a run that never used the LLM or never logged raw snippets
        # does not leave empty llm/ and artifacts/ directories behind.
        self.prescan_dir = self.scan_folder / "prescan"
        self.ir_dir = self.scan_folder / "ir"
        self.llm_dir = self.scan_folder / "llm"
        self.findings_dir = self.scan_folder / "findings"
        self.artifacts_dir = self.scan_folder / "artifacts"
        self.logs_dir = self.scan_folder / "logs"
        
        # Initialize tracking
        self.timing = {}
        self.id_mappings = defaultdict(dict)
        self.batch_counters = {1: 0, 2: 0, 3: 0}
        self.stage_counts = {"time_t_aliases": 0, "ir_candidates": 0}
        
        # Start timing
        self.start_time = time.time()
        
        # The batch run carries its own documentation and metadata; a per-repo
        # README restating the session layout would only add noise there.
        if not self.batch_mode:
            self._create_readme()
    
    @staticmethod
    def _ensure_dir(dir_path: Path) -> Path:
        """Create an artifact subdirectory on first use."""
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path
    
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
- stage_stats.json: Per-stage counters and LLM token usage
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
            "defined_in": self.relative_path(defined_in),
            "line": line
        }
        
        self.stage_counts["time_t_aliases"] += 1
        typedef_file = self._ensure_dir(self.prescan_dir) / "typedefs.jsonl"
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
            "defined_in": self.relative_path(defined_in),
            "line": line
        }
        
        with open(self._ensure_dir(self.prescan_dir) / "defines.jsonl", 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def log_candidate(self, candidate_id: str, file: str, line: int, col_start: int, col_end: int, 
                     symbol: str, rule: str, snippet: str):
        """Log an IR candidate."""
        entry = {
            "id": candidate_id,
            "file": self.relative_path(file),
            "line": line,
            "col_start": col_start,
            "col_end": col_end,
            "symbol": symbol,
            "rule": rule,
            "one_line_snippet": snippet
        }
        
        self.stage_counts["ir_candidates"] += 1
        with open(self._ensure_dir(self.ir_dir) / "candidates.jsonl", 'a') as f:
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
            
            batches_dir = self._ensure_dir(self.llm_dir / f"pass{pass_num}" / "batches")
            with open(batches_dir / f"{batch_num}_input.jsonl", 'a') as f:
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
            
            batches_dir = self._ensure_dir(self.llm_dir / f"pass{pass_num}" / "batches")
            with open(batches_dir / f"{batch_num}_output.jsonl", 'a') as f:
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
        
        with open(self.scan_folder / self.metadata_filename, 'w') as f:
            json.dump(meta, f, indent=2)
        
        # Save config snapshot
        with open(self.scan_folder / "config.snapshot.json", 'w') as f:
            json.dump(config, f, indent=2)
        
        # Save metrics
        with open(self.scan_folder / "metrics.json", 'w') as f:
            json.dump(metrics, f, indent=2)
        
        # Save ID mappings. Batch output omits the file when nothing recorded a
        # mapping rather than publishing an empty document per repository.
        if self.id_mappings or not self.batch_mode:
            with open(self.scan_folder / "ids.json", 'w') as f:
                json.dump(dict(self.id_mappings), f, indent=2)
    
    def save_stage_stats(self, stage_stats: Dict[str, Any]):
        """
        Save per-stage counters and token usage in machine-readable form.

        Batch aggregation reads this rather than parsing summary.txt, so reworded
        summary text cannot silently zero out a run's reported stage statistics.
        """
        with open(self.scan_folder / "stage_stats.json", 'w') as f:
            json.dump(stage_stats, f, indent=2)
    
    def save_findings(self, findings: List[Dict[str, Any]], summary: str):
        """
        Save the scan summary, plus a session copy of the findings.

        Batch mode writes only summary.txt: ``tacs repos`` publishes the canonical
        findings.json at the same root, and that document ({meta, findings}) is a
        superset of the bare findings array kept for standalone sessions.
        """
        if self.batch_mode:
            summary_path = self.scan_folder / "summary.txt"
        else:
            findings_dir = self._ensure_dir(self.findings_dir)
            with open(findings_dir / "findings.json", 'w') as f:
                json.dump(findings, f, indent=2)
            summary_path = findings_dir / "summary.txt"
        
        with open(summary_path, 'w') as f:
            f.write(summary)
    
    def save_snippet(self, item_id: str, snippet: str):
        """Save raw code snippet if allowed."""
        if self.allow_raw_code_logging:
            snippet_file = self._ensure_dir(self.artifacts_dir / "snippets") / f"{item_id}.txt"
            with open(snippet_file, 'w') as f:
                f.write(snippet)
    
    def log_message(self, level: str, message: str):
        """Log a message to the run log."""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] {level.upper()}: {message}\n"
        
        with open(self._ensure_dir(self.logs_dir) / "run.log", 'a') as f:
            f.write(log_entry)
    
    def relative_path(self, path: str) -> str:
        """Name a scanned file relative to the scan root."""
        return repo_relative_path(path, self.root_path)
    
    def create_latest_symlink(self):
        """Point results/scans/latest at this session's folder."""
        if self.batch_mode:
            # The batch run's own results/batch_runs/latest covers this; a link
            # inside a per-repo bundle would point at the bundle itself.
            return
        if self._output_base is not None:
            latest_path = self._output_base / "results" / "scans" / "latest"
        else:
            latest_path = Path("results/scans/latest")
        update_latest_symlink(latest_path, self.scan_folder)
    
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
            self._ensure_dir(self.prescan_dir)
            with open(rules_file, 'w', encoding='utf-8') as f:
                json.dump(rules_data, f, indent=2)
                f.flush()  # Ensure data is written immediately
        except Exception as e:
            # Log error but don't fail the scan
            import sys
            print(f"Warning: Failed to save discovered rules to {rules_file}: {e}", file=sys.stderr)
    
    def _redact_function_batch_prompt(self, prompt: str, functions: List[Any]) -> str:
        """
        Remove embedded source from a function-batch prompt.

        Each function body is replaced by a placeholder, then any remaining prompt
        line that reproduces a source line is dropped. The result is passed through
        the shared LLM log redaction so paths are hashed and long lines truncated.
        """
        from tacs.core.llm_logger import redact_prompt_text

        redacted = prompt
        source_lines: set[str] = set()

        for func in functions:
            body = getattr(func, 'body', None)
            if not body:
                continue
            function_id = getattr(func, 'function_id', 'unknown')
            placeholder = (
                f"<REDACTED FUNCTION BODY function_id={function_id} "
                f"lines={len(body.splitlines())} chars={len(body)}>"
            )
            redacted = redacted.replace(body, placeholder)
            for line in body.splitlines():
                stripped = line.strip()
                if len(stripped) >= 4:
                    source_lines.add(stripped)

        if source_lines:
            kept: List[str] = []
            for line in redacted.split('\n'):
                unprefixed = _SOURCE_LINE_PREFIX.sub('', line).strip()
                if line.strip() in source_lines or unprefixed in source_lines:
                    kept.append("<REDACTED SOURCE LINE>")
                else:
                    kept.append(line)
            redacted = '\n'.join(kept)

        return redact_prompt_text(redacted)

    def save_function_batch(self, pass_name: str, batch_num: int, function_batch: Any, prompt: str, 
                           response: Optional[List[Dict[str, Any]]] = None):
        """
        Save a function-batch artifact for audit and debugging.

        The manifest (batch/function ids, relative paths, line ranges, candidate line
        numbers, prompt size and digest) is always written. Source-bearing content is
        gated:

        - enable_llm_logging=False: manifest only, no prompt or body text
        - enable_llm_logging=True: prompt is persisted in redacted form
        - enable_llm_logging=True and allow_raw_code_logging=True: verbatim prompt
          and function bodies are persisted

        allow_raw_code_logging is authoritative for verbatim source retention, so
        redact_prompts=False alone does not permit raw prompt/body persistence.
        """
        # pass_name should be in format like "stage_8_pass_2a" or "stage_8_pass_2b" - use as-is without prefix
        batches_dir = self._ensure_dir(self.llm_dir / pass_name.lower() / "batches")

        functions = list(function_batch.functions) if hasattr(function_batch, 'functions') else []
        persist_prompt = bool(self.enable_llm_logging)
        persist_raw_code = bool(self.enable_llm_logging and self.allow_raw_code_logging)

        function_entries: List[Dict[str, Any]] = []
        for func in functions:
            body = getattr(func, 'body', None) or ""
            candidate_lines = getattr(func, 'candidate_lines', None) or []
            entry: Dict[str, Any] = {
                "function_id": getattr(func, 'function_id', None),
                "file_path": self.relative_path(func.file_path) if hasattr(func, 'file_path') else None,
                "start_line": getattr(func, 'start_line', None),
                "end_line": getattr(func, 'end_line', None),
                "symbol": getattr(func, 'symbol', None),
                "candidate_lines": list(candidate_lines),
                "candidate_count": len(candidate_lines),
                "body_lines": len(body.splitlines()),
                "body_chars": len(body),
            }
            if persist_raw_code:
                entry["body"] = body
            function_entries.append(entry)

        # Save batch manifest (always) plus gated prompt/body content
        batch_input = {
            "batch_id": f"{pass_name}_batch_{batch_num:04d}",
            "pass": pass_name,
            "batch_num": batch_num,
            "function_count": len(functions),
            "functions": function_entries,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "privacy": {
                "enable_llm_logging": bool(self.enable_llm_logging),
                "redact_prompts": bool(self.redact_prompts),
                "allow_raw_code_logging": bool(self.allow_raw_code_logging),
                "raw_function_bodies_persisted": persist_raw_code,
                "prompt_persisted": (
                    "verbatim" if persist_raw_code else "redacted" if persist_prompt else "none"
                ),
            },
        }

        if prompt:
            batch_input["prompt_chars"] = len(prompt)
            batch_input["prompt_sha256"] = hashlib.sha256(prompt.encode('utf-8')).hexdigest()
            if persist_raw_code:
                batch_input["full_prompt"] = prompt
            elif persist_prompt:
                batch_input["prompt_redacted"] = self._redact_function_batch_prompt(prompt, functions)

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
        if self.batch_mode:
            # Scan history is a standalone concept; inside a batch run the repo
            # bundle is the only scan, and an index here would just record a path
            # that breaks as soon as the run directory moves.
            return
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
