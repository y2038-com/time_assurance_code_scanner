# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import hashlib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional
from tacs.core.schema import LLMLogEntry


def redact_prompt_text(prompt: str) -> str:
    """
    Redact sensitive information from a prompt.

    Shared by LLMLogger and ScanSession so both write artifacts under one
    redaction scheme: source file paths become hashes and long lines are
    truncated.
    """
    import re

    # Pattern to match file paths
    file_path_pattern = r'/[^\s\n]+\.(c|h|cpp|hpp)'

    def hash_path(match):
        path = match.group(0)
        return f"<HASH:{hashlib.md5(path.encode()).hexdigest()[:8]}>"

    redacted = re.sub(file_path_pattern, hash_path, prompt)

    # Remove long code spans (keep only line numbers and short context)
    lines = redacted.split('\n')
    redacted_lines = []

    for line in lines:
        if len(line) > 200:  # Long lines
            # Keep first part and indicate truncation
            redacted_lines.append(line[:100] + "... [TRUNCATED]")
        else:
            redacted_lines.append(line)

    return '\n'.join(redacted_lines)


class LLMLogger:
    """LLM request/response logger with redaction support."""
    
    def __init__(self, log_dir: str = "results/llm_logs", redact_prompts: bool = True):
        """
        Initialize the LLM logger.
        
        Args:
            log_dir: Directory to store log files
            redact_prompts: Whether to redact prompts in logs
        """
        self.log_dir = Path(log_dir)
        self.redact_prompts = redact_prompts
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    def log_request(
        self,
        repo_id_hash: str,
        model: str,
        model_version: Optional[str],
        prompt_preamble_hash: str,
        items: list[str],
        request_tokens: int,
        response_tokens: int,
        latency_ms: int,
        prompt: str,
        response: str,
        pass_number: int,
        batch_number: int
    ):
        """
        Log an LLM request/response.
        
        Args:
            repo_id_hash: Hash of repository ID
            model: Model name used
            model_version: Model version (if available)
            prompt_preamble_hash: Hash of prompt preamble
            items: List of item IDs processed
            request_tokens: Number of request tokens
            response_tokens: Number of response tokens
            latency_ms: Request latency in milliseconds
            prompt: Full prompt (may be redacted)
            response: Full response
            pass_number: Pass number (1, 2, or 3)
            batch_number: Batch number within the pass
        """
        # Create filename
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
        filename = f"{timestamp}_pass{pass_number}_batch{batch_number:02d}.jsonl"
        log_file = self.log_dir / filename
        
        # Redact prompt if requested
        if self.redact_prompts:
            prompt = self._redact_prompt(prompt)
        
        # Create log entry
        log_entry = LLMLogEntry(
            repo_id_hash=repo_id_hash,
            model=model,
            model_version=model_version,
            prompt_preamble_hash=prompt_preamble_hash,
            items=items,
            request_tokens=request_tokens,
            response_tokens=response_tokens,
            latency_ms=latency_ms,
            prompt=prompt,
            response=response,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )
        
        # Write to log file
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry.json() + '\n')
    
    def _redact_prompt(self, prompt: str) -> str:
        """Redact sensitive information from prompt."""
        return redact_prompt_text(prompt)
    
    def cleanup_old_logs(self, days: int = 30):
        """
        Clean up log files older than specified days.
        
        Args:
            days: Number of days to keep logs
        """
        cutoff_time = datetime.now() - timedelta(days=days)
        deleted_count = 0
        
        for log_file in self.log_dir.glob("*.jsonl"):
            if log_file.stat().st_mtime < cutoff_time.timestamp():
                log_file.unlink()
                deleted_count += 1
        
        print(f"Cleaned up {deleted_count} log files older than {days} days")
