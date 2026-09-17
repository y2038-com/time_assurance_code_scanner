# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, validator
from enum import Enum


class SeverityLevel(str, Enum):
    """Severity levels for findings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Y2038Issue(str, Enum):
    """Y2038 issue classification."""
    YES = "yes"
    NO = "no"
    ABSTAIN = "abstain"


class TimeIssueType(str, Enum):
    """Type of time overflow issue."""
    Y2038 = "y2038"      # 32-bit signed time_t overflow (2038)
    Y2106 = "y2106"      # 32-bit unsigned time_t overflow (2106)
    BOTH = "both"        # Both Y2038 and Y2106 (rare, e.g., mixed signed/unsigned usage)
    NONE = "none"        # No time overflow issue
    ABSTAIN = "abstain"  # Cannot determine


class IOCandidateType(str, Enum):
    """Type of I/O boundary finding."""
    FORMATTED_IO_MISMATCH = "formatted_io_mismatch"
    RAW_REPRESENTATION_RISK = "raw_representation_risk"
    EXTERNAL_INTERFACE_RISK = "external_interface_risk"


class RemediationClass(str, Enum):
    """Remediation guidance class."""
    AUTOFIX_CANDIDATE = "autofix_candidate"
    MANUAL_CODE_REVIEW = "manual_code_review"
    MANUAL_INTERFACE_REVIEW_REQUIRED = "manual_interface_review_required"


class MigrationRiskType(str, Enum):
    """Type of migration risk."""
    WIDTH_ASSUMPTION = "width_assumption"
    SIGNEDNESS_ASSUMPTION = "signedness_assumption"
    ARCHITECTURE_ASSUMPTION = "architecture_assumption"
    IO_FORMAT_MISMATCH = "io_format_mismatch"
    IO_SIZE_MISMATCH = "io_size_mismatch"
    STRUCT_LAYOUT_CHANGE = "struct_layout_change"
    API_BOUNDARY_BREAK = "api_boundary_break"


class MigrationSeverity(str, Enum):
    """Migration risk severity."""
    BLOCKER = "blocker"  # Would prevent migration
    HIGH_RISK = "high_risk"  # Would cause significant issues
    MEDIUM_RISK = "medium_risk"  # Might cause issues
    LOW_RISK = "low_risk"  # Minor concern


class Candidate(BaseModel):
    """A candidate finding from IR stage."""
    file: str = Field(..., description="File path")
    line: int = Field(..., description="Line number")
    symbol: str = Field(..., description="Symbol name")
    one_line_snippet: str = Field(..., description="Source line content")
    risk: str = Field(..., description="Risk level from rules")
    description: str = Field(default="", description="Rule description")
    col_start: Optional[int] = Field(default=None, description="Column start")
    col_end: Optional[int] = Field(default=None, description="Column end")
    symbol_role: Optional[str] = Field(default=None, description="AST role tag")


class IOCandidate(Candidate):
    """I/O-boundary specific candidate extending base Candidate."""
    io_category: IOCandidateType = Field(..., description="I/O category")
    io_function: str = Field(..., description="I/O function name (printf, write, etc.)")
    io_score: float = Field(..., description="I/O-specific risk score")
    io_confidence: str = Field(..., description="Confidence level: low_confidence, medium_confidence, high_confidence")
    remediation_class: RemediationClass = Field(..., description="Remediation guidance class")
    affected_symbols: List[str] = Field(default_factory=list, description="List of affected time-bearing symbols")
    abi_assumptions: Dict[str, Any] = Field(default_factory=dict, description="ABI assumptions used in analysis")
    reasoning: str = Field(..., description="Explanation of why this was flagged")
    originating_stage: str = Field(default="io_boundary_analysis", description="Stage that generated this candidate")


class LLMResponse(BaseModel):
    """LLM response for a single candidate."""
    id: str = Field(..., description="Candidate ID (file:line)")
    y2038_issue: Y2038Issue = Field(..., description="Issue classification")
    severity: Optional[SeverityLevel] = Field(default=None, description="Severity level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    reason: str = Field(..., max_length=200, description="Reason (max 200 characters)")
    needs_more_context: bool = Field(default=False, description="Needs more context")
    line: Optional[int] = Field(default=None, description="Line number for Pass 1")
    col_start: Optional[int] = Field(default=None, description="Column start for Pass 1")
    col_end: Optional[int] = Field(default=None, description="Column end for Pass 1")
    region: Optional[Dict[str, int]] = Field(default=None, description="Region for Pass 2/3")


class Finding(BaseModel):
    """Final finding result."""
    file: str = Field(..., description="File path")
    region: Dict[str, int] = Field(..., description="Region with start_line and end_line")
    lines: List[int] = Field(..., description="List of line numbers")
    symbol: str = Field(..., description="Symbol name")
    severity: Optional[SeverityLevel] = Field(default=None, description="Severity level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    reason: str = Field(..., description="Reason")
    scenario: Optional[str] = Field(default=None, description="Scenario context")
    preprocessor_context: List[str] = Field(default_factory=list, description="Preprocessor guards")
    source_snippet: str = Field(..., description="Source code snippet")
    y2038_issue: Y2038Issue = Field(..., description="Issue classification (backward compatibility)")
    needs_more_context: bool = Field(default=False, description="Needs more context")
    
    # Y2106 detection fields (new)
    issue_type: Optional[TimeIssueType] = Field(default=None, description="Type of time overflow issue (Y2038, Y2106, both, none, abstain)")
    y2106_issue: Optional[Y2038Issue] = Field(default=None, description="Y2106 issue classification (when Y2106 detection enabled)")
    issues: List[Dict[str, Any]] = Field(default_factory=list, description="Detailed issue list with types")
    
    # Function-first fields
    function_id: Optional[str] = Field(default=None, description="Function identifier")
    iteration_count: Optional[int] = Field(default=None, description="Number of iterations performed")
    final_pass: Optional[str] = Field(default=None, description="Final pass that resolved this finding")
    
    # I/O-boundary specific fields
    io_category: Optional[IOCandidateType] = Field(default=None, description="I/O category if from I/O-boundary analysis")
    io_function: Optional[str] = Field(default=None, description="I/O function name if from I/O-boundary analysis")
    remediation_class: Optional[RemediationClass] = Field(default=None, description="Remediation guidance class")
    abi_impact: Optional[str] = Field(default=None, description="Description of ABI impact")
    persistence_impact: Optional[str] = Field(default=None, description="Description of persistence impact")
    protocol_impact: Optional[str] = Field(default=None, description="Description of protocol impact")
    
    # Migration analysis fields
    migration_risk_type: Optional[MigrationRiskType] = Field(default=None, description="Migration risk type if from migration analysis")
    migration_severity: Optional[MigrationSeverity] = Field(default=None, description="Migration risk severity")
    migration_impact: Optional[str] = Field(default=None, description="Description of migration impact")
    migration_remediation: Optional[str] = Field(default=None, description="Remediation guidance for migration")
    from_config_id: Optional[str] = Field(default=None, description="Source config ID for migration")
    to_config_id: Optional[str] = Field(default=None, description="Target config ID for migration")


class Metrics(BaseModel):
    """Code metrics for the scan."""
    total_files: int = Field(..., description="Total number of files")
    total_lines: int = Field(..., description="Total number of lines")
    total_chars: int = Field(..., description="Total number of characters")
    total_words: int = Field(..., description="Total number of words")
    max_line_length: int = Field(..., description="Maximum line length")
    avg_line_length: float = Field(..., description="Average line length")
    max_file_length: int = Field(..., description="Maximum file length")
    avg_file_length: float = Field(..., description="Average file length")
    max_file_size: Optional[int] = Field(
        default=None,
        description="Effective per-file size limit in bytes (null when unlimited)",
    )
    files_skipped_too_large: int = Field(
        default=0, description="Files skipped for exceeding max_file_size"
    )
    skipped_too_large: List[Dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Repo-relative path and size of skipped files, capped at "
            "file_limits.MAX_RECORDED_SKIPS entries; files_skipped_too_large is exact"
        ),
    )
    files_skipped_external: int = Field(
        default=0,
        description=(
            "Source symlinks whose targets resolve outside the repository root"
        ),
    )
    skipped_external: List[str] = Field(
        default_factory=list,
        description=(
            "In-repo link paths (lexical, not followed) for external symlink "
            "skips, capped at file_limits.MAX_RECORDED_SKIPS; "
            "files_skipped_external is exact"
        ),
    )


class ScanMetadata(BaseModel):
    """Metadata for the scan."""
    root: str = Field(..., description="Root directory scanned")
    rules_path: str = Field(..., description="Rules file path")
    model: str = Field(..., description="LLM model used (\"none\" when LLM is disabled)")
    confidence_floor: float = Field(..., description="Confidence threshold")
    metrics: Metrics = Field(..., description="Code metrics")
    timestamp: str = Field(..., description="Scan timestamp (UTC ISO 8601)")
    environment_config: Optional[Dict[str, Any]] = Field(default=None, description="Environment configuration")


class ScanResults(BaseModel):
    """Complete scan results."""
    meta: ScanMetadata = Field(..., description="Scan metadata")
    findings: List[Finding] = Field(..., description="List of findings")
