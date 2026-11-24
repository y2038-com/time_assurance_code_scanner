# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, validator
from enum import Enum

#: Schema 1.3 bounds for structured propagation evidence.
MAX_PROPAGATION_PATHS = 32
MAX_ORIGIN_CANDIDATE_IDS = 32
MAX_PROPAGATION_EXPRESSION_CHARS = 512


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


#: Controlled vocabulary for how a deterministic candidate was produced.
#: Not a catalog rule id — detectors without a genuine rule_id use these labels.
DISCOVERY_METHODS = frozenset({
    "catalog_symbol_match",
    "time_t_cast",
    "define_scanner",
    "arithmetic_scanner",
    "io_boundary",
    "migration",
    "direct_callee_time_propagation",
    "unknown",
})

#: Max characters kept on a public CandidateEvidence snippet (one line).
CANDIDATE_SNIPPET_MAX_CHARS = 240

#: Max characters kept on a public ModelAssessment reason.
ASSESSMENT_REASON_MAX_CHARS = 200

#: Allowlisted keys for public assessments[] serialization.
PUBLIC_ASSESSMENT_KEYS = (
    "assessment_id",
    "function_id",
    "candidate_ids",
    "execution_status",
    "verdict",
    "confidence",
    "reason",
    "analysis_mode",
)

#: Public result JSON schema version (independent of the package version).
#: Schema 1.3 adds optional ``candidates[].propagation_paths`` for one-hop
#: direct-callee time-argument evidence (issue #57). Schema 1.0–1.2 remain
#: loadable; missing paths mean no structured propagation was recorded.
PUBLIC_RESULT_SCHEMA_VERSION = "1.3"


class PropagationKind(str, Enum):
    """How time semantics reached the sink candidate."""

    DIRECT_CALLEE_ARGUMENT = "direct_callee_argument"


class CallResolutionState(str, Enum):
    """Conservative call-target resolution classification."""

    RESOLVED = "resolved"
    PROBABLE = "probable"
    AMBIGUOUS = "ambiguous"
    CONFIGURATION_DEPENDENT = "configuration_dependent"
    INDIRECT = "indirect"
    EXTERNAL = "external"
    UNRESOLVED = "unresolved"


class CallResolutionBasis(str, Enum):
    """Evidence basis when ``CallResolutionState.RESOLVED``."""

    SAME_FILE_STATIC = "same_file_static"
    VISIBLE_DECLARATION_UNIQUE_DEFINITION = "visible_declaration_unique_definition"


class TimeSemantic(str, Enum):
    """Structured time semantic attached to a propagated value."""

    UNIX_EPOCH_SECONDS = "unix_epoch_seconds"
    ABSOLUTE_UTC_SECONDS = "absolute_utc_seconds"
    TIME_T_VALUE = "time_t_value"
    TIME_RELATED_UNKNOWN = "time_related_unknown"


class PropagationStopReason(str, Enum):
    """Deterministic reason a propagation attempt stopped or was truncated."""

    ARGUMENT_EXPRESSION_TOO_LONG = "argument_expression_too_long"
    TOO_MANY_PROPAGATED_PARAMETERS = "too_many_propagated_parameters"
    AMBIGUOUS_TARGET_LIMIT = "ambiguous_target_limit"
    UNSUPPORTED_CALL_FORM = "unsupported_call_form"
    UNSUPPORTED_PARAMETER_FORM = "unsupported_parameter_form"
    ARITY_MISMATCH = "arity_mismatch"
    EXTERNAL_TARGET = "external_target"
    INDIRECT_CALL = "indirect_call"
    RECURSIVE_PATH = "recursive_path"
    UNRESOLVED_TARGET = "unresolved_target"
    NO_TIME_PROVENANCE = "no_time_provenance"
    POINTER_OR_REFERENCE_PARAMETER = "pointer_or_reference_parameter"
    VARIADIC_PARAMETER = "variadic_parameter"
    PARSE_TRUNCATED = "parse_truncated"


def _reject_unsafe_source_path(value: str) -> str:
    """Require repository-relative paths (no absolute or ``..`` segments)."""
    text = (value or "").strip()
    if not text:
        raise ValueError("source path must be non-empty")
    if text.startswith("/") or text.startswith("\\"):
        raise ValueError("absolute source paths are not allowed")
    if re.match(r"^[A-Za-z]:[\\/]", text):
        raise ValueError("absolute source paths are not allowed")
    parts = text.replace("\\", "/").split("/")
    if any(part == ".." for part in parts):
        raise ValueError("source paths must not contain '..'")
    return text


class PropagationCallSite(BaseModel):
    """Call-site location for a propagation path (1-based line/column)."""

    file: str = Field(..., description="Repository-relative source path")
    line: int = Field(..., ge=1, description="1-based line number")
    column: Optional[int] = Field(
        default=None,
        ge=1,
        description="1-based column of the called identifier when known",
    )

    @field_validator("file")
    @classmethod
    def _safe_file(cls, value: str) -> str:
        return _reject_unsafe_source_path(value)


class PropagationResolution(BaseModel):
    """Resolution classification for the caller-to-callee edge."""

    state: CallResolutionState = Field(..., description="Resolution state")
    basis: Optional[CallResolutionBasis] = Field(
        default=None,
        description="Basis when state is resolved; otherwise null",
    )


class PropagationArgument(BaseModel):
    """Caller argument mapped into a callee parameter.

    Indexes are **zero-based** (argument 0 is the first parameter).
    """

    index: int = Field(..., ge=0, description="Zero-based argument position")
    expression: str = Field(
        ...,
        max_length=MAX_PROPAGATION_EXPRESSION_CHARS,
        description=(
            f"Bounded source expression text for the argument "
            f"(max {MAX_PROPAGATION_EXPRESSION_CHARS} characters; never silently truncated)"
        ),
    )


class PropagationParameter(BaseModel):
    """Callee parameter that received propagated time semantics.

    Indexes are **zero-based** and match ``PropagationArgument.index``.
    """

    index: int = Field(..., ge=0, description="Zero-based parameter position")
    name: str = Field(..., description="Parameter name from the definition")
    declared_type: str = Field(..., description="Declared parameter type text")


class PropagationPath(BaseModel):
    """One deterministic one-hop caller→callee time-propagation evidence path.

    Argument and parameter indexes are **zero-based**. Schema 1.3 only; absent
    on legacy 1.0–1.2 reports. Fail-closed validation rejects malformed paths.
    """

    kind: PropagationKind = Field(
        default=PropagationKind.DIRECT_CALLEE_ARGUMENT,
        description="Propagation relationship kind",
    )
    depth: int = Field(
        default=1,
        ge=1,
        le=1,
        description="Call-boundary depth (exactly 1 for issue #57)",
    )
    origin_candidate_ids: List[str] = Field(
        default_factory=list,
        max_length=MAX_ORIGIN_CANDIDATE_IDS,
        description=(
            "Deterministic origin candidate_id values in the caller "
            f"(deduplicated, sorted; max {MAX_ORIGIN_CANDIDATE_IDS})"
        ),
    )
    caller_function_id: str = Field(..., description="Public caller function_id")
    call_site: PropagationCallSite = Field(..., description="Call-site location")
    resolution: PropagationResolution = Field(
        ..., description="Call resolution state and basis"
    )
    argument: PropagationArgument = Field(..., description="Caller argument")
    callee_function_id: str = Field(..., description="Public callee function_id")
    parameter: PropagationParameter = Field(..., description="Callee parameter")
    time_semantic: TimeSemantic = Field(
        ..., description="Propagated time semantic classification"
    )
    propagation_depth: int = Field(
        default=1,
        ge=1,
        le=1,
        description="Alias of depth for report clarity (always 1 in #57)",
    )
    truncated: bool = Field(
        default=False,
        description=(
            "True when a bound stopped further detail (e.g. too many parameters); "
            "expression text itself is never silently truncated"
        ),
    )
    stop_reasons: List[PropagationStopReason] = Field(
        default_factory=list,
        description="Deterministic stop or truncation reasons",
    )

    @field_validator("origin_candidate_ids")
    @classmethod
    def _sorted_unique_origins(cls, value: List[str]) -> List[str]:
        if value is None:
            return []
        if len(value) > MAX_ORIGIN_CANDIDATE_IDS:
            raise ValueError(
                f"at most {MAX_ORIGIN_CANDIDATE_IDS} origin_candidate_ids allowed"
            )
        return sorted(set(value))


class AnalysisCoverage(str, Enum):
    """Factual pipeline coverage for a deterministic candidate.

    ``grouped``: function association found an enclosing analysis unit.
    ``ungrouped``: association was attempted and no enclosing function was found.
    Does not describe model verdicts or Stage 7 triage outcomes.
    """
    GROUPED = "grouped"
    UNGROUPED = "ungrouped"


class AssessmentExecutionStatus(str, Enum):
    """Whether a model assessment unit ran to a usable conclusion."""

    COMPLETED = "completed"
    ANALYSIS_ERROR = "analysis_error"
    NOT_REQUESTED = "not_requested"


class ModelVerdict(str, Enum):
    """Model conclusion when execution_status is completed."""

    YES = "yes"
    NO = "no"
    ABSTAIN = "abstain"


class RunAnalysisStatus(str, Enum):
    """Run-level model-analysis status for the public result."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_REQUESTED = "not_requested"


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
    discovery_method: Optional[str] = Field(
        default=None,
        description=(
            "Controlled detector label (see DISCOVERY_METHODS); not a catalog rule_id"
        ),
    )
    rule_id: Optional[str] = Field(
        default=None,
        description=(
            "Producer-authored catalog rule_id when this candidate came from an "
            "identified catalog rule; otherwise null"
        ),
    )
    propagation_paths: Optional[List[PropagationPath]] = Field(
        default=None,
        max_length=MAX_PROPAGATION_PATHS,
        description=(
            "Optional schema 1.3 structured one-hop propagation evidence; "
            f"null/absent when none was recorded (max {MAX_PROPAGATION_PATHS} paths). "
            "Cross-record integrity (origin IDs, caller/callee spans) is enforced "
            "during report construction in callee_propagation, not solely by this model."
        ),
    )


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


class CandidateEvidence(BaseModel):
    """Canonical deterministic discovery evidence for the public result JSON.

    Authorship is scanner/deterministic only. Model verdicts, confidence,
    severity, rationales, and human dispositions do not belong here.
    ``rule_id`` is a genuine packaged/external catalog identifier when the
    producer emitted one; otherwise null. It is never inferred from symbol,
    risk, description, or detector name.
    """
    candidate_id: str = Field(
        ...,
        description=(
            "Weak in-report foreign key from make_candidate_id "
            "(relpath:line:cols:risk:symbol). Stable within equivalent scans "
            "with correct per-match risk; not a suppression or long-term "
            "baseline key across catalog severity edits or unrelated source "
            "changes. rule_id is attribution only and is not part of the id."
        ),
    )
    file: str = Field(..., description="Repository-relative source path")
    line: int = Field(..., description="1-based line number")
    col_start: Optional[int] = Field(default=None, description="Column start when known")
    col_end: Optional[int] = Field(default=None, description="Column end when known")
    symbol: str = Field(..., description="Matched symbol or detector label")
    symbol_role: Optional[str] = Field(default=None, description="Optional role tag")
    risk: str = Field(..., description="Risk category from the detector/rules")
    description: str = Field(default="", description="Deterministic description text")
    one_line_snippet: str = Field(
        ...,
        description=f"Bounded source line (max {CANDIDATE_SNIPPET_MAX_CHARS} chars)",
    )
    discovery_method: str = Field(
        ...,
        description="Controlled detector vocabulary entry; not a fabricated rule id",
    )
    rule_id: Optional[str] = Field(
        default=None,
        description="Genuine catalog rule id when one exists; otherwise null",
    )
    function_id: Optional[str] = Field(
        default=None,
        description="Enclosing function analysis unit id when grouped; null if ungrouped",
    )
    analysis_coverage: AnalysisCoverage = Field(
        ...,
        description="grouped if linked to a function unit; ungrouped if association found none",
    )
    propagation_paths: Optional[List[PropagationPath]] = Field(
        default=None,
        max_length=MAX_PROPAGATION_PATHS,
        description=(
            "Schema 1.3 optional structured propagation paths. Absent or null on "
            "legacy 1.0–1.2 reports and when no propagation was recorded. "
            f"Argument/parameter indexes are zero-based (max {MAX_PROPAGATION_PATHS} paths). "
            "Pipeline-level referential integrity is enforced in callee_propagation."
        ),
    )


class DeterministicCandidateSummary(BaseModel):
    """Counts for deterministic candidates in the public result."""
    total: int = Field(0, description="Candidates in the canonical public collection")
    grouped: int = Field(0, description="Candidates with a function_id")
    ungrouped: int = Field(
        0,
        description="Candidates for which function association found no enclosing function",
    )
    functions_with_candidates: int = Field(
        0,
        description="Distinct function units that contain at least one candidate",
    )
    findings: int = Field(
        0,
        description="Compatibility findings retained in this result (post-filter)",
    )


class ModelAssessment(BaseModel):
    """Public model-authored analysis of one function analysis unit.

    Distinct from deterministic ``CandidateEvidence`` and from the compatibility
    ``Finding`` projection. A verdict does not validate or erase candidates.
    Operational stubs use ``execution_status=analysis_error`` with ``verdict``
    null; genuine model abstention is ``completed`` + ``abstain``.
    """

    assessment_id: str = Field(
        ...,
        description="In-report assessment id (stable within this result document)",
    )
    function_id: str = Field(..., description="Analyzed function unit id")
    candidate_ids: List[str] = Field(
        default_factory=list,
        description="Canonical candidate_id values linked to this analysis unit",
    )
    execution_status: AssessmentExecutionStatus = Field(
        ...,
        description="completed | analysis_error | not_requested",
    )
    verdict: Optional[ModelVerdict] = Field(
        default=None,
        description=(
            "Aggregate model yes/no/abstain when execution_status is completed; "
            "else null. When Y2106 detection was enabled, yes if any enabled "
            "issue-specific summary is yes; issue-specific fields on findings "
            "remain authoritative for Y2038 vs Y2106"
        ),
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Model confidence when present",
    )
    reason: Optional[str] = Field(
        default=None,
        max_length=ASSESSMENT_REASON_MAX_CHARS,
        description=(
            f"Short model or controlled operational reason "
            f"(max {ASSESSMENT_REASON_MAX_CHARS} chars); never prompts, "
            "bodies, or raw exception dumps"
        ),
    )
    analysis_mode: str = Field(
        default="function_first",
        description="Analysis task mode (e.g. function_first)",
    )


class AssessmentSummary(BaseModel):
    """Counts for public assessments, reconciled from serialized arrays."""

    total: int = Field(0, description="Assessments in the public collection")
    completed: int = Field(0, description="execution_status=completed")
    yes: int = Field(
        0,
        description=(
            "completed with aggregate verdict=yes (any enabled rollover issue)"
        ),
    )
    no: int = Field(
        0,
        description="completed with aggregate verdict=no",
    )
    abstain: int = Field(
        0,
        description="completed with aggregate verdict=abstain",
    )
    analysis_errors: int = Field(0, description="execution_status=analysis_error")
    not_requested: int = Field(
        0,
        description="Per-assessment not_requested count (usually 0 when run-level)",
    )
    findings: int = Field(
        0,
        description="Compatibility findings retained in this result (post-filter)",
    )


class ScanMetadata(BaseModel):
    """Metadata for the scan."""
    root: str = Field(
        ...,
        description=(
            "Scan root in display form (cwd-relative, package-relative, or '.' "
            "for cache clones); not a host absolute path"
        ),
    )
    rules_path: str = Field(
        ...,
        description=(
            "Rules file in display form (tacs/rules/... when packaged, else "
            "cwd-relative or basename)"
        ),
    )
    model: str = Field(..., description="LLM model used (\"none\" when LLM is disabled)")
    llm_provider: Optional[str] = Field(
        default=None,
        description=(
            "LLM provider id (openai, ollama, anthropic, gemini, none). "
            "Absent on pre-1.2 results."
        ),
    )
    reasoning_effort: Optional[str] = Field(
        default=None,
        description=(
            "Effective OpenAI reasoning effort for this scan (\"none\" or \"low\" "
            "for GPT-6 Luna). Null/absent for non-reasoning models and providers "
            "(schema 1.2+)."
        ),
    )
    confidence_floor: float = Field(..., description="Confidence threshold")
    metrics: Metrics = Field(..., description="Code metrics")
    timestamp: str = Field(..., description="Scan timestamp (UTC ISO 8601)")
    environment_config: Optional[Dict[str, Any]] = Field(default=None, description="Environment configuration")
    candidate_summary: Optional[DeterministicCandidateSummary] = Field(
        default=None,
        description="Deterministic candidate counts (absent on pre-1.0 results)",
    )
    analysis_status: Optional[RunAnalysisStatus] = Field(
        default=None,
        description=(
            "Run-level model analysis status: complete | partial | failed | "
            "not_requested (absent on pre-1.1 results)"
        ),
    )
    assessment_summary: Optional[AssessmentSummary] = Field(
        default=None,
        description="Model assessment counts (absent on pre-1.1 results)",
    )


class ScanResults(BaseModel):
    """Complete scan results.

    ``candidates`` is the canonical deterministic evidence collection.
    ``assessments`` is the durable model-analysis record (schema 1.1+).
    ``findings`` remains the model-oriented compatibility projection (filtering
    unchanged). ``schema_version`` versions this public document shape, not the
    package release.
    """
    schema_version: str = Field(
        default=PUBLIC_RESULT_SCHEMA_VERSION,
        description='Public result schema version (e.g. "1.3")',
    )
    meta: ScanMetadata = Field(..., description="Scan metadata")
    candidates: List[CandidateEvidence] = Field(
        default_factory=list,
        description="Canonical deterministic candidate evidence",
    )
    assessments: List[ModelAssessment] = Field(
        default_factory=list,
        description="Model assessments linked to candidate ids (schema 1.1+)",
    )
    findings: List[Finding] = Field(..., description="List of findings")
