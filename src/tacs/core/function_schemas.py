# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Function-first analysis schemas for Y2038 scanner.
"""

from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
from enum import Enum
from tacs.core.schema import TimeIssueType


class Y2038Summary(str, Enum):
    """Y2038 summary classification."""
    YES = "yes"
    NO = "no"
    ABSTAIN = "abstain"


class ContextNeed(str, Enum):
    """Types of context that can be requested."""
    TYPEDEF = "typedef"
    STRUCT = "struct"
    MACRO = "macro"
    CALLEE = "callee"
    HEADER = "header"


class FunctionAnalysis(BaseModel):
    """Result of function analysis."""
    function_id: str = Field(..., description="Function identifier: <relpath>@<symbol>:<start>-<end>")
    y2038_summary: Y2038Summary = Field(..., description="Overall Y2038 assessment")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the assessment")
    issues: List[Dict[str, Any]] = Field(default_factory=list, description="Specific issues found (Y2038, Y2106, or both)")
    needs_more_context: bool = Field(default=False, description="Whether more context is needed")
    needs: List[ContextNeed] = Field(default_factory=list, description="Types of context needed")
    
    # Y2106 detection fields (optional, populated when Y2106 detection enabled)
    y2106_summary: Optional[Y2038Summary] = Field(default=None, description="Overall Y2106 assessment (when Y2106 detection enabled)")
    issue_type: Optional[TimeIssueType] = Field(default=None, description="Type of time overflow issue (Y2038, Y2106, both, none, abstain)")


class FunctionBody(BaseModel):
    """A function body with metadata."""
    function_id: str = Field(..., description="Function identifier")
    file_path: str = Field(..., description="Path to the source file")
    symbol: str = Field(..., description="Function name/symbol")
    start_line: int = Field(..., description="Starting line number")
    end_line: int = Field(..., description="Ending line number")
    body: str = Field(..., description="Full function body")
    candidate_lines: List[int] = Field(default_factory=list, description="Lines containing Y2038 candidates")
    context_additions: Optional[Dict[str, Any]] = Field(default=None, description="Additional context for iterative analysis")
    is_partial: bool = Field(default=False, description="Whether this is a partial function (split from a larger function)")
    original_function_id: Optional[str] = Field(default=None, description="Original function_id if this is a partial function")
    part_number: Optional[int] = Field(default=None, description="Part number if this is a partial function (1-based)")


class FunctionBatch(BaseModel):
    """A batch of functions for analysis."""
    batch_id: str = Field(..., description="Unique batch identifier")
    functions: List[FunctionBody] = Field(..., description="Functions in this batch")
    iteration: int = Field(default=1, description="Iteration number (1 for F1, 2+ for F2)")


class FunctionCache(BaseModel):
    """Cache entry for function analysis."""
    function_hash: str = Field(..., description="Hash of function body")
    scenario_hint: str = Field(..., description="Environment scenario")
    rules_version: str = Field(..., description="Rules version")
    prompt_version: str = Field(..., description="Prompt version")
    model_name: str = Field(..., description="LLM model name")
    analysis: FunctionAnalysis = Field(..., description="Cached analysis result")


class IssueSpan(BaseModel):
    """Span information for an issue."""
    start_line: int = Field(..., description="Starting line")
    end_line: int = Field(..., description="Ending line")
    start_col: Optional[int] = Field(default=None, description="Starting column")
    end_col: Optional[int] = Field(default=None, description="Ending column")
    symbol: Optional[str] = Field(default=None, description="Symbol involved")


class FunctionFinding(BaseModel):
    """Finding from function analysis."""
    function_id: str = Field(..., description="Function identifier")
    y2038_summary: Y2038Summary = Field(..., description="Overall assessment")
    confidence: float = Field(..., description="Confidence level")
    issues: List[Dict[str, Any]] = Field(default_factory=list, description="Specific issues")
    issue_spans: List[IssueSpan] = Field(default_factory=list, description="Issue locations")
    iteration_count: int = Field(default=1, description="Number of iterations performed")
    final_pass: str = Field(default="S2_P1", description="Final stage and pass that resolved this function (e.g., S2_P1, S2_P2, S3_P1)")
