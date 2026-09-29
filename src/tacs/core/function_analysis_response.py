# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Strict wire-contract validation for function-level model responses.

Model items become completed assessments only when ``function_id`` is an exact
requested string and every required field uses the documented vocabulary.
Positional binding and undocumented aliases are rejected.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from tacs.core.function_schemas import (
    ContextNeed,
    FunctionAnalysis,
    FunctionBody,
    Y2038Summary,
)
from tacs.core.schema import AssessmentExecutionStatus, TimeIssueType

# Controlled issue types for operational stubs (public assessments map these).
ISSUE_MISSING_EXPECTED = "missing_expected_result"
ISSUE_DUPLICATE_ID = "duplicate_function_id"
ISSUE_INVALID_SCHEMA = "invalid_result_schema"
ISSUE_ANALYSIS_ERROR = "analysis_error"

_SUMMARY_VALUES = frozenset({"yes", "no", "abstain"})
_NEED_VALUES = frozenset(n.value for n in ContextNeed)
_ISSUE_TYPE_VALUES = frozenset(t.value for t in TimeIssueType)


class WireIssue(BaseModel):
    """One issue object from the model wire format.

    Canonical fields only: ``type``, ``line``, ``description``. Undocumented
    extras are rejected (no documented provider contract requires them).
    """

    model_config = ConfigDict(extra="forbid")

    type: str
    line: int
    description: str

    @field_validator("type", "description", mode="before")
    @classmethod
    def _require_str(cls, value: Any) -> str:
        if type(value) is not str:
            raise ValueError("must be a JSON string")
        return value

    @field_validator("line", mode="before")
    @classmethod
    def _require_int_line(cls, value: Any) -> int:
        if type(value) is bool or type(value) is not int:
            # Reject bool (subclass of int) and non-integers including floats.
            if type(value) is float and value.is_integer():
                return int(value)
            raise ValueError("line must be a JSON integer")
        return value


class FunctionAnalysisWireItem(BaseModel):
    """Canonical F1/F2/F3 model item (Y2038-only mode)."""

    model_config = ConfigDict(extra="forbid")

    function_id: str
    y2038_summary: str
    confidence: float
    # Present JSON array required; empty [] is valid (especially for no/abstain).
    issues: List[WireIssue]
    needs_more_context: bool
    needs: List[str]

    @field_validator("function_id", mode="before")
    @classmethod
    def _function_id_plain_str(cls, value: Any) -> str:
        if type(value) is not str:
            raise ValueError("function_id must be a JSON string")
        return value

    @field_validator("y2038_summary", mode="before")
    @classmethod
    def _summary_exact(cls, value: Any) -> str:
        if type(value) is not str or value not in _SUMMARY_VALUES:
            raise ValueError("y2038_summary must be exactly yes|no|abstain")
        return value

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence_finite_number(cls, value: Any) -> float:
        if type(value) is bool or type(value) not in (int, float):
            raise ValueError("confidence must be a finite JSON number")
        conf = float(value)
        if not math.isfinite(conf):
            raise ValueError("confidence must be finite")
        if conf < 0.0 or conf > 1.0:
            raise ValueError("confidence must be in [0.0, 1.0]")
        return conf

    @field_validator("needs_more_context", mode="before")
    @classmethod
    def _needs_more_context_bool(cls, value: Any) -> bool:
        if type(value) is not bool:
            raise ValueError("needs_more_context must be a JSON boolean")
        return value

    @field_validator("needs", mode="before")
    @classmethod
    def _needs_list(cls, value: Any) -> List[str]:
        if not isinstance(value, list):
            raise ValueError("needs must be a JSON array")
        out: List[str] = []
        for entry in value:
            if type(entry) is not str or entry not in _NEED_VALUES:
                raise ValueError("needs entries must be documented context enums")
            out.append(entry)
        return out

    @field_validator("issues", mode="before")
    @classmethod
    def _issues_list(cls, value: Any) -> Any:
        if not isinstance(value, list):
            raise ValueError("issues must be a JSON array")
        return value


class FunctionAnalysisWireItemY2106(FunctionAnalysisWireItem):
    """Canonical item when Y2106 detection is enabled."""

    y2106_summary: str
    issue_type: str

    @field_validator("y2106_summary", mode="before")
    @classmethod
    def _y2106_summary_exact(cls, value: Any) -> str:
        if type(value) is not str or value not in _SUMMARY_VALUES:
            raise ValueError("y2106_summary must be exactly yes|no|abstain")
        return value

    @field_validator("issue_type", mode="before")
    @classmethod
    def _issue_type_exact(cls, value: Any) -> str:
        if type(value) is not str or value not in _ISSUE_TYPE_VALUES:
            raise ValueError(
                "issue_type must be exactly y2038|y2106|both|none|abstain"
            )
        return value


def _error_stub(
    function: FunctionBody,
    *,
    issue_type: str,
    description: str,
    pass_name: str,
) -> FunctionAnalysis:
    line0 = function.start_line if getattr(function, "start_line", None) else 1
    return FunctionAnalysis(
        function_id=function.function_id,
        y2038_summary=Y2038Summary.ABSTAIN,
        confidence=0.0,
        issues=[
            {
                "type": issue_type,
                "description": description,
                "line": line0,
            }
        ],
        needs_more_context=False,
        needs=[],
        execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
    )


def _wire_to_analysis(item: FunctionAnalysisWireItem) -> FunctionAnalysis:
    data: Dict[str, Any] = {
        "function_id": item.function_id,
        "y2038_summary": Y2038Summary(item.y2038_summary),
        "confidence": float(item.confidence),
        "issues": [issue.model_dump() for issue in item.issues],
        "needs_more_context": item.needs_more_context,
        "needs": [ContextNeed(n) for n in item.needs],
        "execution_status": AssessmentExecutionStatus.COMPLETED,
    }
    if isinstance(item, FunctionAnalysisWireItemY2106):
        data["y2106_summary"] = Y2038Summary(item.y2106_summary)
        data["issue_type"] = TimeIssueType(item.issue_type)
    return FunctionAnalysis(**data)


def _raw_string_function_id(item: Any) -> Optional[str]:
    """Return the raw ``function_id`` string when present as a JSON string.

    Does not trim or coerce. Non-string or missing values yield ``None``.
    """
    if not isinstance(item, dict):
        return None
    if "function_id" not in item:
        return None
    value = item.get("function_id")
    if type(value) is not str:
        return None
    return value


def align_model_items_to_functions(
    raw_items: Sequence[Any],
    functions: Sequence[FunctionBody],
    *,
    pass_name: str,
    detect_y2106: bool = False,
) -> Tuple[List[FunctionAnalysis], Dict[str, int]]:
    """Validate model items and return one analysis per requested function.

    Mixed valid/invalid policy: independently valid exact-ID items complete;
    every requested ID not represented by exactly one valid canonical item
    receives ``analysis_error``. Unknown extras never attach to a function.

    Returns ``(aligned_analyses, diagnostics)`` where diagnostics counts
    controlled categories (no raw item content).
    """
    requested = [f.function_id for f in functions]
    requested_set: Set[str] = set(requested)
    diagnostics: Dict[str, int] = {
        "unknown_function_id": 0,
        "missing_function_id": 0,
        "invalid_item": 0,
        "duplicate_function_id": 0,
    }

    # --- Pass 1: duplicate detection on raw string IDs (before schema skip) ---
    id_occurrences: Dict[str, int] = {}
    for item in raw_items:
        raw_id = _raw_string_function_id(item)
        if raw_id is None:
            if isinstance(item, dict) and "function_id" not in item:
                diagnostics["missing_function_id"] += 1
            elif isinstance(item, dict):
                diagnostics["invalid_item"] += 1
            else:
                diagnostics["invalid_item"] += 1
            continue
        id_occurrences[raw_id] = id_occurrences.get(raw_id, 0) + 1

    duplicate_ids = {fid for fid, count in id_occurrences.items() if count > 1}
    if duplicate_ids:
        diagnostics["duplicate_function_id"] = len(duplicate_ids)

    # --- Pass 2: validate unique candidates that claim a requested ID ---
    # Map requested_id -> validated FunctionAnalysis OR error reason code
    validated: Dict[str, FunctionAnalysis] = {}
    errored: Dict[str, str] = {}  # function_id -> issue type for schema failures

    wire_cls = (
        FunctionAnalysisWireItemY2106 if detect_y2106 else FunctionAnalysisWireItem
    )

    for item in raw_items:
        raw_id = _raw_string_function_id(item)
        if raw_id is None:
            continue
        if raw_id not in requested_set:
            diagnostics["unknown_function_id"] += 1
            continue
        if raw_id in duplicate_ids:
            # Poisoned: never complete this ID from any item.
            continue
        if raw_id in validated or raw_id in errored:
            continue
        try:
            wire = wire_cls.model_validate(item)
        except (ValidationError, ValueError):
            errored[raw_id] = ISSUE_INVALID_SCHEMA
            continue
        # Exact equality already enforced: wire.function_id is raw_id string.
        if wire.function_id != raw_id or wire.function_id not in requested_set:
            errored[raw_id] = ISSUE_INVALID_SCHEMA
            continue
        validated[raw_id] = _wire_to_analysis(wire)

    # --- Pass 3: emit trusted request order ---
    out: List[FunctionAnalysis] = []
    for function in functions:
        fid = function.function_id
        if fid in duplicate_ids:
            out.append(
                _error_stub(
                    function,
                    issue_type=ISSUE_DUPLICATE_ID,
                    description=(
                        f"{pass_name}: duplicate function_id in model response"
                    ),
                    pass_name=pass_name,
                )
            )
            continue
        if fid in validated:
            out.append(validated[fid])
            continue
        if fid in errored:
            out.append(
                _error_stub(
                    function,
                    issue_type=ISSUE_INVALID_SCHEMA,
                    description=(
                        f"{pass_name}: model item failed canonical schema validation"
                    ),
                    pass_name=pass_name,
                )
            )
            continue
        out.append(
            _error_stub(
                function,
                issue_type=ISSUE_MISSING_EXPECTED,
                description=(
                    f"{pass_name}: no usable model item with exact function_id"
                ),
                pass_name=pass_name,
            )
        )
    return out, diagnostics
