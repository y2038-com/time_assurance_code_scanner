# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Thin factory seam over ``LLMClient`` (stable for adapters / future registry)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def create_llm_client(
    llm_type: str = "none",
    model: Optional[str] = None,
    **kwargs: Any,
):
    """Construct the current LLM client implementation.

    Call sites (CLI, pipeline, config detector) should prefer this helper so a
    future ``tacs.llm`` provider registry can swap implementations without
    changing ``ScanningPipeline`` construction patterns more than necessary.
    """
    from tacs.core.llm_client import LLMClient
    from tacs.llm.env import default_model_id

    return LLMClient(
        llm_type=llm_type,
        model=model or default_model_id(),
        **kwargs,
    )
