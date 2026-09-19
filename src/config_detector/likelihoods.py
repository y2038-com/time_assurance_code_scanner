# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Experimental config likelihood helpers that return plain dictionaries.

Build-system auto-detection of the eight ABI/time_t configs is best-effort.
Callers should prefer an explicit env_config / config_id when accuracy matters.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional


ALL_CONFIG_IDS = (
    "ilp32_signed_32bit",
    "ilp32_signed_64bit",
    "ilp32_unsigned_32bit",
    "ilp32_unsigned_64bit",
    "lp64_signed_32bit",
    "lp64_signed_64bit",
    "lp64_unsigned_32bit",
    "lp64_unsigned_64bit",
)


class ConfigDetectionError(Exception):
    """Raised when experimental config detection fails."""


def _parse_config_id(config_id: str) -> Optional[Dict[str, Any]]:
    """Parse ``ilp32_signed_32bit``-style IDs into plain component fields."""
    parts = config_id.split("_")
    if len(parts) < 3:
        return None
    hardware_model = parts[0].upper()
    signedness = parts[1]
    size_str = parts[2]
    if hardware_model not in {"ILP32", "LP64"}:
        return None
    if signedness not in {"signed", "unsigned"}:
        return None
    if not size_str.endswith("bit"):
        return None
    try:
        size_bits = int(size_str.replace("bit", ""))
    except ValueError:
        return None
    if size_bits not in {32, 64}:
        return None
    return {
        "hardware_model": hardware_model,
        "time_t_signed": signedness,
        "time_t_size_bits": size_bits,
        "config_id": config_id,
    }


def detect_config_likelihoods(
    project_path: str | Path,
    *,
    use_llm: bool = False,
    llm_model: str = "gpt-oss:120b-cloud",
) -> Dict[str, Any]:
    """
    Detect likelihoods for all eight environment configs (experimental).

    Returns a plain dict::

        {
          "likelihoods": [{"config_id": str, "likelihood": float, "confidence": str, ...}],
          "recommended": {components...} | None,
          "recommended_config_id": str | None,
          "overall_confidence": float,
          "experimental": True,
        }
    """
    from .detector import ConfigDetector
    from .hybrid_detector import HybridConfigDetector

    project_path_obj = Path(project_path)
    if not project_path_obj.exists():
        raise ConfigDetectionError(f"Project path does not exist: {project_path}")

    try:
        if use_llm:
            detector = HybridConfigDetector(
                root_path=project_path_obj,
                llm_type="ollama",
                llm_model=llm_model,
                llm_timeout=60,
                confidence_threshold=0.7,
                use_cache=True,
                debug=False,
            )
            results = detector.detect(force_llm=False, keyword_only=False)
        else:
            detector = ConfigDetector(project_path_obj)
            results = detector.detect()
    except Exception as exc:
        raise ConfigDetectionError(f"Config detection failed: {exc}") from exc

    likelihoods_data = results.get("likelihoods", [])
    detected_likelihoods: Dict[str, float] = {}
    for item in likelihoods_data:
        if hasattr(item, "name"):
            config_id = item.name
            likelihood_val = float(item.likelihood)
        else:
            config_id = item.get("name", "unknown")
            likelihood_val = float(item.get("likelihood", 0.0))
        detected_likelihoods[config_id] = likelihood_val

    detected_values = [v for v in detected_likelihoods.values() if v > 0.0]
    is_unsure = False
    if detected_values:
        if len(detected_values) == 4 and all(abs(v - 0.25) < 0.01 for v in detected_values):
            is_unsure = True
        elif len({round(v, 2) for v in detected_values}) == 1 and max(detected_values) < 0.3:
            is_unsure = True

    likelihoods: List[Dict[str, Any]] = []
    for config_id in ALL_CONFIG_IDS:
        likelihood_val = detected_likelihoods.get(config_id, 0.0)
        if is_unsure or likelihood_val == 0.0:
            likelihood_val = 1.0 / 8.0
        confidence = (
            "high" if likelihood_val > 0.7 else "medium" if likelihood_val > 0.3 else "low"
        )
        components = _parse_config_id(config_id) or {}
        likelihoods.append(
            {
                "config_id": config_id,
                "name": config_id,
                "likelihood": likelihood_val,
                "confidence": confidence,
                **{k: v for k, v in components.items() if k != "config_id"},
            }
        )

    likelihoods.sort(key=lambda item: item["likelihood"], reverse=True)

    recommended = None
    recommended_config_id = None
    overall_confidence = 1.0 / 8.0
    if likelihoods:
        max_likelihood = max(item["likelihood"] for item in likelihoods)
        overall_confidence = max_likelihood
        if max_likelihood > 0.7:
            top = likelihoods[0]
            recommended_config_id = top["config_id"]
            recommended = _parse_config_id(recommended_config_id)
            overall_confidence = top["likelihood"]
        elif max_likelihood <= 1.0 / 8.0 + 0.001:
            all_same = all(abs(item["likelihood"] - max_likelihood) < 0.001 for item in likelihoods)
            if all_same:
                overall_confidence = 1.0 / 8.0

    return {
        "likelihoods": likelihoods,
        "recommended": recommended,
        "recommended_config_id": recommended_config_id,
        "overall_confidence": float(overall_confidence),
        "experimental": True,
    }
