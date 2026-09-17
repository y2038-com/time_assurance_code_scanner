# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Tri-state reading of the environment config's capability fields.

Whether a target offers time64 entry points, and whether its C library honours
``_TIME_BITS``, are facts about a library build. Neither follows from the ABI a
config id names: a 64-bit ``time_t`` does not put 64-bit variants in the library,
and no ABI implies ``_TIME_BITS`` support. So these fields carry three states,
and the third is that nothing established the answer.

That third state only survives if no reader tests them for plain truth.
``if config.get("d_time_bits_supported"):`` maps unknown onto unsupported, and
the scan then tells the model a feature is absent that nobody checked. Read them
with :func:`capability` and phrase them with :func:`describe_capability`, which
has no branch that can quietly turn unknown into no.
"""

from __future__ import annotations

from typing import Any

#: Value ``d_time_bits_setting`` carries when the setting is not established.
#: Distinct from ``"not_available"``, which asserts the feature is absent, and
#: from ``"not_set"``, which asserts the build leaves the macro undefined.
UNKNOWN_SETTING = "unknown"

#: Capability fields that are tri-state: true, false, or unknown.
CAPABILITY_FIELDS = ("time64_functions_available", "d_time_bits_supported")

_TRUE_TEXT = frozenset({"true", "yes", "1", "available", "supported"})
_FALSE_TEXT = frozenset({"false", "no", "0", "unavailable", "unsupported"})


def capability(value: Any) -> bool | None:
    """Read a capability field as ``True``, ``False``, or ``None`` for unknown.

    Absent, null and "unknown" all say the same thing, so they answer alike. A
    value that parses as neither true nor false is unknown rather than false:
    guessing absent from unrecognised input is how an unevidenced 'no' gets in.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUE_TEXT:
            return True
        if text in _FALSE_TEXT:
            return False
    return None


def capability_of(config: dict[str, Any] | None, field: str) -> bool | None:
    """Read one capability field out of a config, where absent means unknown."""
    if not config:
        return None
    return capability(config.get(field))


def describe_capability(value: Any, *, yes: str, no: str, unknown: str) -> str:
    """Phrase a capability for a reader, keeping all three states apart."""
    state = capability(value)
    if state is True:
        return yes
    if state is False:
        return no
    return unknown


def setting(value: Any) -> str:
    """Read ``d_time_bits_setting``, with anything unestablished as unknown.

    ``"not_available"`` is preserved: a caller that knows the feature is absent
    is saying more than a caller who never found out.
    """
    if value is None:
        return UNKNOWN_SETTING
    text = str(value).strip()
    if not text or text.lower() in {"unknown", "unspecified", "none", "null", "n/a"}:
        return UNKNOWN_SETTING
    return text


def setting_of(config: dict[str, Any] | None, field: str = "d_time_bits_setting") -> str:
    """Read ``d_time_bits_setting`` out of a config, where absent means unknown."""
    if not config:
        return UNKNOWN_SETTING
    return setting(config.get(field))


def time64_suffix(value: Any) -> str:
    """The ``time64_*`` half of a scenario hint, which has three forms."""
    return describe_capability(value, yes="yes", no="no", unknown=UNKNOWN_SETTING)
