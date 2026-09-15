# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Central console logging configuration for TACS CLI diagnostics."""

from __future__ import annotations

import logging
import sys
from typing import Optional

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
DEFAULT_LOG_LEVEL = "INFO"

_TACS_LOGGER_NAME = "tacs"
_HANDLER_ATTR = "_tacs_console_handler"


def normalize_log_level(value: str) -> str:
    """Return a canonical log level name or raise ValueError."""
    level = (value or "").strip().upper()
    if level not in LOG_LEVELS:
        raise ValueError(
            f"invalid log level {value!r}; expected one of {', '.join(LOG_LEVELS)}"
        )
    return level


def resolve_log_level(
    *,
    log_level: Optional[str] = None,
    verbose: bool = False,
) -> str:
    """
    Resolve effective level.

    Explicit ``log_level`` wins over ``verbose``. ``verbose`` alone means DEBUG.
    """
    if log_level is not None and str(log_level).strip() != "":
        return normalize_log_level(str(log_level))
    if verbose:
        return "DEBUG"
    return DEFAULT_LOG_LEVEL


def configure_logging(level: str = DEFAULT_LOG_LEVEL) -> logging.Logger:
    """
    Configure the ``tacs`` logger for stderr diagnostics.

    Idempotent: replaces any previous TACS console handler so CliRunner / repeated
    invocations do not duplicate messages. Child loggers (``tacs.*``) propagate here.
    Does not attach handlers to the root logger.
    """
    level_name = normalize_log_level(level)
    numeric = getattr(logging, level_name)

    logger = logging.getLogger(_TACS_LOGGER_NAME)
    logger.setLevel(numeric)
    logger.propagate = False

    for handler in list(logger.handlers):
        if getattr(handler, _HANDLER_ATTR, False):
            logger.removeHandler(handler)
            handler.close()

    handler = logging.StreamHandler(sys.stderr)
    setattr(handler, _HANDLER_ATTR, True)
    handler.setLevel(numeric)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(handler)
    return logger


def get_logger(name: str = _TACS_LOGGER_NAME) -> logging.Logger:
    """Return a child logger under ``tacs`` (or ``tacs`` itself)."""
    if name == _TACS_LOGGER_NAME or name.startswith(_TACS_LOGGER_NAME + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{_TACS_LOGGER_NAME}.{name}")
