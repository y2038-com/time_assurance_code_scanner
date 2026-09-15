# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
from typing import Any, Optional

from tacs.core.logging_config import get_logger


class StatusLogger:
    """Compatibility adapter: timestamped_* helpers over standard logging."""

    _logger: logging.Logger = get_logger("tacs.status")

    @classmethod
    def _log(cls, level: int, message: str, **_ignored: Any) -> None:
        # ``file`` / ``flush`` from legacy call sites are ignored; diagnostics go to
        # the configured tacs stderr handler.
        cls._logger.log(level, "%s", message)

    @staticmethod
    def timestamped_debug(message: str, file: Optional[Any] = None, flush: bool = True) -> None:
        """Log a DEBUG diagnostic message."""
        StatusLogger._log(logging.DEBUG, message, file=file, flush=flush)

    @staticmethod
    def timestamped_print(message: str, file: Optional[Any] = None, flush: bool = True) -> None:
        """Log an INFO diagnostic message (legacy name preserved)."""
        StatusLogger._log(logging.INFO, message, file=file, flush=flush)

    @staticmethod
    def timestamped_info(message: str, file: Optional[Any] = None, flush: bool = True) -> None:
        """Log an INFO diagnostic message."""
        StatusLogger._log(logging.INFO, message, file=file, flush=flush)

    @staticmethod
    def timestamped_warning(message: str, file: Optional[Any] = None, flush: bool = True) -> None:
        """Log a WARNING diagnostic message."""
        StatusLogger._log(logging.WARNING, message, file=file, flush=flush)

    @staticmethod
    def timestamped_error(message: str, file: Optional[Any] = None, flush: bool = True) -> None:
        """Log an ERROR diagnostic message."""
        StatusLogger._log(logging.ERROR, message, file=file, flush=flush)


def log_status(message: str) -> None:
    """Log a status message."""
    StatusLogger.timestamped_print(message)


def log_error(message: str) -> None:
    """Log an error message."""
    StatusLogger.timestamped_error(message)


def log_warning(message: str) -> None:
    """Log a warning message."""
    StatusLogger.timestamped_warning(message)


def log_info(message: str) -> None:
    """Log an info message."""
    StatusLogger.timestamped_info(message)


def log_debug(message: str) -> None:
    """Log a debug message."""
    StatusLogger.timestamped_debug(message)
