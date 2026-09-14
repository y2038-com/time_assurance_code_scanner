# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sys
from datetime import datetime
from typing import Optional


class StatusLogger:
    """Utility class for timestamped status messages."""
    
    @staticmethod
    def timestamped_print(message: str, file=None, flush: bool = True) -> None:
        """
        Print a message with a timestamp prefix.
        
        Args:
            message: The message to print
            file: Output file (default: current sys.stdout, resolved at call time)
            flush: Whether to flush the output immediately
        """
        if file is None:
            file = sys.stdout
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]  # HH:MM:SS.mmm
        print(f"[{timestamp}] {message}", file=file, flush=flush)
    
    @staticmethod
    def timestamped_error(message: str, file=None, flush: bool = True) -> None:
        """
        Print an error message with a timestamp prefix.
        
        Args:
            message: The error message to print
            file: Output file (default: current sys.stderr, resolved at call time)
            flush: Whether to flush the output immediately
        """
        if file is None:
            file = sys.stderr
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]  # HH:MM:SS.mmm
        print(f"[{timestamp}] ERROR: {message}", file=file, flush=flush)
    
    @staticmethod
    def timestamped_warning(message: str, file=None, flush: bool = True) -> None:
        """
        Print a warning message with a timestamp prefix.
        
        Args:
            message: The warning message to print
            file: Output file (default: current sys.stdout, resolved at call time)
            flush: Whether to flush the output immediately
        """
        if file is None:
            file = sys.stdout
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]  # HH:MM:SS.mmm
        print(f"[{timestamp}] WARNING: {message}", file=file, flush=flush)
    
    @staticmethod
    def timestamped_info(message: str, file=None, flush: bool = True) -> None:
        """
        Print an info message with a timestamp prefix.
        
        Args:
            message: The info message to print
            file: Output file (default: current sys.stdout, resolved at call time)
            flush: Whether to flush the output immediately
        """
        if file is None:
            file = sys.stdout
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]  # HH:MM:SS.mmm
        print(f"[{timestamp}] INFO: {message}", file=file, flush=flush)


# Convenience functions for backward compatibility
def log_status(message: str) -> None:
    """Log a status message with timestamp."""
    StatusLogger.timestamped_print(message)


def log_error(message: str) -> None:
    """Log an error message with timestamp."""
    StatusLogger.timestamped_error(message)


def log_warning(message: str) -> None:
    """Log a warning message with timestamp."""
    StatusLogger.timestamped_warning(message)


def log_info(message: str) -> None:
    """Log an info message with timestamp."""
    StatusLogger.timestamped_info(message)
