# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Analyzers for detecting architecture, time_t configuration, and C library."""

from .architecture import ArchitectureDetector
from .time_t_config import TimeTConfigDetector

__all__ = ['ArchitectureDetector', 'TimeTConfigDetector']
