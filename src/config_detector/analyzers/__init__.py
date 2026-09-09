"""Analyzers for detecting architecture, time_t configuration, and C library."""

from .architecture import ArchitectureDetector
from .time_t_config import TimeTConfigDetector

__all__ = ['ArchitectureDetector', 'TimeTConfigDetector']
