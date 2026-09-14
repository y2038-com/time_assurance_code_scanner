# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""time_t configuration detection analyzer."""

import re
from typing import Dict, Tuple, Optional, List
from dataclasses import dataclass


@dataclass
class TimeTEvidence:
    """Evidence for time_t configuration detection."""
    source: str  # "makefile", "cmake", etc.
    indicator: str  # What was detected
    time_t_size: Optional[int] = None  # 32 or 64, or None
    time_t_signed: Optional[str] = None  # "signed" or "unsigned" or None
    confidence: float = 0.0  # 0.0 to 1.0


class TimeTConfigDetector:
    """Detects time_t size and signedness configuration from build system information."""
    
    def __init__(self):
        """Initialize the time_t config detector."""
        pass
    
    def detect(self, extracted_info: Dict, architecture: Optional[str] = None) -> Tuple[Optional[int], float, Optional[str], float, List[TimeTEvidence]]:
        """
        Detect time_t size and signedness from extracted build system information.
        
        Args:
            extracted_info: Dictionary from build parser
            architecture: Detected architecture (ILP32 or LP64) for inference
        
        Returns:
            Tuple of (time_t_size, time_t_size_confidence, time_t_signed, time_t_signed_confidence, evidence_list)
            - time_t_size: 32, 64, or None if uncertain
            - time_t_size_confidence: 0.0 to 1.0
            - time_t_signed: "signed" or "unsigned" or None if uncertain
            - time_t_signed_confidence: 0.0 to 1.0
            - evidence_list: List of TimeTEvidence objects
        """
        evidence: List[TimeTEvidence] = []
        
        defines = extracted_info.get('defines', [])
        cflags = extracted_info.get('cflags', [])
        
        # Check for explicit _TIME_BITS define (highest confidence)
        time_bits_value = None
        for define in defines:
            if define.startswith('TIME_BITS='):
                time_bits_value = define.split('=')[1]
            elif define == 'TIME_BITS':
                # Check cflags for -D_TIME_BITS=64
                for flag in cflags:
                    match = re.search(r'-D_TIME_BITS=(\d+)', flag)
                    if match:
                        time_bits_value = match.group(1)
                        break
        
        # Also check cflags directly
        for flag in cflags:
            match = re.search(r'-D_TIME_BITS=(\d+)', flag)
            if match:
                time_bits_value = match.group(1)
                evidence.append(TimeTEvidence(
                    source='compiler_flag',
                    indicator=f'-D_TIME_BITS={time_bits_value}',
                    time_t_size=int(time_bits_value),
                    confidence=0.95
                ))
                break
        
        # Detect time_t signedness
        time_t_signed = None
        time_t_signed_confidence = 0.0
        
        # Check for explicit unsigned time_t defines
        for define in defines:
            if 'TIME_T_UNSIGNED' in define.upper() or 'CONFIG_TIME_T_UNSIGNED' in define.upper():
                time_t_signed = 'unsigned'
                time_t_signed_confidence = 0.85
                evidence.append(TimeTEvidence(
                    source='define',
                    indicator=define,
                    time_t_signed='unsigned',
                    confidence=0.85
                ))
                break
        
        # Check cflags for unsigned time_t
        for flag in cflags:
            if '-D_TIME_T_UNSIGNED' in flag or '-DCONFIG_TIME_T_UNSIGNED' in flag:
                time_t_signed = 'unsigned'
                time_t_signed_confidence = 0.85
                evidence.append(TimeTEvidence(
                    source='compiler_flag',
                    indicator=flag,
                    time_t_signed='unsigned',
                    confidence=0.85
                ))
                break
        
        # Infer signedness from library (if we can detect it)
        # Most standard libraries (glibc, musl) use signed by default
        # Some embedded libraries (Zephyr, picolibc) may use unsigned
        # For now, default to signed if not explicitly detected
        if time_t_signed is None:
            # Default to signed (most common), but with low confidence
            time_t_signed = 'signed'
            time_t_signed_confidence = 0.5  # Low confidence default
        
        if time_bits_value:
            # Add signedness to evidence if not already added
            if time_t_signed and not any(e.time_t_signed == time_t_signed for e in evidence):
                evidence.append(TimeTEvidence(
                    source='default',
                    indicator=f'Default {time_t_signed} (not explicitly detected)',
                    time_t_signed=time_t_signed,
                    confidence=time_t_signed_confidence
                ))
            return int(time_bits_value), 0.95, time_t_signed, time_t_signed_confidence, evidence
        
        # Check for _FILE_OFFSET_BITS=64 (hint for 64-bit time_t)
        for flag in cflags:
            if '-D_FILE_OFFSET_BITS=64' in flag:
                evidence.append(TimeTEvidence(
                    source='compiler_flag',
                    indicator='-D_FILE_OFFSET_BITS=64',
                    time_t_size=64,
                    time_t_signed=time_t_signed,
                    confidence=0.60  # Lower confidence, just a hint
                ))
        
        # Infer from architecture if no explicit flags
        if architecture:
            if architecture == 'LP64':
                # LP64 typically uses 64-bit time_t by default
                # Add signedness to evidence if not already added
                if time_t_signed and not any(e.time_t_signed == time_t_signed for e in evidence):
                    evidence.append(TimeTEvidence(
                        source='default',
                        indicator=f'Default {time_t_signed} (not explicitly detected)',
                        time_t_signed=time_t_signed,
                        confidence=time_t_signed_confidence
                    ))
                evidence.append(TimeTEvidence(
                    source='architecture_inference',
                    indicator=f'LP64 architecture (default 64-bit time_t)',
                    time_t_size=64,
                    time_t_signed=time_t_signed,
                    confidence=0.70
                ))
                return 64, 0.70, time_t_signed, time_t_signed_confidence, evidence
            elif architecture == 'ILP32':
                # ILP32 typically uses 32-bit time_t by default (unless explicitly set)
                # Add signedness to evidence if not already added
                if time_t_signed and not any(e.time_t_signed == time_t_signed for e in evidence):
                    evidence.append(TimeTEvidence(
                        source='default',
                        indicator=f'Default {time_t_signed} (not explicitly detected)',
                        time_t_signed=time_t_signed,
                        confidence=time_t_signed_confidence
                    ))
                evidence.append(TimeTEvidence(
                    source='architecture_inference',
                    indicator=f'ILP32 architecture (default 32-bit time_t)',
                    time_t_size=32,
                    time_t_signed=time_t_signed,
                    confidence=0.65
                ))
                return 32, 0.65, time_t_signed, time_t_signed_confidence, evidence
        
        # No evidence found - still return signedness defaults
        if time_t_signed and not any(e.time_t_signed == time_t_signed for e in evidence):
            evidence.append(TimeTEvidence(
                source='default',
                indicator=f'Default {time_t_signed} (not explicitly detected)',
                time_t_signed=time_t_signed,
                confidence=time_t_signed_confidence
            ))
        return None, 0.0, time_t_signed, time_t_signed_confidence, evidence
