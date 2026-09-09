"""Architecture detection analyzer (ILP32 vs LP64)."""

import re
from typing import Dict, Tuple, Optional, List
from dataclasses import dataclass


@dataclass
class ArchitectureEvidence:
    """Evidence for architecture detection."""
    source: str  # "makefile", "cmake", "toolchain", etc.
    indicator: str  # What was detected
    architecture: str  # "ILP32" or "LP64"
    confidence: float  # 0.0 to 1.0


class ArchitectureDetector:
    """Detects hardware architecture (ILP32 vs LP64) from build system information."""
    
    def __init__(self):
        """Initialize the architecture detector."""
        pass
    
    def detect(self, extracted_info: Dict) -> Tuple[Optional[str], float, List[ArchitectureEvidence]]:
        """
        Detect architecture from extracted build system information.
        
        Args:
            extracted_info: Dictionary from build parser with 'cflags', 'defines', 
                          'variables', 'toolchain'
        
        Returns:
            Tuple of (architecture, confidence, evidence_list)
            - architecture: "ILP32", "LP64", or None if uncertain
            - confidence: 0.0 to 1.0
            - evidence_list: List of ArchitectureEvidence objects
        """
        evidence: List[ArchitectureEvidence] = []
        
        cflags = extracted_info.get('cflags', [])
        variables = extracted_info.get('variables', {})
        toolchain = extracted_info.get('toolchain', '')
        
        # Check explicit architecture flags (highest confidence)
        for flag in cflags:
            if flag == '-m32':
                evidence.append(ArchitectureEvidence(
                    source='compiler_flag',
                    indicator='-m32',
                    architecture='ILP32',
                    confidence=0.95
                ))
            elif flag == '-m64':
                evidence.append(ArchitectureEvidence(
                    source='compiler_flag',
                    indicator='-m64',
                    architecture='LP64',
                    confidence=0.95
                ))
            elif flag.startswith('-march='):
                arch = self._parse_march(flag)
                if arch:
                    evidence.append(ArchitectureEvidence(
                        source='compiler_flag',
                        indicator=flag,
                        architecture=arch[0],
                        confidence=arch[1]
                    ))
        
        # Check toolchain (medium-high confidence)
        if toolchain:
            arch = self._parse_toolchain(toolchain)
            if arch:
                evidence.append(ArchitectureEvidence(
                    source='toolchain',
                    indicator=toolchain,
                    architecture=arch[0],
                    confidence=arch[1]
                ))
        
        # Check CMAKE_SYSTEM_PROCESSOR (medium confidence)
        if 'CMAKE_SYSTEM_PROCESSOR' in variables:
            processor = variables['CMAKE_SYSTEM_PROCESSOR'].lower()
            arch = self._parse_processor(processor)
            if arch:
                evidence.append(ArchitectureEvidence(
                    source='cmake',
                    indicator=f'CMAKE_SYSTEM_PROCESSOR={processor}',
                    architecture=arch[0],
                    confidence=arch[1]
                ))
        
        # Determine final architecture and confidence
        if not evidence:
            return None, 0.0, []
        
        # Count evidence for each architecture
        ilp32_evidence = [e for e in evidence if e.architecture == 'ILP32']
        lp64_evidence = [e for e in evidence if e.architecture == 'LP64']
        
        # If conflicting evidence, use highest confidence
        if ilp32_evidence and lp64_evidence:
            ilp32_max = max(e.confidence for e in ilp32_evidence)
            lp64_max = max(e.confidence for e in lp64_evidence)
            
            if ilp32_max > lp64_max:
                return 'ILP32', ilp32_max * 0.9, evidence  # Slightly reduce due to conflict
            else:
                return 'LP64', lp64_max * 0.9, evidence
        elif ilp32_evidence:
            max_conf = max(e.confidence for e in ilp32_evidence)
            return 'ILP32', max_conf, evidence
        elif lp64_evidence:
            max_conf = max(e.confidence for e in lp64_evidence)
            return 'LP64', max_conf, evidence
        
        return None, 0.0, evidence
    
    def _parse_march(self, flag: str) -> Optional[Tuple[str, float]]:
        """Parse -march= flag to determine architecture."""
        match = re.search(r'-march=([\w-]+)', flag)
        if not match:
            return None
        
        arch_str = match.group(1).lower()
        
        # ILP32 indicators
        if any(x in arch_str for x in ['armv7', 'armv6', 'armv5', 'armv4']):
            return ('ILP32', 0.85)
        if arch_str in ['i386', 'i686']:
            return ('ILP32', 0.85)
        
        # LP64 indicators
        if arch_str in ['x86_64', 'amd64']:
            return ('LP64', 0.95)
        if 'armv8' in arch_str or 'aarch64' in arch_str:
            return ('LP64', 0.90)
        if arch_str.startswith('mips64'):
            return ('LP64', 0.85)
        
        return None
    
    def _parse_toolchain(self, toolchain: str) -> Optional[Tuple[str, float]]:
        """Parse toolchain name to determine architecture."""
        toolchain_lower = toolchain.lower()
        
        # ILP32 toolchains
        if 'arm-none-eabi' in toolchain_lower or 'arm-eabi' in toolchain_lower:
            return ('ILP32', 0.85)
        if toolchain_lower.startswith('arm-'):
            return ('ILP32', 0.80)
        if 'mips32' in toolchain_lower:
            return ('ILP32', 0.80)
        
        # LP64 toolchains
        if 'aarch64' in toolchain_lower:
            return ('LP64', 0.90)
        if 'x86_64' in toolchain_lower or 'amd64' in toolchain_lower:
            return ('LP64', 0.90)
        if 'mips64' in toolchain_lower:
            return ('LP64', 0.85)
        
        return None
    
    def _parse_processor(self, processor: str) -> Optional[Tuple[str, float]]:
        """Parse CMAKE_SYSTEM_PROCESSOR to determine architecture."""
        processor_lower = processor.lower()
        
        # ILP32 processors
        if processor_lower in ['arm', 'armv7', 'armv6', 'armv5']:
            return ('ILP32', 0.80)
        if processor_lower in ['i386', 'i686']:
            return ('ILP32', 0.80)
        if 'mips32' in processor_lower:
            return ('ILP32', 0.75)
        
        # LP64 processors
        if processor_lower in ['aarch64', 'arm64', 'armv8']:
            return ('LP64', 0.85)
        if processor_lower in ['x86_64', 'amd64']:
            return ('LP64', 0.90)
        if 'mips64' in processor_lower:
            return ('LP64', 0.80)
        
        return None
