# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Migration analysis for detecting patterns that would break during config migration."""

import re
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from tacs.core.schema import Candidate, MigrationRiskType, MigrationSeverity
from tacs.core.status_logger import StatusLogger


@dataclass
class MigrationRisk:
    """A migration-specific risk."""
    risk_type: MigrationRiskType
    severity: MigrationSeverity
    description: str
    remediation: str
    line: int
    code_snippet: str


class MigrationAnalyzer:
    """Analyzes code for migration-specific risks."""
    
    def __init__(
        self,
        from_config: Dict[str, Any],
        to_config: Dict[str, Any],
        time_t_aliases: Dict[str, List[str]],
        time_bearing_symbols: Set[str]
    ):
        """
        Initialize migration analyzer.
        
        Args:
            from_config: Source configuration (hardware_model, time_t_size_bits, time_t_signed)
            to_config: Target configuration (hardware_model, time_t_size_bits, time_t_signed)
            time_t_aliases: Known time_t aliases
            time_bearing_symbols: Symbols identified as time-bearing
        """
        self.from_config = from_config
        self.to_config = to_config
        self.time_t_aliases = time_t_aliases
        self.time_bearing_symbols = time_bearing_symbols
        
        # Determine what changed
        self.width_changed = from_config.get('time_t_size_bits') != to_config.get('time_t_size_bits')
        self.signedness_changed = from_config.get('time_t_signed') != to_config.get('time_t_signed')
        self.architecture_changed = from_config.get('hardware_model') != to_config.get('hardware_model')
        
        # Build patterns for detection
        self._build_detection_patterns()
    
    def _build_detection_patterns(self):
        """Build regex patterns for migration risk detection."""
        # Width assumption patterns (for 32→64 migration)
        if self.width_changed and self.from_config.get('time_t_size_bits') == 32:
            # Explicit casts to 32-bit types
            self.width_cast_pattern = re.compile(
                r'\(int32_t\)|\(uint32_t\)|\(int\)|\(unsigned\s+int\)|\(long\)\s*(?!\s*long)',  # long but not long long
                re.IGNORECASE
            )
            # Sizeof assumptions
            self.sizeof_32_pattern = re.compile(
                r'sizeof\s*\(\s*(?:int32_t|uint32_t|int|unsigned\s+int|long)\s*\)',
                re.IGNORECASE
            )
            # Literal 4-byte assumptions
            self.literal_4_pattern = re.compile(r'\b4\s*(?:,|\)|;|\s*$)')
        else:
            self.width_cast_pattern = None
            self.sizeof_32_pattern = None
            self.literal_4_pattern = None
        
        # Signedness assumption patterns (for signed→unsigned migration)
        if self.signedness_changed and self.from_config.get('time_t_signed') == 'signed':
            # Sign checks
            self.sign_check_pattern = re.compile(
                r'<\s*0|>\s*-1|==\s*-1|!=\s*-1|<=?\s*-1|>=?\s*-1',
                re.IGNORECASE
            )
            # Negative constants
            self.negative_constant_pattern = re.compile(
                r'=\s*-?\d+|=\s*-?\d+L',
                re.IGNORECASE
            )
        else:
            self.sign_check_pattern = None
            self.negative_constant_pattern = None
    
    def analyze_migration_risks(
        self,
        candidates: List[Candidate],
        root_path: str,
        include_patterns: List[str],
        exclude_patterns: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Analyze candidates for migration-specific risks.
        
        Args:
            candidates: Existing candidates from previous stages
            root_path: Root directory
            include_patterns: File include patterns
            exclude_patterns: File exclude patterns
        
        Returns:
            List of migration risk dicts (to be converted to candidates)
        """
        if not (self.width_changed or self.signedness_changed or self.architecture_changed):
            # No migration needed
            return []
        
        StatusLogger.timestamped_print(
            f"Migration analysis: {self.from_config.get('hardware_model')} "
            f"{self.from_config.get('time_t_size_bits')}bit {self.from_config.get('time_t_signed')} → "
            f"{self.to_config.get('hardware_model')} {self.to_config.get('time_t_size_bits')}bit "
            f"{self.to_config.get('time_t_signed')}"
        )
        
        migration_risks = []
        
        # Analyze each candidate for migration risks
        for candidate in candidates:
            risks = self._analyze_candidate(candidate)
            migration_risks.extend(risks)
        
        StatusLogger.timestamped_print(f"Found {len(migration_risks)} migration risks")
        
        return migration_risks
    
    def _analyze_candidate(self, candidate: Candidate) -> List[Dict[str, Any]]:
        """Analyze a single candidate for migration risks."""
        risks = []
        code = candidate.one_line_snippet
        
        # Check if candidate involves time-bearing values
        if not self._is_time_bearing(candidate, code):
            return risks
        
        # Width assumption risks
        if self.width_changed:
            width_risks = self._detect_width_assumptions(candidate, code)
            risks.extend(width_risks)
        
        # Signedness assumption risks
        if self.signedness_changed:
            sign_risks = self._detect_signedness_assumptions(candidate, code)
            risks.extend(sign_risks)
        
        # Architecture assumption risks
        if self.architecture_changed:
            arch_risks = self._detect_architecture_assumptions(candidate, code)
            risks.extend(arch_risks)
        
        return risks
    
    def _is_time_bearing(self, candidate: Candidate, code: str) -> bool:
        """Check if candidate involves time-bearing values."""
        # Check symbol
        if candidate.symbol in self.time_bearing_symbols:
            return True
        
        # Check for time_t or aliases in code
        time_patterns = ['time_t'] + list(self.time_t_aliases.keys())
        for pattern in time_patterns:
            if re.search(rf'\b{re.escape(pattern)}\b', code):
                return True
        
        # Check for time function calls
        time_functions = ['time', 'gettimeofday', 'clock_gettime', 'localtime', 'gmtime', 'mktime']
        for func in time_functions:
            if re.search(rf'\b{re.escape(func)}\s*\(', code):
                return True
        
        return False
    
    def _detect_width_assumptions(self, candidate: Candidate, code: str) -> List[Dict[str, Any]]:
        """Detect patterns assuming old time_t width."""
        risks = []
        
        if not self.width_cast_pattern:
            return risks
        
        # Check for explicit casts to 32-bit types
        if self.width_cast_pattern.search(code):
            risks.append({
                'file': candidate.file,
                'type': MigrationRiskType.WIDTH_ASSUMPTION.value,
                'severity': MigrationSeverity.BLOCKER.value,
                'description': f"Explicit cast to 32-bit type assumes {self.from_config.get('time_t_size_bits')}-bit time_t",
                'remediation': f"Remove cast or use explicit conversion to {self.to_config.get('time_t_size_bits')}-bit type",
                'line': candidate.line,
                'code': code
            })
        
        # Check for sizeof assumptions
        if self.sizeof_32_pattern and self.sizeof_32_pattern.search(code):
            risks.append({
                'file': candidate.file,
                'type': MigrationRiskType.WIDTH_ASSUMPTION.value,
                'severity': MigrationSeverity.HIGH_RISK.value,
                'description': f"sizeof() assumes 32-bit type, migration to {self.to_config.get('time_t_size_bits')}-bit would break",
                'remediation': f"Use sizeof(time_t) or explicit {self.to_config.get('time_t_size_bits')}-bit type",
                'line': candidate.line,
                'code': code
            })
        
        # Check for literal 4-byte assumptions (if migrating 32→64)
        if (self.literal_4_pattern and 
            self.from_config.get('time_t_size_bits') == 32 and
            self.to_config.get('time_t_size_bits') == 64):
            # Look for patterns like: read(fd, &t, 4) or write(fd, &t, 4)
            if re.search(r'(read|write|fread|fwrite|memcpy|memmove)\s*\([^,]+,\s*[^,]+,\s*4\s*\)', code):
                risks.append({
                    'file': candidate.file,
                    'type': MigrationRiskType.IO_SIZE_MISMATCH.value,
                    'severity': MigrationSeverity.BLOCKER.value,
                    'description': f"Literal 4-byte assumption in I/O operation, migration to {self.to_config.get('time_t_size_bits')}-bit would break",
                    'remediation': f"Use sizeof(time_t) instead of literal 4",
                    'line': candidate.line,
                    'code': code
                })
        
        return risks
    
    def _detect_signedness_assumptions(self, candidate: Candidate, code: str) -> List[Dict[str, Any]]:
        """Detect patterns assuming old time_t signedness."""
        risks = []
        
        if not self.sign_check_pattern:
            return risks
        
        # Check for sign checks
        if self.sign_check_pattern.search(code):
            risks.append({
                'file': candidate.file,
                'type': MigrationRiskType.SIGNEDNESS_ASSUMPTION.value,
                'severity': MigrationSeverity.BLOCKER.value,
                'description': f"Sign check assumes {self.from_config.get('time_t_signed')} time_t, migration to {self.to_config.get('time_t_signed')} would break",
                'remediation': f"Remove sign check or use unsigned-safe comparison",
                'line': candidate.line,
                'code': code
            })
        
        # Check for negative constants
        if self.negative_constant_pattern and self.negative_constant_pattern.search(code):
            # Check if it's assigned to time_t or time-bearing variable
            if re.search(r'=\s*-?\d+', code):
                risks.append({
                    'file': candidate.file,
                    'type': MigrationRiskType.SIGNEDNESS_ASSUMPTION.value,
                    'severity': MigrationSeverity.BLOCKER.value,
                    'description': f"Negative constant assumes {self.from_config.get('time_t_signed')} time_t, migration to {self.to_config.get('time_t_signed')} would break",
                    'remediation': f"Use unsigned-safe constant or remove negative value",
                    'line': candidate.line,
                    'code': code
                })
        
        return risks
    
    def _detect_architecture_assumptions(self, candidate: Candidate, code: str) -> List[Dict[str, Any]]:
        """Detect patterns assuming old architecture."""
        risks = []
        
        # Check for long type assumptions
        # In ILP32, long is 32-bit; in LP64, long is 64-bit
        if self.from_config.get('hardware_model') == 'ILP32' and self.to_config.get('hardware_model') == 'LP64':
            # Pattern: (long)time_value - assumes 32-bit long in ILP32
            if re.search(r'\(long\)\s*(?!long)', code):  # long but not long long
                risks.append({
                    'file': candidate.file,
                    'type': MigrationRiskType.ARCHITECTURE_ASSUMPTION.value,
                    'severity': MigrationSeverity.MEDIUM_RISK.value,
                    'description': f"long type cast assumes ILP32 (32-bit), migration to LP64 (64-bit long) would change behavior",
                    'remediation': f"Use explicit int32_t or int64_t instead of long",
                    'line': candidate.line,
                    'code': code
                })
        
        return risks
    
    def analyze_io_migration_risks(
        self,
        io_candidate: Dict[str, Any],
        io_function: str,
        code: str
    ) -> List[Dict[str, Any]]:
        """
        Analyze I/O candidate for migration-specific risks.
        
        Args:
            io_candidate: I/O candidate metadata
            io_function: I/O function name
            code: Code snippet
        
        Returns:
            List of migration risk dicts
        """
        risks = []
        
        # Width change risks in I/O
        if self.width_changed:
            from_size = self.from_config.get('time_t_size_bits')
            to_size = self.to_config.get('time_t_size_bits')
            
            # Format specifier risks
            if io_candidate.get('io_category') == 'formatted_io_mismatch':
                # Check if format specifier assumes old width
                # This is already detected by I/O analyzer, but we add migration context
                risks.append({
                    'file': io_candidate.get('file', 'unknown'),
                    'type': MigrationRiskType.IO_FORMAT_MISMATCH.value,
                    'severity': (MigrationSeverity.HIGH_RISK if from_size == 32 else MigrationSeverity.MEDIUM_RISK).value,
                    'description': f"Format specifier assumes {from_size}-bit, migration to {to_size}-bit would break",
                    'remediation': f"Update format specifier for {to_size}-bit time_t",
                    'line': io_candidate.get('line', 0),
                    'code': code
                })
            
            # Raw I/O size risks
            if io_candidate.get('io_category') in ['raw_representation_risk', 'external_interface_risk']:
                risks.append({
                    'file': io_candidate.get('file', 'unknown'),
                    'type': MigrationRiskType.IO_SIZE_MISMATCH.value,
                    'severity': MigrationSeverity.BLOCKER.value,
                    'description': f"Raw I/O assumes {from_size}-bit time_t, migration to {to_size}-bit would break",
                    'remediation': f"Use explicit conversion or schema-defined wire format",
                    'line': io_candidate.get('line', 0),
                    'code': code
                })
        
        # Signedness change risks in I/O
        if self.signedness_changed:
            from_signed = self.from_config.get('time_t_signed')
            to_signed = self.to_config.get('time_t_signed')
            
            if io_candidate.get('io_category') == 'formatted_io_mismatch':
                risks.append({
                    'file': io_candidate.get('file', 'unknown'),
                    'type': MigrationRiskType.SIGNEDNESS_ASSUMPTION.value,
                    'severity': MigrationSeverity.HIGH_RISK.value,
                    'description': f"Format specifier assumes {from_signed} time_t, migration to {to_signed} would break",
                    'remediation': f"Update format specifier for {to_signed} time_t",
                    'line': io_candidate.get('line', 0),
                    'code': code
                })
        
        return risks
