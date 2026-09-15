# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""I/O boundary analyzer for Y2038/Y2106 detection."""

import re
from pathlib import Path
from typing import List, Dict, Set, Optional, Any, Tuple
from tacs.core.schema import Candidate, IOCandidate, IOCandidateType, RemediationClass
from tacs.core.io_format_parser import FormatSpecifierParser, FormatSpec
from tacs.core.status_logger import StatusLogger


class IOFunctionRegistry:
    """Registry of I/O functions to analyze."""
    
    FORMATTED_OUTPUT = [
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf'
    ]
    
    FORMATTED_INPUT = [
        'scanf', 'fscanf', 'sscanf',
        'vscanf', 'vfscanf', 'vsscanf'
    ]
    
    RAW_BYTE_IO = [
        'read', 'write', 'pread', 'pwrite',
        'recv', 'send', 'recvfrom', 'sendto',
        'fread', 'fwrite'
    ]
    
    SERIALIZATION_HELPERS = [
        'memcpy', 'memmove'
    ]
    
    EXTERNAL_INTERFACE = [
        'ioctl',  # Device I/O
    ]
    
    # Combined list for quick pattern matching
    ALL_FUNCTIONS = FORMATTED_OUTPUT + FORMATTED_INPUT + RAW_BYTE_IO + SERIALIZATION_HELPERS + EXTERNAL_INTERFACE


class IOScoringModel:
    """Scores I/O-boundary findings with configurable weights."""
    
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """
        Initialize scoring model with configurable weights.
        
        Args:
            weights: Custom weight dictionary, or None for defaults
        """
        self.weights = weights or {
            'io_function_hit': 1.0,
            'direct_time_t': 2.0,
            'sizeof_time_t': 2.0,
            'struct_time_field': 3.0,
            'explicit_cast': 3.0,
            'format_mismatch': 3.0,
            'external_boundary': 4.0,
            'safe_serialization': -2.0,
            'explicit_safe_conversion': -2.0
        }
    
    def score_candidate(
        self,
        io_call_info: Dict[str, Any],
        time_context: Dict[str, Any],
        abi_config: Dict[str, Any]
    ) -> float:
        """
        Score an I/O-boundary candidate.
        
        CRITICAL: Returns negative score if no time context detected.
        This prevents false positives from unrelated I/O operations.
        
        Args:
            io_call_info: Information about the I/O call
            time_context: Time-bearing context information
            abi_config: ABI configuration
        
        Returns:
            Score (negative if no time context, positive otherwise)
        """
        score = 0.0
        has_time_context = False
        
        # Check for time-bearing indicators
        if time_context.get('is_direct_time_t'):
            score += self.weights['direct_time_t']
            has_time_context = True
        
        if time_context.get('is_sizeof_time_t'):
            score += self.weights['sizeof_time_t']
            has_time_context = True
        
        if time_context.get('is_struct_with_time_field'):
            score += self.weights['struct_time_field']
            has_time_context = True
        
        # Early exit if no time context
        if not has_time_context:
            return -1.0  # Strong negative - clearly not time-related
        
        # Base score for I/O function hit
        score += self.weights['io_function_hit']
        
        # Additional scoring factors
        if io_call_info.get('has_explicit_cast'):
            score += self.weights['explicit_cast']
        
        if io_call_info.get('has_format_mismatch'):
            score += self.weights['format_mismatch']
        
        if io_call_info.get('is_external_boundary'):
            score += self.weights['external_boundary']
        
        # Negative scoring for safe patterns
        if io_call_info.get('is_safe_serialization'):
            score += self.weights['safe_serialization']
        
        if io_call_info.get('is_explicit_safe_conversion'):
            score += self.weights['explicit_safe_conversion']
        
        return score
    
    def get_confidence_level(self, score: float) -> str:
        """
        Determine confidence level from score.
        
        Args:
            score: Calculated score
        
        Returns:
            Confidence level string
        """
        if score >= 8.0:
            return "high_confidence"
        elif score >= 5.0:
            return "medium_confidence"
        else:
            return "low_confidence"


class IOBoundaryAnalyzer:
    """Analyzes I/O operations for Y2038/Y2106 risks."""
    
    def __init__(
        self,
        time_t_aliases: Dict[str, List[str]],
        time_bearing_symbols: Set[str],
        environment_config: Optional[Dict[str, Any]],
        enable_io_analysis: bool = True,
        score_threshold: float = 6.0,
        check_literal_widths: bool = True,
        score_weights: Optional[Dict[str, float]] = None
    ):
        """
        Initialize I/O boundary analyzer.
        
        Args:
            time_t_aliases: Known time_t aliases from discovery stage
            time_bearing_symbols: Symbols identified as time-bearing
            environment_config: Environment configuration for ABI assumptions
            enable_io_analysis: Enable/disable I/O analysis
            score_threshold: Minimum score to escalate to LLM
            check_literal_widths: Check for suspicious literal widths (4/8)
            score_weights: Custom scoring weights
        """
        self.time_t_aliases = time_t_aliases
        self.time_bearing_symbols = set(time_bearing_symbols)
        self.environment_config = environment_config or {}
        self.enable_io_analysis = enable_io_analysis
        self.score_threshold = score_threshold
        self.check_literal_widths = check_literal_widths
        
        # File content cache
        self._file_cache: Dict[str, List[str]] = {}
        
        # Format parser
        self.format_parser = FormatSpecifierParser(environment_config)
        
        # Scoring model
        self.scoring_model = IOScoringModel(score_weights)
        
        # Track time-bearing assignments (enhanced detection)
        self._time_assignments: Dict[str, Set[str]] = {}  # file -> set of variable names
    
    def update_time_context(
        self,
        time_t_aliases: Dict[str, List[str]],
        time_bearing_symbols: Set[str],
        time_function_assignments: Optional[Dict[str, Set[str]]] = None
    ):
        """
        Update time-bearing context from discovery stage and enhanced detection.
        
        Args:
            time_t_aliases: Updated time_t aliases
            time_bearing_symbols: Updated time-bearing symbols
            time_function_assignments: Variables assigned from time functions (file -> variables)
        """
        self.time_t_aliases = time_t_aliases
        self.time_bearing_symbols = set(time_bearing_symbols)
        if time_function_assignments:
            self._time_assignments = time_function_assignments
    
    def analyze_io_boundaries(
        self,
        candidates: List[Candidate],
        root_path: str,
        include_patterns: List[str],
        exclude_patterns: List[str]
    ) -> List[IOCandidate]:
        """
        Analyze I/O boundaries in source code.
        
        Uses lazy file loading - only loads files with I/O function calls.
        
        Args:
            candidates: Existing candidates from previous stages
            root_path: Root directory for file discovery
            include_patterns: File include patterns
            exclude_patterns: File exclude patterns
        
        Returns:
            List of I/O-boundary candidates
        """
        if not self.enable_io_analysis:
            return []
        
        # Step 1: Quick regex pass to identify files with I/O function names
        files_with_io = self._identify_files_with_io(root_path, include_patterns, exclude_patterns)
        
        if not files_with_io:
            return []
        
        StatusLogger.timestamped_debug(f"Found {len(files_with_io)} files with I/O function calls")
        
        # Step 2: Analyze each file for I/O patterns
        io_candidates = []
        
        for file_path in files_with_io:
            try:
                file_candidates = self._analyze_file(file_path)
                io_candidates.extend(file_candidates)
            except Exception as e:
                StatusLogger.timestamped_warning(f"Failed to analyze {file_path} for I/O boundaries: {e}")
                continue
        
        # Filter by score threshold
        filtered_candidates = [
            cand for cand in io_candidates
            if cand.io_score >= self.score_threshold
        ]
        
        StatusLogger.timestamped_debug(
            f"I/O boundary analysis: {len(io_candidates)} candidates found, "
            f"{len(filtered_candidates)} above threshold ({self.score_threshold})"
        )
        
        return filtered_candidates
    
    def _identify_files_with_io(
        self,
        root_path: str,
        include_patterns: List[str],
        exclude_patterns: List[str]
    ) -> List[str]:
        """
        Quick regex pass to find files containing I/O function names.
        
        Args:
            root_path: Root directory
            include_patterns: File include patterns
            exclude_patterns: File exclude patterns
        
        Returns:
            List of file paths that likely contain I/O calls
        """
        from fnmatch import fnmatch
        
        # Build regex pattern for I/O functions
        function_names = '|'.join(re.escape(f) for f in IOFunctionRegistry.ALL_FUNCTIONS)
        io_pattern = re.compile(
            r'\b(' + function_names + r')\s*\(',
            re.IGNORECASE
        )
        
        files_with_io = []
        root = Path(root_path)
        
        # Get files matching include patterns
        all_files = []
        for pattern in include_patterns or ['**/*.c', '**/*.h']:
            for file_path in root.rglob(pattern.replace('**/', '')):
                if file_path.is_file():
                    all_files.append(file_path)
        
        # Filter by exclude patterns
        for file_path in all_files:
            rel_path = str(file_path.relative_to(root))
            if any(fnmatch(rel_path, pattern) for pattern in exclude_patterns or []):
                continue
            
            # Quick regex scan
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(8192)  # Read first 8KB for quick check
                    if io_pattern.search(content):
                        files_with_io.append(str(file_path))
            except Exception:
                continue
        
        return files_with_io
    
    def _analyze_file(self, file_path: str) -> List[IOCandidate]:
        """
        Analyze a single file for I/O-boundary patterns.
        
        Args:
            file_path: Path to file to analyze
        
        Returns:
            List of IOCandidate objects
        """
        # Load file (cached)
        if file_path not in self._file_cache:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self._file_cache[file_path] = f.readlines()
            except Exception as e:
                StatusLogger.timestamped_warning(f"Failed to load {file_path}: {e}")
                return []
        
        lines = self._file_cache[file_path]
        candidates = []
        
        # Track time-bearing variables in this file
        file_time_vars = self._time_assignments.get(file_path, set())
        file_time_vars.update(self.time_bearing_symbols)
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip comments and empty lines
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            # Analyze formatted I/O
            formatted_candidates = self._analyze_formatted_io(
                file_path, line_num, line_stripped, file_time_vars
            )
            candidates.extend(formatted_candidates)
            
            # Analyze raw I/O
            raw_candidates = self._analyze_raw_io(
                file_path, line_num, line_stripped, file_time_vars
            )
            candidates.extend(raw_candidates)
        
        return candidates
    
    def _analyze_formatted_io(
        self,
        file_path: str,
        line_num: int,
        line: str,
        time_vars: Set[str]
    ) -> List[IOCandidate]:
        """Analyze formatted I/O calls (printf, scanf, etc.)."""
        candidates = []
        
        # Pattern for formatted I/O: function(format_string, ...)
        for func_name in IOFunctionRegistry.FORMATTED_OUTPUT + IOFunctionRegistry.FORMATTED_INPUT:
            pattern = rf'\b{re.escape(func_name)}\s*\('
            match = re.search(pattern, line, re.IGNORECASE)
            if not match:
                continue
            
            # Try to extract format string (first argument)
            format_match = self._extract_format_string(line, match.end())
            if not format_match:
                # Variable format string - lower confidence
                if self._has_time_bearing_argument(line, time_vars, func_name):
                    candidate = self._create_io_candidate(
                        file_path, line_num, line, func_name,
                        IOCandidateType.FORMATTED_IO_MISMATCH,
                        score=2.0,
                        reasoning="Variable format string with time-bearing argument"
                    )
                    candidates.append(candidate)
                continue
            
            format_str = format_match['format_string']
            is_literal = format_match['is_literal']
            
            # Parse format string (only if literal for MVP)
            if is_literal:
                specs = self.format_parser.parse_format_string(format_str)
                
                # Check each specifier against time-bearing arguments
                for i, spec in enumerate(specs):
                    # Find corresponding argument (format string is arg 0, so spec i -> arg i+1)
                    arg_idx = i + 1
                    if self._is_time_bearing_argument_at_index(line, arg_idx, time_vars, func_name):
                        # Check for mismatch
                        is_match, reason = self.format_parser.check_specifier_match(
                            spec,
                            self.time_t_size,
                            self.time_t_signed
                        )
                        
                        if not is_match:
                            candidate = self._create_io_candidate(
                                file_path, line_num, line, func_name,
                                IOCandidateType.FORMATTED_IO_MISMATCH,
                                score=self._score_formatted_io(spec, is_match),
                                reasoning=f"Format specifier mismatch: {reason}"
                            )
                            candidates.append(candidate)
        
        return candidates
    
    def _analyze_raw_io(
        self,
        file_path: str,
        line_num: int,
        line: str,
        time_vars: Set[str]
    ) -> List[IOCandidate]:
        """Analyze raw I/O calls (read, write, memcpy, etc.)."""
        candidates = []
        
        # Pattern for raw I/O: function(fd, &var, sizeof(...))
        for func_name in IOFunctionRegistry.RAW_BYTE_IO + IOFunctionRegistry.SERIALIZATION_HELPERS:
            pattern = rf'\b{re.escape(func_name)}\s*\('
            match = re.search(pattern, line, re.IGNORECASE)
            if not match:
                continue
            
            # Check for address-of operator with time-bearing variable
            if self._has_address_of_time_var(line, time_vars):
                # Check size argument
                size_info = self._extract_size_argument(line, match.end())
                
                time_context = {
                    'is_direct_time_t': self._is_direct_time_t_var(line, time_vars),
                    'is_sizeof_time_t': size_info.get('is_sizeof_time_t', False),
                    'is_struct_with_time_field': False  # TODO: Implement struct detection
                }
                
                io_call_info = {
                    'has_explicit_cast': self._has_explicit_cast(line),
                    'is_external_boundary': func_name in IOFunctionRegistry.EXTERNAL_INTERFACE
                }
                
                score = self.scoring_model.score_candidate(
                    io_call_info, time_context, self.environment_config
                )
                
                if score > 0:  # Only create candidate if positive score
                    candidate = self._create_io_candidate(
                        file_path, line_num, line, func_name,
                        IOCandidateType.RAW_REPRESENTATION_RISK,
                        score=score,
                        reasoning=self._generate_raw_io_reasoning(line, size_info, time_context)
                    )
                    candidates.append(candidate)
        
        return candidates
    
    def _extract_format_string(self, line: str, start_pos: int) -> Optional[Dict[str, Any]]:
        """Extract format string from function call starting at start_pos."""
        # Look for first string literal after opening paren
        # Pattern: "format" or 'format'
        pattern = r'["\']([^"\']*)["\']'
        match = re.search(pattern, line[start_pos:])
        if match:
            return {
                'format_string': match.group(1),
                'is_literal': True
            }
        
        # Check for variable (identifier)
        var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[,)]'
        var_match = re.search(var_pattern, line[start_pos:])
        if var_match:
            return {
                'format_string': var_match.group(1),
                'is_literal': False
            }
        
        return None
    
    def _has_time_bearing_argument(self, line: str, time_vars: Set[str], func_name: str) -> bool:
        """Check if line has time-bearing arguments for the given function."""
        # Find function call
        pattern = rf'\b{re.escape(func_name)}\s*\('
        match = re.search(pattern, line, re.IGNORECASE)
        if not match:
            return False
        
        # Check arguments after format string (skip first arg which is format string)
        # Simple heuristic: look for time-bearing variable names
        for var in time_vars:
            if re.search(rf'\b{re.escape(var)}\b', line[match.end():]):
                return True
        
        return False
    
    def _is_time_bearing_argument_at_index(
        self,
        line: str,
        arg_index: int,
        time_vars: Set[str],
        func_name: str
    ) -> bool:
        """Check if argument at given index is time-bearing."""
        # For MVP, use simple heuristic: check if any time-bearing var appears after format string
        return self._has_time_bearing_argument(line, time_vars, func_name)
    
    def _has_address_of_time_var(self, line: str, time_vars: Set[str]) -> bool:
        """Check if line has address-of operator with time-bearing variable."""
        for var in time_vars:
            # Pattern: &var or &(var)
            pattern = rf'&\s*{re.escape(var)}\b'
            if re.search(pattern, line):
                return True
        return False
    
    def _is_direct_time_t_var(self, line: str, time_vars: Set[str]) -> bool:
        """Check if line has direct time_t or alias variable."""
        # Check for time_t type or known aliases
        time_t_patterns = ['time_t'] + list(self.time_t_aliases.keys())
        for pattern in time_t_patterns:
            if re.search(rf'\b{re.escape(pattern)}\s+\w+', line):
                return True
        return False
    
    def _extract_size_argument(self, line: str, start_pos: int) -> Dict[str, Any]:
        """Extract size argument information."""
        # Look for sizeof(...) patterns
        sizeof_pattern = r'sizeof\s*\(([^)]+)\)'
        match = re.search(sizeof_pattern, line[start_pos:])
        if match:
            sizeof_arg = match.group(1).strip()
            # Check if it's sizeof(time_t) or sizeof(alias)
            if 'time_t' in sizeof_arg or any(alias in sizeof_arg for alias in self.time_t_aliases.keys()):
                return {'is_sizeof_time_t': True, 'size_value': None}
            # Check if it's sizeof(variable) where variable is time-bearing
            var_match = re.match(r'\*?\s*(\w+)', sizeof_arg)
            if var_match:
                var_name = var_match.group(1)
                if var_name in self.time_bearing_symbols:
                    return {'is_sizeof_time_t': True, 'size_value': None}
        
        # Check for literal widths (4 or 8)
        if self.check_literal_widths:
            literal_pattern = r'\b([48])\b'
            literal_match = re.search(literal_pattern, line[start_pos:])
            if literal_match:
                size_value = int(literal_match.group(1))
                # 4 bytes = 32-bit, 8 bytes = 64-bit
                time_t_size_bytes = self.time_t_size // 8
                if size_value == time_t_size_bytes:
                    return {'is_sizeof_time_t': True, 'size_value': size_value}
        
        return {'is_sizeof_time_t': False, 'size_value': None}
    
    def _has_explicit_cast(self, line: str) -> bool:
        """Check if line has explicit cast around I/O boundary."""
        # Pattern: (type)variable or (type*)variable
        cast_pattern = r'\([^)]+\*?\)\s*\w+'
        return bool(re.search(cast_pattern, line))
    
    def _score_formatted_io(self, spec: FormatSpec, is_match: bool) -> float:
        """Score a formatted I/O finding."""
        time_context = {
            'is_direct_time_t': True,
            'is_sizeof_time_t': False,
            'is_struct_with_time_field': False
        }
        
        io_call_info = {
            'has_format_mismatch': not is_match,
            'has_explicit_cast': False,
            'is_external_boundary': False
        }
        
        return self.scoring_model.score_candidate(
            io_call_info, time_context, self.environment_config
        )
    
    def _generate_raw_io_reasoning(
        self,
        line: str,
        size_info: Dict[str, Any],
        time_context: Dict[str, Any]
    ) -> str:
        """Generate reasoning for raw I/O finding."""
        reasons = []
        
        if time_context.get('is_direct_time_t'):
            reasons.append("Direct time_t or alias variable")
        
        if size_info.get('is_sizeof_time_t'):
            if size_info.get('size_value'):
                reasons.append(f"Size argument is {size_info['size_value']} bytes (matches time_t width)")
            else:
                reasons.append("Size argument is sizeof(time_t) or sizeof(alias)")
        
        if not reasons:
            reasons.append("Time-bearing variable in I/O operation")
        
        return "; ".join(reasons)
    
    def _create_io_candidate(
        self,
        file_path: str,
        line_num: int,
        line: str,
        io_function: str,
        io_category: IOCandidateType,
        score: float,
        reasoning: str
    ) -> IOCandidate:
        """Create an IOCandidate object."""
        confidence = self.scoring_model.get_confidence_level(score)
        
        # Determine remediation class
        if io_category == IOCandidateType.FORMATTED_IO_MISMATCH:
            remediation = RemediationClass.MANUAL_CODE_REVIEW
        elif io_category == IOCandidateType.EXTERNAL_INTERFACE_RISK:
            remediation = RemediationClass.MANUAL_INTERFACE_REVIEW_REQUIRED
        else:
            remediation = RemediationClass.MANUAL_INTERFACE_REVIEW_REQUIRED
        
        # Extract affected symbols
        affected_symbols = []
        for var in self.time_bearing_symbols:
            if re.search(rf'\b{re.escape(var)}\b', line):
                affected_symbols.append(var)
        
        # ABI assumptions
        abi_assumptions = {
            'hardware_model': self.environment_config.get('hardware_model', 'LP64'),
            'time_t_size_bits': self.time_t_size,
            'time_t_signed': self.time_t_signed
        }
        
        return IOCandidate(
            file=file_path,
            line=line_num,
            symbol=io_function,
            one_line_snippet=line,
            risk="medium",  # Default risk for I/O findings
            description=f"I/O-boundary risk: {io_category.value}",
            io_category=io_category,
            io_function=io_function,
            io_score=score,
            io_confidence=confidence,
            remediation_class=remediation,
            affected_symbols=affected_symbols,
            abi_assumptions=abi_assumptions,
            reasoning=reasoning
        )
    
    @property
    def time_t_size(self) -> int:
        """Get time_t size in bits from environment config."""
        return self.environment_config.get('time_t_size_bits', 64)
    
    @property
    def time_t_signed(self) -> str:
        """Get time_t signedness from environment config."""
        return self.environment_config.get('time_t_signed', 'signed')
