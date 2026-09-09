from __future__ import annotations

from typing import List, Optional
from tacs.core.schema import Candidate


class StructuralFilter:
    """Optional tree-sitter structural filter with safe no-op fallback."""
    
    def __init__(self):
        """Initialize the structural filter."""
        self.tree_sitter_available = self._check_tree_sitter()
        if self.tree_sitter_available:
            self._init_tree_sitter()
    
    def _check_tree_sitter(self) -> bool:
        """Check if tree-sitter is available."""
        try:
            import tree_sitter
            return True
        except ImportError:
            return False
    
    def _init_tree_sitter(self):
        """Initialize tree-sitter if available."""
        try:
            import tree_sitter
            # TODO: Initialize C/C++ parsers when tree-sitter is available
            # For now, we'll just mark it as available but not implement the full parser
            pass
        except Exception:
            self.tree_sitter_available = False
    
    def filter_candidates(self, candidates: List[Candidate]) -> List[Candidate]:
        """
        Filter candidates using structural analysis.
        
        Args:
            candidates: List of candidates to filter
            
        Returns:
            Filtered list of candidates
        """
        if not self.tree_sitter_available:
            # No-op when tree-sitter is not available
            return candidates
        
        # TODO: Implement actual tree-sitter filtering
        # For now, just pass through unchanged
        filtered_candidates = []
        
        for candidate in candidates:
            # Add basic symbol role tagging based on simple heuristics
            symbol_role = self._guess_symbol_role(candidate.one_line_snippet, candidate.symbol)
            candidate.symbol_role = symbol_role
            
            # Skip obvious declaration-only lines and comments
            if self._should_skip_candidate(candidate):
                continue
                
            filtered_candidates.append(candidate)
        
        return filtered_candidates
    
    def _guess_symbol_role(self, line: str, symbol: str) -> str:
        """Guess symbol role from line content."""
        line = line.strip()
        
        # Simple heuristics for symbol roles
        if line.startswith('//') or line.startswith('/*'):
            return "comment"
        elif line.startswith('#warning') or line.startswith('#error') or line.startswith('#pragma'):
            return "preprocessor_directive"
        elif line.startswith('#define') or line.startswith('#if'):
            return "macro"
        elif line.startswith('typedef') or line.startswith('struct'):
            return "type"
        elif '(' in line and ')' in line:
            return "call"
        elif '=' in line and not line.startswith('if') and not line.startswith('while'):
            return "assignment"
        else:
            return "unknown"
    
    def _should_skip_candidate(self, candidate: Candidate) -> bool:
        """Determine if candidate should be skipped."""
        line = candidate.one_line_snippet.strip()
        
        # Skip comments
        if line.startswith('//') or line.startswith('/*'):
            return True
        
        # Skip preprocessor directives (warnings, errors, pragmas, etc.)
        if line.startswith('#warning') or line.startswith('#error') or line.startswith('#pragma'):
            return True
        
        # Skip macro definitions without usage
        if line.startswith('#define') and '(' not in line:
            return True
        
        # Skip typedef declarations
        if line.startswith('typedef'):
            return True
        
        return False
