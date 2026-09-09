"""Main detection logic that orchestrates parsers and analyzers."""

from pathlib import Path
from typing import Dict, Optional
from .build_parsers import MakefileParser, CMakeParser
from .analyzers import ArchitectureDetector, TimeTConfigDetector
from .output import LikelihoodScorer, format_output


class ConfigDetector:
    """Main detector that orchestrates the detection process."""
    
    def __init__(self, root_path: Path):
        """
        Initialize the detector.
        
        Args:
            root_path: Root directory of the project to analyze
        """
        self.root_path = root_path
        self.makefile_parser = MakefileParser(root_path)
        self.cmake_parser = CMakeParser(root_path)
        self.arch_detector = ArchitectureDetector()
        self.time_t_detector = TimeTConfigDetector()
        self.scorer = LikelihoodScorer()
    
    def detect(self) -> Dict:
        """
        Perform detection and return results.
        
        Returns:
            Dictionary with detection results
        """
        # Extract information from build files
        makefile_info = self.makefile_parser.extract_all()
        cmake_info = self.cmake_parser.extract_all()
        
        # Combine information (CMake takes precedence if both exist)
        if cmake_info.get('build_files_found', 0) > 0:
            extracted_info = cmake_info
            extracted_info['source'] = 'cmake'
        elif makefile_info.get('build_files_found', 0) > 0:
            extracted_info = makefile_info
            extracted_info['source'] = 'makefile'
        else:
            # No build files found
            extracted_info = {
                'cflags': [],
                'defines': [],
                'variables': {},
                'toolchain': '',
                'build_files_found': 0,
                'source': 'none'
            }
        
        # Detect architecture
        architecture, arch_confidence, arch_evidence = self.arch_detector.detect(extracted_info)
        
        # Detect time_t size and signedness
        time_t_size, time_t_confidence, time_t_signed, time_t_signed_confidence, time_t_evidence = self.time_t_detector.detect(
            extracted_info,
            architecture=architecture
        )
        
        # Calculate likelihood scores
        likelihoods = self.scorer.score(
            architecture=architecture,
            architecture_confidence=arch_confidence,
            time_t_size=time_t_size,
            time_t_confidence=time_t_confidence,
            time_t_signed=time_t_signed,
            time_t_signed_confidence=time_t_signed_confidence,
            architecture_evidence=arch_evidence,
            time_t_evidence=time_t_evidence
        )
        
        return {
            'extracted_info': extracted_info,
            'architecture': architecture,
            'architecture_confidence': arch_confidence,
            'time_t_size': time_t_size,
            'time_t_confidence': time_t_confidence,
            'time_t_signed': time_t_signed,
            'time_t_signed_confidence': time_t_signed_confidence,
            'likelihoods': likelihoods
        }
    
    def format_results(self, results: Dict, format_type: str = 'human') -> str:
        """
        Format detection results for output.
        
        Args:
            results: Results dictionary from detect()
            format_type: 'human' or 'json'
        
        Returns:
            Formatted output string
        """
        return format_output(
            project_path=str(self.root_path),
            likelihoods=results['likelihoods'],
            format_type=format_type
        )
