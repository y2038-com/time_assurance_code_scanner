# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Hybrid detector that combines keyword-based and LLM analysis."""

from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from .detector import ConfigDetector
from .llm_analyzer import LLMAnalyzer
from .cache import ConfigCache
from .validator import ConfigValidator
from .build_parsers import MakefileParser, CMakeParser
from tacs.core.env_capabilities import UNKNOWN_SETTING


class HybridConfigDetector:
    """Hybrid detector that uses keyword-based detection first, then LLM if needed."""
    
    def __init__(
        self,
        root_path: Path,
        llm_type: str = "ollama",
        llm_model: str = "gpt-oss:120b-cloud",
        llm_timeout: int = 60,
        confidence_threshold: float = 0.7,
        use_cache: bool = True,
        debug: bool = False
    ):
        """
        Initialize the hybrid detector.
        
        Args:
            root_path: Root directory of the project
            llm_type: LLM type to use (ollama, none)
            llm_model: LLM model name
            llm_timeout: LLM request timeout in seconds
            confidence_threshold: Confidence threshold for triggering LLM analysis
            use_cache: Whether to use caching for LLM results
            debug: Enable debug output
        """
        self.root_path = root_path
        self.confidence_threshold = confidence_threshold
        self.use_cache = use_cache
        self.debug = debug
        
        # Initialize components
        self.keyword_detector = ConfigDetector(root_path)
        self.llm_analyzer = LLMAnalyzer(
            llm_type=llm_type,
            model=llm_model,
            timeout_sec=llm_timeout,
            debug=debug
        )
        self.cache = ConfigCache() if use_cache else None
        self.validator = ConfigValidator()
        
        # Build file parsers for collecting files for LLM
        self.makefile_parser = MakefileParser(root_path)
        self.cmake_parser = CMakeParser(root_path)
    
    def detect(
        self,
        force_llm: bool = False,
        keyword_only: bool = False
    ) -> Dict[str, Any]:
        """
        Perform hybrid detection.
        
        Args:
            force_llm: Force LLM analysis even if confidence is high
            keyword_only: Only use keyword-based detection (no LLM)
        
        Returns:
            Dictionary with detection results including both keyword and LLM results
        """
        # Phase 1: Keyword-based detection
        keyword_results = self.keyword_detector.detect()
        
        # Calculate confidence for each field
        confidence = self._calculate_confidence(keyword_results)
        
        # Check if LLM analysis is needed
        needs_llm = self._needs_llm_analysis(confidence, force_llm, keyword_only)
        
        if not needs_llm:
            # Generate config from likelihoods for keyword-only mode
            final_config = self._generate_config_from_likelihoods(keyword_results)
            return {
                'method': 'keyword-based',
                'keyword_results': keyword_results,
                'llm_results': None,
                'final_config': final_config,
                'confidence': confidence
            }
        
        # Phase 2: LLM analysis
        llm_config, llm_confidence, llm_reasoning = self._run_llm_analysis(
            keyword_results,
            confidence
        )
        
        # Combine results
        final_config = self._combine_results(
            keyword_results,
            llm_config,
            confidence,
            llm_confidence
        )
        
        return {
            'method': 'hybrid',
            'keyword_results': keyword_results,
            'llm_results': {
                'config': llm_config,
                'confidence': llm_confidence,
                'reasoning': llm_reasoning
            },
            'final_config': final_config,
            'confidence': confidence
        }
    
    def _calculate_confidence(self, keyword_results: Dict[str, Any]) -> Dict[str, float]:
        """Calculate confidence scores for each detected field."""
        confidence = {}
        
        # Architecture confidence
        confidence['hardware_model'] = keyword_results.get('architecture_confidence', 0.0)
        
        # time_t size confidence
        confidence['time_t_size_bits'] = keyword_results.get('time_t_confidence', 0.0)
        
        # time_t signedness confidence (now detected by keyword-based detector)
        confidence['time_t_signed'] = keyword_results.get('time_t_signed_confidence', 0.3)
        confidence['c_library'] = 0.3  # May be detected but low confidence
        confidence['time64_functions_available'] = 0.3
        confidence['d_time_bits_supported'] = 0.3
        confidence['d_time_bits_setting'] = keyword_results.get('time_t_confidence', 0.3)
        
        return confidence
    
    def _needs_llm_analysis(
        self,
        confidence: Dict[str, float],
        force_llm: bool,
        keyword_only: bool
    ) -> bool:
        """Determine if LLM analysis is needed."""
        if keyword_only:
            return False
        
        if force_llm:
            return True
        
        # Check if any field has low confidence
        min_confidence = min(confidence.values()) if confidence else 1.0
        return min_confidence < self.confidence_threshold
    
    def _run_llm_analysis(
        self,
        keyword_results: Dict[str, Any],
        confidence: Dict[str, float]
    ) -> Tuple[Dict[str, Any], Dict[str, float], Dict[str, str]]:
        """Run LLM analysis on build files."""
        
        # Collect build files
        build_files = self._collect_build_files()
        
        if not build_files:
            if self.debug:
                print("Warning: No build files found for LLM analysis")
            return {}, {}, {}
        
        # Check cache
        if self.cache:
            cache_key = self.cache.get_cache_key(build_files, self.llm_analyzer.model)
            cached = self.cache.get(cache_key)
            if cached:
                if self.debug:
                    print("Using cached LLM results")
                return cached['config'], cached['confidence'], cached.get('reasoning', {})
        
        # Prepare keyword hints
        keyword_hints = {
            'architecture': keyword_results.get('architecture'),
            'architecture_confidence': keyword_results.get('architecture_confidence', 0.0),
            'time_t_size': keyword_results.get('time_t_size'),
            'time_t_confidence': keyword_results.get('time_t_confidence', 0.0),
            'extracted_info': keyword_results.get('extracted_info', {})
        }
        
        # Identify low-confidence fields
        low_confidence_fields = [
            field for field, conf in confidence.items()
            if conf < self.confidence_threshold
        ]
        
        # Run LLM analysis
        llm_config, llm_confidence, llm_reasoning = self.llm_analyzer.analyze_build_system(
            build_files=build_files,
            keyword_hints=keyword_hints,
            low_confidence_fields=low_confidence_fields
        )
        
        # Validate and normalize LLM results
        llm_config = self.validator.normalize(llm_config)
        is_valid, errors = self.validator.validate(llm_config)
        
        if not is_valid:
            if self.debug:
                print(f"Warning: LLM response validation errors: {errors}")
            # Try to fix common issues
            llm_config = self._fix_llm_response(llm_config, errors)
        
        # Cache results
        if self.cache and is_valid:
            cache_key = self.cache.get_cache_key(build_files, self.llm_analyzer.model)
            self.cache.set(cache_key, {
                'config': llm_config,
                'confidence': llm_confidence,
                'reasoning': llm_reasoning
            })
        
        return llm_config, llm_confidence, llm_reasoning
    
    def _collect_build_files(self) -> Dict[str, str]:
        """Collect build files for LLM analysis."""
        build_files = {}
        
        # Find Makefiles
        makefiles = self.makefile_parser.find_build_files()
        for makefile in makefiles[:3]:  # Limit to 3 most relevant
            try:
                content = makefile.read_text(encoding='utf-8', errors='ignore')
                build_files[str(makefile.relative_to(self.root_path))] = content
            except Exception as e:
                if self.debug:
                    print(f"Warning: Failed to read {makefile}: {e}")
        
        # Find CMake files
        cmake_files = self.cmake_parser.find_build_files()
        for cmake_file in cmake_files[:3]:  # Limit to 3 most relevant
            try:
                content = cmake_file.read_text(encoding='utf-8', errors='ignore')
                build_files[str(cmake_file.relative_to(self.root_path))] = content
            except Exception as e:
                if self.debug:
                    print(f"Warning: Failed to read {cmake_file}: {e}")
        
        return build_files
    
    def _combine_results(
        self,
        keyword_results: Dict[str, Any],
        llm_config: Dict[str, Any],
        keyword_confidence: Dict[str, float],
        llm_confidence: Dict[str, float]
    ) -> Optional[Dict[str, Any]]:
        """
        Combine keyword-based and LLM results.
        
        Strategy: Use LLM results for low-confidence fields, keep keyword results for high-confidence fields.
        """
        if not llm_config:
            return None
        
        # Start with LLM config as base
        combined = llm_config.copy()
        
        # Override with keyword-based results for high-confidence fields
        if keyword_confidence.get('hardware_model', 0.0) >= 0.9:
            # Use keyword-based architecture if high confidence
            if keyword_results.get('architecture'):
                combined['hardware_model'] = keyword_results['architecture']
        
        if keyword_confidence.get('time_t_size_bits', 0.0) >= 0.9:
            # Use keyword-based time_t size if high confidence
            if keyword_results.get('time_t_size'):
                combined['time_t_size_bits'] = keyword_results['time_t_size']
        
        if keyword_confidence.get('time_t_signed', 0.0) >= 0.9:
            # Use keyword-based time_t signedness if high confidence
            if keyword_results.get('time_t_signed'):
                combined['time_t_signed'] = keyword_results['time_t_signed']
        
        # Validate combined result
        combined = self.validator.normalize(combined)
        is_valid, errors = self.validator.validate(combined)
        
        if not is_valid:
            if self.debug:
                print(f"Warning: Combined config validation errors: {errors}")
            # Return LLM config if combined is invalid
            return llm_config
        
        # Generate config_id
        try:
            from tacs.core.config_validator import ConfigValidator as ScannerConfigValidator
            config_id = ScannerConfigValidator.get_config_id(combined)
            if config_id:
                combined['config_id'] = config_id
        except Exception as e:
            if self.debug:
                print(f"Warning: Failed to generate config_id: {e}")
        
        return combined
    
    def _fix_llm_response(self, config: Dict[str, Any], errors: List[str]) -> Dict[str, Any]:
        """Try to fix common LLM response issues."""
        fixed = config.copy()
        
        # Fix d_time_bits_setting based on d_time_bits_supported
        if "d_time_bits_setting must be 'not_available'" in str(errors):
            fixed['d_time_bits_setting'] = 'not_available'
        elif "d_time_bits_setting cannot be 'not_available'" in str(errors):
            if fixed.get('d_time_bits_setting') == 'not_available':
                fixed['d_time_bits_setting'] = 'not_set'
        
        return fixed
    
    def _generate_config_from_likelihoods(self, keyword_results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate config from likelihood scores when LLM is not used."""
        likelihoods = keyword_results.get('likelihoods', [])
        if not likelihoods:
            return None
        
        # Find most likely config (likelihoods is now a list of ConfigurationLikelihood objects)
        max_likelihood = 0.0
        best_config = None
        
        # Handle both list of objects and dict formats for backward compatibility
        if isinstance(likelihoods, list):
            for likelihood_obj in likelihoods:
                # Handle both object and dict formats
                if hasattr(likelihood_obj, 'name'):
                    config_name = likelihood_obj.name
                    likelihood_val = likelihood_obj.likelihood
                else:
                    config_name = likelihood_obj.get('name')
                    likelihood_val = likelihood_obj.get('likelihood', 0.0)
                
                if not likelihood_obj.ruled_out if hasattr(likelihood_obj, 'ruled_out') else not likelihood_obj.get('ruled_out', False):
                    if likelihood_val > max_likelihood:
                        max_likelihood = likelihood_val
                        best_config = config_name
        else:
            # Old dict format (backward compatibility)
            for config_name, likelihood_val in likelihoods.items():
                if likelihood_val > max_likelihood:
                    max_likelihood = likelihood_val
                    best_config = config_name
        
        if not best_config:
            return None
        
        # Map config name to actual config dict
        # Config names are like "ilp32_signed_32bit"
        try:
            from tacs.core.config_validator import ConfigValidator
            config_info = ConfigValidator.get_config_info(best_config)
            if config_info:
                # Create minimal config dict
                config = {
                    'hardware_model': config_info['hardware_model'],
                    'time_t_size_bits': config_info['time_t_size_bits'],
                    'time_t_signed': config_info['time_t_signed'],
                    'config_id': best_config,
                    # A likelihood over ABIs establishes the ABI and nothing about
                    # the C library, so the capability fields stay unknown instead
                    # of reporting features as absent on no evidence.
                    'time64_functions_available': None,
                    'd_time_bits_supported': None,
                    'd_time_bits_setting': UNKNOWN_SETTING,
                    'c_library': 'unknown'
                }
                return config
        except Exception as e:
            if self.debug:
                print(f"Warning: Failed to generate config from likelihoods: {e}")
        
        return None