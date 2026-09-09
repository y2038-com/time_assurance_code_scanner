"""Likelihood scoring and output formatting."""

import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from datetime import datetime


@dataclass
class Evidence:
    """Piece of evidence supporting or contradicting a configuration."""
    source: str
    indicator: str
    supports: List[str]  # Which configs this supports
    contradicts: List[str]  # Which configs this contradicts
    confidence: float


@dataclass
class ConfigurationLikelihood:
    """Likelihood score for a configuration."""
    name: str  # e.g., "ilp32_signed_32bit"
    likelihood: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    evidence: List[Evidence]
    ruled_out: bool
    ruled_out_reason: Optional[str] = None


class LikelihoodScorer:
    """Scores likelihood for all 8 possible configurations."""
    
    # All 8 possible configurations
    CONFIGS = [
        'ilp32_signed_32bit',
        'ilp32_signed_64bit',
        'ilp32_unsigned_32bit',
        'ilp32_unsigned_64bit',
        'lp64_signed_32bit',
        'lp64_signed_64bit',
        'lp64_unsigned_32bit',
        'lp64_unsigned_64bit'
    ]
    
    def __init__(self):
        """Initialize the likelihood scorer."""
        pass
    
    def score(
        self,
        architecture: Optional[str],
        architecture_confidence: float,
        time_t_size: Optional[int],
        time_t_confidence: float,
        time_t_signed: Optional[str] = None,
        time_t_signed_confidence: float = 0.0,
        architecture_evidence: List = None,
        time_t_evidence: List = None
    ) -> List[ConfigurationLikelihood]:
        """
        Calculate likelihood scores for all 8 configurations.
        
        Args:
            architecture: "ILP32" or "LP64" or None
            architecture_confidence: Confidence in architecture detection
            time_t_size: 32 or 64 or None
            time_t_confidence: Confidence in time_t size detection
            time_t_signed: "signed" or "unsigned" or None
            time_t_signed_confidence: Confidence in time_t signedness detection
            architecture_evidence: Evidence from architecture detection
            time_t_evidence: Evidence from time_t detection
        
        Returns:
            List of ConfigurationLikelihood objects
        """
        if architecture_evidence is None:
            architecture_evidence = []
        if time_t_evidence is None:
            time_t_evidence = []
        
        results = []
        
        for config_name in self.CONFIGS:
            config_parts = config_name.split('_')
            config_arch = config_parts[0].upper()  # ILP32 or LP64
            config_signedness = config_parts[1]  # signed or unsigned
            config_time_t_size = int(config_parts[2].replace('bit', ''))  # 32 or 64
            
            # Rule out configurations based on architecture
            if architecture:
                if architecture != config_arch:
                    results.append(ConfigurationLikelihood(
                        name=config_name,
                        likelihood=0.0,
                        confidence=architecture_confidence,
                        evidence=[],
                        ruled_out=True,
                        ruled_out_reason=f"Architecture is {architecture}, not {config_arch}"
                    ))
                    continue
            
            # Rule out configurations based on time_t size
            if time_t_size:
                if time_t_size != config_time_t_size:
                    results.append(ConfigurationLikelihood(
                        name=config_name,
                        likelihood=0.0,
                        confidence=time_t_confidence,
                        evidence=[],
                        ruled_out=True,
                        ruled_out_reason=f"time_t is {time_t_size}-bit, not {config_time_t_size}-bit"
                    ))
                    continue
            
            # Rule out configurations based on time_t signedness (if detected)
            if time_t_signed:
                if time_t_signed != config_signedness:
                    results.append(ConfigurationLikelihood(
                        name=config_name,
                        likelihood=0.0,
                        confidence=time_t_signed_confidence,
                        evidence=[],
                        ruled_out=True,
                        ruled_out_reason=f"time_t is {time_t_signed}, not {config_signedness}"
                    ))
                    continue
            
            # Calculate likelihood for non-ruled-out configurations
            evidence_list = []
            base_likelihood = 1.0 / 8.0  # Start with equal probability (12.5% for 8 configs)
            
            # Architecture evidence
            if architecture == config_arch:
                for arch_ev in architecture_evidence:
                    evidence_list.append(Evidence(
                        source=arch_ev.source,
                        indicator=arch_ev.indicator,
                        supports=[config_name],
                        contradicts=[],
                        confidence=arch_ev.confidence
                    ))
                    # Boost likelihood based on architecture confidence
                    base_likelihood += 0.3 * architecture_confidence
            
            # time_t size evidence
            if time_t_size == config_time_t_size:
                for time_ev in time_t_evidence:
                    evidence_list.append(Evidence(
                        source=time_ev.source,
                        indicator=time_ev.indicator,
                        supports=[config_name],
                        contradicts=[],
                        confidence=time_ev.confidence
                    ))
                    # Boost likelihood based on time_t confidence
                    base_likelihood += 0.2 * time_t_confidence
            
            # time_t signedness evidence
            if time_t_signed == config_signedness:
                # Boost likelihood based on signedness confidence
                base_likelihood += 0.15 * time_t_signed_confidence
                evidence_list.append(Evidence(
                    source='time_t_signedness',
                    indicator=f'time_t is {time_t_signed}',
                    supports=[config_name],
                    contradicts=[],
                    confidence=time_t_signed_confidence
                ))
            
            # Normalize likelihood to 0.0-1.0 range
            likelihood = min(1.0, base_likelihood)
            
            # Calculate overall confidence (weighted average of all detected fields)
            confidence_values = []
            confidence_weights = []
            
            if architecture:
                confidence_values.append(architecture_confidence)
                confidence_weights.append(0.4)
            if time_t_size:
                confidence_values.append(time_t_confidence)
                confidence_weights.append(0.4)
            if time_t_signed:
                confidence_values.append(time_t_signed_confidence)
                confidence_weights.append(0.2)
            
            if confidence_values:
                # Weighted average
                total_weight = sum(confidence_weights)
                overall_confidence = sum(v * w for v, w in zip(confidence_values, confidence_weights)) / total_weight
            else:
                overall_confidence = 0.3  # Low confidence if nothing detected
            
            results.append(ConfigurationLikelihood(
                name=config_name,
                likelihood=likelihood,
                confidence=overall_confidence,
                evidence=evidence_list,
                ruled_out=False
            ))
        
        return results


def format_output(
    project_path: str,
    likelihoods: List[ConfigurationLikelihood],
    format_type: str = 'human'
) -> str:
    """
    Format likelihood scores for output.
    
    Args:
        project_path: Path to the project
        likelihoods: List of ConfigurationLikelihood objects
        format_type: 'human' or 'json'
    
    Returns:
        Formatted output string
    """
    if format_type == 'json':
        return format_json(project_path, likelihoods)
    else:
        return format_human(project_path, likelihoods)


def format_json(project_path: str, likelihoods: List[ConfigurationLikelihood]) -> str:
    """Format output as JSON."""
    # Find most likely config
    non_ruled_out = [l for l in likelihoods if not l.ruled_out]
    most_likely = max(non_ruled_out, key=lambda x: x.likelihood) if non_ruled_out else None
    
    # Convert likelihoods to dict, handling Evidence objects
    configs_list = []
    for l in likelihoods:
        config_dict = {
            'name': l.name,
            'likelihood': l.likelihood,
            'confidence': l.confidence,
            'evidence': [asdict(e) for e in l.evidence],
            'ruled_out': l.ruled_out
        }
        if l.ruled_out_reason:
            config_dict['ruled_out_reason'] = l.ruled_out_reason
        configs_list.append(config_dict)
    
    output = {
        'project_path': project_path,
        'detection_timestamp': datetime.utcnow().isoformat() + 'Z',
        'detector_version': '1.0.0',
        'configurations': configs_list,
        'summary': {
            'most_likely': most_likely.name if most_likely else None,
            'recommended_configs': [l.name for l in non_ruled_out if l.likelihood > 0.5],
            'ruled_out_configs': [l.name for l in likelihoods if l.ruled_out]
        }
    }
    
    return json.dumps(output, indent=2)


def format_human(project_path: str, likelihoods: List[ConfigurationLikelihood]) -> str:
    """Format output as human-readable text."""
    lines = []
    lines.append("Configuration Detection Results")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"Project: {project_path}")
    lines.append(f"Detected: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("Likelihood Scores:")
    
    for likelihood in likelihoods:
        if likelihood.ruled_out:
            symbol = "✗"
            percent = "0%"
            conf_str = f"(Ruled out: {likelihood.ruled_out_reason})"
        else:
            percent_val = int(likelihood.likelihood * 100)
            percent = f"{percent_val}%"
            if likelihood.likelihood > 0.7:
                symbol = "✓"
            elif likelihood.likelihood > 0.3:
                symbol = "⚠"
            else:
                symbol = "○"
            
            conf_level = "High" if likelihood.confidence > 0.8 else "Medium" if likelihood.confidence > 0.5 else "Low"
            conf_str = f"({conf_level} confidence)"
        
        lines.append(f"  {symbol} {likelihood.name:25s} {percent:>4s} {conf_str}")
    
    # Find most likely
    non_ruled_out = [l for l in likelihoods if not l.ruled_out]
    if non_ruled_out:
        most_likely = max(non_ruled_out, key=lambda x: x.likelihood)
        lines.append("")
        lines.append(f"Recommendation: Use {most_likely.name} configuration")
    
    # Show evidence
    all_evidence = []
    for likelihood in likelihoods:
        all_evidence.extend(likelihood.evidence)
    
    if all_evidence:
        lines.append("")
        lines.append("Evidence:")
        for ev in all_evidence[:10]:  # Limit to first 10
            lines.append(f"  - {ev.source}: {ev.indicator} (supports {', '.join(ev.supports)})")
    
    return "\n".join(lines)
