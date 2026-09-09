# Scripts Directory

This directory contains utility scripts, test scripts, and analysis tools for the Y2038 Scanner.

## Directory Structure

### [debug/](debug/)
Debug and diagnostic scripts used during development:
- `debug_abstain_issue.py` - Debug script to investigate abstain issues
- `test_abstain_reasons.py` - Test abstain reason generation
- `test_bypass_options.py` - Test bypass options
- `test_improved_prompt.py` - Test improved prompts
- `test_prescan.py` - Test prescan functionality
- `test_specific_reasons.py` - Test specific reason generation

### [test/](test/)
Component test scripts:
- `test_typedef_scanner.py` - Test multi-level typedef scanning
- `verify_typedef_scanner.py` - Verify typedef scanner functionality

## Main Scripts

### Analysis Scripts
- `analyze_all_configs.py` - Analyze findings across all configurations
- `analyze_findings_by_config.py` - Analyze findings by configuration
- `analyze_findings_simple.py` - Simple findings analysis
- `analyze_pipeline_comparison.py` - Compare pipeline performance
- `compare_pipelines.sh` - Compare Legacy vs Function-First pipelines

### Utility Scripts
- `run_env_wizard.py` - Launcher for environment wizard
- `show_latest_abstains.sh` - Show latest abstain findings (shell script)
- `cleanup_logs.py` - Clean up old log files
- `cleanup_old_scans.py` - Clean up old scan results
- `validate_findings.py` - Validate findings JSON structure

### Test Scripts
- `test_scanner.py` - Basic scanner test
- `test_discovery.py` - Test discovery functionality
- `test_basic.py` - Basic functionality test
- Various other test scripts for specific features

## Usage

Most scripts can be run directly:
```bash
python scripts/analyze_findings_simple.py findings.json
./scripts/compare_pipelines.sh test_file.c config.json
python scripts/run_env_wizard.py
```

See individual script files for specific usage instructions.
