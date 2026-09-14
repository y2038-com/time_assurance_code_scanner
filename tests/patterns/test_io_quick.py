#!/usr/bin/env python3
"""
Quick test script for I/O boundary patterns.
Run from project root: python3 tests/patterns/test_io_quick.py

Not collected as a pytest module — side effects are under ``__main__``.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    # Create rules file if it doesn't exist
    rules_file = Path(__file__).parent / "test_patterns_rules.json"
    if not rules_file.exists():
        print("Creating rules file...")
        rules = [
            {"symbol": "time", "risk": "high", "category": "function", "description": "Time function"},
            {"symbol": "time_t", "risk": "high", "category": "type", "description": "Time type"},
            {"symbol": "timespec", "risk": "high", "category": "structure", "description": "Time structure"},
            {"symbol": "timeval", "risk": "high", "category": "structure", "description": "Time structure"},
            {"symbol": "localtime", "risk": "medium", "category": "function", "description": "Time function"},
            {"symbol": "mktime", "risk": "medium", "category": "function", "description": "Time function"},
            {"symbol": "clock_gettime", "risk": "medium", "category": "function", "description": "Time function"},
            {"symbol": "gettimeofday", "risk": "medium", "category": "function", "description": "Time function"},
        ]
        with open(rules_file, "w") as f:
            json.dump(rules, f, indent=2)
        print(f"Created {rules_file}")

    project_root = Path(__file__).parent.parent.parent
    test_patterns_dir = Path(__file__).parent

    print("Running I/O boundary test...")
    print(f"Project root: {project_root}")
    print(f"Test file: {test_patterns_dir / 'test_io_boundary_patterns.c'}")
    print()

    cmd = [
        "tacs",
        "scan",
        "--root",
        str(test_patterns_dir),
        "--rules",
        str(rules_file),
        "--include",
        "test_io_boundary_patterns.c",
        "--llm",
        "none",
        "--io-analysis",
        "--out",
        str(project_root / "test_io_results.json"),
    ]

    print("Command:", " ".join(cmd))
    print()

    result = subprocess.run(cmd, cwd=project_root)
    if result.returncode == 0:
        print()
        print("Test complete! Results saved to test_io_results.json")
        return 0

    print()
    print(f"Test failed with exit code {result.returncode}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
