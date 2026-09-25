# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

import json
import re
import tempfile
import subprocess
import sys
from pathlib import Path


def test_smoke_scan():
    """Test the scanner with a simple C file that calls time()."""
    
    # Create a temporary directory with a test C file
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create a test C file
        test_c_file = temp_path / "test.c"
        test_c_file.write_text("""
#include <time.h>

int main() {
    time_t t = time(NULL);
    return 0;
}
""")
        
        # Create a temporary rules file (external catalog with an explicit ID)
        rules_file = temp_path / "rules.json"
        rules_file.write_text("""[
  {
    "symbol": "time",
    "risk": "high",
    "category": "function",
    "description": "32-bit time function that may overflow in 2038",
    "rule_id": "TACS-RULE-9001"
  }
]""")
        
        # Create a temporary output file
        output_file = temp_path / "output.json"
        
        # Run the scanner from the temp dir so any relative default write would land here
        cmd = [
            sys.executable, "-m", "tacs.cli",
            "scan",
            "--root", str(temp_path),
            "--rules", str(rules_file),
            "--include", "*.c",
            "--min-risk", "medium",
            "--confidence-floor", "0.6",
            "--llm", "none",
            "--out", str(output_file)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=temp_path)
        
        # Check that the command succeeded
        assert result.returncode == 0, f"Scanner failed: {result.stderr}\n{result.stdout}"
        
        # Check that output file was created
        assert output_file.exists(), "Output file was not created"

        # --out must be exclusive for the public report (no implicit ./findings.json)
        stray = temp_path / "findings.json"
        assert not stray.exists(), (
            f"Unexpected default findings.json written at {stray}; "
            "--out should control the only top-level public report"
        )

        # Session provenance must track the installed package version
        from tacs import __version__ as tacs_version

        meta_files = list((temp_path / "results" / "scans").glob("*/meta.json"))
        assert meta_files, "Expected a session meta.json under results/scans"
        with open(meta_files[0], "r", encoding="utf-8") as f:
            session_meta = json.load(f)
        assert session_meta.get("version", {}).get("scanner_cli") == tacs_version, (
            f"scanner_cli provenance {session_meta.get('version', {}).get('scanner_cli')!r} "
            f"does not match tacs.__version__ {tacs_version!r}"
        )
        
        # Load and validate the JSON output
        with open(output_file, 'r') as f:
            results = json.load(f)
        
        # Validate JSON structure
        assert "meta" in results, "Missing 'meta' field in results"
        assert "findings" in results, "Missing 'findings' field in results"
        assert results.get("schema_version") == "1.1", "Expected schema_version 1.1"
        assert isinstance(results.get("candidates"), list), "Missing candidates[]"
        assert len(results["candidates"]) > 0, "Expected deterministic candidates"
        catalog_rows = [
            c
            for c in results["candidates"]
            if c.get("discovery_method") == "catalog_symbol_match"
        ]
        assert catalog_rows, "Expected catalog_symbol_match candidates"
        # External catalog supplied a valid ID — must propagate exactly.
        time_rows = [c for c in catalog_rows if c.get("symbol") == "time"]
        assert time_rows
        assert all(c.get("rule_id") == "TACS-RULE-9001" for c in time_rows)
        for c in results["candidates"]:
            if c.get("discovery_method") != "catalog_symbol_match":
                assert c.get("rule_id") is None
        assert results["meta"].get("candidate_summary", {}).get("total") == len(
            results["candidates"]
        )
        
        meta = results["meta"]
        assert "root" in meta, "Missing 'root' in meta"
        assert "rules_path" in meta, "Missing 'rules_path' in meta"
        assert not Path(meta["root"]).is_absolute(), (
            f"Published meta.root should not be host-absolute: {meta['root']!r}"
        )
        assert not Path(meta["rules_path"]).is_absolute(), (
            f"Published meta.rules_path should not be host-absolute: {meta['rules_path']!r}"
        )
        assert "/home/" not in meta["root"] and "/home/" not in meta["rules_path"]
        assert "model" in meta, "Missing 'model' in meta"
        assert meta["model"] == "none", (
            f"Discovery-only scan should report model 'none', got {meta['model']!r}"
        )
        assert session_meta.get("models", {}).get("llm_type") == "none"
        assert session_meta.get("models", {}).get("llm_model") == "none", (
            f"Session llm_model should be 'none' for --llm none, "
            f"got {session_meta.get('models', {}).get('llm_model')!r}"
        )

        summary_file = meta_files[0].parent / "findings" / "summary.txt"
        assert summary_file.exists(), "Expected session findings/summary.txt"
        summary_text = summary_file.read_text(encoding="utf-8")
        assert "{session.timing" not in summary_text, (
            "Session summary timing section left uninterpolated placeholders"
        )
        assert "Timing (ms):" in summary_text
        assert "- Total:" in summary_text
        # summary.txt and scan meta.json must share the same finalized wall clock.
        total_match = re.search(r"- Total:\s*(\d+)", summary_text)
        assert total_match, "Expected '- Total: <ms>' in summary.txt"
        summary_total = int(total_match.group(1))
        meta_total = int(session_meta.get("timing_ms", {}).get("total", 0))
        assert summary_total > 0, "summary.txt Total must not be zero after a real scan"
        assert meta_total > 0, "scan metadata timing_ms.total must not be zero"
        assert summary_total == meta_total, (
            f"summary Total ({summary_total}) must match metadata total ({meta_total})"
        )

        assert "confidence_floor" in meta, "Missing 'confidence_floor' in meta"
        assert "metrics" in meta, "Missing 'metrics' in meta"
        
        metrics = meta["metrics"]
        assert "total_files" in metrics, "Missing 'total_files' in metrics"
        assert "total_lines" in metrics, "Missing 'total_lines' in metrics"
        assert "total_chars" in metrics, "Missing 'total_chars' in metrics"
        
        # Check that we found at least one candidate
        findings = results["findings"]
        assert len(findings) > 0, "No findings were generated"
        
        # Check that at least one finding has y2038_issue="abstain" (since we used --llm=none)
        abstain_findings = [f for f in findings if f.get("y2038_issue") == "abstain"]
        assert len(abstain_findings) > 0, "No abstain findings found (expected with --llm=none)"
        
        # Validate finding structure
        finding = findings[0]
        required_fields = [
            "file", "region", "lines", "symbol", "severity", "confidence", 
            "reason", "scenario", "preprocessor_context", "source_snippet", 
            "y2038_issue", "needs_more_context"
        ]
        
        for field in required_fields:
            assert field in finding, f"Missing '{field}' field in finding"
        
        print("✓ Smoke test passed!")
        print(f"✓ Found {len(findings)} findings")
        print(f"✓ Found {len(abstain_findings)} abstain findings")
        print(f"✓ JSON structure is valid")


if __name__ == "__main__":
    test_smoke_scan()
