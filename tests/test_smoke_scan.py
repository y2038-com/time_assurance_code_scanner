import json
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
        
        # Create a temporary rules file
        rules_file = temp_path / "rules.json"
        rules_file.write_text("""[
  {
    "symbol": "time",
    "risk": "high",
    "category": "function",
    "description": "32-bit time function that may overflow in 2038"
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
        
        # Load and validate the JSON output
        with open(output_file, 'r') as f:
            results = json.load(f)
        
        # Validate JSON structure
        assert "meta" in results, "Missing 'meta' field in results"
        assert "findings" in results, "Missing 'findings' field in results"
        
        meta = results["meta"]
        assert "root" in meta, "Missing 'root' in meta"
        assert "rules_path" in meta, "Missing 'rules_path' in meta"
        assert "model" in meta, "Missing 'model' in meta"
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
