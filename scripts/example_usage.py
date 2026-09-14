#!/usr/bin/env python3
"""
Example command to demonstrate the Y2038 scanner usage.
This shows how to run the scanner with different options.
"""

import subprocess
import sys
import tempfile
import json
from pathlib import Path

def create_example_files():
    """Create example files for testing."""
    
    # Create temporary directory
    temp_dir = Path(tempfile.mkdtemp())
    
    # Create example C file
    c_file = temp_dir / "example.c"
    c_file.write_text("""
#include <time.h>
#include <stdio.h>

int main() {
    time_t current_time = time(NULL);
    printf("Current time: %ld\\n", current_time);
    
    // This is a potential Y2038 issue
    struct tm *local_time = localtime(&current_time);
    
    return 0;
}
""")
    
    # Create example rules file
    rules_file = temp_dir / "rules.json"
    rules_file.write_text("""[
  {
    "symbol": "time",
    "risk": "high",
    "category": "function",
    "description": "32-bit time function that may overflow in 2038"
  },
  {
    "symbol": "localtime",
    "risk": "medium", 
    "category": "function",
    "description": "Time conversion function using time_t"
  },
  {
    "symbol": "time_t",
    "risk": "high",
    "category": "type",
    "description": "32-bit time type that will overflow in 2038"
  }
]""")
    
    return temp_dir, c_file, rules_file

def run_scanner_example():
    """Run the scanner with example files."""
    
    print("Creating example files...")
    temp_dir, c_file, rules_file = create_example_files()
    
    print(f"Created temporary directory: {temp_dir}")
    print(f"Created C file: {c_file}")
    print(f"Created rules file: {rules_file}")
    
    # Example 1: Run with LLM disabled (for testing)
    print("\n=== Example 1: Scan with LLM disabled ===")
    cmd1 = [
        sys.executable, "-m", "tacs.cli",
        "--root", str(temp_dir),
        "--rules", str(rules_file),
        "--include", "*.c",
        "--min-risk", "medium",
        "--llm", "none",
        "--out", str(temp_dir / "findings_none.json")
    ]
    
    print(f"Command: {' '.join(cmd1)}")
    
    try:
        result = subprocess.run(cmd1, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print("✓ Scan completed successfully")
            print(f"Output: {result.stdout}")
            
            # Check output file
            output_file = temp_dir / "findings_none.json"
            if output_file.exists():
                with open(output_file, 'r') as f:
                    data = json.load(f)
                print(f"✓ Found {len(data.get('findings', []))} findings")
                print(f"✓ Metrics: {data.get('meta', {}).get('metrics', {})}")
            else:
                print("✗ Output file not created")
        else:
            print(f"✗ Scan failed: {result.stderr}")
    except subprocess.TimeoutExpired:
        print("✗ Scan timed out")
    except Exception as e:
        print(f"✗ Scan failed with exception: {e}")
    
    # Example 2: Show what the command would look like with Ollama
    print("\n=== Example 2: Scan with Ollama LLM (command only) ===")
    cmd2 = [
        sys.executable, "-m", "tacs.cli",
        "--root", str(temp_dir),
        "--rules", str(rules_file),
        "--include", "*.c",
        "--min-risk", "medium",
        "--confidence-floor", "0.7",
        "--llm", "ollama",
        "--model", "gpt-oss:120b-cloud",
        "--log-llm",
        "--out", str(temp_dir / "findings_ollama.json")
    ]
    
    print(f"Command: {' '.join(cmd2)}")
    print("Note: This requires OLLAMA_API_KEY (legacy: OLLAMA_CLOUD_TOKEN)")
    
    # Clean up
    print(f"\nCleaning up temporary directory: {temp_dir}")
    # Note: In a real scenario, you might want to keep the files for inspection
    # import shutil
    # shutil.rmtree(temp_dir)

if __name__ == "__main__":
    run_scanner_example()
