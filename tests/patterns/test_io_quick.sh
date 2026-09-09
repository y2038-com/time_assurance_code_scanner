#!/bin/bash
# Quick test script for I/O boundary patterns
# Run from project root: bash tests/patterns/test_io_quick.sh

# Create rules file if it doesn't exist
RULES_FILE="tests/patterns/test_patterns_rules.json"
if [ ! -f "$RULES_FILE" ]; then
    echo "Creating rules file..."
    python3 -c "
import json
rules = [
    {'symbol': 'time', 'risk': 'high', 'category': 'function', 'description': 'Time function'},
    {'symbol': 'time_t', 'risk': 'high', 'category': 'type', 'description': 'Time type'},
    {'symbol': 'timespec', 'risk': 'high', 'category': 'structure', 'description': 'Time structure'},
    {'symbol': 'timeval', 'risk': 'high', 'category': 'structure', 'description': 'Time structure'},
    {'symbol': 'localtime', 'risk': 'medium', 'category': 'function', 'description': 'Time function'},
    {'symbol': 'mktime', 'risk': 'medium', 'category': 'function', 'description': 'Time function'},
    {'symbol': 'clock_gettime', 'risk': 'medium', 'category': 'function', 'description': 'Time function'},
    {'symbol': 'gettimeofday', 'risk': 'medium', 'category': 'function', 'description': 'Time function'},
]
with open('$RULES_FILE', 'w') as f:
    json.dump(rules, f, indent=2)
"
fi

# Run the scanner
echo "Running I/O boundary test..."
python3 -m scanner.cli \
  --root tests/patterns \
  --rules "$RULES_FILE" \
  --include "test_io_boundary_patterns.c" \
  --llm none \
  --io-analysis \
  --out test_io_results.json

echo ""
echo "Test complete! Results saved to test_io_results.json"
echo ""
echo "To view results:"
echo "  cat test_io_results.json | python3 -m json.tool | less"
echo ""
echo "To count I/O findings (if you have jq):"
echo "  cat test_io_results.json | jq '.findings | length'"
