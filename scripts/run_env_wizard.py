#!/usr/bin/env python3
"""
Launcher script for the environment wizard that handles import issues.
"""

import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Now import and run the wizard
if __name__ == '__main__':
    from envui.cli.env_wizard import main
    main()
