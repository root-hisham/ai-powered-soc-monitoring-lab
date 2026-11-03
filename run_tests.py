"""run_tests.py  -  ai-powered-soc-monitoring-lab, Task 13

Runs the whole automated test suite with one command, from the project root:

    py run_tests.py

It does NOT need Ollama running and does NOT need any VM running, and it never
touches the real database in data\\soc_ai.db (every test uses its own
temporary, throwaway database).
"""

import sys
import unittest
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent / "ai-engine" / "app" / "tests"

if __name__ == "__main__":
    if not TEST_DIR.exists():
        print(f"Test folder not found: {TEST_DIR}")
        sys.exit(1)
    suite = unittest.TestLoader().discover(start_dir=str(TEST_DIR), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
