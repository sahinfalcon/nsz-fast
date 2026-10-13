# Run with: python -m unittest discover -s tests -t .
import sys

# nsz.nut.Print parses sys.argv on import; keep the test runner's flags away from it
sys.argv = sys.argv[:1]
