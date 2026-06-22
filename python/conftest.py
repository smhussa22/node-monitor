import sys
import os

# add this directory to sys.path so tests can do "from simulators.x import ..."
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
