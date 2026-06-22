# CAN BE RAN WITH ./run.sh all for all tests, OR:
# ./run.sh [test file name w/o test_] e.g. cisco_router

#!/bin/bash

# navigate to the python directory (one level up from script location)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

# run tests based on argument
if [ "$1" == "all" ]; then
    python3 -m pytest tests/ -v
else
    python3 -m pytest tests/test_$1.py -v
fi
