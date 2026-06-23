# CAN BE RAN WITH ./build.sh to configure and build,
# OR ./build.sh clean to wipe the build directory first

#!/bin/bash

# navigate to the cc directory (script location)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# optionally wipe the build directory for a clean build
if [ "$1" == "clean" ]; then
    rm -rf build
fi

# use gcc-14 for full c++23 library support (including <print>)
export CC=gcc-14
export CXX=g++-14

# configure and build
cmake -B build
cmake --build build
