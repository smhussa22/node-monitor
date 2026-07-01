#!/usr/bin/env bash
# build and run the GoogleTest suite inside the same gcc:14 container the main binary uses.
#
# usage:
#   scripts/run_tests.sh              # build + run all tests
#   scripts/run_tests.sh --filter     # run tests matching a filter pattern
#
# examples:
#   bash cc/run_tests.sh
#   bash cc/run_tests.sh --filter DhcpPacket
#   bash cc/run_tests.sh --filter AclEngine.ThreadSafe

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

FILTER="${1:-}"

echo "=== node-monitor C++ test suite ==="
echo ""

docker run --rm \
    -v "${REPO_ROOT}:/src" \
    -w /src/cc \
    gcc:14 \
    bash -c "
        apt-get update -qq && apt-get install -y -qq cmake git ca-certificates libpq-dev libcurl4-openssl-dev >/dev/null 2>&1
        git config --global --add safe.directory '*'
        export CC=gcc-14 CXX=g++-14
        cmake -B build_tests -DCMAKE_BUILD_TYPE=Debug >/dev/null
        cmake --build build_tests --target node_monitor_tests -j\$(nproc)
        echo ''
        echo '--- running tests ---'
        cd build_tests
        if [ -n '${FILTER}' ]; then
            ./node_monitor_tests --gtest_filter='${FILTER}*'
        else
            ./node_monitor_tests
        fi
    "
