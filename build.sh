#!/usr/bin/env bash
# Build MONEU from a clean state.
#
# Run it from the directory this file is in:
#
#     ./build.sh
#
# A stale build/ directory from an earlier extraction keeps a CMakeCache
# pointing at wherever it was configured, which is why an old cache makes
# cmake complain about a source directory that no longer exists. This
# removes it first, so the build never depends on what was there before.
set -e

cd "$(dirname "$0")"

if [ ! -f CMakeLists.txt ]; then
    echo "error: CMakeLists.txt not found next to this script."
    exit 1
fi

echo "==> removing any previous build directory"
rm -rf build

echo "==> configuring"
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release

echo "==> building on $(nproc) cores"
make -j"$(nproc)"

echo
echo "Done. Binaries are in build/src:"
ls -1 src/moneud src/moneu-cli src/moneu-test-noise
echo
echo "Self-test:   ./build/src/moneu-test-noise"
echo "Run node:    ./build/src/moneud -loglevel=debug"
