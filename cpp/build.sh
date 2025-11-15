#!/bin/bash
#
# NLITPv8 Build Script
# Cross-Platform: macOS 15+, Linux (Ubuntu 22+), Windows 10+ (via WSL/MSYS2)
#
# Copyright © 2025 Fortified Solutions Inc.
#

set -e

echo "================================================================================"
echo "  NLITPv8 - C++ Build System"
echo "================================================================================"
echo ""

# Detect platform
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM=Linux;;
    Darwin*)    PLATFORM=macOS;;
    CYGWIN*|MINGW*|MSYS*) PLATFORM=Windows;;
    *)          PLATFORM="UNKNOWN:${OS}"
esac

echo "Platform: ${PLATFORM}"

# Check dependencies
echo ""
echo "Checking dependencies..."

# CMake
if command -v cmake &> /dev/null; then
    CMAKE_VERSION=$(cmake --version | head -n1 | awk '{print $3}')
    echo "  CMake ${CMAKE_VERSION}"
else
    echo "ERROR: CMake not found. Please install CMake 3.20+"
    exit 1
fi

# C++ compiler
if command -v g++ &> /dev/null; then
    GCC_VERSION=$(g++ --version | head -n1 | awk '{print $4}')
    echo "  GCC ${GCC_VERSION}"
elif command -v clang++ &> /dev/null; then
    CLANG_VERSION=$(clang++ --version | head -n1 | awk '{print $4}')
    echo "  Clang ${CLANG_VERSION}"
else
    echo "ERROR: C++ compiler not found. Please install GCC or Clang"
    exit 1
fi

# libsodium
if pkg-config --exists libsodium; then
    SODIUM_VERSION=$(pkg-config --modversion libsodium)
    echo "  libsodium ${SODIUM_VERSION}"
else
    echo "ERROR: libsodium not found"
    echo ""
    echo "Please install libsodium:"
    echo "  macOS:   brew install libsodium"
    echo "  Ubuntu:  sudo apt-get install libsodium-dev"
    echo "  Windows: vcpkg install libsodium"
    exit 1
fi

# SQLite3
if pkg-config --exists sqlite3; then
    SQLITE_VERSION=$(pkg-config --modversion sqlite3)
    echo "  SQLite3 ${SQLITE_VERSION}"
else
    echo "ERROR: SQLite3 not found"
    echo ""
    echo "Please install SQLite3:"
    echo "  macOS:   brew install sqlite3"
    echo "  Ubuntu:  sudo apt-get install libsqlite3-dev"
    echo "  Windows: vcpkg install sqlite3"
    exit 1
fi

echo ""
echo "All dependencies satisfied."
echo ""

# Build directory
BUILD_DIR="build"
BUILD_TYPE="${1:-Release}"

echo "Creating build directory: ${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Configure
echo ""
echo "Configuring CMake (${BUILD_TYPE})..."
cd "${BUILD_DIR}"
cmake -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" ..

if [ $? -ne 0 ]; then
    echo "ERROR: CMake configuration failed"
    exit 1
fi

echo "Configuration complete."

# Build
echo ""
echo "Building NLITPv8..."
cmake --build . --config "${BUILD_TYPE}" -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

if [ $? -ne 0 ]; then
    echo "ERROR: Build failed"
    exit 1
fi

echo ""
echo "Build complete."

# Run tests
echo ""
echo "Running tests..."
ctest --output-on-failure

if [ $? -ne 0 ]; then
    echo "ERROR: Tests failed"
    exit 1
fi

echo "All tests passed."

# Summary
echo ""
echo "================================================================================"
echo "NLITPv8 Build Complete"
echo "================================================================================"
echo ""
echo "  Platform:      ${PLATFORM}"
echo "  Build Type:    ${BUILD_TYPE}"
echo "  Build Dir:     ${BUILD_DIR}"
echo ""
echo "  Library:       ${BUILD_DIR}/libnlitp8.a"
echo "  Examples:      ${BUILD_DIR}/nlitp_agent_example"
echo "                 ${BUILD_DIR}/nlitp_mesh_demo"
echo ""
echo "To install:"
echo "  cd ${BUILD_DIR} && sudo cmake --install ."
echo ""
