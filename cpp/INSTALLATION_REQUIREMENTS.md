# NLITPv8 Installation Requirements

**NLITPv8 - Next Level Intelligence Transport Protocol v8**

Copyright © 2025 Fortified Solutions Inc.

This document outlines all dependencies and installation requirements for building and running NLITPv8.

---

## Supported Platforms

- **macOS 15+** (Sequoia and later)
- **Linux** (Ubuntu 22.04 LTS and later)
- **Windows 10+** / Windows Server 2016+

---

## Build Tools

### All Platforms

- **CMake 3.20+** - Modern build system
- **C++20 Compiler**:
  - GCC 11+ (Linux)
  - Clang 14+ (macOS)
  - MSVC 2022+ (Windows)

### Installation

#### macOS
```bash
# Install Xcode Command Line Tools (includes Clang)
xcode-select --install

# Install CMake via Homebrew
brew install cmake
```

#### Ubuntu/Debian
```bash
# Update package lists
sudo apt-get update

# Install build tools
sudo apt-get install -y build-essential cmake pkg-config
```

#### Windows
```powershell
# Install Visual Studio 2022 with C++ workload
# Download from: https://visualstudio.microsoft.com/downloads/

# Install CMake
# Download from: https://cmake.org/download/
```

---

## Required Dependencies

### 1. libsodium (Cryptographic Library)

**Purpose:** Ed25519, X25519, ChaCha20-Poly1305 cryptographic primitives
**Minimum Version:** 1.0.18

#### macOS
```bash
brew install libsodium
```

#### Ubuntu/Debian
```bash
sudo apt-get install -y libsodium-dev
```

#### Windows (via vcpkg)
```powershell
# Install vcpkg
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat

# Install libsodium
.\vcpkg install libsodium:x64-windows
```

### 2. SQLite3 (Database)

**Purpose:** Trust ledger and persistent storage
**Minimum Version:** 3.35.0

#### macOS
```bash
brew install sqlite3
```

#### Ubuntu/Debian
```bash
sudo apt-get install -y libsqlite3-dev
```

#### Windows (via vcpkg)
```powershell
.\vcpkg install sqlite3:x64-windows
```

### 3. nlohmann/json (JSON Library)

**Purpose:** Message serialization and configuration
**Minimum Version:** 3.11.0

**Note:** Header-only library, automatically fetched by CMake via FetchContent

### 4. ASIO (Async Networking)

**Purpose:** Non-blocking TCP/UDP networking
**Minimum Version:** 1.24.0

**Note:** Header-only library, automatically fetched by CMake via FetchContent

### 5. spdlog (Logging)

**Purpose:** Fast C++ logging
**Minimum Version:** 1.11.0

**Note:** Header-only library, automatically fetched by CMake via FetchContent

---

## Build Instructions

### Quick Start (All Platforms)

```bash
# Clone repository
git clone https://github.com/FSI-GH/NLITP-Public.git
cd NLITP-Public/cpp

# Build (Release mode)
./build.sh

# Build (Debug mode)
./build.sh Debug

# Run tests
cd build
ctest --output-on-failure
```

### Manual Build (Advanced)

```bash
# Create build directory
mkdir -p build
cd build

# Configure CMake
cmake -DCMAKE_BUILD_TYPE=Release ..

# Build
cmake --build . -j$(nproc)

# Run tests
ctest --output-on-failure

# Install (optional)
sudo cmake --install .
```

---

## Installation Verification

After building, verify the installation:

```bash
# Check library was built
ls build/libnlitp8.a

# Check examples were built
ls build/nlitp_agent_example

# Run basic smoke test
cd build
./nlitp_agent_example
```

---

## Troubleshooting

### libsodium not found

**Error:** `libsodium not found`

**Solution:**
```bash
# macOS
brew install libsodium

# Ubuntu/Debian
sudo apt-get install libsodium-dev

# Verify installation
pkg-config --modversion libsodium
```

### SQLite3 not found

**Error:** `Could NOT find SQLite3`

**Solution:**
```bash
# macOS
brew install sqlite3

# Ubuntu/Debian
sudo apt-get install libsqlite3-dev

# Verify installation
pkg-config --modversion sqlite3
```

### CMake version too old

**Error:** `CMake 3.20 or higher is required`

**Solution:**
```bash
# Ubuntu (if apt-get provides old version)
wget https://github.com/Kitware/CMake/releases/download/v3.28.0/cmake-3.28.0-Linux-x86_64.sh
chmod +x cmake-3.28.0-Linux-x86_64.sh
sudo ./cmake-3.28.0-Linux-x86_64.sh --prefix=/usr/local --skip-license
```

### Compiler does not support C++20

**Error:** `Compiler does not support C++20`

**Solution:**
```bash
# Ubuntu - Install newer GCC
sudo apt-get install -y gcc-11 g++-11
export CXX=g++-11
export CC=gcc-11

# Rebuild
./build.sh
```

---

## License

Copyright © 2025 Fortified Solutions Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
