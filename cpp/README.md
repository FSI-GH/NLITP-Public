# NLITPv8 - C++ Implementation

**Next Level Intelligence Transport Protocol v8**


**Copyright © 2025 Fortified Solutions Inc.**
**License:** Apache 2.0

---

## Features


- **Thread-safe** database access with mutex protection
- **Message size limits** (10MB max)
- **Path traversal prevention** via filename sanitization
- **Replay attack protection** (SHA-256 + 60s window)
- **Rate limiting** (token bucket, 100 msg/s)
- **File size limits** (50MB max)
- **Input validation** (alphanumeric IDs only)
- **Network timeouts** (5s connection, 30s read/write)

### Performance

- **C++20:** Modern language features and optimizations
- **Zero-Copy:** Efficient memory management
- **Async I/O:** ASIO-based networking (non-blocking)
- **Thread-Safe:** Lock-free where possible, fine-grained locking
- **Cross-Platform:** Native performance on all platforms

### Cryptography

- **Ed25519:** Digital signatures (128-bit security)
- **X25519:** Key exchange (ECDH)
- **ChaCha20-Poly1305:** AEAD cipher for encryption
- **libsodium:** Industry-standard cryptographic library

### Cross-Platform Support

- **macOS 15+** (Sequoia and later)
- **Linux** (Ubuntu 22.04 LTS and later)
- **Windows 10+** / Windows Server 2016+

---

## Quick Start

### Prerequisites

#### macOS
```bash
brew install cmake libsodium sqlite3
```

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install cmake build-essential libsodium-dev libsqlite3-dev pkg-config
```

#### Windows
```powershell
# Using vcpkg
vcpkg install libsodium sqlite3
```

### Build

```bash
# Clone repository
git clone https://github.com/FSI-GH/NLITP-Public.git
cd NLITP-Public/cpp

# Build (Release)
./build.sh

# Build (Debug)
./build.sh Debug

# Run tests
cd build
ctest --output-on-failure
```

---

## Architecture

### Core Components

- **AgentIdentity** - Ed25519 + X25519 cryptographic identity
- **AgentDiscovery** - UDP multicast peer discovery
- **DecentralizedMessenger** - End-to-end encrypted messaging
- **TrustLedger** - Byzantine fault-tolerant trust scoring
- **RateLimiter** - Token bucket rate limiting
- **MessageReplayProtection** - Replay attack prevention
- **PortAllocator** - Thread-safe port management
- **AgentNode** - Complete agent implementation

### Security Layers

```
Layer 5: Application    [File Transfer, Trust Network]
Layer 4: Message        [Replay Protection, Rate Limiting]
Layer 3: Crypto         [Ed25519 Signatures, ChaCha20 Encryption]
Layer 2: Transport      [UDP Primary, TCP Fallback, Timeouts]
Layer 1: Validation     [Size Limits, Path Sanitization, Input Validation]
```

---

## API Usage

### Basic Agent

```cpp
#include <nlitp/agent_node.hpp>

int main() {
    // Create agent with cryptographic identity
    nlitp::AgentNode agent(
        "my-agent-id",
        "session-id",
        {"code", "research"}
    );

    // Start agent (joins mesh network)
    agent.start();

    // Send encrypted message to peer
    nlohmann::json payload = {
        {"action", "collaborate"},
        {"task", "project-x"}
    };

    agent.messenger()->send_message(
        "peer-agent-id",
        nlitp::MessageType::DIRECT,
        payload,
        true  // encrypted
    );

    // Graceful shutdown
    agent.shutdown();

    return 0;
}
```

### Trust Network

```cpp
// Record positive observation
agent.trust_ledger()->record_observation(
    "peer-agent-id",
    "session-id",
    0.85,  // trust score (0.0-1.0)
    true,  // verified
    "Successfully completed task"
);

// Get peer trust score
double trust = agent.trust_ledger()->get_trust("peer-agent-id");
```

---

## WISDOM Integration

NLITPv8 includes the WISDOM Protocol for behavioral trust evaluation:

```
W = (U × C × H × A × I × Ad)^(1/6)

Where:
U = Understanding (with significance synthesis)
C = Compassion (concern for conscious entities)
H = Humility (recognition of limitations)
A = Action (appropriate response)
I = Intent (alignment of purpose)
Ad = Adaptability (learning and evolution)
```

**Key Properties:**
- **ANY component at zero = W = 0**: High intelligence cannot compensate for zero humility
- **Geometric mean**: All components must be present for high wisdom
- **Behavioral measurement**: Trust based on observed actions, not claims

Agents track peer WISDOM scores to evaluate trustworthiness.

---

## Security Configuration

### Constants (in `security_config.hpp`)

```cpp
// Message and file size limits
MAX_MESSAGE_SIZE = 10 MB
MAX_FILE_SIZE = 50 MB
MAX_JSON_SIZE = 1 MB

// Network timeouts
CONNECTION_TIMEOUT = 5 seconds
READ_TIMEOUT = 30 seconds
WRITE_TIMEOUT = 30 seconds

// Rate limiting
RATE_LIMIT_PER_SECOND = 100  // per peer
RATE_LIMIT_BURST = 200

// Replay protection
REPLAY_WINDOW = 60 seconds
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

---

## Research Foundation

Based on wisdom-based trust research (August 2025):
[Protocol-Wisdom Research Essay](https://github.com/FSI-GH/Protocol-Wisdom)

Core principles:
- Wisdom as measurable behavior
- Trust decay for continuous verification
- Byzantine fault tolerance through behavioral consensus
- Emergent safety without imposed constraints

---

**Fortified Solutions Inc. - Building the Foundation for Trustworthy AI**
