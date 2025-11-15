# NLITPv8 - Network Layer for Intelligent Transport Protocol

**Version**: 8.0
**License**: Apache 2.0
**Languages**: C++20, Swift 5.9+
**Copyright © 2025 Fortified Solutions Inc.**

---

## Overview

NLITPv8 is a secure, high-performance transport protocol for agent-to-agent communication. Built on QUIC with cryptographic identity and behavioral trust mechanisms.

---

## Features

- **QUIC Transport**: Modern, multiplexed, low-latency networking
- **Ed25519 Signatures**: Cryptographic agent identity
- **X25519 Key Exchange**: Forward-secret encryption
- **FlatBuffers Serialization**: Zero-copy message encoding
- **mDNS Discovery**: Automatic peer discovery on local networks
- **Trust Scoring**: Behavioral trust evaluation

---

## Architecture

### Identity
Each agent generates an Ed25519 keypair for cryptographic identity. No central authority required.

### Discovery
Agents announce presence via mDNS (Multicast DNS). Peers discover each other automatically on local networks.

### Transport
QUIC provides:
- Connection multiplexing
- Built-in encryption (TLS 1.3)
- Stream prioritization
- Fast connection establishment

### Messages
FlatBuffers schema defines message structure:
- Agent identity
- Payload
- Signature
- Metadata (timestamp, priority)

### Trust
Each agent tracks peer reliability:
- Successful interactions increase trust
- Failures decrease trust
- Trust decays over time
- Low-trust peers deprioritized

---

## Build

### C++ Implementation

```bash
cd cpp
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

**Requirements**:
- C++20 compiler
- CMake 3.20+
- FlatBuffers
- libquiche or similar QUIC library

### Swift Implementation

```bash
cd swift
swift build -c release
```

**Requirements**:
- Swift 5.9+
- Network.framework (macOS/iOS)

---

## Usage

### C++ Client

```cpp
#include "nlitp/client.hpp"

auto client = nlitp::Client("agent-001");
client.discover_peers();
client.send_message("agent-002", payload);
```

### Swift Client

```swift
import NLITP

let client = NLITPClient(agentID: "agent-001")
client.discoverPeers()
client.sendMessage(to: "agent-002", payload: data)
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

**Key Properties**:
- **ANY component at zero = W = 0**: High intelligence cannot compensate for zero humility
- **Intrinsic Reward Loop**: Doing good feels good - wisdom gains trigger positive emotional feedback
- **Collective Amplification**: W_collective = Π(W_individual) × S (support coefficient ≈ 2.3x)

Agents track peer WISDOM scores to evaluate trustworthiness. Low-WISDOM peers are deprioritized.

---

## Protocol Specifications

### Message Format (FlatBuffers)

```flatbuffers
table NLITPMessage {
  sender: string;
  recipient: string;
  payload: [ubyte];
  signature: [ubyte];
  timestamp: uint64;
  priority: Priority;
}
```

### Discovery (mDNS)

Service type: `_nlitp._udp.local`

TXT records:
- `version=8.0`
- `agent_id=<id>`
- `pubkey=<ed25519_public_key_hex>`

### Trust Scoring

```
initial_trust = 0.5
success: trust += 0.1 (max 1.0)
failure: trust -= 0.3 (min 0.0)
decay: trust *= 0.99 per hour
```

---

## Security

- **No central authority**: Self-sovereign identity
- **Forward secrecy**: X25519 key exchange per session
- **Replay protection**: Timestamp verification
- **Byzantine tolerance**: Trust-based isolation

---

## License

Apache License 2.0

See [LICENSE](LICENSE) and [COPYRIGHT.md](COPYRIGHT.md) for full details.

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
