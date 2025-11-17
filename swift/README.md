# NLITPv8 - Swift Implementation

**Version**: 8.0
**License**: Apache 2.0
**Copyright © 2025 Fortified Solutions Inc.**

---

## Overview

Swift implementation of NLITPv8 transport protocol for iOS, iPadOS, and macOS.

---

## Requirements

- Swift 5.9+
- macOS 12.0+ / iOS 15.0+ / iPadOS 15.0+
- Network.framework

---

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/FSI-GH/NLITP-Public.git", from: "8.0.0")
]
```

---

## Usage

```swift
import NLITP

let identity = try NLITPv8AgentIdentity(
    agentID: "agent-001",
    sessionID: UUID().uuidString,
    tcpPort: 11000,
    udpPort: 12000
)

let node = NLITPv8AgentNode(identity: identity)
try await node.start()
try await node.sendMessage(to: "agent-002", type: .direct, payload: data)
```

---

## Features

- Ed25519 signatures
- X25519 key exchange
- UDP multicast discovery
- TCP reliable messaging
- Trust-based peer evaluation
- Byzantine fault tolerance

---

## License

Apache License 2.0

See [LICENSE](../LICENSE) for details.
