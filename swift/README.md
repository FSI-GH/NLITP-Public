# NLITPv8 - Swift Implementation

**Version**: 8.0
**License**: Apache 2.0
**Copyright © 2025 Fortified Solutions Inc.**

---

## Overview

Swift-native implementation of NLITPv8 for iOS, iPadOS, and macOS.

---

## Requirements

- Swift 5.9+
- macOS 12.0+ / iOS 15.0+ / iPadOS 15.0+
- Network.framework

---

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/FSI-GH/NLITP-Public.git", from: "8.0.0")
]
```

---

## Usage

```swift
import NLITP

let identity = try NLITPv8AgentIdentity(agentID: "agent-001")
let client = NLITPv8Client(identity: identity)

try await client.start()
try await client.sendMessage(to: "agent-002", payload: data)
```

---

## Features

- Ed25519 cryptographic signatures
- X25519 key exchange
- UDP discovery
- TCP reliable transport
- Trust scoring
- Byzantine fault tolerance

---

## License

Apache License 2.0

See [LICENSE](../LICENSE) for details.
