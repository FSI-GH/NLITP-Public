# AgentNode - Main Agent Orchestrator

## Overview

`AgentNode` is the main orchestrator class for NLITPv8 agents. It integrates all NLITP subsystems into a cohesive, production-grade agent capable of secure peer-to-peer communication, file transfer, trust management, and more.

## Architecture

### Component Integration

AgentNode coordinates the following subsystems:

1. **AgentIdentity** - Cryptographic identity management (Ed25519 + X25519)
2. **AgentDiscovery** - UDP multicast peer discovery
3. **DecentralizedMessenger** - End-to-end encrypted messaging
4. **TrustLedger** - Trust score management with time decay
5. **RateLimiter** - DoS protection via token bucket algorithm
6. **MessageReplayProtection** - Replay attack prevention
7. **PortAllocator** - Network port management
8. **ASIO** - Async I/O for network operations

### Thread Safety

AgentNode is fully thread-safe with:
- Mutex-protected shared state
- Atomic flags for status variables
- ASIO async I/O with work guards
- Multiple worker threads for concurrent operations

## Features

### Core Capabilities

- **Identity Management**: Automatic key generation and persistence
- **Peer Discovery**: UDP multicast announcements and queries
- **Secure Messaging**: ChaCha20-Poly1305 encrypted messages
- **File Transfer**: Chunked file transfer with integrity verification
- **Trust Management**: Record and query trust scores
- **Session Management**: Establish and maintain encrypted sessions
- **Security**: Rate limiting, replay protection, input validation

## API Reference

### Construction

```cpp
AgentNode(
    const std::string& agent_id,
    const std::string& data_dir = "",
    uint16_t discovery_port = 10001,
    bool auto_accept_sessions = false
);
```

**Parameters:**
- `agent_id`: Unique agent identifier (alphanumeric, max 64 chars)
- `data_dir`: Data directory for keys, database, files (default: ~/.nlitp)
- `discovery_port`: UDP port for peer discovery (default: 10001)
- `auto_accept_sessions`: Automatically accept session requests (default: false)

### Lifecycle Management

#### start()
```cpp
bool start();
```
Starts the agent node and all subsystems. Returns `true` on success.

**Operations:**
1. Initialize data directory structure
2. Load or create agent identity
3. Initialize all subsystems
4. Start discovery service
5. Start messenger
6. Spawn worker threads
7. Send initial announcement

#### stop()
```cpp
void stop();
```
Gracefully shuts down the agent node.

**Operations:**
1. Stop discovery service
2. Stop messenger
3. Close all sessions
4. Stop ASIO worker threads
5. Release allocated port

#### run()
```cpp
void run();
```
Runs the main event loop (blocking until stopped). Performs periodic maintenance:
- Cleanup stale peers every 30 seconds
- Re-announce presence
- Handle signals

### Peer Discovery

#### get_peers()
```cpp
std::vector<PeerConnection> get_peers() const;
```
Returns list of all discovered peers.

#### get_peer()
```cpp
std::shared_ptr<PeerConnection> get_peer(const std::string& peer_id) const;
```
Returns specific peer by ID, or nullptr if not found.

#### announce()
```cpp
bool announce();
```
Manually broadcast presence to network.

### Messaging

#### send_message()
```cpp
bool send_message(const std::string& peer_id, const std::string& content);
```
Sends encrypted message to peer. Returns `true` on success.

**Requirements:**
- Peer must be discovered
- Active session required (auto-established if needed)

#### send_file()
```cpp
bool send_file(const std::string& peer_id, const std::string& file_path);
```
Initiates file transfer to peer. Returns `true` on success.

**Requirements:**
- File must exist and be readable
- File size must be ≤ 50MB
- Peer must be discovered

#### on_message_received()
```cpp
void on_message_received(
    std::function<void(const std::string& peer_id, const std::string& content)> callback
);
```
Registers callback for received messages.

#### on_file_received()
```cpp
void on_file_received(
    std::function<void(const std::string& peer_id, const std::string& file_path, const std::string& filename)> callback
);
```
Registers callback for received files.

### Trust Management

#### record_trust_observation()
```cpp
bool record_trust_observation(
    const std::string& peer_id,
    double trust_score,
    bool verified,
    const std::string& observation
);
```
Records trust observation about peer.

**Parameters:**
- `peer_id`: Peer agent ID
- `trust_score`: Trust value (0.0 = no trust, 1.0 = full trust)
- `verified`: Whether observation is verified
- `observation`: Human-readable reason

#### get_trust_score()
```cpp
double get_trust_score(const std::string& peer_id) const;
```
Returns aggregate trust score for peer (0.0-1.0). Returns 0.5 if unknown.

#### get_peer_trust_stats()
```cpp
std::optional<PeerStats> get_peer_trust_stats(const std::string& peer_id) const;
```
Returns detailed trust statistics for peer.

### Session Management

#### request_session()
```cpp
bool request_session(const std::string& peer_id);
```
Requests encrypted session with peer.

#### close_session()
```cpp
bool close_session(const std::string& peer_id);
```
Closes active session with peer.

#### get_active_session_count()
```cpp
size_t get_active_session_count() const;
```
Returns number of active encrypted sessions.

### Statistics

#### get_stats()
```cpp
AgentNodeStats get_stats() const;
```
Returns comprehensive statistics:
```cpp
struct AgentNodeStats {
    size_t active_peers;        // Discovered peers
    size_t active_sessions;     // Encrypted sessions
    size_t active_transfers;    // File transfers
    size_t messages_sent;       // Total messages sent
    size_t messages_received;   // Total messages received
    size_t bytes_sent;          // Total bytes sent
    size_t bytes_received;      // Total bytes received
    uint64_t uptime_seconds;    // Node uptime
};
```

#### get_uptime()
```cpp
uint64_t get_uptime() const;
```
Returns uptime in seconds.

#### print_status()
```cpp
void print_status() const;
```
Prints formatted status to console.

## Usage Examples

### Basic Agent

```cpp
#include "nlitp/agent_node.hpp"
#include <iostream>

int main() {
    // Create agent
    nlitp::AgentNode node("alice");

    // Set message callback
    node.on_message_received([](const std::string& peer_id, const std::string& content) {
        std::cout << "Message from " << peer_id << ": " << content << "\n";
    });

    // Start agent
    if (!node.start()) {
        std::cerr << "Failed to start agent\n";
        return 1;
    }

    // Run event loop
    node.run();

    return 0;
}
```

### Send Message

```cpp
// Wait for peer discovery
auto peers = node.get_peers();
if (peers.empty()) {
    std::cout << "No peers discovered yet\n";
} else {
    // Send to first peer
    node.send_message(peers[0].agent_id, "Hello from Alice!");
}
```

### Record Trust

```cpp
// Record positive trust observation
node.record_trust_observation(
    "bob",
    0.9,
    true,
    "Successful message exchange"
);

// Check trust score
double trust = node.get_trust_score("bob");
std::cout << "Trust score for bob: " << trust << "\n";
```

### File Transfer

```cpp
// Send file to peer
if (node.send_file("bob", "/path/to/document.pdf")) {
    std::cout << "File transfer initiated\n";
}

// Handle received files
node.on_file_received([](const std::string& peer_id, const std::string& path, const std::string& name) {
    std::cout << "Received " << name << " from " << peer_id << "\n";
    std::cout << "Saved to: " << path << "\n";
});
```

## Data Directory Structure

AgentNode creates the following directory structure:

```
data_dir/
├── keys/
│   ├── {agent_id}_signature.key    # Ed25519 signature keypair
│   └── {agent_id}_encryption.key   # X25519 encryption keypair
├── database/
│   └── {agent_id}_trust.db         # SQLite trust ledger
├── received/
│   └── {filename}                  # Received files
└── logs/
    └── agent.log                   # Log files
```

## Security Considerations

### Trust Model

- Default trust score is 0.5 (neutral)
- Peers with trust < 0.5 trigger warnings (but are not blocked)
- Trust scores aggregate from multiple observations
- Verified observations weighted higher

### Rate Limiting

- 100 messages per second per peer (sustained)
- 200 message burst capacity
- Automatic token refill

### Replay Protection

- 60-second time window for message acceptance
- SHA-256 message IDs
- Automatic cleanup of expired entries

### Input Validation

- Agent IDs: alphanumeric + underscore/hyphen only
- File sizes: ≤ 50MB
- Message sizes: ≤ 10MB
- Path traversal prevention

## Error Handling

AgentNode uses exceptions for construction errors and returns `false` for operation failures:

```cpp
try {
    AgentNode node("alice");  // May throw on invalid ID

    if (!node.start()) {      // Returns false on failure
        // Handle startup error
    }

    if (!node.send_message("bob", "test")) {  // Returns false on failure
        // Handle send error
    }
} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
}
```

## Performance

### Scalability

- **Peers**: Tested with 100+ simultaneous peers
- **Sessions**: Supports 1000+ concurrent encrypted sessions
- **Messages**: 100 msg/s sustained, 200 msg/s burst per peer
- **File Transfers**: 100 concurrent transfers
- **Memory**: ~10MB base + ~1KB per peer + ~10KB per session

### Threading

- Worker threads: `std::thread::hardware_concurrency()` (typically 2-8)
- All I/O operations are async via ASIO
- Minimal thread contention with fine-grained locking

## Known Limitations

1. **Discovery**: UDP multicast limited to local network (by design)
2. **File Size**: 50MB limit to prevent resource exhaustion
3. **Sessions**: No session resumption after crash
4. **Trust Ledger**: SQLite not distributed (Gatekeeper replication required)

## Future Enhancements

1. **Gatekeeper Integration**: Route messages through Gatekeepers
2. **DHT Discovery**: Global peer discovery via distributed hash table
3. **Session Resumption**: Persist session keys for reconnection
4. **Compression**: Message/file compression for bandwidth savings
5. **IPv6 Support**: Full IPv6 compatibility

## CLI Example

See `examples/agent_node_example.cpp` for a complete CLI application.

```bash
# Build and run
cd NLITPv8Core
./build.sh
./build/agent_node_example alice

# Commands
> help                  # Show help
> status                # Show status
> peers                 # List peers
> msg bob Hello!        # Send message
> file bob doc.pdf      # Send file
> trust bob 0.9         # Record trust
```

## Testing

Unit tests available in `tests/test_agent_node.cpp`:

```bash
cd NLITPv8Core
./build.sh
./build/tests/test_agent_node
```

## License

Copyright © 2025 Fortified Solutions Inc.

NLITPv8 is licensed under the Apache License 2.0. See LICENSE and COPYRIGHT.md files for details.
