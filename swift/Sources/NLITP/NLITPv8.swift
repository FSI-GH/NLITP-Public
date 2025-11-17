// NLITPv8.swift
// Decentralized Mesh Agent Network with Cryptographic Trust
//
// Swift-native implementation for iOS/iPadOS/macOS support.
// Supersedes NLITPv7 (Python).
//
// Copyright © 2025 Fortified Solutions Inc.
// PATENT PENDING - See PATENT_NOTICES.md

import Foundation
import CryptoKit
#if canImport(Network)
import Network
#endif

// MARK: - Configuration

@available(macOS 12.0, iOS 15.0, iPadOS 15.0, *)
public struct NLITPv8Config: Sendable {
    // Port ranges
    public static let baseTCPPort: UInt16 = 11000
    public static let baseUDPPort: UInt16 = 12000
    public static let discoveryPort: UInt16 = 10001
    public static let maxAgents: Int = 100

    // Discovery intervals
    public static let discoveryInterval: TimeInterval = 5.0
    public static let trustDecayPeriod: TimeInterval = 3600.0 // 1 hour

    // Trust calculation weights
    public static let trustBaseWeight: Double = 0.7
    public static let trustTrendWeight: Double = 0.2
    public static let trustVerificationWeight: Double = 0.1

    // AC App (Architecture Controller) - Trusted central authority
    public static let acAppTCPPort: UInt16 = 10000
    public static let acAppUDPPort: UInt16 = 10002
    public static let acAppAgentID: String = "ac-app"
    public static let acHeartbeatInterval: TimeInterval = 10.0
    public static let acDefaultTrust: Double = 1.0
    public static let acRegistrationRequired: Bool = true
}

// MARK: - Message Types

/// NLITPv8 message types
public enum NLITPv8MessageType: String, Sendable, Codable {
    // Discovery
    case agentAnnounce = "agent_announce"
    case agentAck = "agent_ack"
    case agentGoodbye = "agent_goodbye"

    // Direct messaging
    case direct = "direct"
    case request = "request"
    case response = "response"

    // Trust network
    case wisdomShare = "wisdom_share"
    case trustQuery = "trust_query"
    case trustResponse = "trust_response"

    // Coordination
    case workOffer = "work_offer"
    case workAccept = "work_accept"
    case workComplete = "work_complete"

    // File transfer (explicit accept/deny)
    case fileOffer = "file_offer"
    case fileAccept = "file_accept"
    case fileDeny = "file_deny"
    case fileChunk = "file_chunk"
    case fileComplete = "file_complete"

    // AC App Integration
    case acRegister = "ac_register"
    case acHeartbeat = "ac_heartbeat"
    case acStatusQuery = "ac_status_query"
    case acStatusResponse = "ac_status_response"
    case acShutdown = "ac_shutdown"
    case acCoordinate = "ac_coordinate"
}

// MARK: - Agent Identity

/// Cryptographic identity of an agent
@available(macOS 12.0, iOS 15.0, iPadOS 15.0, *)
public struct NLITPv8AgentIdentity: Sendable {
    public let agentID: String
    public let sessionID: String

    // Signing keypair (Ed25519)
    public let signingKey: Curve25519.Signing.PrivateKey
    public var signingPublicKey: Curve25519.Signing.PublicKey {
        signingKey.publicKey
    }

    // Key exchange keypair (X25519)
    public let exchangeKey: Curve25519.KeyAgreement.PrivateKey
    public var exchangePublicKey: Curve25519.KeyAgreement.PublicKey {
        exchangeKey.publicKey
    }

    // Network location
    public let tcpPort: UInt16
    public let udpPort: UInt16

    // Metadata
    public let capabilities: [String]
    public let wisdomEnabled: Bool

    public init(
        agentID: String,
        sessionID: String,
        tcpPort: UInt16,
        udpPort: UInt16,
        capabilities: [String] = [],
        wisdomEnabled: Bool = true
    ) {
        self.agentID = agentID
        self.sessionID = sessionID
        self.signingKey = Curve25519.Signing.PrivateKey()
        self.exchangeKey = Curve25519.KeyAgreement.PrivateKey()
        self.tcpPort = tcpPort
        self.udpPort = udpPort
        self.capabilities = capabilities
        self.wisdomEnabled = wisdomEnabled
    }

    /// Export public identity for broadcast
    public func publicIdentity() -> [String: Any] {
        return [
            "agent_id": agentID,
            "session_id": sessionID,
            "signing_pubkey": signingPublicKey.rawRepresentation.base64EncodedString(),
            "exchange_pubkey": exchangePublicKey.rawRepresentation.base64EncodedString(),
            "tcp_port": tcpPort,
            "udp_port": udpPort,
            "capabilities": capabilities,
            "wisdom_enabled": wisdomEnabled
        ]
    }
}

// MARK: - Peer Info

/// Information about a discovered peer agent
@available(macOS 12.0, iOS 15.0, iPadOS 15.0, *)
public struct NLITPv8PeerInfo: Sendable {
    public let agentID: String
    public let sessionID: String

    // Public keys
    public let signingPublicKey: Data
    public let exchangePublicKey: Data

    // Network location
    public let tcpPort: UInt16
    public let udpPort: UInt16

    // Discovery metadata
    public let firstSeen: Date
    public var lastSeen: Date
    public let capabilities: [String]
    public let wisdomEnabled: Bool

    // Trust data (computed locally)
    public var trustScore: Double = 0.0
    public var wisdomObservations: [[String: Any]] = []

    public init(
        agentID: String,
        sessionID: String,
        signingPublicKey: Data,
        exchangePublicKey: Data,
        tcpPort: UInt16,
        udpPort: UInt16,
        capabilities: [String],
        wisdomEnabled: Bool
    ) {
        self.agentID = agentID
        self.sessionID = sessionID
        self.signingPublicKey = signingPublicKey
        self.exchangePublicKey = exchangePublicKey
        self.tcpPort = tcpPort
        self.udpPort = udpPort
        self.firstSeen = Date()
        self.lastSeen = Date()
        self.capabilities = capabilities
        self.wisdomEnabled = wisdomEnabled
    }
}

// MARK: - Trust Entry

/// Trust ledger entry for a peer
@available(macOS 12.0, iOS 15.0, iPadOS 15.0, *)
public struct NLITPv8TrustEntry: Sendable {
    public let peerAgentID: String
    public let peerSessionID: String

    // Observed wisdom
    public var wisdomObservations: [[String: Any]]

    // Computed trust
    public var baseWisdom: Double
    public var wisdomTrend: Double
    public var lastVerification: Date
    public var finalTrust: Double

    public init(
        peerAgentID: String,
        peerSessionID: String,
        wisdomObservations: [[String: Any]] = [],
        baseWisdom: Double = 0.0,
        wisdomTrend: Double = 0.0
    ) {
        self.peerAgentID = peerAgentID
        self.peerSessionID = peerSessionID
        self.wisdomObservations = wisdomObservations
        self.baseWisdom = baseWisdom
        self.wisdomTrend = wisdomTrend
        self.lastVerification = Date()
        self.finalTrust = 0.0
    }

    /// Calculate trust score with decay
    public mutating func calculateTrust() -> Double {
        let decayFactor = max(0.0, 1.0 - (Date().timeIntervalSince(lastVerification) / NLITPv8Config.trustDecayPeriod))

        let baseComponent = baseWisdom * NLITPv8Config.trustBaseWeight
        let trendComponent = wisdomTrend * NLITPv8Config.trustTrendWeight
        let verificationComponent = decayFactor * NLITPv8Config.trustVerificationWeight

        finalTrust = baseComponent + trendComponent + verificationComponent
        return finalTrust
    }
}

// MARK: - Decentralized Message

/// Decentralized mesh message
@available(macOS 12.0, iOS 15.0, iPadOS 15.0, *)
public struct NLITPv8Message: Sendable, Codable {
    public let messageType: String
    public let sourceAgentID: String
    public let sourceSessionID: String
    public let destinationAgentID: String?
    public let timestamp: TimeInterval
    public let payload: [String: String] // Simplified for Codable compliance
    public var signature: String?

    public init(
        messageType: NLITPv8MessageType,
        sourceAgentID: String,
        sourceSessionID: String,
        destinationAgentID: String? = nil,
        payload: [String: String] = [:]
    ) {
        self.messageType = messageType.rawValue
        self.sourceAgentID = sourceAgentID
        self.sourceSessionID = sourceSessionID
        self.destinationAgentID = destinationAgentID
        self.timestamp = Date().timeIntervalSince1970
        self.payload = payload
        self.signature = nil
    }
}

// MARK: - Agent Node

/// Decentralized mesh agent node
@available(macOS 12.0, iOS 15.0, iPadOS 15.0, *)
public actor NLITPv8AgentNode {

    // MARK: - Properties

    private let identity: NLITPv8AgentIdentity
    private var peers: [String: NLITPv8PeerInfo] = [:]
    private var trustLedger: [String: NLITPv8TrustEntry] = [:]
    private var running: Bool = false

    #if canImport(Network)
    // Network listeners (macOS/iOS only)
    private var tcpListener: NWListener?
    private var udpListener: NWListener?
    private var discoveryConnection: NWConnection?
    private var discoveryTask: Task<Void, Never>?
    private var tcpConnections: [String: NWConnection] = [:]
    #endif

    // Message handlers
    public var onMessageReceived: (@Sendable (NLITPv8Message) async -> Void)?
    public var onPeerDiscovered: (@Sendable (NLITPv8PeerInfo) async -> Void)?
    public var onPeerLost: (@Sendable (String) async -> Void)?

    // MARK: - Initialization

    public init(identity: NLITPv8AgentIdentity) {
        self.identity = identity
    }

    public convenience init(
        agentID: String,
        sessionID: String,
        tcpPort: UInt16,
        udpPort: UInt16,
        capabilities: [String] = [],
        wisdomEnabled: Bool = true
    ) {
        let identity = NLITPv8AgentIdentity(
            agentID: agentID,
            sessionID: sessionID,
            tcpPort: tcpPort,
            udpPort: udpPort,
            capabilities: capabilities,
            wisdomEnabled: wisdomEnabled
        )
        self.init(identity: identity)
    }

    // MARK: - Public Methods

    /// Start mesh networking
    public func start() async throws {
        running = true
        print("NLITPv8: Agent \(identity.agentID) starting mesh networking")
        print("  TCP: \(identity.tcpPort)")
        print("  UDP: \(identity.udpPort)")
        print("  Discovery: \(NLITPv8Config.discoveryPort)")

        #if canImport(Network)
        // Start TCP listener for direct messages
        try await startTCPListener()

        // Start UDP listener for broadcasts
        try await startUDPListener()

        // Start discovery broadcaster
        await startDiscoveryBroadcaster()

        // Broadcast initial presence
        await broadcastPresence()

        print("NLITPv8: Agent \(identity.agentID) fully operational")
        #else
        print("NLITPv8: Network framework not available on this platform")
        await broadcastPresence()
        #endif
    }

    /// Stop mesh networking
    public func stop() async {
        running = false
        await broadcastGoodbye()

        #if canImport(Network)
        // Cancel discovery task
        discoveryTask?.cancel()
        discoveryTask = nil

        // Close all TCP connections
        for (_, connection) in tcpConnections {
            connection.cancel()
        }
        tcpConnections.removeAll()

        // Stop listeners
        tcpListener?.cancel()
        tcpListener = nil

        udpListener?.cancel()
        udpListener = nil

        discoveryConnection?.cancel()
        discoveryConnection = nil
        #endif

        print("NLITPv8: Agent \(identity.agentID) stopped")
    }

    /// Broadcast presence to network
    private func broadcastPresence() async {
        print("NLITPv8: Broadcasting presence for \(identity.agentID)")

        #if canImport(Network)
        do {
            // Create AGENT_ANNOUNCE message
            let publicIdentity = identity.publicIdentity()
            var payload: [String: String] = [:]

            // Convert all values to strings for Codable compliance
            for (key, value) in publicIdentity {
                if let stringValue = value as? String {
                    payload[key] = stringValue
                } else if let intValue = value as? Int {
                    payload[key] = String(intValue)
                } else if let uintValue = value as? UInt16 {
                    payload[key] = String(uintValue)
                } else if let boolValue = value as? Bool {
                    payload[key] = String(boolValue)
                } else if let arrayValue = value as? [String] {
                    payload[key] = arrayValue.joined(separator: ",")
                }
            }

            var message = NLITPv8Message(
                messageType: .agentAnnounce,
                sourceAgentID: identity.agentID,
                sourceSessionID: identity.sessionID,
                destinationAgentID: nil,
                payload: payload
            )

            // Sign message
            let messageData = try JSONEncoder().encode(message)
            let signature = try identity.signingKey.signature(for: messageData)
            message.signature = signature.base64EncodedString()

            // Broadcast via UDP to discovery port
            try await sendUDPBroadcast(message)

        } catch {
            print("NLITPv8: Failed to broadcast presence: \(error.localizedDescription)")
        }
        #endif
    }

    /// Broadcast goodbye to network
    private func broadcastGoodbye() async {
        print("NLITPv8: Broadcasting goodbye for \(identity.agentID)")

        #if canImport(Network)
        do {
            var message = NLITPv8Message(
                messageType: .agentGoodbye,
                sourceAgentID: identity.agentID,
                sourceSessionID: identity.sessionID,
                destinationAgentID: nil,
                payload: [:]
            )

            // Sign message
            let messageData = try JSONEncoder().encode(message)
            let signature = try identity.signingKey.signature(for: messageData)
            message.signature = signature.base64EncodedString()

            // Broadcast via UDP
            try await sendUDPBroadcast(message)

        } catch {
            print("NLITPv8: Failed to broadcast goodbye: \(error.localizedDescription)")
        }
        #endif
    }

    /// Send direct message to peer
    public func sendMessage(
        to destinationAgentID: String,
        payload: [String: String],
        messageType: NLITPv8MessageType = .direct
    ) async throws {
        guard let peer = peers[destinationAgentID] else {
            throw NLITPv8Error.peerNotFound(destinationAgentID)
        }

        var message = NLITPv8Message(
            messageType: messageType,
            sourceAgentID: identity.agentID,
            sourceSessionID: identity.sessionID,
            destinationAgentID: destinationAgentID,
            payload: payload
        )

        // Sign message
        let messageData = try JSONEncoder().encode(message)
        let signature = try identity.signingKey.signature(for: messageData)
        message.signature = signature.base64EncodedString()

        #if canImport(Network)
        // Establish TCP connection to peer
        try await sendTCPMessage(message, to: peer)
        print("NLITPv8: Sent message to \(destinationAgentID)")
        #else
        print("NLITPv8: Network framework not available - message not sent")
        throw NLITPv8Error.networkError("Network framework not available")
        #endif
    }

    /// Add discovered peer
    public func addPeer(_ peerInfo: NLITPv8PeerInfo) {
        peers[peerInfo.agentID] = peerInfo

        // Initialize trust ledger entry
        if trustLedger[peerInfo.agentID] == nil {
            trustLedger[peerInfo.agentID] = NLITPv8TrustEntry(
                peerAgentID: peerInfo.agentID,
                peerSessionID: peerInfo.sessionID
            )
        }

        print("NLITPv8: Added peer \(peerInfo.agentID)")
    }

    /// Update peer trust score
    public func updateTrust(for agentID: String, wisdomObservation: Double) {
        guard var trustEntry = trustLedger[agentID] else { return }

        let observation: [String: Any] = [
            "timestamp": Date().timeIntervalSince1970,
            "wisdom": wisdomObservation,
            "verified": true
        ]

        trustEntry.wisdomObservations.append(observation)
        trustEntry.lastVerification = Date()

        // Recalculate trust
        let _ = trustEntry.calculateTrust()

        trustLedger[agentID] = trustEntry

        print("NLITPv8: Updated trust for \(agentID): \(trustEntry.finalTrust)")
    }

    /// Get list of known peers
    public func getPeers() -> [NLITPv8PeerInfo] {
        return Array(peers.values)
    }

    /// Get trust score for peer
    public func getTrust(for agentID: String) -> Double? {
        return trustLedger[agentID]?.finalTrust
    }

    // MARK: - Network Implementation (macOS/iOS)

    #if canImport(Network)

    /// Start TCP listener for direct messages
    private func startTCPListener() async throws {
        guard let port = NWEndpoint.Port(rawValue: identity.tcpPort) else {
            throw NLITPv8Error.networkError("TCP port \(identity.tcpPort) is invalid")
        }
        let listener = try NWListener(using: .tcp, on: port)

        listener.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                print("NLITPv8: TCP listener ready on port \(self?.identity.tcpPort ?? 0)")
            case .failed(let error):
                print("NLITPv8: TCP listener failed: \(error.localizedDescription)")
            case .cancelled:
                print("NLITPv8: TCP listener cancelled")
            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self] connection in
            Task {
                await self?.handleTCPConnection(connection)
            }
        }

        listener.start(queue: .global(qos: .userInitiated))
        self.tcpListener = listener
    }

    /// Handle incoming TCP connection
    private func handleTCPConnection(_ connection: NWConnection) async {
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                print("NLITPv8: TCP connection established")
            case .failed(let error):
                print("NLITPv8: TCP connection failed: \(error.localizedDescription)")
            case .cancelled:
                print("NLITPv8: TCP connection cancelled")
            default:
                break
            }
        }

        connection.start(queue: .global(qos: .userInitiated))

        // Receive message length (4 bytes)
        connection.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] data, _, isComplete, error in
            guard let self = self, let data = data, error == nil else {
                connection.cancel()
                return
            }

            // Parse message length
            let length = data.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

            // Receive full message
            connection.receive(minimumIncompleteLength: Int(length), maximumLength: Int(length)) { messageData, _, isComplete, error in
                guard let messageData = messageData, error == nil else {
                    connection.cancel()
                    return
                }

                Task {
                    await self.processReceivedMessage(messageData)
                    connection.cancel() // Close after processing
                }
            }
        }
    }

    /// Start UDP listener for broadcasts
    private func startUDPListener() async throws {
        guard let port = NWEndpoint.Port(rawValue: identity.udpPort) else {
            throw NLITPv8Error.networkError("UDP port \(identity.udpPort) is invalid")
        }
        let listener = try NWListener(using: .udp, on: port)

        listener.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                print("NLITPv8: UDP listener ready on port \(self?.identity.udpPort ?? 0)")
            case .failed(let error):
                print("NLITPv8: UDP listener failed: \(error.localizedDescription)")
            case .cancelled:
                print("NLITPv8: UDP listener cancelled")
            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self] connection in
            Task {
                await self?.handleUDPConnection(connection)
            }
        }

        listener.start(queue: .global(qos: .userInitiated))
        self.udpListener = listener
    }

    /// Handle incoming UDP connection
    private func handleUDPConnection(_ connection: NWConnection) async {
        connection.stateUpdateHandler = { state in
            if case .failed(let error) = state {
                print("NLITPv8: UDP connection failed: \(error.localizedDescription)")
            }
        }

        connection.start(queue: .global(qos: .userInitiated))

        // Receive UDP message
        connection.receiveMessage { [weak self] data, _, isComplete, error in
            guard let self = self, let data = data, error == nil else {
                connection.cancel()
                return
            }

            Task {
                await self.processReceivedMessage(data)
            }
        }
    }

    /// Start discovery broadcaster
    private func startDiscoveryBroadcaster() async {
        discoveryTask = Task { [weak self] in
            guard let self = self else { return }

            while await self.isRunning() {
                await self.broadcastPresence()

                // Wait for discovery interval
                try? await Task.sleep(nanoseconds: UInt64(NLITPv8Config.discoveryInterval * 1_000_000_000))
            }
        }
    }

    /// Check if node is running
    private func isRunning() -> Bool {
        return running
    }

    /// Send UDP broadcast
    private func sendUDPBroadcast(_ message: NLITPv8Message) async throws {
        let host = NWEndpoint.Host("255.255.255.255") // Broadcast address
        guard let port = NWEndpoint.Port(rawValue: NLITPv8Config.discoveryPort) else {
            throw NLITPv8Error.networkError("Discovery port \(NLITPv8Config.discoveryPort) is invalid")
        }

        let connection = NWConnection(
            host: host,
            port: port,
            using: .udp
        )

        connection.stateUpdateHandler = { state in
            if case .failed(let error) = state {
                print("NLITPv8: UDP broadcast connection failed: \(error.localizedDescription)")
            }
        }

        connection.start(queue: .global(qos: .userInitiated))

        // Wait for connection to be ready
        try await Task.sleep(nanoseconds: 100_000_000) // 100ms

        // Encode and send message
        let encoder = JSONEncoder()
        let messageData = try encoder.encode(message)

        connection.send(content: messageData, completion: .contentProcessed { error in
            if let error = error {
                print("NLITPv8: UDP broadcast send failed: \(error.localizedDescription)")
            }
            connection.cancel()
        })
    }

    /// Send TCP message to peer
    private func sendTCPMessage(_ message: NLITPv8Message, to peer: NLITPv8PeerInfo) async throws {
        let host = NWEndpoint.Host("127.0.0.1") // Localhost for now
        guard let port = NWEndpoint.Port(rawValue: peer.tcpPort) else {
            throw NLITPv8Error.networkError("Peer TCP port \(peer.tcpPort) is invalid")
        }

        let connection = NWConnection(
            host: host,
            port: port,
            using: .tcp
        )

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                print("NLITPv8: TCP connection to \(peer.agentID) ready")
            case .failed(let error):
                print("NLITPv8: TCP connection to \(peer.agentID) failed: \(error.localizedDescription)")
            default:
                break
            }
        }

        connection.start(queue: .global(qos: .userInitiated))

        // Wait for connection to be ready
        try await Task.sleep(nanoseconds: 500_000_000) // 500ms

        // Encode message
        let encoder = JSONEncoder()
        let messageData = try encoder.encode(message)

        // Send message length first (4 bytes, big-endian)
        let length = UInt32(messageData.count).bigEndian
        let lengthData = withUnsafeBytes(of: length) { Data($0) }

        connection.send(content: lengthData, completion: .contentProcessed { error in
            if let error = error {
                print("NLITPv8: Failed to send message length: \(error.localizedDescription)")
            }
        })

        // Send actual message
        connection.send(content: messageData, completion: .contentProcessed { error in
            if let error = error {
                print("NLITPv8: Failed to send message: \(error.localizedDescription)")
            }
            connection.cancel()
        })
    }

    /// Process received message
    private func processReceivedMessage(_ data: Data) async {
        do {
            let decoder = JSONDecoder()
            let message = try decoder.decode(NLITPv8Message.self, from: data)

            // Verify signature if present
            if let signature = message.signature {
                guard let peer = peers[message.sourceAgentID],
                      let signatureData = Data(base64Encoded: signature) else {
                    print("NLITPv8: Message signature verification failed - unknown peer")
                    return
                }

                // Reconstruct message without signature for verification
                var messageToVerify = message
                messageToVerify.signature = nil
                let messageData = try JSONEncoder().encode(messageToVerify)

                let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: peer.signingPublicKey)
                let isValid = publicKey.isValidSignature(signatureData, for: messageData)

                guard isValid else {
                    print("NLITPv8: Message signature verification failed - invalid signature")
                    return
                }
            }

            // Process message based on type
            switch NLITPv8MessageType(rawValue: message.messageType) {
            case .agentAnnounce:
                await handleAgentAnnounce(message)

            case .agentGoodbye:
                await handleAgentGoodbye(message)

            case .direct, .request, .response:
                // Call user-provided handler
                if let handler = onMessageReceived {
                    await handler(message)
                }

            default:
                print("NLITPv8: Received message type: \(message.messageType)")
            }

        } catch {
            print("NLITPv8: Failed to process message: \(error.localizedDescription)")
        }
    }

    /// Handle agent announce message
    private func handleAgentAnnounce(_ message: NLITPv8Message) async {
        // Parse peer info from payload
        guard let agentID = message.payload["agent_id"],
              let sessionID = message.payload["session_id"],
              let signingPubkeyBase64 = message.payload["signing_pubkey"],
              let exchangePubkeyBase64 = message.payload["exchange_pubkey"],
              let tcpPortString = message.payload["tcp_port"],
              let udpPortString = message.payload["udp_port"],
              let tcpPort = UInt16(tcpPortString),
              let udpPort = UInt16(udpPortString),
              let signingPubkey = Data(base64Encoded: signingPubkeyBase64),
              let exchangePubkey = Data(base64Encoded: exchangePubkeyBase64) else {
            print("NLITPv8: Invalid agent announce payload")
            return
        }

        let capabilities = message.payload["capabilities"]?.split(separator: ",").map(String.init) ?? []
        let wisdomEnabled = message.payload["wisdom_enabled"] == "true"

        // Don't add ourselves
        guard agentID != identity.agentID else { return }

        // Create or update peer info
        let peerInfo = NLITPv8PeerInfo(
            agentID: agentID,
            sessionID: sessionID,
            signingPublicKey: signingPubkey,
            exchangePublicKey: exchangePubkey,
            tcpPort: tcpPort,
            udpPort: udpPort,
            capabilities: capabilities,
            wisdomEnabled: wisdomEnabled
        )

        addPeer(peerInfo)

        // Notify handler
        if let handler = onPeerDiscovered {
            await handler(peerInfo)
        }

        print("NLITPv8: Discovered peer: \(agentID)")
    }

    /// Handle agent goodbye message
    private func handleAgentGoodbye(_ message: NLITPv8Message) async {
        let agentID = message.sourceAgentID

        // Remove peer
        peers.removeValue(forKey: agentID)

        // Notify handler
        if let handler = onPeerLost {
            await handler(agentID)
        }

        print("NLITPv8: Peer left: \(agentID)")
    }

    #endif
}

// MARK: - Errors

public enum NLITPv8Error: Error, LocalizedError {
    case peerNotFound(String)
    case messagingFailed(String)
    case cryptographyFailed(String)
    case networkError(String)

    public var errorDescription: String? {
        switch self {
        case .peerNotFound(let agentID):
            return "Peer not found: \(agentID)"
        case .messagingFailed(let reason):
            return "Messaging failed: \(reason)"
        case .cryptographyFailed(let reason):
            return "Cryptography failed: \(reason)"
        case .networkError(let reason):
            return "Network error: \(reason)"
        }
    }
}
