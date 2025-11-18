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
import Logging
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
    public var payload: [String: String] // Mutable for decryption - Simplified for Codable compliance
    public var signature: String?
    public var encrypted: Bool = false

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
        self.encrypted = false
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
    private let logger: Logger

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
        self.logger = Logger(label: "com.fsi.nlitp.v8.\(identity.agentID)")
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
        logger.info("Agent starting mesh networking", metadata: [
            "agentID": .string(identity.agentID),
            "tcpPort": .stringConvertible(identity.tcpPort),
            "udpPort": .stringConvertible(identity.udpPort),
            "discoveryPort": .stringConvertible(NLITPv8Config.discoveryPort)
        ])

        #if canImport(Network)
        // Start TCP listener for direct messages
        try await startTCPListener()

        // Start UDP listener for broadcasts
        try await startUDPListener()

        // Start discovery broadcaster
        await startDiscoveryBroadcaster()

        // Broadcast initial presence
        await broadcastPresence()

        logger.info("Agent fully operational", metadata: ["agentID": .string(identity.agentID)])
        #else
        logger.warning("Network framework not available on this platform")
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

        logger.info("Agent stopped", metadata: ["agentID": .string(identity.agentID)])
    }

    /// Broadcast presence to network
    private func broadcastPresence() async {
        logger.debug("Broadcasting presence", metadata: ["agentID": .string(identity.agentID)])

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
            logger.error("Failed to broadcast presence", metadata: ["error": .string(error.localizedDescription)])
        }
        #endif
    }

    /// Broadcast goodbye to network
    private func broadcastGoodbye() async {
        logger.debug("Broadcasting goodbye", metadata: ["agentID": .string(identity.agentID)])

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
            logger.error("Failed to broadcast goodbye", metadata: ["error": .string(error.localizedDescription)])
        }
        #endif
    }

    // MARK: - Encryption Methods

    /// Derive shared secret using X25519 key exchange
    private func deriveSharedSecret(
        peerExchangePublicKey: Data
    ) throws -> SymmetricKey {
        let peerPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerExchangePublicKey)
        let sharedSecret = try identity.exchangeKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        return sharedSecret.withUnsafeBytes { bytes in
            SymmetricKey(data: bytes)
        }
    }

    /// Encrypt payload using ChaCha20-Poly1305
    private func encryptPayload(
        _ payload: [String: String],
        withSharedSecret sharedSecret: SymmetricKey
    ) throws -> [String: String] {
        let payloadData = try JSONEncoder().encode(payload)
        let nonce = ChaChaPoly.Nonce()
        let sealedBox = try ChaChaPoly.seal(payloadData, using: sharedSecret, nonce: nonce)

        // Combine nonce + ciphertext + tag for transmission
        var encryptedData = Data(nonce.withUnsafeBytes { Data($0) })
        encryptedData.append(sealedBox.ciphertext)
        encryptedData.append(sealedBox.tag)

        return [
            "encrypted_data": encryptedData.base64EncodedString()
        ]
    }

    /// Decrypt payload using ChaCha20-Poly1305
    private func decryptPayload(
        _ encryptedPayload: [String: String],
        withSharedSecret sharedSecret: SymmetricKey
    ) throws -> [String: String] {
        guard let encryptedDataBase64 = encryptedPayload["encrypted_data"],
              let encryptedData = Data(base64Encoded: encryptedDataBase64) else {
            throw NLITPv8Error.cryptographyFailed("Invalid encrypted payload format")
        }

        // Extract components (nonce: 12 bytes, tag: 16 bytes, rest is ciphertext)
        guard encryptedData.count > 28 else {
            throw NLITPv8Error.cryptographyFailed("Encrypted data too short")
        }

        let nonceBytes = encryptedData.subdata(in: 0..<12)
        let ciphertextStart = 12
        let ciphertextEnd = encryptedData.count - 16
        let ciphertext = encryptedData.subdata(in: ciphertextStart..<ciphertextEnd)
        let tag = encryptedData.subdata(in: ciphertextEnd..<encryptedData.count)

        let nonce = try ChaChaPoly.Nonce(data: nonceBytes)
        let sealedBox = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let decryptedData = try ChaChaPoly.open(sealedBox, using: sharedSecret)
        let payload = try JSONDecoder().decode([String: String].self, from: decryptedData)

        return payload
    }

    /// Send direct message to peer (UDP fast path with TCP fallback)
    public func sendMessage(
        to destinationAgentID: String,
        payload: [String: String],
        messageType: NLITPv8MessageType = .direct
    ) async throws {
        guard let peer = peers[destinationAgentID] else {
            throw NLITPv8Error.peerNotFound(destinationAgentID)
        }

        // Derive shared secret using X25519 key exchange
        let sharedSecret = try deriveSharedSecret(peerExchangePublicKey: peer.exchangePublicKey)

        // Encrypt payload BEFORE creating message
        let encryptedPayload = try encryptPayload(payload, withSharedSecret: sharedSecret)

        var message = NLITPv8Message(
            messageType: messageType,
            sourceAgentID: identity.agentID,
            sourceSessionID: identity.sessionID,
            destinationAgentID: destinationAgentID,
            payload: encryptedPayload
        )
        message.encrypted = true

        // Sign entire message (with encrypted payload)
        let messageData = try JSONEncoder().encode(message)
        let signature = try identity.signingKey.signature(for: messageData)
        message.signature = signature.base64EncodedString()

        #if canImport(Network)
        // Determine transport: UDP fast path (< 65KB) or TCP fallback
        let encoder = JSONEncoder()
        let encodedMessage = try encoder.encode(message)
        let messageSize = encodedMessage.count

        if messageSize < 65000 {
            // Try UDP fast path
            do {
                try await sendUDPMessage(message, to: peer)
                logger.debug("Sent encrypted message via UDP", metadata: [
                    "destinationAgentID": .string(destinationAgentID),
                    "messageSize": .stringConvertible(messageSize)
                ])
                return
            } catch {
                logger.debug("UDP send failed, falling back to TCP", metadata: ["error": .string(error.localizedDescription)])
                // Fall through to TCP fallback
            }
        } else {
            logger.debug("Message size exceeds 65KB, using TCP fallback", metadata: ["messageSize": .stringConvertible(messageSize)])
        }

        // TCP fallback for large messages or UDP failure
        try await sendTCPMessage(message, to: peer)
        logger.debug("Sent encrypted message via TCP fallback", metadata: [
            "destinationAgentID": .string(destinationAgentID),
            "messageSize": .stringConvertible(messageSize)
        ])
        #else
        logger.error("Network framework not available - message not sent")
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

        logger.info("Peer added", metadata: ["peerAgentID": .string(peerInfo.agentID)])
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

        logger.debug("Updated trust score", metadata: [
            "agentID": .string(agentID),
            "trustScore": .stringConvertible(String(format: "%.3f", trustEntry.finalTrust))
        ])
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
                self?.logger.info("TCP listener ready", metadata: ["port": .stringConvertible(self?.identity.tcpPort ?? 0)])
            case .failed(let error):
                self?.logger.error("TCP listener failed", metadata: ["error": .string(error.localizedDescription)])
            case .cancelled:
                self?.logger.info("TCP listener cancelled")
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
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.logger.info("TCP connection established")
            case .failed(let error):
                self?.logger.error("TCP connection failed", metadata: ["error": .string(error.localizedDescription)])
            case .cancelled:
                self?.logger.info("TCP connection cancelled")
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
                self?.logger.info("UDP listener ready", metadata: ["port": .stringConvertible(self?.identity.udpPort ?? 0)])
            case .failed(let error):
                self?.logger.error("UDP listener failed", metadata: ["error": .string(error.localizedDescription)])
            case .cancelled:
                self?.logger.info("UDP listener cancelled")
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
        connection.stateUpdateHandler = { [weak self] state in
            if case .failed(let error) = state {
                self?.logger.error("UDP connection failed", metadata: ["error": .string(error.localizedDescription)])
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

        connection.stateUpdateHandler = { [weak self] state in
            if case .failed(let error) = state {
                self?.logger.error("UDP broadcast connection failed", metadata: ["error": .string(error.localizedDescription)])
            }
        }

        connection.start(queue: .global(qos: .userInitiated))

        // Wait for connection to be ready
        try await Task.sleep(nanoseconds: 100_000_000) // 100ms

        // Encode and send message
        let encoder = JSONEncoder()
        let messageData = try encoder.encode(message)

        connection.send(content: messageData, completion: .contentProcessed { [weak self] error in
            if let error = error {
                self?.logger.error("UDP broadcast send failed", metadata: ["error": .string(error.localizedDescription)])
            }
            connection.cancel()
        })
    }

    /// Send UDP message to peer (fast path for messages < 65KB)
    private func sendUDPMessage(_ message: NLITPv8Message, to peer: NLITPv8PeerInfo) async throws {
        let host = NWEndpoint.Host("127.0.0.1") // Localhost for now
        guard let port = NWEndpoint.Port(rawValue: peer.udpPort) else {
            throw NLITPv8Error.networkError("Peer UDP port \(peer.udpPort) is invalid")
        }

        let connection = NWConnection(
            host: host,
            port: port,
            using: .udp
        )

        connection.stateUpdateHandler = { [weak self] state in
            if case .failed(let error) = state {
                self?.logger.error("UDP connection to peer failed", metadata: [
                    "peerID": .string(peer.agentID),
                    "error": .string(error.localizedDescription)
                ])
            }
        }

        connection.start(queue: .global(qos: .userInitiated))

        // Wait for connection to be ready
        try await Task.sleep(nanoseconds: 100_000_000) // 100ms

        // Encode and send message
        let encoder = JSONEncoder()
        let messageData = try encoder.encode(message)

        // Use sendMessage for UDP (no length prefix required)
        connection.send(content: messageData, completion: .contentProcessed { [weak self] error in
            if let error = error {
                self?.logger.error("UDP message send failed", metadata: ["error": .string(error.localizedDescription)])
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

        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.logger.info("TCP connection to peer ready", metadata: ["peerID": .string(peer.agentID)])
            case .failed(let error):
                self?.logger.error("TCP connection to peer failed", metadata: [
                    "peerID": .string(peer.agentID),
                    "error": .string(error.localizedDescription)
                ])
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

        connection.send(content: lengthData, completion: .contentProcessed { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to send message length", metadata: ["error": .string(error.localizedDescription)])
            }
        })

        // Send actual message
        connection.send(content: messageData, completion: .contentProcessed { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to send message", metadata: ["error": .string(error.localizedDescription)])
            }
            connection.cancel()
        })
    }

    /// Process received message
    private func processReceivedMessage(_ data: Data) async {
        do {
            let decoder = JSONDecoder()
            var message = try decoder.decode(NLITPv8Message.self, from: data)

            // Verify signature if present
            if let signature = message.signature {
                guard let peer = peers[message.sourceAgentID],
                      let signatureData = Data(base64Encoded: signature) else {
                    logger.warning("Message signature verification failed - unknown peer", metadata: ["sourceAgentID": .string(message.sourceAgentID)])
                    return
                }

                // Reconstruct message without signature for verification
                var messageToVerify = message
                messageToVerify.signature = nil
                let messageData = try JSONEncoder().encode(messageToVerify)

                let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: peer.signingPublicKey)
                let isValid = publicKey.isValidSignature(signatureData, for: messageData)

                guard isValid else {
                    logger.warning("Message signature verification failed - invalid signature", metadata: ["sourceAgentID": .string(message.sourceAgentID)])
                    return
                }
            }

            // Decrypt payload if message is encrypted
            if message.encrypted {
                guard let peer = peers[message.sourceAgentID] else {
                    logger.warning("Cannot decrypt message - unknown peer", metadata: ["sourceAgentID": .string(message.sourceAgentID)])
                    return
                }

                // Derive shared secret using peer's X25519 public key
                let sharedSecret = try deriveSharedSecret(peerExchangePublicKey: peer.exchangePublicKey)

                // Decrypt the payload
                let decryptedPayload = try decryptPayload(message.payload, withSharedSecret: sharedSecret)
                message.payload = decryptedPayload
                message.encrypted = false

                logger.debug("Message decrypted", metadata: ["sourceAgentID": .string(message.sourceAgentID)])
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
                logger.debug("Received message type", metadata: ["messageType": .string(message.messageType)])
            }

        } catch {
            logger.error("Failed to process message", metadata: ["error": .string(error.localizedDescription)])
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
            logger.warning("Invalid agent announce payload")
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

        logger.info("Peer discovered", metadata: ["peerID": .string(agentID)])
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

        logger.info("Peer left", metadata: ["peerID": .string(agentID)])
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
