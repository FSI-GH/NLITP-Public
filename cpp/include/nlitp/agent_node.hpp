/**
 * @file agent_node.hpp
 * @brief Main SCU agent orchestrator - integrates all NLITP components
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * AgentNode coordinates all subsystems:
 * - Agent identity and cryptography
 * - Peer discovery and announcement
 * - Encrypted messaging and file transfer
 * - Trust ledger and blockchain
 * - Security (rate limiting, replay protection)
 * - Port allocation and network management
 */

#pragma once

#include "nlitp/agent_identity.hpp"
#include "nlitp/agent_discovery.hpp"
#include "nlitp/decentralized_messenger.hpp"
#include "nlitp/trust_ledger.hpp"
#include "nlitp/rate_limiter.hpp"
#include "nlitp/replay_protection.hpp"
#include "nlitp/port_allocator.hpp"
#include "nlitp/security_config.hpp"
#include "nlitp/utilities.hpp"

#include <asio.hpp>
#include <string>
#include <memory>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <map>

namespace nlitp {

/**
 * @brief Peer connection information
 */
struct PeerConnection {
    std::string agent_id;               ///< Peer agent ID
    std::string host;                   ///< Peer IP address
    uint16_t port;                      ///< Peer port
    double trust_score;                 ///< Current trust score
    bool has_active_session;            ///< Whether encrypted session exists
    uint64_t last_seen;                 ///< Last contact timestamp
};

/**
 * @brief AgentNode statistics
 */
struct AgentNodeStats {
    size_t active_peers;                ///< Number of discovered peers
    size_t active_sessions;             ///< Number of encrypted sessions
    size_t active_transfers;            ///< Number of ongoing file transfers
    size_t messages_sent;               ///< Total messages sent
    size_t messages_received;           ///< Total messages received
    size_t bytes_sent;                  ///< Total bytes sent
    size_t bytes_received;              ///< Total bytes received
    uint64_t uptime_seconds;            ///< Node uptime in seconds
};

/**
 * @brief AgentNode - Main SCU agent orchestrator
 *
 * Production-grade agent node that integrates all NLITP subsystems:
 * - Identity management (Ed25519 + X25519 keys)
 * - Peer discovery (UDP multicast)
 * - Encrypted messaging (ChaCha20-Poly1305)
 * - File transfer (chunked with verification)
 * - Trust management (blockchain-based)
 * - Security (rate limiting, replay protection)
 * - Async I/O with ASIO
 *
 */
class AgentNode {
public:
    /**
     * @brief Construct agent node with configuration
     * @param agent_id Unique agent identifier
     * @param data_dir Data directory for keys, database, files
     * @param discovery_port Discovery port (default: 10001)
     * @param auto_accept_sessions Auto-accept session requests (default: false)
     */
    explicit AgentNode(
        const std::string& agent_id,
        const std::string& data_dir = "",
        uint16_t discovery_port = security::DISCOVERY_PORT,
        bool auto_accept_sessions = false
    );

    /**
     * @brief Destructor - graceful shutdown
     */
    ~AgentNode();

    // Disable copy and move
    AgentNode(const AgentNode&) = delete;
    AgentNode& operator=(const AgentNode&) = delete;
    AgentNode(AgentNode&&) = delete;
    AgentNode& operator=(AgentNode&&) = delete;

    // ========================================================================
    // Lifecycle Management
    // ========================================================================

    /**
     * @brief Start agent node and all subsystems
     * @return true if started successfully, false otherwise
     */
    bool start();

    /**
     * @brief Stop agent node and gracefully shutdown
     */
    void stop();

    /**
     * @brief Run main event loop (blocking until stopped)
     */
    void run();

    /**
     * @brief Check if node is running
     * @return true if running, false otherwise
     */
    bool is_running() const;

    /**
     * @brief Get agent ID
     * @return Agent identifier
     */
    std::string get_agent_id() const;

    /**
     * @brief Get listening port
     * @return Port number
     */
    uint16_t get_port() const;

    // ========================================================================
    // Peer Discovery and Management
    // ========================================================================

    /**
     * @brief Get list of discovered peers
     * @return Vector of peer connections
     */
    std::vector<PeerConnection> get_peers() const;

    /**
     * @brief Get specific peer by ID
     * @param peer_id Peer agent ID
     * @return Peer connection info or nullptr if not found
     */
    std::shared_ptr<PeerConnection> get_peer(const std::string& peer_id) const;

    /**
     * @brief Manually announce presence to network
     * @return true if announced successfully, false otherwise
     */
    bool announce();

    // ========================================================================
    // Messaging
    // ========================================================================

    /**
     * @brief Send text message to peer
     * @param peer_id Peer agent ID
     * @param content Message content
     * @return true if sent successfully, false otherwise
     */
    bool send_message(const std::string& peer_id, const std::string& content);

    /**
     * @brief Send file to peer
     * @param peer_id Peer agent ID
     * @param file_path Path to file to send
     * @return true if transfer initiated successfully, false otherwise
     */
    bool send_file(const std::string& peer_id, const std::string& file_path);

    /**
     * @brief Set callback for received messages
     * @param callback Function to call when message is received
     */
    void on_message_received(std::function<void(const std::string& peer_id, const std::string& content)> callback);

    /**
     * @brief Set callback for received files
     * @param callback Function to call when file is received
     */
    void on_file_received(std::function<void(const std::string& peer_id, const std::string& file_path, const std::string& filename)> callback);

    // ========================================================================
    // Trust Management
    // ========================================================================

    /**
     * @brief Record trust observation about peer
     * @param peer_id Peer agent ID
     * @param trust_score Trust score (0.0-1.0)
     * @param verified Whether observation is verified
     * @param observation Human-readable reason
     * @return true if recorded successfully, false otherwise
     */
    bool record_trust_observation(
        const std::string& peer_id,
        double trust_score,
        bool verified,
        const std::string& observation
    );

    /**
     * @brief Get trust score for peer
     * @param peer_id Peer agent ID
     * @return Trust score (0.0-1.0), or 0.5 if unknown
     */
    double get_trust_score(const std::string& peer_id) const;

    /**
     * @brief Get peer statistics from trust ledger
     * @param peer_id Peer agent ID
     * @return Peer statistics or std::nullopt if not found
     */
    std::optional<PeerStats> get_peer_trust_stats(const std::string& peer_id) const;

    // ========================================================================
    // Session Management
    // ========================================================================

    /**
     * @brief Request encrypted session with peer
     * @param peer_id Peer agent ID
     * @return true if request sent successfully, false otherwise
     */
    bool request_session(const std::string& peer_id);

    /**
     * @brief Close session with peer
     * @param peer_id Peer agent ID
     * @return true if closed successfully, false otherwise
     */
    bool close_session(const std::string& peer_id);

    /**
     * @brief Get active session count
     * @return Number of active encrypted sessions
     */
    size_t get_active_session_count() const;

    // ========================================================================
    // Statistics and Monitoring
    // ========================================================================

    /**
     * @brief Get node statistics
     * @return Current statistics
     */
    AgentNodeStats get_stats() const;

    /**
     * @brief Get uptime in seconds
     * @return Node uptime
     */
    uint64_t get_uptime() const;

    /**
     * @brief Print status to console
     */
    void print_status() const;

private:
    // ========================================================================
    // Member Variables
    // ========================================================================

    /// Agent ID
    std::string agent_id_;

    /// Data directory
    std::filesystem::path data_dir_;

    /// Discovery port
    uint16_t discovery_port_;

    /// Auto-accept session requests
    bool auto_accept_sessions_;

    /// Running flag
    std::atomic<bool> running_;

    /// Start time
    std::chrono::steady_clock::time_point start_time_;

    /// Statistics
    mutable std::mutex stats_mutex_;
    size_t messages_sent_;
    size_t messages_received_;
    size_t bytes_sent_;
    size_t bytes_received_;

    /// ASIO I/O context
    asio::io_context io_context_;

    /// ASIO work guard (keeps io_context running)
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> work_guard_;

    /// Worker threads
    std::vector<std::thread> worker_threads_;

    /// Agent identity
    std::shared_ptr<AgentIdentity> identity_;

    /// Port allocator
    std::unique_ptr<PortAllocator> port_allocator_;

    /// Allocated port
    uint16_t allocated_port_;

    /// Agent discovery
    std::unique_ptr<AgentDiscovery> discovery_;

    /// Decentralized messenger
    std::shared_ptr<DecentralizedMessenger> messenger_;

    /// Trust ledger
    std::unique_ptr<TrustLedger> trust_ledger_;

    /// Rate limiter
    std::unique_ptr<RateLimiter> rate_limiter_;

    /// Replay protection
    std::unique_ptr<MessageReplayProtection> replay_protection_;

    /// Peer connections map (peer_id -> connection info)
    mutable std::mutex peers_mutex_;
    std::map<std::string, std::shared_ptr<PeerConnection>> peers_;

    /// Message received callback
    std::function<void(const std::string&, const std::string&)> message_callback_;

    /// File received callback
    std::function<void(const std::string&, const std::string&, const std::string&)> file_callback_;

    /// Callback mutex
    mutable std::mutex callback_mutex_;

    // ========================================================================
    // Private Methods - Initialization
    // ========================================================================

    /**
     * @brief Initialize data directory structure
     * @return true if successful, false otherwise
     */
    bool initialize_data_directory();

    /**
     * @brief Load or create agent identity
     * @return true if successful, false otherwise
     */
    bool initialize_identity();

    /**
     * @brief Initialize all subsystems
     * @return true if successful, false otherwise
     */
    bool initialize_subsystems();

    // ========================================================================
    // Private Methods - Event Handlers
    // ========================================================================

    /**
     * @brief Handle peer discovered event
     * @param peer Discovered peer
     */
    void handle_peer_discovered(const PeerInfo& peer);

    /**
     * @brief Handle message received event
     * @param message Received message
     */
    void handle_message_received(const Message& message);

    /**
     * @brief Handle session request event
     * @param session_id Session ID
     * @param peer_id Peer agent ID
     * @param success Whether successful
     */
    void handle_session_event(const std::string& session_id, const std::string& peer_id, bool success);

    /**
     * @brief Handle file transfer progress
     * @param file_id File ID
     * @param bytes_transferred Bytes transferred
     * @param total_bytes Total bytes
     */
    void handle_file_progress(const std::string& file_id, uint64_t bytes_transferred, uint64_t total_bytes);

    // ========================================================================
    // Private Methods - Utilities
    // ========================================================================

    /**
     * @brief Update peer connection info
     * @param peer Discovered peer
     */
    void update_peer_connection(const PeerInfo& peer);

    /**
     * @brief Cleanup stale peer connections
     * @return Number of peers removed
     */
    size_t cleanup_stale_peers();

    /**
     * @brief Validate peer is trusted
     * @param peer_id Peer agent ID
     * @return true if trusted, false otherwise
     */
    bool is_peer_trusted(const std::string& peer_id) const;

    /**
     * @brief Get database path
     * @return Path to trust ledger database
     */
    std::string get_database_path() const;

    /**
     * @brief Get received files directory
     * @return Path to received files directory
     */
    std::string get_received_files_dir() const;
};

} // namespace nlitp
