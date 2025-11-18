/**
 * @file decentralized_messenger.hpp
 * @brief Decentralized P2P messaging with encryption for NLITP
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Provides encrypted P2P messaging with:
 * - UDP/TCP transport using ASIO
 * - Session management with X25519 key exchange
 * - ChaCha20-Poly1305 encrypted messaging
 * - Chunked file transfer
 * - Connection pooling and message queuing
 * - DoS protection via rate limiting
 * - Replay attack prevention
 * - Thread-safe async operations
 */

#pragma once

#include "nlitp/agent_crypto.hpp"
#include "nlitp/message_types.hpp"
#include "nlitp/rate_limiter.hpp"
#include "nlitp/replay_protection.hpp"
#include "nlitp/agent_identity.hpp"

#include <asio.hpp>
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <memory>
#include <functional>
#include <mutex>
#include <thread>
#include <optional>
#include <atomic>
#include <chrono>

namespace nlitp {

// ============================================================================
// Forward Declarations and Type Aliases
// ============================================================================

/**
 * @brief Callback for received messages
 * @param message Received message
 */
using MessageCallback = std::function<void(const Message&)>;

/**
 * @brief Callback for session events (request, accept, close)
 * @param session_id Session identifier
 * @param peer_id Peer agent ID
 * @param success Whether the operation succeeded
 */
using SessionCallback = std::function<void(
    const std::string& session_id,
    const std::string& peer_id,
    bool success
)>;

/**
 * @brief Callback for file transfer progress
 * @param file_id File identifier
 * @param bytes_transferred Bytes transferred so far
 * @param total_bytes Total file size
 */
using FileProgressCallback = std::function<void(
    const std::string& file_id,
    uint64_t bytes_transferred,
    uint64_t total_bytes
)>;

// ============================================================================
// Session Structures
// ============================================================================

/**
 * @brief Active session with encryption context
 */
struct Session {
    std::string session_id;                 ///< Unique session ID
    std::string peer_id;                    ///< Peer agent ID
    std::string peer_host;                  ///< Peer IP address
    uint16_t peer_port;                     ///< Peer port
    SharedSecret shared_secret;             ///< X25519 shared secret
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> peer_enc_key; ///< Peer's X25519 public key
    uint64_t established_time;              ///< Session establishment timestamp
    uint64_t last_activity;                 ///< Last message timestamp
    bool is_initiator;                      ///< Whether we initiated the session
};

/**
 * @brief Queued message for transmission
 */
struct QueuedMessage {
    Message message;                        ///< Message to send
    std::string destination_host;           ///< Destination IP address
    uint16_t destination_port;              ///< Destination port
    bool use_tcp;                           ///< Whether to use TCP (vs UDP)
    int retry_count;                        ///< Number of retry attempts
};

/**
 * @brief File transfer state
 */
struct FileTransfer {
    std::string file_id;                    ///< Unique file identifier
    std::string session_id;                 ///< Associated session
    std::string filename;                   ///< Original filename
    uint64_t file_size;                     ///< Total file size
    std::vector<uint8_t> file_hash;         ///< SHA-256 hash
    std::vector<std::vector<uint8_t>> chunks; ///< Received/pending chunks
    uint64_t bytes_transferred;             ///< Bytes received/sent
    uint64_t total_chunks;                  ///< Total number of chunks
    bool is_sender;                         ///< Whether we're sending
    std::chrono::steady_clock::time_point start_time; ///< Transfer start time
};

// ============================================================================
// DecentralizedMessenger Class
// ============================================================================

/**
 * @brief DecentralizedMessenger - P2P encrypted messaging system
 *
 * Production-grade P2P messaging with:
 * - UDP for discovery and lightweight messages
 * - TCP for reliable session data and file transfer
 * - X25519 ECDH for key exchange
 * - ChaCha20-Poly1305 AEAD for message encryption
 * - Session management with automatic cleanup
 * - Message queue with retry logic
 * - Connection pooling for efficiency
 * - Rate limiting and replay protection
 * - Thread-safe async operations
 *
 */
class DecentralizedMessenger {
public:
    /**
     * @brief Construct messenger with identity and network configuration
     * @param identity Agent identity (for signing and key exchange)
     * @param listen_port Port to listen on (0 for automatic)
     * @param max_connections Maximum concurrent connections (default: 100)
     * @param chunk_size File transfer chunk size in bytes (default: 64KB)
     */
    explicit DecentralizedMessenger(
        std::shared_ptr<AgentIdentity> identity,
        uint16_t listen_port = 0,
        size_t max_connections = 100,
        size_t chunk_size = 65536
    );

    /**
     * @brief Destructor - stops all operations and cleans up
     */
    ~DecentralizedMessenger();

    // Disable copy and move
    DecentralizedMessenger(const DecentralizedMessenger&) = delete;
    DecentralizedMessenger& operator=(const DecentralizedMessenger&) = delete;
    DecentralizedMessenger(DecentralizedMessenger&&) = delete;
    DecentralizedMessenger& operator=(DecentralizedMessenger&&) = delete;

    // ========================================================================
    // Lifecycle Management
    // ========================================================================

    /**
     * @brief Start messenger (begin listening and processing)
     * @return true if started successfully, false otherwise
     */
    bool start();

    /**
     * @brief Stop messenger (close all connections)
     */
    void stop();

    /**
     * @brief Check if messenger is running
     * @return true if running, false otherwise
     */
    bool is_running() const;

    /**
     * @brief Get listening port
     * @return Port number (0 if not started)
     */
    uint16_t get_listen_port() const;

    // ========================================================================
    // Session Management
    // ========================================================================

    /**
     * @brief Request encrypted session with peer
     * @param peer_id Peer agent ID
     * @param peer_host Peer IP address or hostname
     * @param peer_port Peer port
     * @param peer_enc_key Peer's X25519 public key
     * @return Session ID if request sent, std::nullopt on error
     */
    std::optional<std::string> request_session(
        const std::string& peer_id,
        const std::string& peer_host,
        uint16_t peer_port,
        const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& peer_enc_key
    );

    /**
     * @brief Accept pending session request
     * @param session_id Session ID from request
     * @return true if accepted, false on error
     */
    bool accept_session(const std::string& session_id);

    /**
     * @brief Reject session request
     * @param session_id Session ID from request
     * @return true if rejected, false on error
     */
    bool reject_session(const std::string& session_id);

    /**
     * @brief Close active session
     * @param session_id Session ID to close
     * @return true if closed, false if not found
     */
    bool close_session(const std::string& session_id);

    /**
     * @brief Get active session by peer ID
     * @param peer_id Peer agent ID
     * @return Session if found, std::nullopt otherwise
     */
    std::optional<Session> get_session(const std::string& peer_id) const;

    /**
     * @brief Get all active sessions
     * @return Vector of active sessions
     */
    std::vector<Session> get_all_sessions() const;

    // ========================================================================
    // Messaging
    // ========================================================================

    /**
     * @brief Send encrypted message to peer (requires active session)
     * @param peer_id Peer agent ID
     * @param payload Message payload (will be encrypted)
     * @return Message ID if sent, std::nullopt on error
     */
    std::optional<std::string> send_message(
        const std::string& peer_id,
        const std::vector<uint8_t>& payload
    );

    /**
     * @brief Send encrypted message with custom type
     * @param peer_id Peer agent ID
     * @param message_type Type of message
     * @param payload Message payload
     * @return Message ID if sent, std::nullopt on error
     */
    std::optional<std::string> send_message_typed(
        const std::string& peer_id,
        MessageType message_type,
        const std::vector<uint8_t>& payload
    );

    /**
     * @brief Broadcast unencrypted message (UDP, no session required)
     * @param message_type Type of message
     * @param payload Message payload
     * @param port Broadcast port (default: 9999)
     * @return Message ID if sent, std::nullopt on error
     */
    std::optional<std::string> broadcast_message(
        MessageType message_type,
        const std::vector<uint8_t>& payload,
        uint16_t port = 9999
    );

    // ========================================================================
    // File Transfer
    // ========================================================================

    /**
     * @brief Offer file for transfer to peer
     * @param peer_id Peer agent ID
     * @param filename File path to send
     * @return File ID if offered, std::nullopt on error
     */
    std::optional<std::string> send_file(
        const std::string& peer_id,
        const std::string& filename
    );

    /**
     * @brief Accept file transfer offer
     * @param file_id File identifier from offer
     * @param save_path Path to save received file
     * @return true if accepted, false on error
     */
    bool accept_file(const std::string& file_id, const std::string& save_path);

    /**
     * @brief Reject file transfer offer
     * @param file_id File identifier from offer
     * @return true if rejected, false on error
     */
    bool reject_file(const std::string& file_id);

    /**
     * @brief Get file transfer progress
     * @param file_id File identifier
     * @return Progress (0.0 to 1.0), or std::nullopt if not found
     */
    std::optional<double> get_file_progress(const std::string& file_id) const;

    // ========================================================================
    // Callbacks
    // ========================================================================

    /**
     * @brief Set callback for received messages
     * @param callback Callback function
     */
    void set_message_callback(MessageCallback callback);

    /**
     * @brief Set callback for session events
     * @param callback Callback function
     */
    void set_session_callback(SessionCallback callback);

    /**
     * @brief Set callback for file transfer progress
     * @param callback Callback function
     */
    void set_file_progress_callback(FileProgressCallback callback);

    // ========================================================================
    // Statistics
    // ========================================================================

    /**
     * @brief Get number of active sessions
     * @return Session count
     */
    size_t get_active_session_count() const;

    /**
     * @brief Get number of queued messages
     * @return Queue size
     */
    size_t get_queue_size() const;

    /**
     * @brief Get number of active file transfers
     * @return Transfer count
     */
    size_t get_active_transfer_count() const;

private:
    // ========================================================================
    // Member Variables
    // ========================================================================

    /// Agent identity
    std::shared_ptr<AgentIdentity> identity_;

    /// ASIO I/O context
    asio::io_context io_context_;

    /// UDP socket for discovery and lightweight messages
    std::unique_ptr<asio::ip::udp::socket> udp_socket_;

    /// TCP acceptor for incoming connections
    std::unique_ptr<asio::ip::tcp::acceptor> tcp_acceptor_;

    /// Listen port
    uint16_t listen_port_;

    /// Maximum concurrent connections
    [[maybe_unused]] size_t max_connections_;

    /// File transfer chunk size
    size_t chunk_size_;

    /// Rate limiter for DoS protection
    RateLimiter rate_limiter_;

    /// Replay protection
    MessageReplayProtection replay_protection_;

    /// Active sessions (peer_id -> session)
    std::map<std::string, Session> sessions_;

    /// Pending session requests (session_id -> session)
    std::map<std::string, Session> pending_sessions_;

    /// Active file transfers (file_id -> transfer)
    std::map<std::string, FileTransfer> file_transfers_;

    /// Message queue
    std::queue<QueuedMessage> message_queue_;

    /// Worker threads
    std::vector<std::thread> worker_threads_;

    /// Running flag
    std::atomic<bool> running_;

    /// Callbacks
    MessageCallback message_callback_;
    SessionCallback session_callback_;
    FileProgressCallback file_progress_callback_;

    /// Mutexes for thread safety
    mutable std::mutex sessions_mutex_;
    mutable std::mutex pending_sessions_mutex_;
    mutable std::mutex transfers_mutex_;
    mutable std::mutex queue_mutex_;
    mutable std::mutex callbacks_mutex_;

    // ========================================================================
    // Private Methods - Network I/O
    // ========================================================================

    void start_udp_receive();
    void start_tcp_accept();
    void handle_udp_receive(
        const asio::error_code& error,
        std::size_t bytes_transferred,
        std::shared_ptr<std::vector<uint8_t>> buffer,
        std::shared_ptr<asio::ip::udp::endpoint> sender_endpoint
    );
    void handle_tcp_accept(
        const asio::error_code& error,
        std::shared_ptr<asio::ip::tcp::socket> socket
    );
    void handle_tcp_receive(
        std::shared_ptr<asio::ip::tcp::socket> socket,
        std::shared_ptr<std::vector<uint8_t>> buffer
    );

    // ========================================================================
    // Private Methods - Message Processing
    // ========================================================================

    void process_message(const Message& message, const std::string& sender_host, uint16_t sender_port);
    void process_session_request(const SessionRequest& request, const Message& message, const std::string& sender_host, uint16_t sender_port);
    void process_session_accept(const SessionAccept& accept, const Message& message);
    void process_session_message(const SessionMessage& session_msg, const Message& message);
    void process_file_offer(const FileOffer& offer, const Message& message);
    void process_file_chunk(const FileChunk& chunk, const Message& message);
    void process_file_complete(const std::string& file_id, const Message& message);

    // ========================================================================
    // Private Methods - Message Sending
    // ========================================================================

    bool send_udp_message(const Message& message, const std::string& host, uint16_t port);
    bool send_tcp_message(const Message& message, const std::string& host, uint16_t port);
    void queue_message(const Message& message, const std::string& host, uint16_t port, bool use_tcp);
    void process_message_queue();

    // ========================================================================
    // Private Methods - Encryption
    // ========================================================================

    std::optional<std::vector<uint8_t>> encrypt_session_message(
        const std::vector<uint8_t>& plaintext,
        const Session& session
    );
    std::optional<std::vector<uint8_t>> decrypt_session_message(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& nonce,
        const Session& session
    );

    // ========================================================================
    // Private Methods - Utilities
    // ========================================================================

    Message create_message(MessageType type, const std::vector<uint8_t>& payload, const std::string& recipient_id = "");
    std::string generate_session_id(const std::string& peer_id);
    std::string generate_file_id(const std::string& filename);
    void cleanup_expired_sessions();
    void cleanup_stale_transfers();
};

} // namespace nlitp
