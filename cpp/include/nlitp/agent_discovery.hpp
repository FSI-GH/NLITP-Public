/**
 * @file agent_discovery.hpp
 * @brief UDP broadcast-based peer discovery for NLITP agents
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Provides UDP-based peer discovery:
 * - Broadcast agent presence announcements
 * - Query for specific agents
 * - Maintain peer cache with automatic cleanup
 * - Thread-safe operations
 */

#pragma once

#include "nlitp/agent_identity.hpp"
#include "nlitp/message_types.hpp"
#include "nlitp/security_config.hpp"
#include <asio.hpp>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <functional>
#include <chrono>
#include <optional>

namespace nlitp {

/**
 * @brief Information about a discovered peer
 */
struct PeerInfo {
    std::string agent_id;                                    ///< Agent identifier
    std::string host;                                        ///< IP address or hostname
    uint16_t port;                                           ///< UDP/TCP port
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> public_key_sign;  ///< Ed25519 public key
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> public_key_enc;    ///< X25519 public key
    std::map<std::string, std::string> capabilities;         ///< Agent capabilities
    std::chrono::steady_clock::time_point last_seen;         ///< Last discovery time
    bool available;                                          ///< Whether peer is available

    /**
     * @brief Construct PeerInfo from DiscoveryAnnounce
     */
    static std::optional<PeerInfo> from_announce(const DiscoveryAnnounce& announce);

    /**
     * @brief Construct PeerInfo from DiscoveryResponse
     */
    static std::optional<PeerInfo> from_response(const DiscoveryResponse& response);
};

/**
 * @brief Callback for peer discovery events
 */
using PeerDiscoveryCallback = std::function<void(const PeerInfo& peer)>;

/**
 * @brief AgentDiscovery - UDP broadcast-based peer discovery
 *
 * Provides decentralized peer discovery using UDP broadcasts:
 * 1. Announce presence periodically on UDP port 10001
 * 2. Listen for announcements from other agents
 * 3. Query for specific agents on-demand
 * 4. Maintain peer cache with automatic expiration
 * 5. Thread-safe operations with ASIO
 *
 * Security features:
 *
 */
class AgentDiscovery {
public:
    /**
     * @brief Construct AgentDiscovery
     * @param identity Agent identity (keys, agent ID)
     * @param io_context ASIO I/O context for async operations
     * @param port UDP port for discovery (default: 10001)
     */
    explicit AgentDiscovery(
        std::shared_ptr<AgentIdentity> identity,
        asio::io_context& io_context,
        uint16_t port = security::DISCOVERY_PORT
    );

    /**
     * @brief Destructor - stops all discovery operations
     */
    ~AgentDiscovery();

    // Disable copy and move
    AgentDiscovery(const AgentDiscovery&) = delete;
    AgentDiscovery& operator=(const AgentDiscovery&) = delete;
    AgentDiscovery(AgentDiscovery&&) = delete;
    AgentDiscovery& operator=(AgentDiscovery&&) = delete;

    // ========================================================================
    // Discovery Operations
    // ========================================================================

    /**
     * @brief Announce agent presence via UDP broadcast
     *
     * Broadcasts agent information including:
     * - Agent ID
     * - Host/port
     * - Public keys
     * - Capabilities
     *
     * @param capabilities Agent capabilities (e.g., {"role": "scu"})
     * @return true if announcement sent successfully, false otherwise
     */
    bool announce_presence(const std::map<std::string, std::string>& capabilities = {});

    /**
     * @brief Query for specific agent via UDP broadcast
     *
     * Sends query message and waits for responses.
     * Use get_peer() or register callback to receive results.
     *
     * @param target_agent_id Agent ID to query for (empty for all)
     * @param required_capabilities Required capabilities filter
     * @return true if query sent successfully, false otherwise
     */
    bool query_peers(
        const std::string& target_agent_id = "",
        const std::map<std::string, std::string>& required_capabilities = {}
    );

    /**
     * @brief Start discovery listener thread
     *
     * Starts UDP listener for:
     * - Announce messages from peers
     * - Query messages requiring response
     * - Response messages to our queries
     *
     * Must be called before announce_presence() or query_peers()
     *
     * @return true if listener started successfully, false otherwise
     */
    bool start_discovery_listener();

    /**
     * @brief Stop discovery listener
     */
    void stop_discovery_listener();

    /**
     * @brief Check if discovery listener is running
     * @return true if running, false otherwise
     */
    bool is_running() const;

    // ========================================================================
    // Peer Cache Management
    // ========================================================================

    /**
     * @brief Get peer information from cache
     * @param agent_id Agent identifier
     * @return PeerInfo if found, std::nullopt otherwise
     */
    std::optional<PeerInfo> get_peer(const std::string& agent_id);

    /**
     * @brief Get all cached peers
     * @return Vector of all discovered peers
     */
    std::vector<PeerInfo> get_all_peers();

    /**
     * @brief Get peers matching capabilities
     * @param required_capabilities Capabilities to filter by
     * @return Vector of matching peers
     */
    std::vector<PeerInfo> get_peers_with_capabilities(
        const std::map<std::string, std::string>& required_capabilities
    );

    /**
     * @brief Remove peer from cache
     * @param agent_id Agent identifier
     * @return true if removed, false if not found
     */
    bool remove_peer(const std::string& agent_id);

    /**
     * @brief Clear all peers from cache
     */
    void clear_peers();

    /**
     * @brief Cleanup stale peers (not seen recently)
     * @param max_age Maximum age before peer is considered stale
     * @return Number of peers removed
     */
    size_t cleanup_stale_peers(
        std::chrono::seconds max_age = std::chrono::minutes(5)
    );

    // ========================================================================
    // Callbacks
    // ========================================================================

    /**
     * @brief Register callback for peer discovery events
     * @param callback Function to call when peer discovered
     */
    void set_peer_discovered_callback(PeerDiscoveryCallback callback);

    /**
     * @brief Clear peer discovery callback
     */
    void clear_peer_discovered_callback();

    // ========================================================================
    // Statistics
    // ========================================================================

    /**
     * @brief Get number of cached peers
     * @return Count of discovered peers
     */
    size_t get_peer_count() const;

    /**
     * @brief Get number of messages sent
     * @return Count of sent messages
     */
    uint64_t get_messages_sent() const;

    /**
     * @brief Get number of messages received
     * @return Count of received messages
     */
    uint64_t get_messages_received() const;

private:
    // ========================================================================
    // Private Methods
    // ========================================================================

    /**
     * @brief Start async receive operation
     */
    void start_receive();

    /**
     * @brief Handle received UDP packet
     * @param error ASIO error code
     * @param bytes_transferred Number of bytes received
     */
    void handle_receive(
        const asio::error_code& error,
        size_t bytes_transferred
    );

    /**
     * @brief Process received discovery message
     * @param data Message data
     * @param sender_endpoint Sender's UDP endpoint
     */
    void process_message(
        const std::vector<uint8_t>& data,
        const asio::ip::udp::endpoint& sender_endpoint
    );

    /**
     * @brief Handle discovery announce message
     * @param announce Announcement payload
     * @param sender_endpoint Sender's UDP endpoint
     */
    void handle_announce(
        const DiscoveryAnnounce& announce,
        const asio::ip::udp::endpoint& sender_endpoint
    );

    /**
     * @brief Handle discovery query message
     * @param query Query payload
     * @param query_msg Full message with sender info
     * @param sender_endpoint Sender's UDP endpoint
     */
    void handle_query(
        const DiscoveryQuery& query,
        const Message& query_msg,
        const asio::ip::udp::endpoint& sender_endpoint
    );

    /**
     * @brief Handle discovery response message
     * @param response Response payload
     * @param sender_endpoint Sender's UDP endpoint
     */
    void handle_response(
        const DiscoveryResponse& response,
        const asio::ip::udp::endpoint& sender_endpoint
    );

    /**
     * @brief Send UDP packet to broadcast address
     * @param data Data to send
     * @return true if sent successfully, false otherwise
     */
    bool send_broadcast(const std::vector<uint8_t>& data);

    /**
     * @brief Send UDP packet to specific endpoint
     * @param data Data to send
     * @param endpoint Destination endpoint
     * @return true if sent successfully, false otherwise
     */
    bool send_to_endpoint(
        const std::vector<uint8_t>& data,
        const asio::ip::udp::endpoint& endpoint
    );

    /**
     * @brief Create discovery message
     * @param type Message type
     * @param payload_json Payload as JSON string
     * @param recipient_id Recipient agent ID (empty for broadcast)
     * @return Serialized message
     */
    std::vector<uint8_t> create_message(
        MessageType type,
        const std::string& payload_json,
        const std::string& recipient_id = ""
    );

    /**
     * @brief Add or update peer in cache
     * @param peer Peer information
     */
    void add_peer(const PeerInfo& peer);

    /**
     * @brief Check if capabilities match requirements
     * @param capabilities Peer capabilities
     * @param required Required capabilities
     * @return true if all required capabilities match, false otherwise
     */
    bool matches_capabilities(
        const std::map<std::string, std::string>& capabilities,
        const std::map<std::string, std::string>& required
    ) const;

    // ========================================================================
    // Member Variables
    // ========================================================================

    /// Agent identity (keys, ID)
    std::shared_ptr<AgentIdentity> identity_;

    /// ASIO I/O context reference
    [[maybe_unused]] asio::io_context& io_context_;

    /// UDP socket for discovery
    asio::ip::udp::socket socket_;

    /// UDP port for discovery
    uint16_t port_;

    /// Broadcast endpoint
    asio::ip::udp::endpoint broadcast_endpoint_;

    /// Receive buffer
    std::array<uint8_t, security::MAX_UDP_PACKET_SIZE> recv_buffer_;

    /// Sender endpoint for received packets
    asio::ip::udp::endpoint sender_endpoint_;

    /// Discovered peers cache
    std::map<std::string, PeerInfo> peers_;

    /// Mutex for thread-safe peer cache access
    mutable std::mutex peers_mutex_;

    /// Peer discovery callback
    PeerDiscoveryCallback peer_discovered_callback_;

    /// Mutex for callback access
    mutable std::mutex callback_mutex_;

    /// Discovery listener running flag
    std::atomic<bool> running_;

    /// Statistics
    std::atomic<uint64_t> messages_sent_;
    std::atomic<uint64_t> messages_received_;
};

} // namespace nlitp
