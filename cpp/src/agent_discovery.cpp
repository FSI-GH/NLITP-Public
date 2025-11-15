/**
 * @file agent_discovery.cpp
 * @brief Implementation of UDP broadcast-based peer discovery
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 */

#include "nlitp/agent_discovery.hpp"
#include "nlitp/utilities.hpp"
#include <algorithm>
#include <stdexcept>

namespace nlitp {

// ============================================================================
// PeerInfo Helper Methods
// ============================================================================

std::optional<PeerInfo> PeerInfo::from_announce(const DiscoveryAnnounce& announce) {
    try {
        if (!security::validate_identifier(announce.agent_id)) {
            return std::nullopt;
        }

        // Validate public keys
        if (announce.public_key_sign.size() != crypto_sign_PUBLICKEYBYTES ||
            announce.public_key_enc.size() != crypto_box_PUBLICKEYBYTES) {
            return std::nullopt;
        }

        PeerInfo peer;
        peer.agent_id = announce.agent_id;
        peer.host = announce.host;
        peer.port = announce.port;
        peer.capabilities = announce.capabilities;
        peer.last_seen = std::chrono::steady_clock::now();
        peer.available = true;

        // Copy public keys
        std::copy(announce.public_key_sign.begin(),
                  announce.public_key_sign.end(),
                  peer.public_key_sign.begin());
        std::copy(announce.public_key_enc.begin(),
                  announce.public_key_enc.end(),
                  peer.public_key_enc.begin());

        return peer;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<PeerInfo> PeerInfo::from_response(const DiscoveryResponse& response) {
    try {
        if (!security::validate_identifier(response.agent_id)) {
            return std::nullopt;
        }

        // Validate public keys
        if (response.public_key_sign.size() != crypto_sign_PUBLICKEYBYTES ||
            response.public_key_enc.size() != crypto_box_PUBLICKEYBYTES) {
            return std::nullopt;
        }

        PeerInfo peer;
        peer.agent_id = response.agent_id;
        peer.host = response.host;
        peer.port = response.port;
        peer.capabilities = response.capabilities;
        peer.last_seen = std::chrono::steady_clock::now();
        peer.available = response.available;

        // Copy public keys
        std::copy(response.public_key_sign.begin(),
                  response.public_key_sign.end(),
                  peer.public_key_sign.begin());
        std::copy(response.public_key_enc.begin(),
                  response.public_key_enc.end(),
                  peer.public_key_enc.begin());

        return peer;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

AgentDiscovery::AgentDiscovery(
    std::shared_ptr<AgentIdentity> identity,
    asio::io_context& io_context,
    uint16_t port
)
    : identity_(std::move(identity))
    , io_context_(io_context)
    , socket_(io_context)
    , port_(port)
    , broadcast_endpoint_(asio::ip::address_v4::broadcast(), port)
    , running_(false)
    , messages_sent_(0)
    , messages_received_(0)
{
    if (!identity_) {
        throw std::invalid_argument("AgentDiscovery: identity cannot be null");
    }
}

AgentDiscovery::~AgentDiscovery() {
    stop_discovery_listener();
}

// ============================================================================
// Discovery Operations
// ============================================================================

bool AgentDiscovery::announce_presence(const std::map<std::string, std::string>& capabilities) {
    try {
        // Create announcement payload
        DiscoveryAnnounce announce;
        announce.agent_id = identity_->get_agent_id();
        announce.host = "0.0.0.0";  // Listeners should use sender's address
        announce.port = port_;

        // Get public keys as vectors
        auto sign_key = identity_->get_signature_public_key();
        auto enc_key = identity_->get_encryption_public_key();

        announce.public_key_sign = std::vector<uint8_t>(sign_key.begin(), sign_key.end());
        announce.public_key_enc = std::vector<uint8_t>(enc_key.begin(), enc_key.end());
        announce.capabilities = capabilities;

        // Serialize announcement
        std::string payload_json = announce.to_json();

        // Create and send message
        auto message_data = create_message(MessageType::DISCOVERY_ANNOUNCE, payload_json);
        bool success = send_broadcast(message_data);

        if (success) {
            utilities::log_debug("Discovery: Announced presence");
        }

        return success;

    } catch (const std::exception& e) {
        utilities::log_error("Discovery: Failed to announce presence: " + std::string(e.what()));
        return false;
    }
}

bool AgentDiscovery::query_peers(
    const std::string& target_agent_id,
    const std::map<std::string, std::string>& required_capabilities
) {
    try {
        if (!target_agent_id.empty() && !security::validate_identifier(target_agent_id)) {
            utilities::log_error("Discovery: Invalid target agent ID");
            return false;
        }

        // Create query payload
        DiscoveryQuery query;
        query.target_agent_id = target_agent_id;
        query.require_capabilities = !required_capabilities.empty();
        query.required_capabilities = required_capabilities;

        // Serialize query
        std::string payload_json = query.to_json();

        // Create and send message
        auto message_data = create_message(MessageType::DISCOVERY_QUERY, payload_json);
        bool success = send_broadcast(message_data);

        if (success) {
            utilities::log_debug("Discovery: Queried peers");
        }

        return success;

    } catch (const std::exception& e) {
        utilities::log_error("Discovery: Failed to query peers: " + std::string(e.what()));
        return false;
    }
}

bool AgentDiscovery::start_discovery_listener() {
    if (running_.load()) {
        return true;  // Already running
    }

    try {
        // Open UDP socket
        socket_.open(asio::ip::udp::v4());

        // Enable broadcast
        socket_.set_option(asio::socket_base::broadcast(true));
        socket_.set_option(asio::socket_base::reuse_address(true));

        // Bind to discovery port
        socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), port_));

        running_.store(true);

        // Start async receive
        start_receive();

        utilities::log_info("Discovery: Listener started on port " + std::to_string(port_));
        return true;

    } catch (const std::exception& e) {
        utilities::log_error("Discovery: Failed to start listener: " + std::string(e.what()));
        running_.store(false);
        return false;
    }
}

void AgentDiscovery::stop_discovery_listener() {
    if (!running_.load()) {
        return;
    }

    running_.store(false);

    try {
        if (socket_.is_open()) {
            socket_.close();
        }
        utilities::log_info("Discovery: Listener stopped");
    } catch (const std::exception& e) {
        utilities::log_error("Discovery: Error stopping listener: " + std::string(e.what()));
    }
}

bool AgentDiscovery::is_running() const {
    return running_.load();
}

// ============================================================================
// Peer Cache Management
// ============================================================================

std::optional<PeerInfo> AgentDiscovery::get_peer(const std::string& agent_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    auto it = peers_.find(agent_id);
    if (it != peers_.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<PeerInfo> AgentDiscovery::get_all_peers() {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    std::vector<PeerInfo> result;
    result.reserve(peers_.size());

    for (const auto& [agent_id, peer] : peers_) {
        result.push_back(peer);
    }

    return result;
}

std::vector<PeerInfo> AgentDiscovery::get_peers_with_capabilities(
    const std::map<std::string, std::string>& required_capabilities
) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    std::vector<PeerInfo> result;

    for (const auto& [agent_id, peer] : peers_) {
        if (matches_capabilities(peer.capabilities, required_capabilities)) {
            result.push_back(peer);
        }
    }

    return result;
}

bool AgentDiscovery::remove_peer(const std::string& agent_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    auto it = peers_.find(agent_id);
    if (it != peers_.end()) {
        peers_.erase(it);
        return true;
    }

    return false;
}

void AgentDiscovery::clear_peers() {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    peers_.clear();
}

size_t AgentDiscovery::cleanup_stale_peers(std::chrono::seconds max_age) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    auto now = std::chrono::steady_clock::now();
    size_t removed = 0;

    for (auto it = peers_.begin(); it != peers_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_seen);

        if (age > max_age) {
            utilities::log_debug("Discovery: Removing stale peer " + it->first);
            it = peers_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }

    return removed;
}

// ============================================================================
// Callbacks
// ============================================================================

void AgentDiscovery::set_peer_discovered_callback(PeerDiscoveryCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    peer_discovered_callback_ = std::move(callback);
}

void AgentDiscovery::clear_peer_discovered_callback() {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    peer_discovered_callback_ = nullptr;
}

// ============================================================================
// Statistics
// ============================================================================

size_t AgentDiscovery::get_peer_count() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return peers_.size();
}

uint64_t AgentDiscovery::get_messages_sent() const {
    return messages_sent_.load();
}

uint64_t AgentDiscovery::get_messages_received() const {
    return messages_received_.load();
}

// ============================================================================
// Private Methods - Network Operations
// ============================================================================

void AgentDiscovery::start_receive() {
    socket_.async_receive_from(
        asio::buffer(recv_buffer_),
        sender_endpoint_,
        [this](const asio::error_code& error, size_t bytes_transferred) {
            handle_receive(error, bytes_transferred);
        }
    );
}

void AgentDiscovery::handle_receive(
    const asio::error_code& error,
    size_t bytes_transferred
) {
    if (error) {
        if (error != asio::error::operation_aborted) {
            utilities::log_error("Discovery: Receive error: " + error.message());
        }
        return;
    }

    if (bytes_transferred > security::MAX_UDP_PACKET_SIZE) {
        utilities::log_warn("Discovery: Oversized packet received, dropping");
        start_receive();  // Continue listening
        return;
    }

    messages_received_++;

    // Process message
    try {
        std::vector<uint8_t> data(recv_buffer_.begin(), recv_buffer_.begin() + bytes_transferred);
        process_message(data, sender_endpoint_);
    } catch (const std::exception& e) {
        utilities::log_error("Discovery: Error processing message: " + std::string(e.what()));
    }

    // Continue listening if still running
    if (running_.load()) {
        start_receive();
    }
}

void AgentDiscovery::process_message(
    const std::vector<uint8_t>& data,
    const asio::ip::udp::endpoint& sender_endpoint
) {
    // Convert to string for JSON parsing
    std::string json_str(data.begin(), data.end());

    // Parse message
    auto message_opt = Message::from_json(json_str);
    if (!message_opt) {
        utilities::log_warn("Discovery: Failed to parse message");
        return;
    }

    const Message& msg = *message_opt;

    // Ignore messages from ourselves
    if (msg.sender_id == identity_->get_agent_id()) {
        return;
    }

    // Parse payload
    std::string payload_str(msg.payload.begin(), msg.payload.end());

    // Handle based on message type
    switch (msg.type) {
        case MessageType::DISCOVERY_ANNOUNCE: {
            auto announce_opt = DiscoveryAnnounce::from_json(payload_str);
            if (announce_opt) {
                handle_announce(*announce_opt, sender_endpoint);
            }
            break;
        }

        case MessageType::DISCOVERY_QUERY: {
            auto query_opt = DiscoveryQuery::from_json(payload_str);
            if (query_opt) {
                handle_query(*query_opt, msg, sender_endpoint);
            }
            break;
        }

        case MessageType::DISCOVERY_RESPONSE: {
            auto response_opt = DiscoveryResponse::from_json(payload_str);
            if (response_opt) {
                handle_response(*response_opt, sender_endpoint);
            }
            break;
        }

        default:
            // Not a discovery message, ignore
            break;
    }
}

void AgentDiscovery::handle_announce(
    const DiscoveryAnnounce& announce,
    const asio::ip::udp::endpoint& sender_endpoint
) {
    // Convert to PeerInfo
    auto peer_opt = PeerInfo::from_announce(announce);
    if (!peer_opt) {
        utilities::log_warn("Discovery: Invalid announce message");
        return;
    }

    // Update host with actual sender address (not the 0.0.0.0 they sent)
    peer_opt->host = sender_endpoint.address().to_string();

    // Add to cache
    add_peer(*peer_opt);

    utilities::log_debug("Discovery: Peer announced: " + announce.agent_id);
}

void AgentDiscovery::handle_query(
    const DiscoveryQuery& query,
    const Message& query_msg,
    const asio::ip::udp::endpoint& sender_endpoint
) {
    // Check if query is for us (or for all agents)
    bool matches = query.target_agent_id.empty() ||
                   query.target_agent_id == identity_->get_agent_id();

    if (!matches) {
        return;  // Not for us
    }

    // Check capabilities if required
    if (query.require_capabilities) {
        // Would need to track our own capabilities - for now assume we match
        // In real implementation, pass capabilities when constructing AgentDiscovery
    }

    // Send response
    try {
        DiscoveryResponse response;
        response.agent_id = identity_->get_agent_id();
        response.host = "0.0.0.0";  // Receiver will use our actual address
        response.port = port_;

        auto sign_key = identity_->get_signature_public_key();
        auto enc_key = identity_->get_encryption_public_key();

        response.public_key_sign = std::vector<uint8_t>(sign_key.begin(), sign_key.end());
        response.public_key_enc = std::vector<uint8_t>(enc_key.begin(), enc_key.end());
        response.available = true;
        // response.capabilities would be set from our stored capabilities

        std::string payload_json = response.to_json();
        auto message_data = create_message(
            MessageType::DISCOVERY_RESPONSE,
            payload_json,
            query_msg.sender_id
        );

        // Send directly to querying peer
        send_to_endpoint(message_data, sender_endpoint);

        utilities::log_debug("Discovery: Responded to query from " + query_msg.sender_id);

    } catch (const std::exception& e) {
        utilities::log_error("Discovery: Failed to respond to query: " + std::string(e.what()));
    }
}

void AgentDiscovery::handle_response(
    const DiscoveryResponse& response,
    const asio::ip::udp::endpoint& sender_endpoint
) {
    // Convert to PeerInfo
    auto peer_opt = PeerInfo::from_response(response);
    if (!peer_opt) {
        utilities::log_warn("Discovery: Invalid response message");
        return;
    }

    // Update host with actual sender address
    peer_opt->host = sender_endpoint.address().to_string();

    // Add to cache
    add_peer(*peer_opt);

    utilities::log_debug("Discovery: Received response from " + response.agent_id);
}

bool AgentDiscovery::send_broadcast(const std::vector<uint8_t>& data) {
    try {
        if (data.size() > security::MAX_UDP_PACKET_SIZE) {
            utilities::log_error("Discovery: Message too large to send");
            return false;
        }

        socket_.send_to(asio::buffer(data), broadcast_endpoint_);
        messages_sent_++;
        return true;

    } catch (const std::exception& e) {
        utilities::log_error("Discovery: Failed to send broadcast: " + std::string(e.what()));
        return false;
    }
}

bool AgentDiscovery::send_to_endpoint(
    const std::vector<uint8_t>& data,
    const asio::ip::udp::endpoint& endpoint
) {
    try {
        if (data.size() > security::MAX_UDP_PACKET_SIZE) {
            utilities::log_error("Discovery: Message too large to send");
            return false;
        }

        socket_.send_to(asio::buffer(data), endpoint);
        messages_sent_++;
        return true;

    } catch (const std::exception& e) {
        utilities::log_error("Discovery: Failed to send to endpoint: " + std::string(e.what()));
        return false;
    }
}

std::vector<uint8_t> AgentDiscovery::create_message(
    MessageType type,
    const std::string& payload_json,
    const std::string& recipient_id
) {
    // Create base message
    Message msg;
    msg.type = type;
    msg.sender_id = identity_->get_agent_id();
    msg.recipient_id = recipient_id;
    msg.timestamp = MessageHelpers::get_current_timestamp();

    // Generate message ID
    msg.message_id = MessageHelpers::generate_message_id(
        msg.sender_id,
        msg.timestamp,
        utilities::generate_random_string(16)
    );

    // Set payload
    msg.payload = std::vector<uint8_t>(payload_json.begin(), payload_json.end());

    // Sign message
    msg.signature = identity_->sign(msg.payload);

    // Serialize message
    std::string json = msg.to_json();

    return std::vector<uint8_t>(json.begin(), json.end());
}

void AgentDiscovery::add_peer(const PeerInfo& peer) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    bool is_new = (peers_.find(peer.agent_id) == peers_.end());

    // Add or update peer
    peers_[peer.agent_id] = peer;

    // Call callback if new peer
    if (is_new) {
        std::lock_guard<std::mutex> cb_lock(callback_mutex_);
        if (peer_discovered_callback_) {
            try {
                peer_discovered_callback_(peer);
            } catch (const std::exception& e) {
                utilities::log_error("Discovery: Callback error: " + std::string(e.what()));
            }
        }
    }
}

bool AgentDiscovery::matches_capabilities(
    const std::map<std::string, std::string>& capabilities,
    const std::map<std::string, std::string>& required
) const {
    // Check if all required capabilities are present and match
    for (const auto& [key, value] : required) {
        auto it = capabilities.find(key);
        if (it == capabilities.end() || it->second != value) {
            return false;
        }
    }

    return true;
}

} // namespace nlitp
