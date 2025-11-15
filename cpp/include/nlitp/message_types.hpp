/**
 * @file message_types.hpp
 * @brief Message type definitions and serialization for NLITP
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * All message types with JSON serialization/deserialization:
 * - Discovery messages (UDP broadcast)
 * - Session messages (encrypted P2P)
 * - File transfer messages
 * - Trust update messages
 * - Gatekeeper routing messages
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <optional>

namespace nlitp {

/**
 * @brief Message types in NLITP protocol
 */
enum class MessageType {
    // Discovery messages (UDP broadcast)
    DISCOVERY_ANNOUNCE,      ///< Agent announces presence
    DISCOVERY_QUERY,         ///< Query for specific agent
    DISCOVERY_RESPONSE,      ///< Response to query

    // Session messages (encrypted P2P)
    SESSION_REQUEST,         ///< Request encrypted session
    SESSION_ACCEPT,          ///< Accept session with keys
    SESSION_REJECT,          ///< Reject session request
    SESSION_MESSAGE,         ///< Encrypted session message
    SESSION_CLOSE,           ///< Close session

    // File transfer
    FILE_OFFER,              ///< Offer file for transfer
    FILE_ACCEPT,             ///< Accept file transfer
    FILE_REJECT,             ///< Reject file transfer
    FILE_CHUNK,              ///< File data chunk
    FILE_COMPLETE,           ///< File transfer complete

    // Trust updates
    TRUST_OBSERVATION,       ///< Report trust observation
    TRUST_QUERY,             ///< Query peer's trust score
    TRUST_RESPONSE,          ///< Response with trust score

    // Gatekeeper routing
    GATEKEEPER_REGISTER,     ///< SCU registers with Gatekeeper
    GATEKEEPER_ROUTE,        ///< Route message through Gatekeeper
    GATEKEEPER_BLOCK,        ///< Gatekeeper blocks message
    GATEKEEPER_SANITIZE,     ///< Traffic sanitization notification

    // Health/maintenance
    PING,                    ///< Ping for connectivity check
    PONG,                    ///< Pong response
    HEARTBEAT                ///< Periodic heartbeat
};

/**
 * @brief Base message structure for all NLITP messages
 */
struct Message {
    MessageType type;               ///< Message type
    std::string message_id;         ///< Unique message ID (SHA-256)
    uint64_t timestamp;             ///< Unix timestamp (seconds)
    std::string sender_id;          ///< Sender agent ID
    std::string recipient_id;       ///< Recipient agent ID (empty for broadcast)
    std::vector<uint8_t> signature; ///< Ed25519 signature
    std::vector<uint8_t> payload;   ///< Message payload (JSON or binary)

    /**
     * @brief Serialize message to JSON
     * @return JSON string
     */
    std::string to_json() const;

    /**
     * @brief Deserialize message from JSON
     * @param json JSON string
     * @return Message or std::nullopt if invalid
     */
    static std::optional<Message> from_json(const std::string& json);
};

/**
 * @brief Discovery announce message payload
 */
struct DiscoveryAnnounce {
    std::string agent_id;                   ///< Agent identifier
    std::string host;                       ///< IP address or hostname
    uint16_t port;                          ///< UDP/TCP port
    std::vector<uint8_t> public_key_sign;   ///< Ed25519 public key
    std::vector<uint8_t> public_key_enc;    ///< X25519 public key
    std::map<std::string, std::string> capabilities; ///< Agent capabilities

    std::string to_json() const;
    static std::optional<DiscoveryAnnounce> from_json(const std::string& json);
};

/**
 * @brief Discovery query message payload
 */
struct DiscoveryQuery {
    std::string target_agent_id;            ///< Agent ID being queried (empty for all)
    bool require_capabilities;              ///< Whether to filter by capabilities
    std::map<std::string, std::string> required_capabilities; ///< Required capabilities

    std::string to_json() const;
    static std::optional<DiscoveryQuery> from_json(const std::string& json);
};

/**
 * @brief Discovery response message payload
 */
struct DiscoveryResponse {
    std::string agent_id;                   ///< Agent identifier
    std::string host;                       ///< IP address or hostname
    uint16_t port;                          ///< UDP/TCP port
    std::vector<uint8_t> public_key_sign;   ///< Ed25519 public key
    std::vector<uint8_t> public_key_enc;    ///< X25519 public key
    std::map<std::string, std::string> capabilities; ///< Agent capabilities
    bool available;                          ///< Whether agent is available for connection

    std::string to_json() const;
    static std::optional<DiscoveryResponse> from_json(const std::string& json);
};

/**
 * @brief Session request message payload
 */
struct SessionRequest {
    std::string session_id;                 ///< Proposed session ID
    std::vector<uint8_t> ephemeral_key;     ///< X25519 ephemeral public key
    std::vector<uint8_t> nonce;             ///< Random nonce

    std::string to_json() const;
    static std::optional<SessionRequest> from_json(const std::string& json);
};

/**
 * @brief Session accept message payload
 */
struct SessionAccept {
    std::string session_id;                 ///< Accepted session ID
    std::vector<uint8_t> ephemeral_key;     ///< X25519 ephemeral public key
    std::vector<uint8_t> nonce;             ///< Random nonce

    std::string to_json() const;
    static std::optional<SessionAccept> from_json(const std::string& json);
};

/**
 * @brief Encrypted session message payload
 */
struct SessionMessage {
    std::string session_id;                 ///< Session ID
    std::vector<uint8_t> encrypted_data;    ///< ChaCha20-Poly1305 ciphertext
    std::vector<uint8_t> nonce;             ///< Encryption nonce

    std::string to_json() const;
    static std::optional<SessionMessage> from_json(const std::string& json);
};

/**
 * @brief File offer message payload
 */
struct FileOffer {
    std::string file_id;                    ///< Unique file identifier
    std::string filename;                   ///< Original filename (sanitized)
    uint64_t file_size;                     ///< File size in bytes
    std::vector<uint8_t> file_hash;         ///< SHA-256 hash of file
    std::string mime_type;                  ///< MIME type

    std::string to_json() const;
    static std::optional<FileOffer> from_json(const std::string& json);
};

/**
 * @brief File chunk message payload
 */
struct FileChunk {
    std::string file_id;                    ///< File identifier
    uint64_t chunk_number;                  ///< Chunk sequence number
    uint64_t total_chunks;                  ///< Total number of chunks
    std::vector<uint8_t> data;              ///< Chunk data (encrypted)
    std::vector<uint8_t> chunk_hash;        ///< SHA-256 hash of this chunk

    std::string to_json() const;
    static std::optional<FileChunk> from_json(const std::string& json);
};

/**
 * @brief Trust observation message payload
 */
struct TrustObservationMsg {
    std::string peer_id;                    ///< Peer being evaluated
    double trust_score;                     ///< Trust score (0.0-1.0)
    double wisdom_score;                    ///< Wisdom score (0.0-1.0)
    bool verified;                          ///< Whether observation is verified
    std::string observation;                ///< Human-readable reason

    std::string to_json() const;
    static std::optional<TrustObservationMsg> from_json(const std::string& json);
};

/**
 * @brief Gatekeeper registration message payload
 */
struct GatekeeperRegister {
    std::string scu_id;                     ///< SCU agent ID
    std::string cluster_id;                 ///< Desired cluster ID
    std::vector<uint8_t> public_key_sign;   ///< Ed25519 public key
    std::vector<uint8_t> public_key_enc;    ///< X25519 public key

    std::string to_json() const;
    static std::optional<GatekeeperRegister> from_json(const std::string& json);
};

/**
 * @brief Gatekeeper routing message payload
 */
struct GatekeeperRoute {
    std::string source_scu;                 ///< Source SCU ID
    std::string destination_scu;            ///< Destination SCU ID
    std::string destination_cluster;        ///< Destination cluster ID
    std::vector<uint8_t> encrypted_payload; ///< Encrypted message payload
    bool requires_sanitization;             ///< Whether to sanitize traffic

    std::string to_json() const;
    static std::optional<GatekeeperRoute> from_json(const std::string& json);
};

/**
 * @brief Helper functions for message handling
 */
class MessageHelpers {
public:
    /**
     * @brief Convert MessageType enum to string
     * @param type Message type
     * @return String representation
     */
    static std::string message_type_to_string(MessageType type);

    /**
     * @brief Convert string to MessageType enum
     * @param str String representation
     * @return MessageType or std::nullopt if invalid
     */
    static std::optional<MessageType> string_to_message_type(const std::string& str);

    /**
     * @brief Generate unique message ID
     * @param sender_id Sender agent ID
     * @param timestamp Message timestamp
     * @param nonce Random nonce
     * @return SHA-256 message ID
     */
    static std::string generate_message_id(
        const std::string& sender_id,
        uint64_t timestamp,
        const std::string& nonce
    );

    /**
     * @brief Get current timestamp in seconds since epoch
     * @return Unix timestamp
     */
    static uint64_t get_current_timestamp();

    /**
     * @brief Validate message size is within limits
     * @param size Message size in bytes
     * @return true if valid, false if exceeds MAX_MESSAGE_SIZE
     */
    static bool validate_message_size(size_t size);

    /**
     * @brief Validate file size is within limits
     * @param size File size in bytes
     * @return true if valid, false if exceeds MAX_FILE_SIZE
     */
    static bool validate_file_size(uint64_t size);
};

} // namespace nlitp
