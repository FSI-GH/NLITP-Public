/**
 * @file replay_protection.hpp
 * @brief Replay attack protection using SHA-256 message IDs and time windows
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * - SHA-256 message ID generation
 * - 60-second time window
 * - Automatic cleanup of expired entries
 * - Thread-safe implementation
 */

#pragma once

#include <string>
#include <unordered_set>
#include <chrono>
#include <mutex>
#include <map>

namespace nlitp {

/**
 * @brief MessageReplayProtection - Prevents replay attacks
 *
 * Thread-safe replay attack protection using:
 * 1. SHA-256 message ID generation (peer + timestamp + nonce)
 * 2. Time window validation (60 seconds)
 * 3. Deduplication cache with automatic cleanup
 *
 */
class MessageReplayProtection {
public:
    /**
     * @brief Construct replay protection with configurable time window
     * @param window_seconds Time window for accepting messages (default: 60s)
     */
    explicit MessageReplayProtection(
        std::chrono::seconds window_seconds = std::chrono::seconds(60)
    );

    /**
     * @brief Destructor
     */
    ~MessageReplayProtection() = default;

    // Disable copy and move (singleton pattern recommended)
    MessageReplayProtection(const MessageReplayProtection&) = delete;
    MessageReplayProtection& operator=(const MessageReplayProtection&) = delete;
    MessageReplayProtection(MessageReplayProtection&&) = delete;
    MessageReplayProtection& operator=(MessageReplayProtection&&) = delete;

    /**
     * @brief Generate unique message ID using SHA-256
     * @param peer_id Peer agent ID
     * @param timestamp Message timestamp (seconds since epoch)
     * @param nonce Random nonce for uniqueness
     * @return SHA-256 message ID (64 hex characters)
     */
    static std::string generate_message_id(
        const std::string& peer_id,
        uint64_t timestamp,
        const std::string& nonce
    );

    /**
     * @brief Validate message is not a replay attack
     * @param message_id Message ID to validate
     * @param timestamp Message timestamp (seconds since epoch)
     * @return true if message is valid (not a replay), false if replay detected
     */
    bool validate_message(const std::string& message_id, uint64_t timestamp);

    /**
     * @brief Check if message has been seen before (without recording it)
     * @param message_id Message ID to check
     * @return true if message has been seen, false otherwise
     */
    bool has_seen(const std::string& message_id) const;

    /**
     * @brief Get current time window in seconds
     * @return Time window for message acceptance
     */
    std::chrono::seconds get_window() const;

    /**
     * @brief Get number of tracked message IDs
     * @return Count of message IDs in cache
     */
    size_t get_cache_size() const;

    /**
     * @brief Manually trigger cleanup of expired entries
     * @return Number of expired entries removed
     */
    size_t cleanup_expired();

    /**
     * @brief Clear all cached message IDs (use with caution)
     */
    void clear();

private:
    /// Time window for message acceptance
    std::chrono::seconds time_window_;

    /// Cache of seen message IDs with expiration times
    std::map<std::string, std::chrono::system_clock::time_point> message_cache_;

    /// Mutex for thread-safe access
    mutable std::mutex mutex_;

    /**
     * @brief Get current timestamp in seconds since epoch
     * @return Current timestamp
     */
    static uint64_t get_current_timestamp();

    /**
     * @brief Check if timestamp is within acceptable time window
     * @param message_timestamp Message timestamp (seconds since epoch)
     * @return true if within window, false if too old or too far in future
     */
    bool is_timestamp_valid(uint64_t message_timestamp) const;
};

} // namespace nlitp
