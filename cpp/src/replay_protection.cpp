/**
 * @file replay_protection.cpp
 * @brief Implementation of replay attack protection
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 */

#include "nlitp/replay_protection.hpp"
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace nlitp {

// ============================================================================
// Constructor
// ============================================================================

MessageReplayProtection::MessageReplayProtection(std::chrono::seconds window_seconds)
    : time_window_(window_seconds)
{
    // Initialize libsodium for crypto_hash_sha256
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

// ============================================================================
// Message ID Generation
// ============================================================================

std::string MessageReplayProtection::generate_message_id(
    const std::string& peer_id,
    uint64_t timestamp,
    const std::string& nonce
) {
    // Concatenate peer_id + timestamp + nonce
    std::ostringstream oss;
    oss << peer_id << ":" << timestamp << ":" << nonce;
    std::string input = oss.str();

    // Compute SHA-256 hash
    std::vector<uint8_t> hash(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(
        hash.data(),
        reinterpret_cast<const uint8_t*>(input.c_str()),
        input.length()
    );

    // Convert hash to hexadecimal string
    std::ostringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');
    for (uint8_t byte : hash) {
        hex_stream << std::setw(2) << static_cast<int>(byte);
    }

    return hex_stream.str();
}

// ============================================================================
// Message Validation
// ============================================================================

bool MessageReplayProtection::validate_message(const std::string& message_id, uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if timestamp is within acceptable window
    if (!is_timestamp_valid(timestamp)) {
        return false;
    }

    // Check if message ID has been seen before
    if (message_cache_.find(message_id) != message_cache_.end()) {
        // Replay attack detected
        return false;
    }

    // Record message ID with expiration time
    auto now = std::chrono::system_clock::now();
    auto expiration = now + time_window_;
    message_cache_[message_id] = expiration;

    // Cleanup expired entries (opportunistic cleanup)
    if (message_cache_.size() % 100 == 0) {
        cleanup_expired();
    }

    return true;
}

bool MessageReplayProtection::has_seen(const std::string& message_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return message_cache_.find(message_id) != message_cache_.end();
}

// ============================================================================
// Time Window Management
// ============================================================================

std::chrono::seconds MessageReplayProtection::get_window() const {
    return time_window_;
}

uint64_t MessageReplayProtection::get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

bool MessageReplayProtection::is_timestamp_valid(uint64_t message_timestamp) const {
    uint64_t now = get_current_timestamp();

    // Calculate acceptable time range
    uint64_t window_seconds = static_cast<uint64_t>(time_window_.count());

    // Message must not be too old
    if (message_timestamp < now - window_seconds) {
        return false;
    }

    // Message must not be too far in the future (allow small clock skew)
    if (message_timestamp > now + window_seconds) {
        return false;
    }

    return true;
}

// ============================================================================
// Cache Management
// ============================================================================

size_t MessageReplayProtection::get_cache_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return message_cache_.size();
}

size_t MessageReplayProtection::cleanup_expired() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::system_clock::now();
    size_t removed = 0;

    // Remove expired entries
    for (auto it = message_cache_.begin(); it != message_cache_.end(); ) {
        if (it->second < now) {
            it = message_cache_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }

    return removed;
}

void MessageReplayProtection::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    message_cache_.clear();
}

} // namespace nlitp
