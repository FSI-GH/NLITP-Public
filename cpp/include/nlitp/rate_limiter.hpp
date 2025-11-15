/**
 * @file rate_limiter.hpp
 * @brief Token bucket rate limiting for DoS protection
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * - 100 messages per second per peer (sustained rate)
 * - 200 message burst capacity
 * - Automatic token refill
 * - Thread-safe implementation
 */

#pragma once

#include <string>
#include <chrono>
#include <mutex>
#include <map>

namespace nlitp {

/**
 * @brief Token bucket for single peer rate limiting
 */
struct TokenBucket {
    /// Number of tokens currently available
    double tokens;

    /// Maximum token capacity (burst limit)
    double capacity;

    /// Token refill rate (tokens per second)
    double refill_rate;

    /// Last refill timestamp
    std::chrono::steady_clock::time_point last_refill;

    /**
     * @brief Construct token bucket
     * @param rate Refill rate (tokens per second)
     * @param burst Maximum burst capacity
     */
    TokenBucket(double rate, double burst)
        : tokens(burst)
        , capacity(burst)
        , refill_rate(rate)
        , last_refill(std::chrono::steady_clock::now())
    {}
};

/**
 * @brief RateLimiter - Token bucket rate limiting per peer
 *
 * Thread-safe rate limiting using token bucket algorithm:
 * 1. Each peer has independent token bucket
 * 2. Tokens refill at constant rate (100/second)
 * 3. Burst capacity allows temporary spikes (200 tokens)
 * 4. Messages consume tokens, rejected if bucket empty
 *
 */
class RateLimiter {
public:
    /**
     * @brief Construct rate limiter with configurable parameters
     * @param rate_per_second Sustained message rate per peer (default: 100)
     * @param burst_capacity Burst capacity per peer (default: 200)
     */
    explicit RateLimiter(
        double rate_per_second = 100.0,
        double burst_capacity = 200.0
    );

    /**
     * @brief Destructor
     */
    ~RateLimiter() = default;

    // Disable copy and move (singleton pattern recommended)
    RateLimiter(const RateLimiter&) = delete;
    RateLimiter& operator=(const RateLimiter&) = delete;
    RateLimiter(RateLimiter&&) = delete;
    RateLimiter& operator=(RateLimiter&&) = delete;

    /**
     * @brief Check if message from peer is allowed (consumes 1 token if allowed)
     * @param peer_id Peer agent ID
     * @return true if message is allowed, false if rate limit exceeded
     */
    bool allow_message(const std::string& peer_id);

    /**
     * @brief Check if message would be allowed without consuming token
     * @param peer_id Peer agent ID
     * @return true if message would be allowed, false if rate limit exceeded
     */
    bool check_message(const std::string& peer_id);

    /**
     * @brief Get current token count for peer
     * @param peer_id Peer agent ID
     * @return Number of tokens available (0 if peer not tracked)
     */
    double get_tokens(const std::string& peer_id);

    /**
     * @brief Get number of tracked peers
     * @return Count of peers with token buckets
     */
    size_t get_peer_count() const;

    /**
     * @brief Manually trigger cleanup of inactive peers
     * @param inactive_threshold Remove peers inactive for this duration
     * @return Number of peers removed
     */
    size_t cleanup_inactive(std::chrono::seconds inactive_threshold = std::chrono::minutes(5));

    /**
     * @brief Reset rate limit for specific peer (use with caution)
     * @param peer_id Peer agent ID
     */
    void reset_peer(const std::string& peer_id);

    /**
     * @brief Clear all rate limits (use with caution)
     */
    void clear();

private:
    /// Token refill rate (tokens per second)
    double rate_per_second_;

    /// Burst capacity (maximum tokens)
    double burst_capacity_;

    /// Token buckets per peer
    std::map<std::string, TokenBucket> peer_buckets_;

    /// Mutex for thread-safe access
    mutable std::mutex mutex_;

    /**
     * @brief Refill tokens for peer's bucket based on elapsed time
     * @param bucket Token bucket to refill
     */
    void refill_tokens(TokenBucket& bucket);

    /**
     * @brief Get or create token bucket for peer
     * @param peer_id Peer agent ID
     * @return Reference to peer's token bucket
     */
    TokenBucket& get_or_create_bucket(const std::string& peer_id);
};

} // namespace nlitp
