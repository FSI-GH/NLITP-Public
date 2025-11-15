/**
 * @file rate_limiter.cpp
 * @brief Implementation of token bucket rate limiting
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 */

#include "nlitp/rate_limiter.hpp"
#include <algorithm>

namespace nlitp {

// ============================================================================
// Constructor
// ============================================================================

RateLimiter::RateLimiter(double rate_per_second, double burst_capacity)
    : rate_per_second_(rate_per_second)
    , burst_capacity_(burst_capacity)
{
}

// ============================================================================
// Rate Limiting
// ============================================================================

bool RateLimiter::allow_message(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Get or create token bucket for peer
    TokenBucket& bucket = get_or_create_bucket(peer_id);

    // Refill tokens based on elapsed time
    refill_tokens(bucket);

    // Check if tokens available
    if (bucket.tokens >= 1.0) {
        // Consume 1 token
        bucket.tokens -= 1.0;
        return true;
    }

    // Rate limit exceeded
    return false;
}

bool RateLimiter::check_message(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Get or create token bucket for peer
    TokenBucket& bucket = get_or_create_bucket(peer_id);

    // Refill tokens based on elapsed time
    refill_tokens(bucket);

    // Check if tokens available (without consuming)
    return bucket.tokens >= 1.0;
}

double RateLimiter::get_tokens(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = peer_buckets_.find(peer_id);
    if (it == peer_buckets_.end()) {
        return 0.0;
    }

    // Refill tokens before returning count
    refill_tokens(it->second);

    return it->second.tokens;
}

// ============================================================================
// Token Bucket Management
// ============================================================================

void RateLimiter::refill_tokens(TokenBucket& bucket) {
    auto now = std::chrono::steady_clock::now();

    // Calculate elapsed time since last refill
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - bucket.last_refill
    ).count();

    if (elapsed > 0) {
        // Calculate tokens to add based on elapsed time
        double seconds_elapsed = elapsed / 1000.0;
        double tokens_to_add = seconds_elapsed * bucket.refill_rate;

        // Add tokens (capped at capacity)
        bucket.tokens = std::min(bucket.tokens + tokens_to_add, bucket.capacity);

        // Update last refill time
        bucket.last_refill = now;
    }
}

TokenBucket& RateLimiter::get_or_create_bucket(const std::string& peer_id) {
    auto it = peer_buckets_.find(peer_id);

    if (it == peer_buckets_.end()) {
        // Create new token bucket for peer
        auto result = peer_buckets_.emplace(
            peer_id,
            TokenBucket(rate_per_second_, burst_capacity_)
        );
        return result.first->second;
    }

    return it->second;
}

// ============================================================================
// Management Functions
// ============================================================================

size_t RateLimiter::get_peer_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return peer_buckets_.size();
}

size_t RateLimiter::cleanup_inactive(std::chrono::seconds inactive_threshold) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    size_t removed = 0;

    // Remove peers inactive for longer than threshold
    for (auto it = peer_buckets_.begin(); it != peer_buckets_.end(); ) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_refill
        );

        if (elapsed > inactive_threshold) {
            it = peer_buckets_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }

    return removed;
}

void RateLimiter::reset_peer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = peer_buckets_.find(peer_id);
    if (it != peer_buckets_.end()) {
        // Reset bucket to full capacity
        it->second.tokens = it->second.capacity;
        it->second.last_refill = std::chrono::steady_clock::now();
    }
}

void RateLimiter::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    peer_buckets_.clear();
}

} // namespace nlitp
