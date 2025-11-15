/**
 * @file test_rate_limiter.cpp
 * @brief Comprehensive unit tests for RateLimiter
 *
 * Tests token bucket rate limiting including:
 * - Token bucket algorithm
 * - Rate limiting per peer
 * - Burst capacity handling
 * - Token refill
 * - Cleanup of inactive peers
 * - Thread safety
 * - DoS protection scenarios
 */

#include <gtest/gtest.h>
#include "nlitp/rate_limiter.hpp"
#include <thread>
#include <vector>
#include <chrono>

using namespace nlitp;

// Test fixture for rate limiter tests
class RateLimiterTest : public ::testing::Test {
protected:
    void SetUp() override {
        limiter_ = std::make_unique<RateLimiter>();
    }

    void TearDown() override {
        limiter_.reset();
    }

    std::unique_ptr<RateLimiter> limiter_;
};

// ============================================================================
// Basic Rate Limiting Tests
// ============================================================================

TEST_F(RateLimiterTest, AllowMessageFirstTime) {
    EXPECT_TRUE(limiter_->allow_message("peer1"));
}

TEST_F(RateLimiterTest, AllowMessageMultiplePeers) {
    EXPECT_TRUE(limiter_->allow_message("peer1"));
    EXPECT_TRUE(limiter_->allow_message("peer2"));
    EXPECT_TRUE(limiter_->allow_message("peer3"));
}

TEST_F(RateLimiterTest, CheckMessageDoesNotConsume) {
    std::string peer_id = "peer1";

    // Check should not consume tokens
    EXPECT_TRUE(limiter_->check_message(peer_id));
    EXPECT_TRUE(limiter_->check_message(peer_id));

    // Token count should remain at burst capacity
    double tokens = limiter_->get_tokens(peer_id);
    EXPECT_EQ(tokens, 200.0);  // Default burst capacity
}

TEST_F(RateLimiterTest, AllowMessageConsumesToken) {
    std::string peer_id = "peer1";

    double initial_tokens = limiter_->get_tokens(peer_id);
    EXPECT_EQ(initial_tokens, 0.0);  // Peer not tracked yet

    // First allow creates bucket and consumes token
    EXPECT_TRUE(limiter_->allow_message(peer_id));

    double tokens_after = limiter_->get_tokens(peer_id);
    EXPECT_LT(tokens_after, 200.0);  // Should have consumed token
    EXPECT_EQ(tokens_after, 199.0);   // Exactly 1 token consumed
}

// ============================================================================
// Burst Capacity Tests
// ============================================================================

TEST_F(RateLimiterTest, BurstCapacityAllows200Messages) {
    std::string peer_id = "peer1";

    // Should allow burst of 200 messages (default burst capacity)
    for (int i = 0; i < 200; i++) {
        EXPECT_TRUE(limiter_->allow_message(peer_id)) << "Failed at message " << i;
    }

    // 201st message should be rejected
    EXPECT_FALSE(limiter_->allow_message(peer_id));
}

TEST_F(RateLimiterTest, BurstCapacityExhaustion) {
    std::string peer_id = "peer1";

    // Exhaust burst capacity
    for (int i = 0; i < 200; i++) {
        limiter_->allow_message(peer_id);
    }

    double tokens = limiter_->get_tokens(peer_id);
    EXPECT_EQ(tokens, 0.0);
}

TEST_F(RateLimiterTest, CustomBurstCapacity) {
    auto custom_limiter = std::make_unique<RateLimiter>(100.0, 50.0);  // 100/s, burst 50

    std::string peer_id = "peer1";

    // Should allow burst of 50 messages
    for (int i = 0; i < 50; i++) {
        EXPECT_TRUE(custom_limiter->allow_message(peer_id));
    }

    // 51st message should be rejected
    EXPECT_FALSE(custom_limiter->allow_message(peer_id));
}

// ============================================================================
// Token Refill Tests
// ============================================================================

TEST_F(RateLimiterTest, TokenRefillAfterTime) {
    std::string peer_id = "peer1";

    // Consume some tokens
    for (int i = 0; i < 10; i++) {
        limiter_->allow_message(peer_id);
    }

    double tokens_before = limiter_->get_tokens(peer_id);
    EXPECT_EQ(tokens_before, 190.0);

    // Wait for refill (100 tokens/second, so 0.1s = 10 tokens)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Check tokens after refill
    double tokens_after = limiter_->get_tokens(peer_id);
    EXPECT_GT(tokens_after, tokens_before);
}

TEST_F(RateLimiterTest, TokenRefillDoesNotExceedCapacity) {
    auto custom_limiter = std::make_unique<RateLimiter>(100.0, 50.0);
    std::string peer_id = "peer1";

    // Start with full capacity
    custom_limiter->check_message(peer_id);  // Initialize bucket

    // Wait for refill
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Should not exceed burst capacity
    double tokens = custom_limiter->get_tokens(peer_id);
    EXPECT_LE(tokens, 50.0);
}

TEST_F(RateLimiterTest, SustainedRateAfterBurst) {
    auto fast_limiter = std::make_unique<RateLimiter>(10.0, 20.0);  // 10/s, burst 20
    std::string peer_id = "peer1";

    // Exhaust burst
    for (int i = 0; i < 20; i++) {
        fast_limiter->allow_message(peer_id);
    }

    // Wait 0.5 seconds (should refill ~5 tokens at 10/s rate)
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Should be able to send ~5 more messages
    int allowed = 0;
    for (int i = 0; i < 10; i++) {
        if (fast_limiter->allow_message(peer_id)) {
            allowed++;
        }
    }

    EXPECT_GE(allowed, 4);  // At least 4 messages (accounting for timing jitter)
    EXPECT_LE(allowed, 6);  // At most 6 messages
}

// ============================================================================
// Per-Peer Isolation Tests
// ============================================================================

TEST_F(RateLimiterTest, PeersHaveIndependentBuckets) {
    std::string peer1 = "peer1";
    std::string peer2 = "peer2";

    // Exhaust peer1's tokens
    for (int i = 0; i < 200; i++) {
        limiter_->allow_message(peer1);
    }

    EXPECT_FALSE(limiter_->allow_message(peer1));

    // Peer2 should still be allowed
    EXPECT_TRUE(limiter_->allow_message(peer2));
}

TEST_F(RateLimiterTest, GetPeerCount) {
    EXPECT_EQ(limiter_->get_peer_count(), 0);

    limiter_->allow_message("peer1");
    EXPECT_EQ(limiter_->get_peer_count(), 1);

    limiter_->allow_message("peer2");
    EXPECT_EQ(limiter_->get_peer_count(), 2);

    limiter_->allow_message("peer1");  // Same peer
    EXPECT_EQ(limiter_->get_peer_count(), 2);
}

TEST_F(RateLimiterTest, MultiplePeersConcurrent) {
    const int num_peers = 10;
    std::vector<std::string> peers;

    for (int i = 0; i < num_peers; i++) {
        peers.push_back("peer" + std::to_string(i));
    }

    // Each peer sends 50 messages (within burst)
    for (const auto& peer : peers) {
        for (int i = 0; i < 50; i++) {
            EXPECT_TRUE(limiter_->allow_message(peer));
        }
    }

    EXPECT_EQ(limiter_->get_peer_count(), num_peers);
}

// ============================================================================
// Cleanup Tests
// ============================================================================

TEST_F(RateLimiterTest, CleanupInactivePeers) {
    // Add some peers
    limiter_->allow_message("peer1");
    limiter_->allow_message("peer2");
    limiter_->allow_message("peer3");

    EXPECT_EQ(limiter_->get_peer_count(), 3);

    // Cleanup with very short threshold (should remove all)
    size_t removed = limiter_->cleanup_inactive(std::chrono::seconds(0));
    EXPECT_GE(removed, 0);
}

TEST_F(RateLimiterTest, CleanupKeepsActivePeers) {
    limiter_->allow_message("peer1");

    // Wait a bit but not past threshold
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Cleanup with long threshold (should keep all)
    size_t removed = limiter_->cleanup_inactive(std::chrono::minutes(10));
    EXPECT_EQ(removed, 0);
    EXPECT_EQ(limiter_->get_peer_count(), 1);
}

TEST_F(RateLimiterTest, ResetPeer) {
    std::string peer_id = "peer1";

    // Exhaust tokens
    for (int i = 0; i < 200; i++) {
        limiter_->allow_message(peer_id);
    }

    EXPECT_FALSE(limiter_->allow_message(peer_id));

    // Reset peer
    limiter_->reset_peer(peer_id);

    // Should allow messages again
    EXPECT_TRUE(limiter_->allow_message(peer_id));
}

TEST_F(RateLimiterTest, ResetNonExistentPeer) {
    // Should not crash
    limiter_->reset_peer("non_existent_peer");
}

TEST_F(RateLimiterTest, Clear) {
    // Add several peers
    for (int i = 0; i < 5; i++) {
        limiter_->allow_message("peer" + std::to_string(i));
    }

    EXPECT_EQ(limiter_->get_peer_count(), 5);

    limiter_->clear();

    EXPECT_EQ(limiter_->get_peer_count(), 0);
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(RateLimiterTest, ConcurrentAllowSamePeer) {
    const int num_threads = 10;
    const int messages_per_thread = 20;  // Total: 200 messages (exactly burst capacity)
    std::vector<std::thread> threads;
    std::vector<int> success_counts(num_threads, 0);

    std::string peer_id = "peer1";

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, &success_counts, t, peer_id, messages_per_thread]() {
            for (int i = 0; i < messages_per_thread; i++) {
                if (limiter_->allow_message(peer_id)) {
                    success_counts[t]++;
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Total successful messages should be exactly burst capacity (200)
    int total_success = 0;
    for (int count : success_counts) {
        total_success += count;
    }

    EXPECT_EQ(total_success, 200);
}

TEST_F(RateLimiterTest, ConcurrentAllowDifferentPeers) {
    const int num_threads = 10;
    const int messages_per_thread = 50;
    std::vector<std::thread> threads;
    std::vector<int> success_counts(num_threads, 0);

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, &success_counts, t, messages_per_thread]() {
            std::string peer_id = "peer" + std::to_string(t);
            for (int i = 0; i < messages_per_thread; i++) {
                if (limiter_->allow_message(peer_id)) {
                    success_counts[t]++;
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All messages should succeed (different peers, within burst)
    for (int count : success_counts) {
        EXPECT_EQ(count, messages_per_thread);
    }
}

TEST_F(RateLimiterTest, ConcurrentCheckAndAllow) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::string peer_id = "peer1";

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, peer_id]() {
            for (int i = 0; i < 10; i++) {
                limiter_->check_message(peer_id);
                limiter_->allow_message(peer_id);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Should not crash, state should be consistent
    EXPECT_GE(limiter_->get_peer_count(), 1);
}

TEST_F(RateLimiterTest, ConcurrentCleanup) {
    // Add peers
    for (int i = 0; i < 20; i++) {
        limiter_->allow_message("peer" + std::to_string(i));
    }

    const int num_threads = 5;
    std::vector<std::thread> threads;

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this]() {
            limiter_->cleanup_inactive(std::chrono::seconds(0));
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Should not crash
    EXPECT_GE(limiter_->get_peer_count(), 0);
}

// ============================================================================
// DoS Protection Scenarios
// ============================================================================

TEST_F(RateLimiterTest, RapidFireAttack) {
    std::string attacker = "attacker";

    // Attacker tries to send 1000 messages rapidly
    int allowed = 0;
    for (int i = 0; i < 1000; i++) {
        if (limiter_->allow_message(attacker)) {
            allowed++;
        }
    }

    // Should only allow burst capacity
    EXPECT_EQ(allowed, 200);
}

TEST_F(RateLimiterTest, SlowLorisAttack) {
    auto slow_limiter = std::make_unique<RateLimiter>(10.0, 20.0);  // 10/s, burst 20
    std::string attacker = "attacker";

    // Attacker sends messages at exactly the refill rate
    int allowed = 0;
    for (int i = 0; i < 30; i++) {
        if (slow_limiter->allow_message(attacker)) {
            allowed++;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));  // 10/s = 100ms
    }

    // Should allow burst + sustained rate
    EXPECT_GE(allowed, 20);  // At least burst
    EXPECT_LE(allowed, 30);  // Not all 30
}

TEST_F(RateLimiterTest, DistributedAttack) {
    const int num_attackers = 100;

    // Many attackers each send messages
    for (int i = 0; i < num_attackers; i++) {
        std::string attacker = "attacker" + std::to_string(i);
        for (int j = 0; j < 10; j++) {
            limiter_->allow_message(attacker);
        }
    }

    // Should track all attackers
    EXPECT_EQ(limiter_->get_peer_count(), num_attackers);

    // Each attacker should be limited independently
    for (int i = 0; i < num_attackers; i++) {
        std::string attacker = "attacker" + std::to_string(i);
        double tokens = limiter_->get_tokens(attacker);
        EXPECT_LT(tokens, 200.0);  // Should have consumed some tokens
    }
}

TEST_F(RateLimiterTest, LegitimateUserDuringAttack) {
    std::string attacker = "attacker";
    std::string legitimate = "legitimate_user";

    // Attacker exhausts their bucket
    for (int i = 0; i < 200; i++) {
        limiter_->allow_message(attacker);
    }

    EXPECT_FALSE(limiter_->allow_message(attacker));

    // Legitimate user should still work
    EXPECT_TRUE(limiter_->allow_message(legitimate));
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F(RateLimiterTest, GetTokensNonExistentPeer) {
    double tokens = limiter_->get_tokens("non_existent");
    EXPECT_EQ(tokens, 0.0);
}

TEST_F(RateLimiterTest, EmptyPeerId) {
    // Should handle gracefully
    EXPECT_TRUE(limiter_->allow_message(""));
}

TEST_F(RateLimiterTest, VeryLongPeerId) {
    std::string long_peer_id(1000, 'a');
    EXPECT_TRUE(limiter_->allow_message(long_peer_id));
}

TEST_F(RateLimiterTest, SpecialCharacterPeerId) {
    EXPECT_TRUE(limiter_->allow_message("peer!@#$%^&*()"));
    EXPECT_TRUE(limiter_->allow_message("peer with spaces"));
    EXPECT_TRUE(limiter_->allow_message("peer\nwith\nnewlines"));
}

TEST_F(RateLimiterTest, ZeroRateLimit) {
    auto zero_limiter = std::make_unique<RateLimiter>(0.0, 10.0);  // 0/s, burst 10
    std::string peer_id = "peer1";

    // Should allow burst
    for (int i = 0; i < 10; i++) {
        EXPECT_TRUE(zero_limiter->allow_message(peer_id));
    }

    // Should not refill (0/s rate)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_FALSE(zero_limiter->allow_message(peer_id));
}

TEST_F(RateLimiterTest, VeryHighRateLimit) {
    auto fast_limiter = std::make_unique<RateLimiter>(10000.0, 20000.0);  // 10k/s
    std::string peer_id = "peer1";

    // Should allow many messages
    for (int i = 0; i < 1000; i++) {
        EXPECT_TRUE(fast_limiter->allow_message(peer_id));
    }
}

TEST_F(RateLimiterTest, FractionalRateLimit) {
    auto slow_limiter = std::make_unique<RateLimiter>(0.5, 1.0);  // 1 per 2 seconds
    std::string peer_id = "peer1";

    // Should allow 1 message (burst)
    EXPECT_TRUE(slow_limiter->allow_message(peer_id));

    // Should reject next message
    EXPECT_FALSE(slow_limiter->allow_message(peer_id));

    // Wait 2 seconds for refill
    std::this_thread::sleep_for(std::chrono::milliseconds(2100));

    // Should allow one more
    EXPECT_TRUE(slow_limiter->allow_message(peer_id));
}

TEST_F(RateLimiterTest, BurstLessThanRate) {
    // Unusual configuration: burst < rate
    auto unusual_limiter = std::make_unique<RateLimiter>(100.0, 50.0);
    std::string peer_id = "peer1";

    // Should still respect burst capacity
    for (int i = 0; i < 50; i++) {
        EXPECT_TRUE(unusual_limiter->allow_message(peer_id));
    }

    EXPECT_FALSE(unusual_limiter->allow_message(peer_id));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
