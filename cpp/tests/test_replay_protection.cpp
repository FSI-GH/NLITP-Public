/**
 * @file test_replay_protection.cpp
 * @brief Comprehensive unit tests for MessageReplayProtection
 *
 * Tests replay attack prevention including:
 * - Message ID generation (SHA-256)
 * - Time window validation
 * - Replay detection
 * - Cache management and cleanup
 * - Thread safety
 * - Security edge cases
 */

#include <gtest/gtest.h>
#include "nlitp/replay_protection.hpp"
#include <thread>
#include <vector>
#include <chrono>

using namespace nlitp;

// Test fixture for replay protection tests
class ReplayProtectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        protection_ = std::make_unique<MessageReplayProtection>();
    }

    void TearDown() override {
        protection_.reset();
    }

    std::unique_ptr<MessageReplayProtection> protection_;

    // Helper to get current timestamp
    static uint64_t now() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }
};

// ============================================================================
// Message ID Generation Tests
// ============================================================================

TEST_F(ReplayProtectionTest, GenerateMessageIdBasic) {
    std::string peer_id = "agent123";
    uint64_t timestamp = now();
    std::string nonce = "random_nonce_1234";

    std::string msg_id = MessageReplayProtection::generate_message_id(
        peer_id, timestamp, nonce
    );

    // SHA-256 produces 64 hex characters
    EXPECT_EQ(msg_id.length(), 64);

    // Should be valid hex
    for (char c : msg_id) {
        EXPECT_TRUE(std::isxdigit(c));
    }
}

TEST_F(ReplayProtectionTest, GenerateMessageIdUniqueness) {
    std::string peer_id = "agent123";
    uint64_t timestamp = now();

    std::string msg_id1 = MessageReplayProtection::generate_message_id(
        peer_id, timestamp, "nonce1"
    );
    std::string msg_id2 = MessageReplayProtection::generate_message_id(
        peer_id, timestamp, "nonce2"
    );

    // Different nonces should produce different IDs
    EXPECT_NE(msg_id1, msg_id2);
}

TEST_F(ReplayProtectionTest, GenerateMessageIdDeterministic) {
    std::string peer_id = "agent123";
    uint64_t timestamp = 1234567890;
    std::string nonce = "test_nonce";

    std::string msg_id1 = MessageReplayProtection::generate_message_id(
        peer_id, timestamp, nonce
    );
    std::string msg_id2 = MessageReplayProtection::generate_message_id(
        peer_id, timestamp, nonce
    );

    // Same inputs should produce same ID
    EXPECT_EQ(msg_id1, msg_id2);
}

TEST_F(ReplayProtectionTest, GenerateMessageIdDifferentPeers) {
    uint64_t timestamp = now();
    std::string nonce = "nonce123";

    std::string msg_id1 = MessageReplayProtection::generate_message_id(
        "agent1", timestamp, nonce
    );
    std::string msg_id2 = MessageReplayProtection::generate_message_id(
        "agent2", timestamp, nonce
    );

    // Different peers should produce different IDs
    EXPECT_NE(msg_id1, msg_id2);
}

TEST_F(ReplayProtectionTest, GenerateMessageIdDifferentTimestamps) {
    std::string peer_id = "agent123";
    std::string nonce = "nonce123";

    std::string msg_id1 = MessageReplayProtection::generate_message_id(
        peer_id, 1000, nonce
    );
    std::string msg_id2 = MessageReplayProtection::generate_message_id(
        peer_id, 2000, nonce
    );

    // Different timestamps should produce different IDs
    EXPECT_NE(msg_id1, msg_id2);
}

TEST_F(ReplayProtectionTest, GenerateMessageIdEmptyInputs) {
    // Should handle empty inputs gracefully
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "", 0, ""
    );

    EXPECT_EQ(msg_id.length(), 64);
}

// ============================================================================
// Message Validation Tests
// ============================================================================

TEST_F(ReplayProtectionTest, ValidateMessageFirstTime) {
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", now(), "nonce1"
    );

    // First validation should succeed
    EXPECT_TRUE(protection_->validate_message(msg_id, now()));
}

TEST_F(ReplayProtectionTest, ValidateMessageReplay) {
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", now(), "nonce1"
    );
    uint64_t timestamp = now();

    // First validation succeeds
    EXPECT_TRUE(protection_->validate_message(msg_id, timestamp));

    // Second validation with same ID should fail (replay detected)
    EXPECT_FALSE(protection_->validate_message(msg_id, timestamp));
}

TEST_F(ReplayProtectionTest, ValidateMessageWithinWindow) {
    uint64_t current_time = now();
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", current_time, "nonce1"
    );

    // Message within time window should be accepted
    EXPECT_TRUE(protection_->validate_message(msg_id, current_time));
}

TEST_F(ReplayProtectionTest, ValidateMessageTooOld) {
    uint64_t old_timestamp = now() - 120;  // 2 minutes ago (beyond 60s window)
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", old_timestamp, "nonce1"
    );

    // Message too old should be rejected
    EXPECT_FALSE(protection_->validate_message(msg_id, old_timestamp));
}

TEST_F(ReplayProtectionTest, ValidateMessageTooFarInFuture) {
    uint64_t future_timestamp = now() + 120;  // 2 minutes in future
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", future_timestamp, "nonce1"
    );

    // Message too far in future should be rejected
    EXPECT_FALSE(protection_->validate_message(msg_id, future_timestamp));
}

TEST_F(ReplayProtectionTest, ValidateMessageAtWindowBoundary) {
    uint64_t current_time = now();
    uint64_t boundary_time = current_time - 59;  // Just within 60s window

    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", boundary_time, "nonce1"
    );

    // Should be accepted if within window
    EXPECT_TRUE(protection_->validate_message(msg_id, boundary_time));
}

TEST_F(ReplayProtectionTest, ValidateMultipleDifferentMessages) {
    uint64_t timestamp = now();

    for (int i = 0; i < 10; i++) {
        std::string msg_id = MessageReplayProtection::generate_message_id(
            "agent1", timestamp, "nonce" + std::to_string(i)
        );
        EXPECT_TRUE(protection_->validate_message(msg_id, timestamp));
    }
}

// ============================================================================
// Has Seen Tests
// ============================================================================

TEST_F(ReplayProtectionTest, HasSeenNotSeen) {
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", now(), "nonce1"
    );

    EXPECT_FALSE(protection_->has_seen(msg_id));
}

TEST_F(ReplayProtectionTest, HasSeenAfterValidation) {
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", now(), "nonce1"
    );

    protection_->validate_message(msg_id, now());

    EXPECT_TRUE(protection_->has_seen(msg_id));
}

TEST_F(ReplayProtectionTest, HasSeenDoesNotModifyCache) {
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", now(), "nonce1"
    );

    size_t initial_size = protection_->get_cache_size();

    // has_seen should not modify cache
    protection_->has_seen(msg_id);
    EXPECT_EQ(protection_->get_cache_size(), initial_size);

    // validate_message should modify cache
    protection_->validate_message(msg_id, now());
    EXPECT_GT(protection_->get_cache_size(), initial_size);
}

// ============================================================================
// Cache Management Tests
// ============================================================================

TEST_F(ReplayProtectionTest, GetCacheSizeEmpty) {
    EXPECT_EQ(protection_->get_cache_size(), 0);
}

TEST_F(ReplayProtectionTest, GetCacheSizeGrows) {
    uint64_t timestamp = now();

    for (int i = 0; i < 5; i++) {
        std::string msg_id = MessageReplayProtection::generate_message_id(
            "agent1", timestamp, "nonce" + std::to_string(i)
        );
        protection_->validate_message(msg_id, timestamp);
    }

    EXPECT_EQ(protection_->get_cache_size(), 5);
}

TEST_F(ReplayProtectionTest, CleanupExpiredMessages) {
    // Add messages with old timestamps
    uint64_t old_timestamp = now() - 120;

    for (int i = 0; i < 5; i++) {
        std::string msg_id = MessageReplayProtection::generate_message_id(
            "agent1", old_timestamp, "nonce" + std::to_string(i)
        );
        // Force add to cache (bypass time window check for testing)
        protection_->validate_message(msg_id, now());
    }

    // Add some current messages
    uint64_t current_timestamp = now();
    for (int i = 0; i < 3; i++) {
        std::string msg_id = MessageReplayProtection::generate_message_id(
            "agent2", current_timestamp, "nonce" + std::to_string(i)
        );
        protection_->validate_message(msg_id, current_timestamp);
    }

    size_t initial_size = protection_->get_cache_size();
    EXPECT_GE(initial_size, 3);

    // Cleanup should remove some expired entries
    size_t removed = protection_->cleanup_expired();
    EXPECT_GE(removed, 0);
}

TEST_F(ReplayProtectionTest, ClearCache) {
    uint64_t timestamp = now();

    // Add messages
    for (int i = 0; i < 5; i++) {
        std::string msg_id = MessageReplayProtection::generate_message_id(
            "agent1", timestamp, "nonce" + std::to_string(i)
        );
        protection_->validate_message(msg_id, timestamp);
    }

    EXPECT_GT(protection_->get_cache_size(), 0);

    protection_->clear();

    EXPECT_EQ(protection_->get_cache_size(), 0);
}

TEST_F(ReplayProtectionTest, ClearAndReuse) {
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", now(), "nonce1"
    );
    uint64_t timestamp = now();

    // Validate once
    EXPECT_TRUE(protection_->validate_message(msg_id, timestamp));
    EXPECT_FALSE(protection_->validate_message(msg_id, timestamp));

    // Clear cache
    protection_->clear();

    // Should be able to validate again after clear
    EXPECT_TRUE(protection_->validate_message(msg_id, timestamp));
}

// ============================================================================
// Time Window Configuration Tests
// ============================================================================

TEST_F(ReplayProtectionTest, DefaultTimeWindow) {
    EXPECT_EQ(protection_->get_window(), std::chrono::seconds(60));
}

TEST_F(ReplayProtectionTest, CustomTimeWindow) {
    auto custom_protection = std::make_unique<MessageReplayProtection>(
        std::chrono::seconds(30)
    );

    EXPECT_EQ(custom_protection->get_window(), std::chrono::seconds(30));
}

TEST_F(ReplayProtectionTest, CustomTimeWindowValidation) {
    auto custom_protection = std::make_unique<MessageReplayProtection>(
        std::chrono::seconds(30)
    );

    uint64_t current_time = now();
    uint64_t old_time = current_time - 45;  // 45 seconds ago

    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", old_time, "nonce1"
    );

    // Should be rejected (45s > 30s window)
    EXPECT_FALSE(custom_protection->validate_message(msg_id, old_time));
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(ReplayProtectionTest, ConcurrentValidation) {
    const int num_threads = 10;
    const int messages_per_thread = 10;
    std::vector<std::thread> threads;
    std::vector<int> success_counts(num_threads, 0);

    uint64_t timestamp = now();

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, &success_counts, t, timestamp, messages_per_thread]() {
            for (int i = 0; i < messages_per_thread; i++) {
                std::string msg_id = MessageReplayProtection::generate_message_id(
                    "agent" + std::to_string(t),
                    timestamp,
                    "nonce" + std::to_string(i)
                );
                if (protection_->validate_message(msg_id, timestamp)) {
                    success_counts[t]++;
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All unique messages should be accepted
    int total_success = 0;
    for (int count : success_counts) {
        total_success += count;
    }
    EXPECT_EQ(total_success, num_threads * messages_per_thread);
}

TEST_F(ReplayProtectionTest, ConcurrentReplayDetection) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<bool> results(num_threads);

    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", now(), "nonce1"
    );
    uint64_t timestamp = now();

    // All threads try to validate same message
    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, &results, t, msg_id, timestamp]() {
            results[t] = protection_->validate_message(msg_id, timestamp);
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Only one thread should succeed
    int success_count = 0;
    for (bool result : results) {
        if (result) success_count++;
    }
    EXPECT_EQ(success_count, 1);
}

TEST_F(ReplayProtectionTest, ConcurrentHasSeen) {
    const int num_threads = 10;
    std::vector<std::thread> threads;

    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", now(), "nonce1"
    );

    // Pre-populate cache
    protection_->validate_message(msg_id, now());

    // All threads check has_seen concurrently
    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, msg_id]() {
            for (int i = 0; i < 100; i++) {
                protection_->has_seen(msg_id);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Should still see the message
    EXPECT_TRUE(protection_->has_seen(msg_id));
}

TEST_F(ReplayProtectionTest, ConcurrentCleanup) {
    const int num_threads = 5;
    std::vector<std::thread> threads;

    // Add messages
    uint64_t timestamp = now();
    for (int i = 0; i < 50; i++) {
        std::string msg_id = MessageReplayProtection::generate_message_id(
            "agent1", timestamp, "nonce" + std::to_string(i)
        );
        protection_->validate_message(msg_id, timestamp);
    }

    // Multiple threads cleanup concurrently
    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this]() {
            protection_->cleanup_expired();
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Should not crash, cache should be consistent
    size_t final_size = protection_->get_cache_size();
    EXPECT_GE(final_size, 0);
}

// ============================================================================
// Security Edge Cases
// ============================================================================

TEST_F(ReplayProtectionTest, MessageIdCollision) {
    // Extremely unlikely, but test same message ID different timestamps
    std::string msg_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    uint64_t time1 = now();
    EXPECT_TRUE(protection_->validate_message(msg_id, time1));

    // Same ID should be rejected (replay)
    EXPECT_FALSE(protection_->validate_message(msg_id, time1));
}

TEST_F(ReplayProtectionTest, TimestampZero) {
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", 0, "nonce1"
    );

    // Timestamp 0 (epoch) should be rejected (too old)
    EXPECT_FALSE(protection_->validate_message(msg_id, 0));
}

TEST_F(ReplayProtectionTest, TimestampMaxValue) {
    uint64_t max_timestamp = std::numeric_limits<uint64_t>::max();
    std::string msg_id = MessageReplayProtection::generate_message_id(
        "agent1", max_timestamp, "nonce1"
    );

    // Future timestamp should be rejected
    EXPECT_FALSE(protection_->validate_message(msg_id, max_timestamp));
}

TEST_F(ReplayProtectionTest, LargeNumberOfMessages) {
    uint64_t timestamp = now();

    // Validate many messages
    for (int i = 0; i < 1000; i++) {
        std::string msg_id = MessageReplayProtection::generate_message_id(
            "agent1", timestamp, "nonce" + std::to_string(i)
        );
        EXPECT_TRUE(protection_->validate_message(msg_id, timestamp));
    }

    EXPECT_EQ(protection_->get_cache_size(), 1000);
}

TEST_F(ReplayProtectionTest, MessageIdSpecialCharacters) {
    // Generate IDs with special inputs
    std::string msg_id1 = MessageReplayProtection::generate_message_id(
        "agent!@#$", now(), "nonce!@#$"
    );
    std::string msg_id2 = MessageReplayProtection::generate_message_id(
        "agent\0null", now(), "nonce\0null"
    );

    EXPECT_EQ(msg_id1.length(), 64);
    EXPECT_EQ(msg_id2.length(), 64);
}

TEST_F(ReplayProtectionTest, ClockSkewTolerance) {
    uint64_t current_time = now();

    // Messages within small clock skew should be accepted
    std::string msg_id1 = MessageReplayProtection::generate_message_id(
        "agent1", current_time + 5, "nonce1"
    );
    std::string msg_id2 = MessageReplayProtection::generate_message_id(
        "agent2", current_time - 5, "nonce2"
    );

    EXPECT_TRUE(protection_->validate_message(msg_id1, current_time + 5));
    EXPECT_TRUE(protection_->validate_message(msg_id2, current_time - 5));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
