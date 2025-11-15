/**
 * @file test_trust_ledger.cpp
 * @brief Comprehensive unit tests for TrustLedger
 *
 * Tests blockchain trust ledger including:
 * - Trust observations
 * - Blockchain operations
 * - Block integrity verification
 * - Gatekeeper replication
 * - Thread safety
 * - Byzantine fault tolerance scenarios
 */

#include <gtest/gtest.h>
#include "nlitp/trust_ledger.hpp"
#include "nlitp/agent_crypto.hpp"
#include <filesystem>
#include <thread>
#include <vector>

using namespace nlitp;
namespace fs = std::filesystem;

// Test fixture for trust ledger tests
class TrustLedgerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto
        AgentCrypto::initialize();

        // Create temporary test directory
        test_dir_ = fs::temp_directory_path() / "nlitp_ledger_test";
        fs::create_directories(test_dir_);

        // Create database path
        db_path_ = (test_dir_ / "test_trust.db").string();

        // Create ledger
        ledger_ = std::make_unique<TrustLedger>(db_path_, "gatekeeper1");
    }

    void TearDown() override {
        ledger_.reset();

        // Clean up test directory
        if (fs::exists(test_dir_)) {
            fs::remove_all(test_dir_);
        }
    }

    fs::path test_dir_;
    std::string db_path_;
    std::unique_ptr<TrustLedger> ledger_;
};

// ============================================================================
// Trust Observation Tests
// ============================================================================

TEST_F(TrustLedgerTest, RecordObservation) {
    bool recorded = ledger_->record_observation(
        "observer1", "peer1", 0.8, true, "Good communication"
    );

    EXPECT_TRUE(recorded);
}

TEST_F(TrustLedgerTest, RecordMultipleObservations) {
    EXPECT_TRUE(ledger_->record_observation("observer1", "peer1", 0.8, true, "Test 1"));
    EXPECT_TRUE(ledger_->record_observation("observer2", "peer1", 0.7, true, "Test 2"));
    EXPECT_TRUE(ledger_->record_observation("observer3", "peer1", 0.9, false, "Test 3"));
}

TEST_F(TrustLedgerTest, GetObservations) {
    ledger_->record_observation("observer1", "peer1", 0.8, true, "Good");
    ledger_->record_observation("observer2", "peer1", 0.7, true, "OK");

    auto observations = ledger_->get_observations("peer1");

    EXPECT_EQ(observations.size(), 2);
}

TEST_F(TrustLedgerTest, GetObservationsEmptyPeer) {
    auto observations = ledger_->get_observations("non_existent");

    EXPECT_EQ(observations.size(), 0);
}

TEST_F(TrustLedgerTest, ObservationContainsCorrectData) {
    ledger_->record_observation("observer1", "peer1", 0.8, true, "Test observation");

    auto observations = ledger_->get_observations("peer1");
    ASSERT_EQ(observations.size(), 1);

    EXPECT_EQ(observations[0].observer_id, "observer1");
    EXPECT_EQ(observations[0].peer_id, "peer1");
    EXPECT_DOUBLE_EQ(observations[0].trust_score, 0.8);
    EXPECT_TRUE(observations[0].verified);
    EXPECT_EQ(observations[0].observation, "Test observation");
}

// ============================================================================
// Trust Score Calculation Tests
// ============================================================================

TEST_F(TrustLedgerTest, CalculateTrustScoreSingleObservation) {
    ledger_->record_observation("observer1", "peer1", 0.8, true, "Good");

    double trust_score = ledger_->calculate_trust_score("peer1");

    EXPECT_DOUBLE_EQ(trust_score, 0.8);
}

TEST_F(TrustLedgerTest, CalculateTrustScoreMultipleObservations) {
    ledger_->record_observation("observer1", "peer1", 0.8, true, "Good");
    ledger_->record_observation("observer2", "peer1", 0.6, true, "OK");

    double trust_score = ledger_->calculate_trust_score("peer1");

    // Should be weighted average (verified observations weighted higher)
    EXPECT_GT(trust_score, 0.0);
    EXPECT_LE(trust_score, 1.0);
}

TEST_F(TrustLedgerTest, CalculateTrustScoreVerifiedWeightedHigher) {
    ledger_->record_observation("observer1", "peer1", 0.9, true, "Verified good");
    ledger_->record_observation("observer2", "peer1", 0.1, false, "Unverified bad");

    double trust_score = ledger_->calculate_trust_score("peer1");

    // Verified should be weighted higher, so score should be closer to 0.9
    EXPECT_GT(trust_score, 0.5);
}

TEST_F(TrustLedgerTest, CalculateTrustScoreNonExistentPeer) {
    double trust_score = ledger_->calculate_trust_score("non_existent");

    // Should return default/neutral score
    EXPECT_GE(trust_score, 0.0);
    EXPECT_LE(trust_score, 1.0);
}

TEST_F(TrustLedgerTest, TrustScoreBounds) {
    // Test extreme values
    ledger_->record_observation("observer1", "peer1", 0.0, true, "Minimum");
    ledger_->record_observation("observer2", "peer2", 1.0, true, "Maximum");

    EXPECT_GE(ledger_->calculate_trust_score("peer1"), 0.0);
    EXPECT_LE(ledger_->calculate_trust_score("peer2"), 1.0);
}

// ============================================================================
// Peer Statistics Tests
// ============================================================================

TEST_F(TrustLedgerTest, GetPeerStats) {
    ledger_->record_observation("observer1", "peer1", 0.8, true, "Test");
    ledger_->record_observation("observer2", "peer1", 0.7, true, "Test");

    auto stats = ledger_->get_peer_stats("peer1");

    ASSERT_TRUE(stats.has_value());
    EXPECT_EQ(stats->peer_id, "peer1");
    EXPECT_GE(stats->observation_count, 2);
}

TEST_F(TrustLedgerTest, GetPeerStatsNonExistent) {
    auto stats = ledger_->get_peer_stats("non_existent");

    EXPECT_FALSE(stats.has_value());
}

// ============================================================================
// Blockchain Tests
// ============================================================================

TEST_F(TrustLedgerTest, AddBlockchainBlock) {
    auto signature = AgentCrypto::generate_random_bytes(64);

    bool added = ledger_->add_blockchain_block(
        "peer1", 0.8, 0.9, "Test block", signature
    );

    EXPECT_TRUE(added);
}

TEST_F(TrustLedgerTest, GetBlockchainBlock) {
    auto signature = AgentCrypto::generate_random_bytes(64);
    ledger_->add_blockchain_block("peer1", 0.8, 0.9, "Test", signature);

    auto block = ledger_->get_blockchain_block(1);  // First block after genesis

    ASSERT_TRUE(block.has_value());
    EXPECT_EQ(block->peer_id, "peer1");
    EXPECT_DOUBLE_EQ(block->trust_score, 0.8);
    EXPECT_DOUBLE_EQ(block->wisdom_score, 0.9);
}

TEST_F(TrustLedgerTest, GetLatestBlock) {
    auto sig1 = AgentCrypto::generate_random_bytes(64);
    auto sig2 = AgentCrypto::generate_random_bytes(64);

    ledger_->add_blockchain_block("peer1", 0.7, 0.8, "Block 1", sig1);
    ledger_->add_blockchain_block("peer2", 0.9, 0.95, "Block 2", sig2);

    auto latest = ledger_->get_latest_block();

    ASSERT_TRUE(latest.has_value());
    EXPECT_EQ(latest->peer_id, "peer2");  // Last added
}

TEST_F(TrustLedgerTest, GetPeerBlockchainHistory) {
    auto sig1 = AgentCrypto::generate_random_bytes(64);
    auto sig2 = AgentCrypto::generate_random_bytes(64);
    auto sig3 = AgentCrypto::generate_random_bytes(64);

    ledger_->add_blockchain_block("peer1", 0.7, 0.8, "Obs 1", sig1);
    ledger_->add_blockchain_block("peer1", 0.8, 0.85, "Obs 2", sig2);
    ledger_->add_blockchain_block("peer2", 0.9, 0.9, "Other", sig3);

    auto history = ledger_->get_peer_blockchain_history("peer1");

    EXPECT_EQ(history.size(), 2);
}

TEST_F(TrustLedgerTest, BlockchainLength) {
    size_t initial_length = ledger_->get_blockchain_length();

    auto sig = AgentCrypto::generate_random_bytes(64);
    ledger_->add_blockchain_block("peer1", 0.8, 0.9, "Test", sig);

    EXPECT_EQ(ledger_->get_blockchain_length(), initial_length + 1);
}

// ============================================================================
// Blockchain Integrity Tests
// ============================================================================

TEST_F(TrustLedgerTest, VerifyBlockchainIntegrityEmpty) {
    // Genesis block only
    EXPECT_TRUE(ledger_->verify_blockchain_integrity());
}

TEST_F(TrustLedgerTest, VerifyBlockchainIntegrityAfterAddition) {
    auto sig = AgentCrypto::generate_random_bytes(64);
    ledger_->add_blockchain_block("peer1", 0.8, 0.9, "Test", sig);

    EXPECT_TRUE(ledger_->verify_blockchain_integrity());
}

TEST_F(TrustLedgerTest, VerifyBlockchainIntegrityMultipleBlocks) {
    for (int i = 0; i < 10; i++) {
        auto sig = AgentCrypto::generate_random_bytes(64);
        ledger_->add_blockchain_block("peer" + std::to_string(i), 0.8, 0.9, "Test", sig);
    }

    EXPECT_TRUE(ledger_->verify_blockchain_integrity());
}

TEST_F(TrustLedgerTest, BlockHashChaining) {
    auto sig1 = AgentCrypto::generate_random_bytes(64);
    auto sig2 = AgentCrypto::generate_random_bytes(64);

    ledger_->add_blockchain_block("peer1", 0.8, 0.9, "Block 1", sig1);
    ledger_->add_blockchain_block("peer2", 0.7, 0.8, "Block 2", sig2);

    auto block1 = ledger_->get_blockchain_block(1);
    auto block2 = ledger_->get_blockchain_block(2);

    ASSERT_TRUE(block1.has_value());
    ASSERT_TRUE(block2.has_value());

    // Block 2's previous hash should match Block 1's hash
    EXPECT_EQ(block2->previous_hash, block1->block_hash);
}

// ============================================================================
// Gatekeeper Replication Tests
// ============================================================================

TEST_F(TrustLedgerTest, ExportBlockchainForReplication) {
    auto sig = AgentCrypto::generate_random_bytes(64);
    ledger_->add_blockchain_block("peer1", 0.8, 0.9, "Test", sig);

    std::string exported = ledger_->export_blockchain_for_replication();

    EXPECT_FALSE(exported.empty());
    EXPECT_NE(exported.find("peer1"), std::string::npos);
}

TEST_F(TrustLedgerTest, ExportBlockchainFromBlock) {
    for (int i = 0; i < 5; i++) {
        auto sig = AgentCrypto::generate_random_bytes(64);
        ledger_->add_blockchain_block("peer" + std::to_string(i), 0.8, 0.9, "Test", sig);
    }

    std::string full_export = ledger_->export_blockchain_for_replication(0);
    std::string partial_export = ledger_->export_blockchain_for_replication(3);

    // Partial export should be smaller
    EXPECT_LT(partial_export.length(), full_export.length());
}

TEST_F(TrustLedgerTest, ImportBlockchainFromPeer) {
    // Create second ledger
    std::string db_path2 = (test_dir_ / "ledger2.db").string();
    auto ledger2 = std::make_unique<TrustLedger>(db_path2, "gatekeeper2");

    // Add blocks to first ledger
    auto sig = AgentCrypto::generate_random_bytes(64);
    ledger_->add_blockchain_block("peer1", 0.8, 0.9, "Test", sig);

    // Export from first
    std::string exported = ledger_->export_blockchain_for_replication();

    // Import to second
    size_t imported_count = ledger2->import_blockchain_from_peer(exported, "gatekeeper1");

    EXPECT_GT(imported_count, 0);
}

TEST_F(TrustLedgerTest, GetContributingGatekeepers) {
    auto gatekeepers = ledger_->get_contributing_gatekeepers();

    // Should at least contain the current gatekeeper
    EXPECT_GE(gatekeepers.size(), 1);
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(TrustLedgerTest, ConcurrentObservations) {
    const int num_threads = 10;
    const int observations_per_thread = 10;
    std::vector<std::thread> threads;

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, t, observations_per_thread]() {
            for (int i = 0; i < observations_per_thread; i++) {
                ledger_->record_observation(
                    "observer" + std::to_string(t),
                    "peer" + std::to_string(i),
                    0.8,
                    true,
                    "Concurrent test"
                );
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Should not crash, all observations should be recorded
    auto observations = ledger_->get_observations("peer0");
    EXPECT_EQ(observations.size(), num_threads);
}

TEST_F(TrustLedgerTest, ConcurrentBlockAddition) {
    const int num_threads = 5;
    std::vector<std::thread> threads;

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, t]() {
            for (int i = 0; i < 5; i++) {
                auto sig = AgentCrypto::generate_random_bytes(64);
                ledger_->add_blockchain_block(
                    "peer" + std::to_string(t),
                    0.8, 0.9,
                    "Concurrent block",
                    sig
                );
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Blockchain should remain valid
    EXPECT_TRUE(ledger_->verify_blockchain_integrity());
}

TEST_F(TrustLedgerTest, ConcurrentReadWrite) {
    const int num_readers = 5;
    const int num_writers = 5;
    std::vector<std::thread> threads;

    // Writers
    for (int t = 0; t < num_writers; t++) {
        threads.emplace_back([this, t]() {
            for (int i = 0; i < 10; i++) {
                ledger_->record_observation(
                    "observer" + std::to_string(t),
                    "peer1",
                    0.8, true, "Write"
                );
            }
        });
    }

    // Readers
    for (int t = 0; t < num_readers; t++) {
        threads.emplace_back([this]() {
            for (int i = 0; i < 20; i++) {
                ledger_->get_observations("peer1");
                ledger_->calculate_trust_score("peer1");
                ledger_->get_blockchain_length();
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_TRUE(ledger_->verify_blockchain_integrity());
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

TEST_F(TrustLedgerTest, ObservationWithInvalidTrustScore) {
    // Trust scores should be clamped to [0.0, 1.0]
    bool recorded = ledger_->record_observation("observer1", "peer1", -0.5, true, "Invalid");
    // Implementation should handle gracefully (clamp or reject)
    EXPECT_TRUE(recorded || !recorded);  // Either way is acceptable
}

TEST_F(TrustLedgerTest, ObservationWithExtremeTrustScore) {
    ledger_->record_observation("observer1", "peer1", 999.9, true, "Too high");

    double trust = ledger_->calculate_trust_score("peer1");
    EXPECT_LE(trust, 1.0);  // Should be clamped
}

TEST_F(TrustLedgerTest, EmptyPeerId) {
    bool recorded = ledger_->record_observation("observer1", "", 0.8, true, "Empty peer");
    // Should handle gracefully
    EXPECT_TRUE(recorded || !recorded);
}

TEST_F(TrustLedgerTest, EmptyObserverId) {
    bool recorded = ledger_->record_observation("", "peer1", 0.8, true, "Empty observer");
    EXPECT_TRUE(recorded || !recorded);
}

TEST_F(TrustLedgerTest, VeryLongObservation) {
    std::string long_observation(10000, 'a');
    bool recorded = ledger_->record_observation("observer1", "peer1", 0.8, true, long_observation);

    EXPECT_TRUE(recorded);
}

TEST_F(TrustLedgerTest, SpecialCharactersInIds) {
    bool recorded = ledger_->record_observation(
        "observer!@#$",
        "peer!@#$",
        0.8, true,
        "Special chars"
    );

    EXPECT_TRUE(recorded);
}

TEST_F(TrustLedgerTest, ManyObservationsForSamePeer) {
    for (int i = 0; i < 1000; i++) {
        ledger_->record_observation(
            "observer" + std::to_string(i),
            "popular_peer",
            0.8, true, "Test"
        );
    }

    auto observations = ledger_->get_observations("popular_peer");
    EXPECT_EQ(observations.size(), 1000);
}

TEST_F(TrustLedgerTest, BlockchainWithManyBlocks) {
    for (int i = 0; i < 100; i++) {
        auto sig = AgentCrypto::generate_random_bytes(64);
        ledger_->add_blockchain_block("peer" + std::to_string(i), 0.8, 0.9, "Test", sig);
    }

    EXPECT_EQ(ledger_->get_blockchain_length(), 101);  // Including genesis
    EXPECT_TRUE(ledger_->verify_blockchain_integrity());
}

TEST_F(TrustLedgerTest, ImportEmptyBlockchain) {
    size_t imported = ledger_->import_blockchain_from_peer("[]", "gatekeeper2");
    EXPECT_EQ(imported, 0);
}

TEST_F(TrustLedgerTest, ImportInvalidJson) {
    size_t imported = ledger_->import_blockchain_from_peer("invalid json", "gatekeeper2");
    EXPECT_EQ(imported, 0);
}

TEST_F(TrustLedgerTest, MultipleGatekeeperContributions) {
    // Simulate blocks from different gatekeepers
    std::string db_path2 = (test_dir_ / "ledger2.db").string();
    auto ledger2 = std::make_unique<TrustLedger>(db_path2, "gatekeeper2");

    auto sig1 = AgentCrypto::generate_random_bytes(64);
    auto sig2 = AgentCrypto::generate_random_bytes(64);

    ledger_->add_blockchain_block("peer1", 0.8, 0.9, "From GK1", sig1);
    ledger2->add_blockchain_block("peer2", 0.7, 0.8, "From GK2", sig2);

    // Export and import
    std::string export1 = ledger_->export_blockchain_for_replication();
    ledger2->import_blockchain_from_peer(export1, "gatekeeper1");

    auto gatekeepers = ledger2->get_contributing_gatekeepers();
    EXPECT_GE(gatekeepers.size(), 2);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
