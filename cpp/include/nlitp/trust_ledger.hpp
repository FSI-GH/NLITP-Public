/**
 * @file trust_ledger.hpp
 * @brief Blockchain-based trust ledger for Gatekeeper record keeping
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Byzantine fault-tolerant trust network with blockchain integrity:
 * - Tamper-proof trust observations
 * - Blockchain verification
 * - Distributed replication across Gatekeepers
 * - SQLite persistence
 * - Thread-safe operations
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <optional>
#include <cstdint>

namespace nlitp {

/**
 * @brief Trust observation from one peer about another
 */
struct TrustObservation {
    std::string observer_id;       ///< Who made the observation
    std::string peer_id;            ///< Who is being evaluated
    double trust_score;             ///< Trust value (0.0 = no trust, 1.0 = full trust)
    bool verified;                  ///< Whether observation is verified
    std::string observation;        ///< Human-readable reason
    uint64_t timestamp;             ///< Unix timestamp
};

/**
 * @brief Blockchain block containing trust observation
 */
struct TrustBlock {
    uint64_t block_number;          ///< Sequential block number
    std::string block_hash;         ///< SHA-256 hash of this block
    std::string previous_hash;      ///< Hash of previous block
    uint64_t timestamp;             ///< Block creation time
    std::string peer_id;            ///< Peer being evaluated
    double trust_score;             ///< Trust value (0.0-1.0)
    double wisdom_score;            ///< Wisdom value (0.0-1.0)
    std::string observation;        ///< Reason for trust/wisdom scores
    std::string gatekeeper_id;      ///< Gatekeeper who created block
    std::vector<uint8_t> signature; ///< Ed25519 signature of block
};

/**
 * @brief Statistics for a peer's trust and wisdom
 */
struct PeerStats {
    std::string peer_id;
    double trust_score;
    double wisdom_score;
    size_t observation_count;
    uint64_t last_updated;
};

/**
 * @brief TrustLedger - Blockchain-based trust management
 *
 * Features:
 * - Byzantine fault-tolerant independent trust observations
 * - Blockchain integrity verification
 * - SQLite persistence with thread-safe access
 * - Trust and wisdom score aggregation
 * - Gatekeeper replication support
 *
 * Thread-safe for concurrent access
 */
class TrustLedger {
public:
    /**
     * @brief Construct trust ledger with database path
     * @param database_path Path to SQLite database file
     * @param gatekeeper_id ID of this Gatekeeper (empty if not a Gatekeeper)
     */
    explicit TrustLedger(
        const std::string& database_path,
        const std::string& gatekeeper_id = ""
    );

    /**
     * @brief Destructor - closes database
     */
    ~TrustLedger();

    // Disable copy and move
    TrustLedger(const TrustLedger&) = delete;
    TrustLedger& operator=(const TrustLedger&) = delete;
    TrustLedger(TrustLedger&&) = delete;
    TrustLedger& operator=(TrustLedger&&) = delete;

    // ========================================================================
    // Trust Observations
    // ========================================================================

    /**
     * @brief Record trust observation from observer about peer
     * @param observer_id ID of observer making the observation
     * @param peer_id ID of peer being evaluated
     * @param trust_score Trust score (0.0-1.0)
     * @param verified Whether observation is verified
     * @param observation Human-readable reason
     * @return true if recorded successfully, false otherwise
     */
    bool record_observation(
        const std::string& observer_id,
        const std::string& peer_id,
        double trust_score,
        bool verified,
        const std::string& observation
    );

    /**
     * @brief Get all observations for a peer
     * @param peer_id Peer ID to query
     * @return Vector of trust observations
     */
    std::vector<TrustObservation> get_observations(const std::string& peer_id) const;

    /**
     * @brief Calculate aggregate trust score for peer
     * @param peer_id Peer ID to evaluate
     * @return Weighted average trust score (verified observations weighted higher)
     */
    double calculate_trust_score(const std::string& peer_id) const;

    /**
     * @brief Get statistics for a peer
     * @param peer_id Peer ID to query
     * @return Peer statistics or std::nullopt if not found
     */
    std::optional<PeerStats> get_peer_stats(const std::string& peer_id) const;

    // ========================================================================
    // Blockchain Operations
    // ========================================================================

    /**
     * @brief Add trust observation to blockchain
     * @param peer_id Peer being evaluated
     * @param trust_score Trust score (0.0-1.0)
     * @param wisdom_score Wisdom score (0.0-1.0)
     * @param observation Reason for scores
     * @param signature Ed25519 signature of block data
     * @return true if block added successfully, false otherwise
     */
    bool add_blockchain_block(
        const std::string& peer_id,
        double trust_score,
        double wisdom_score,
        const std::string& observation,
        const std::vector<uint8_t>& signature
    );

    /**
     * @brief Get blockchain block by number
     * @param block_number Block number to retrieve
     * @return TrustBlock or std::nullopt if not found
     */
    std::optional<TrustBlock> get_blockchain_block(uint64_t block_number) const;

    /**
     * @brief Get latest blockchain block
     * @return Latest TrustBlock or std::nullopt if blockchain empty
     */
    std::optional<TrustBlock> get_latest_block() const;

    /**
     * @brief Get all blockchain blocks for a peer
     * @param peer_id Peer ID to query
     * @return Vector of trust blocks
     */
    std::vector<TrustBlock> get_peer_blockchain_history(const std::string& peer_id) const;

    /**
     * @brief Verify blockchain integrity
     * @return true if blockchain is valid, false if tampering detected
     */
    bool verify_blockchain_integrity() const;

    /**
     * @brief Get blockchain length
     * @return Number of blocks in blockchain
     */
    size_t get_blockchain_length() const;

    // ========================================================================
    // Gatekeeper Replication
    // ========================================================================

    /**
     * @brief Export blockchain for replication to other Gatekeepers
     * @param since_block Only export blocks after this block number
     * @return JSON array of blocks
     */
    std::string export_blockchain_for_replication(uint64_t since_block = 0) const;

    /**
     * @brief Import blockchain blocks from another Gatekeeper
     * @param blockchain_json JSON array of blocks
     * @param source_gatekeeper ID of source Gatekeeper
     * @return Number of blocks imported
     */
    size_t import_blockchain_from_peer(
        const std::string& blockchain_json,
        const std::string& source_gatekeeper
    );

    /**
     * @brief Get list of Gatekeepers who have contributed to blockchain
     * @return Vector of Gatekeeper IDs
     */
    std::vector<std::string> get_contributing_gatekeepers() const;

private:
    /// Path to SQLite database
    std::string database_path_;

    /// This Gatekeeper's ID (empty if not a Gatekeeper)
    std::string gatekeeper_id_;

    /// SQLite database connection (opaque pointer)
    void* db_connection_;

    /// Mutex for thread-safe database access
    mutable std::mutex db_mutex_;

    /**
     * @brief Initialize database schema
     * @return true if successful, false otherwise
     */
    bool initialize_database();

    /**
     * @brief Calculate SHA-256 hash of block data
     * @param block Block to hash
     * @return SHA-256 hash as hex string
     */
    std::string calculate_block_hash(const TrustBlock& block) const;

    /**
     * @brief Create genesis block (block 0)
     * @return true if created successfully, false otherwise
     */
    bool create_genesis_block();
};

} // namespace nlitp
