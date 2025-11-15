/**
 * @file trust_ledger.cpp
 * @brief Implementation of blockchain-based trust ledger
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright � 2025 Fortified Solutions Inc.
 *
 * Byzantine fault-tolerant trust network with blockchain integrity
 */

#include "nlitp/trust_ledger.hpp"
#include "nlitp/agent_crypto.hpp"
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>
#include <ctime>

using json = nlohmann::json;

namespace nlitp {

// ============================================================================
// Constructor / Destructor
// ============================================================================

TrustLedger::TrustLedger(const std::string& database_path, const std::string& gatekeeper_id)
    : database_path_(database_path)
    , gatekeeper_id_(gatekeeper_id)
    , db_connection_(nullptr)
{
    // Open SQLite database
    sqlite3* db = nullptr;
    int rc = sqlite3_open(database_path_.c_str(), &db);

    if (rc != SQLITE_OK) {
        if (db) {
            sqlite3_close(db);
        }
        throw std::runtime_error("Failed to open trust ledger database: " + database_path_);
    }

    db_connection_ = static_cast<void*>(db);

    // Initialize database schema
    if (!initialize_database()) {
        sqlite3_close(db);
        db_connection_ = nullptr;
        throw std::runtime_error("Failed to initialize trust ledger schema");
    }

    // Create genesis block if blockchain is empty
    if (get_blockchain_length() == 0) {
        create_genesis_block();
    }
}

TrustLedger::~TrustLedger() {
    if (db_connection_) {
        sqlite3* db = static_cast<sqlite3*>(db_connection_);
        sqlite3_close(db);
        db_connection_ = nullptr;
    }
}

// ============================================================================
// Database Initialization
// ============================================================================

bool TrustLedger::initialize_database() {
    std::lock_guard<std::mutex> lock(db_mutex_);

    sqlite3* db = static_cast<sqlite3*>(db_connection_);
    char* error_msg = nullptr;

    // Create trust_observations table
    const char* create_observations_table = R"(
        CREATE TABLE IF NOT EXISTS trust_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            observer_id TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            trust_score REAL NOT NULL,
            verified INTEGER NOT NULL,
            observation TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            CONSTRAINT valid_score CHECK (trust_score >= 0.0 AND trust_score <= 1.0)
        );
        CREATE INDEX IF NOT EXISTS idx_peer_id ON trust_observations(peer_id);
        CREATE INDEX IF NOT EXISTS idx_timestamp ON trust_observations(timestamp);
    )";

    int rc = sqlite3_exec(db, create_observations_table, nullptr, nullptr, &error_msg);
    if (rc != SQLITE_OK) {
        if (error_msg) {
            sqlite3_free(error_msg);
        }
        return false;
    }

    // Create blockchain table
    const char* create_blockchain_table = R"(
        CREATE TABLE IF NOT EXISTS blockchain (
            block_number INTEGER PRIMARY KEY,
            block_hash TEXT NOT NULL UNIQUE,
            previous_hash TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            peer_id TEXT NOT NULL,
            trust_score REAL NOT NULL,
            wisdom_score REAL NOT NULL,
            observation TEXT NOT NULL,
            gatekeeper_id TEXT NOT NULL,
            signature BLOB NOT NULL,
            CONSTRAINT valid_trust CHECK (trust_score >= 0.0 AND trust_score <= 1.0),
            CONSTRAINT valid_wisdom CHECK (wisdom_score >= 0.0 AND wisdom_score <= 1.0)
        );
        CREATE INDEX IF NOT EXISTS idx_blockchain_peer ON blockchain(peer_id);
        CREATE INDEX IF NOT EXISTS idx_blockchain_gatekeeper ON blockchain(gatekeeper_id);
    )";

    rc = sqlite3_exec(db, create_blockchain_table, nullptr, nullptr, &error_msg);
    if (rc != SQLITE_OK) {
        if (error_msg) {
            sqlite3_free(error_msg);
        }
        return false;
    }

    return true;
}

// ============================================================================
// Trust Observations
// ============================================================================

bool TrustLedger::record_observation(
    const std::string& observer_id,
    const std::string& peer_id,
    double trust_score,
    bool verified,
    const std::string& observation
) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    // Validate trust score
    if (trust_score < 0.0 || trust_score > 1.0) {
        return false;
    }

    sqlite3* db = static_cast<sqlite3*>(db_connection_);

    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    ).count();

    // Prepare INSERT statement
    const char* sql = R"(
        INSERT INTO trust_observations
        (observer_id, peer_id, trust_score, verified, observation, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return false;
    }

    // Bind parameters
    sqlite3_bind_text(stmt, 1, observer_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, peer_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 3, trust_score);
    sqlite3_bind_int(stmt, 4, verified ? 1 : 0);
    sqlite3_bind_text(stmt, 5, observation.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, timestamp);

    // Execute
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

std::vector<TrustObservation> TrustLedger::get_observations(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(db_mutex_);

    std::vector<TrustObservation> observations;

    sqlite3* db = static_cast<sqlite3*>(db_connection_);

    const char* sql = R"(
        SELECT observer_id, peer_id, trust_score, verified, observation, timestamp
        FROM trust_observations
        WHERE peer_id = ?
        ORDER BY timestamp DESC
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return observations;
    }

    sqlite3_bind_text(stmt, 1, peer_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TrustObservation obs;
        obs.observer_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        obs.peer_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        obs.trust_score = sqlite3_column_double(stmt, 2);
        obs.verified = sqlite3_column_int(stmt, 3) != 0;
        obs.observation = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        obs.timestamp = sqlite3_column_int64(stmt, 5);

        observations.push_back(obs);
    }

    sqlite3_finalize(stmt);

    return observations;
}

double TrustLedger::calculate_trust_score(const std::string& peer_id) const {
    auto observations = get_observations(peer_id);

    if (observations.empty()) {
        return 0.5; // Neutral trust for unknown peers
    }

    // Calculate weighted average (verified observations weighted 2x)
    double total_weight = 0.0;
    double weighted_sum = 0.0;

    for (const auto& obs : observations) {
        double weight = obs.verified ? 2.0 : 1.0;
        weighted_sum += obs.trust_score * weight;
        total_weight += weight;
    }

    return weighted_sum / total_weight;
}

std::optional<PeerStats> TrustLedger::get_peer_stats(const std::string& peer_id) const {
    auto observations = get_observations(peer_id);

    if (observations.empty()) {
        return std::nullopt;
    }

    PeerStats stats;
    stats.peer_id = peer_id;
    stats.trust_score = calculate_trust_score(peer_id);
    stats.wisdom_score = stats.trust_score; // Simplified: wisdom = trust for now
    stats.observation_count = observations.size();
    stats.last_updated = observations[0].timestamp; // Most recent

    return stats;
}

// ============================================================================
// Blockchain Operations
// ============================================================================

bool TrustLedger::add_blockchain_block(
    const std::string& peer_id,
    double trust_score,
    double wisdom_score,
    const std::string& observation,
    const std::vector<uint8_t>& signature
) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    // Validate scores
    if (trust_score < 0.0 || trust_score > 1.0 ||
        wisdom_score < 0.0 || wisdom_score > 1.0) {
        return false;
    }

    sqlite3* db = static_cast<sqlite3*>(db_connection_);

    // Get latest block for previous hash
    auto latest_block = get_latest_block();
    std::string previous_hash = latest_block ? latest_block->block_hash : "0";
    uint64_t block_number = latest_block ? latest_block->block_number + 1 : 1;

    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    ).count();

    // Create block structure for hashing
    TrustBlock block;
    block.block_number = block_number;
    block.previous_hash = previous_hash;
    block.timestamp = timestamp;
    block.peer_id = peer_id;
    block.trust_score = trust_score;
    block.wisdom_score = wisdom_score;
    block.observation = observation;
    block.gatekeeper_id = gatekeeper_id_;
    block.signature = signature;

    // Calculate block hash
    block.block_hash = calculate_block_hash(block);

    // Insert into database
    const char* sql = R"(
        INSERT INTO blockchain
        (block_number, block_hash, previous_hash, timestamp, peer_id,
         trust_score, wisdom_score, observation, gatekeeper_id, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, block_number);
    sqlite3_bind_text(stmt, 2, block.block_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, previous_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, timestamp);
    sqlite3_bind_text(stmt, 5, peer_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 6, trust_score);
    sqlite3_bind_double(stmt, 7, wisdom_score);
    sqlite3_bind_text(stmt, 8, observation.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, gatekeeper_id_.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 10, signature.data(), signature.size(), SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

std::optional<TrustBlock> TrustLedger::get_blockchain_block(uint64_t block_number) const {
    std::lock_guard<std::mutex> lock(db_mutex_);

    sqlite3* db = static_cast<sqlite3*>(db_connection_);

    const char* sql = R"(
        SELECT block_number, block_hash, previous_hash, timestamp, peer_id,
               trust_score, wisdom_score, observation, gatekeeper_id, signature
        FROM blockchain
        WHERE block_number = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3_bind_int64(stmt, 1, block_number);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        TrustBlock block;
        block.block_number = sqlite3_column_int64(stmt, 0);
        block.block_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        block.previous_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        block.timestamp = sqlite3_column_int64(stmt, 3);
        block.peer_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        block.trust_score = sqlite3_column_double(stmt, 5);
        block.wisdom_score = sqlite3_column_double(stmt, 6);
        block.observation = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        block.gatekeeper_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));

        const void* sig_data = sqlite3_column_blob(stmt, 9);
        int sig_len = sqlite3_column_bytes(stmt, 9);
        block.signature.assign(
            static_cast<const uint8_t*>(sig_data),
            static_cast<const uint8_t*>(sig_data) + sig_len
        );

        sqlite3_finalize(stmt);
        return block;
    }

    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::optional<TrustBlock> TrustLedger::get_latest_block() const {
    std::lock_guard<std::mutex> lock(db_mutex_);

    sqlite3* db = static_cast<sqlite3*>(db_connection_);

    const char* sql = "SELECT MAX(block_number) FROM blockchain";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return std::nullopt;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (sqlite3_column_type(stmt, 0) == SQLITE_NULL) {
            sqlite3_finalize(stmt);
            return std::nullopt;
        }

        uint64_t max_block = sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);

        // Release lock temporarily to call get_blockchain_block
        db_mutex_.unlock();
        auto result = get_blockchain_block(max_block);
        db_mutex_.lock();

        return result;
    }

    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::vector<TrustBlock> TrustLedger::get_peer_blockchain_history(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(db_mutex_);

    std::vector<TrustBlock> blocks;

    sqlite3* db = static_cast<sqlite3*>(db_connection_);

    const char* sql = R"(
        SELECT block_number, block_hash, previous_hash, timestamp, peer_id,
               trust_score, wisdom_score, observation, gatekeeper_id, signature
        FROM blockchain
        WHERE peer_id = ?
        ORDER BY block_number ASC
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return blocks;
    }

    sqlite3_bind_text(stmt, 1, peer_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TrustBlock block;
        block.block_number = sqlite3_column_int64(stmt, 0);
        block.block_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        block.previous_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        block.timestamp = sqlite3_column_int64(stmt, 3);
        block.peer_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        block.trust_score = sqlite3_column_double(stmt, 5);
        block.wisdom_score = sqlite3_column_double(stmt, 6);
        block.observation = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        block.gatekeeper_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));

        const void* sig_data = sqlite3_column_blob(stmt, 9);
        int sig_len = sqlite3_column_bytes(stmt, 9);
        block.signature.assign(
            static_cast<const uint8_t*>(sig_data),
            static_cast<const uint8_t*>(sig_data) + sig_len
        );

        blocks.push_back(block);
    }

    sqlite3_finalize(stmt);

    return blocks;
}

bool TrustLedger::verify_blockchain_integrity() const {
    std::lock_guard<std::mutex> lock(db_mutex_);

    size_t chain_length = get_blockchain_length();

    if (chain_length == 0) {
        return true; // Empty chain is valid
    }

    // Verify each block's hash and linkage
    for (uint64_t i = 0; i < chain_length; i++) {
        db_mutex_.unlock();
        auto block_opt = get_blockchain_block(i);
        db_mutex_.lock();

        if (!block_opt) {
            return false; // Missing block
        }

        auto& block = *block_opt;

        // Verify block hash
        std::string calculated_hash = calculate_block_hash(block);
        if (calculated_hash != block.block_hash) {
            return false; // Hash mismatch (tampering detected)
        }

        // Verify linkage (except genesis block)
        if (i > 0) {
            db_mutex_.unlock();
            auto prev_block_opt = get_blockchain_block(i - 1);
            db_mutex_.lock();

            if (!prev_block_opt) {
                return false;
            }

            if (block.previous_hash != prev_block_opt->block_hash) {
                return false; // Chain broken
            }
        }
    }

    return true;
}

size_t TrustLedger::get_blockchain_length() const {
    sqlite3* db = static_cast<sqlite3*>(db_connection_);

    const char* sql = "SELECT COUNT(*) FROM blockchain";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return 0;
    }

    size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);

    return count;
}

// ============================================================================
// Private Helper Functions
// ============================================================================

std::string TrustLedger::calculate_block_hash(const TrustBlock& block) const {
    // Concatenate block data for hashing
    std::ostringstream oss;
    oss << block.block_number << ":"
        << block.previous_hash << ":"
        << block.timestamp << ":"
        << block.peer_id << ":"
        << std::fixed << std::setprecision(6) << block.trust_score << ":"
        << std::fixed << std::setprecision(6) << block.wisdom_score << ":"
        << block.observation << ":"
        << block.gatekeeper_id;

    std::string input = oss.str();

    // Compute SHA-256 hash
    std::vector<uint8_t> hash(32); // SHA-256 is 32 bytes
    crypto_hash_sha256(
        hash.data(),
        reinterpret_cast<const uint8_t*>(input.c_str()),
        input.length()
    );

    // Convert to hex string
    return AgentCrypto::bytes_to_hex(hash);
}

bool TrustLedger::create_genesis_block() {
    // Genesis block (block 0) with zero scores
    std::vector<uint8_t> empty_signature;

    return add_blockchain_block(
        "GENESIS",
        0.0,
        0.0,
        "Genesis block for trust ledger blockchain",
        empty_signature
    );
}

// ============================================================================
// Gatekeeper Replication (Stub implementations for future expansion)
// ============================================================================

std::string TrustLedger::export_blockchain_for_replication(uint64_t since_block) const {
    // NOTE: Stub implementation - full JSON export for replication not yet implemented
    // Future version will export blockchain data in JSON format for Gatekeeper sync
    (void)since_block; // Suppress unused parameter warning
    return "{}";
}

size_t TrustLedger::import_blockchain_from_peer(
    const std::string& blockchain_json,
    const std::string& source_gatekeeper
) {
    // NOTE: Stub implementation - blockchain import from peer Gatekeepers not yet implemented
    // Future version will parse and merge blockchain data from trusted Gatekeepers
    (void)blockchain_json; // Suppress unused parameter warnings
    (void)source_gatekeeper;
    return 0;
}

std::vector<std::string> TrustLedger::get_contributing_gatekeepers() const {
    std::lock_guard<std::mutex> lock(db_mutex_);

    std::vector<std::string> gatekeepers;

    sqlite3* db = static_cast<sqlite3*>(db_connection_);

    const char* sql = "SELECT DISTINCT gatekeeper_id FROM blockchain WHERE gatekeeper_id != ''";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return gatekeepers;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string gk_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        gatekeepers.push_back(gk_id);
    }

    sqlite3_finalize(stmt);

    return gatekeepers;
}

} // namespace nlitp
