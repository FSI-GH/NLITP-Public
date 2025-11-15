/**
 * @file security_config.hpp
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 */

#pragma once

#include <cstdint>
#include <chrono>
#include <string>
#include <filesystem>

namespace nlitp {
namespace security {

// ============================================================================
// ============================================================================

/// Maximum message size (10MB) to prevent memory exhaustion attacks
constexpr size_t MAX_MESSAGE_SIZE = 10 * 1024 * 1024;

/// Maximum file size (50MB) to prevent disk exhaustion attacks
constexpr size_t MAX_FILE_SIZE = 50 * 1024 * 1024;

/// Maximum JSON payload size (1MB) to prevent JSON bomb attacks
constexpr size_t MAX_JSON_SIZE = 1024 * 1024;

/// Maximum number of chunks per file transfer
constexpr size_t MAX_CHUNKS = 10000;

/// Maximum concurrent file transfers
constexpr size_t MAX_PENDING_TRANSFERS = 100;

/// Maximum identifier length (agent ID, session ID)
constexpr size_t MAX_IDENTIFIER_LENGTH = 64;

/// Maximum user input length
constexpr size_t MAX_INPUT_LENGTH = 128;

/// Maximum filename length
constexpr size_t MAX_FILENAME_LENGTH = 255;

// ============================================================================
// ============================================================================

/// TCP connection establishment timeout
constexpr auto CONNECTION_TIMEOUT = std::chrono::seconds(5);

/// Read timeout for network operations
constexpr auto READ_TIMEOUT = std::chrono::seconds(30);

/// Write timeout for network operations
constexpr auto WRITE_TIMEOUT = std::chrono::seconds(30);

/// Idle connection timeout
constexpr auto IDLE_TIMEOUT = std::chrono::minutes(5);

// ============================================================================
// ============================================================================

/// Stale transfer cleanup interval
constexpr auto STALE_TRANSFER_TIMEOUT = std::chrono::minutes(5);

/// Resource cleanup interval
constexpr auto CLEANUP_INTERVAL = std::chrono::seconds(60);

// ============================================================================
// ============================================================================

/// Messages per second per peer (sustained rate)
constexpr size_t RATE_LIMIT_PER_SECOND = 100;

/// Burst capacity for rate limiting
constexpr size_t RATE_LIMIT_BURST = 200;

/// Rate limiter cleanup interval
constexpr auto RATE_LIMITER_CLEANUP = std::chrono::seconds(60);

// ============================================================================
// ============================================================================

/// Replay protection time window (accept messages within 60 seconds)
constexpr auto REPLAY_WINDOW = std::chrono::seconds(60);

/// Replay protection cleanup interval
constexpr auto REPLAY_CLEANUP = std::chrono::minutes(5);

// ============================================================================
// Cryptographic Configuration
// ============================================================================

/// Ed25519 signature size
constexpr size_t ED25519_SIGNATURE_SIZE = 64;

/// Ed25519 public key size
constexpr size_t ED25519_PUBKEY_SIZE = 32;

/// Ed25519 secret key size
constexpr size_t ED25519_SECKEY_SIZE = 64;

/// X25519 public key size
constexpr size_t X25519_PUBKEY_SIZE = 32;

/// X25519 secret key size
constexpr size_t X25519_SECKEY_SIZE = 32;

/// ChaCha20-Poly1305 nonce size
constexpr size_t CHACHA20_NONCE_SIZE = 12;

/// ChaCha20-Poly1305 tag size
constexpr size_t CHACHA20_TAG_SIZE = 16;

// ============================================================================
// Network Configuration
// ============================================================================

/// UDP discovery port
constexpr uint16_t DISCOVERY_PORT = 10001;

/// TCP/UDP port allocation start
constexpr uint16_t PORT_RANGE_START = 11000;

/// TCP/UDP port allocation end
constexpr uint16_t PORT_RANGE_END = 61000;

/// Maximum UDP packet size (to avoid fragmentation)
constexpr size_t MAX_UDP_PACKET_SIZE = 65000;

// ============================================================================
// ============================================================================

/**
 * @brief Get NLITP data directory from environment or use default
 * @return Filesystem path to data directory
 */
std::filesystem::path get_data_directory();

/**
 * @brief Get received files directory
 * @return Filesystem path to received files directory
 */
std::filesystem::path get_received_directory();

/**
 * @brief Get database directory
 * @return Filesystem path to database directory
 */
std::filesystem::path get_database_directory();

/**
 * @brief Get log directory
 * @return Filesystem path to log directory
 */
std::filesystem::path get_log_directory();

// ============================================================================
// ============================================================================

/**
 * @brief Validate identifier (alphanumeric + underscore/hyphen only)
 * @param identifier String to validate
 * @param max_length Maximum allowed length
 * @return true if valid, false otherwise
 */
bool validate_identifier(const std::string& identifier, size_t max_length = MAX_IDENTIFIER_LENGTH);

/**
 * @brief Validate user input (no shell metacharacters)
 * @param input String to validate
 * @param max_length Maximum allowed length
 * @return true if valid, false otherwise
 */
bool validate_user_input(const std::string& input, size_t max_length = MAX_INPUT_LENGTH);

/**
 * @brief Sanitize filename to prevent path traversal attacks
 * @param filename User-provided filename
 * @param extension Required file extension (optional)
 * @return Sanitized filename safe for filesystem operations
 */
std::string sanitize_filename(const std::string& filename, const std::string& extension = ".md");

/**
 * @brief Check if path is safe (no traversal, within allowed directory)
 * @param path Path to validate
 * @param base_dir Base directory that path must be within
 * @return true if safe, false if path traversal detected
 */
bool is_safe_path(const std::filesystem::path& path, const std::filesystem::path& base_dir);

} // namespace security
} // namespace nlitp
