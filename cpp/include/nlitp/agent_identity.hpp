/**
 * @file agent_identity.hpp
 * @brief Agent identity management with cryptographic keys
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Manages agent identity including:
 * - Ed25519 signature keys (authentication)
 * - X25519 encryption keys (confidentiality)
 * - Persistent key storage
 * - Key serialization/deserialization
 */

#pragma once

#include "nlitp/agent_crypto.hpp"
#include <string>
#include <filesystem>
#include <optional>
#include <vector>

namespace nlitp {

/**
 * @brief AgentIdentity - Cryptographic identity for NLITP agents
 *
 * Each agent has:
 * - Unique agent ID
 * - Ed25519 signature keypair (for message authentication)
 * - X25519 encryption keypair (for key exchange)
 * - Persistent storage in filesystem
 *
 * Thread-safe identity management
 */
class AgentIdentity {
public:
    /**
     * @brief Create new agent identity with generated keys
     * @param agent_id Unique agent identifier
     */
    explicit AgentIdentity(const std::string& agent_id);

    /**
     * @brief Load existing agent identity from storage
     * @param agent_id Unique agent identifier
     * @param storage_dir Directory containing key files
     * @return AgentIdentity if successful, std::nullopt if not found
     */
    static std::optional<AgentIdentity> load(
        const std::string& agent_id,
        const std::filesystem::path& storage_dir
    );

    /**
     * @brief Save identity to persistent storage
     * @param storage_dir Directory to store key files
     * @return true if successful, false otherwise
     */
    bool save(const std::filesystem::path& storage_dir) const;

    /**
     * @brief Delete identity from persistent storage
     * @param agent_id Agent identifier
     * @param storage_dir Directory containing key files
     * @return true if successful, false otherwise
     */
    static bool remove(
        const std::string& agent_id,
        const std::filesystem::path& storage_dir
    );

    // ========================================================================
    // Identity Information
    // ========================================================================

    /**
     * @brief Get agent ID
     * @return Agent identifier
     */
    std::string get_agent_id() const;

    /**
     * @brief Get Ed25519 signature public key
     * @return Public signing key
     */
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> get_signature_public_key() const;

    /**
     * @brief Get X25519 encryption public key
     * @return Public encryption key
     */
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> get_encryption_public_key() const;

    /**
     * @brief Get signature public key as base64 string
     * @return Base64-encoded public signing key
     */
    std::string get_signature_public_key_b64() const;

    /**
     * @brief Get encryption public key as base64 string
     * @return Base64-encoded public encryption key
     */
    std::string get_encryption_public_key_b64() const;

    // ========================================================================
    // Cryptographic Operations
    // ========================================================================

    /**
     * @brief Sign message with Ed25519 private key
     * @param message Message to sign
     * @return Signature (64 bytes)
     */
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) const;

    /**
     * @brief Verify signature from another agent
     * @param message Original message
     * @param signature Signature to verify
     * @param peer_public_key Peer's Ed25519 public key
     * @return true if signature is valid, false otherwise
     */
    static bool verify(
        const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& signature,
        const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& peer_public_key
    );

    /**
     * @brief Perform key exchange with peer's public key
     * @param peer_public_key Peer's X25519 public key
     * @return Shared secret for symmetric encryption
     */
    std::optional<SharedSecret> key_exchange(
        const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& peer_public_key
    ) const;

    // ========================================================================
    // Serialization
    // ========================================================================

    /**
     * @brief Export identity to JSON (includes private keys - SENSITIVE!)
     * @return JSON string with all keys
     */
    std::string to_json() const;

    /**
     * @brief Import identity from JSON
     * @param json JSON string with identity data
     * @return AgentIdentity if successful, std::nullopt if invalid
     */
    static std::optional<AgentIdentity> from_json(const std::string& json);

private:
    /// Agent identifier
    std::string agent_id_;

    /// Ed25519 signature keypair
    SignatureKeyPair signature_keypair_;

    /// X25519 encryption keypair
    EncryptionKeyPair encryption_keypair_;

    /**
     * @brief Private constructor for loading from existing keys
     */
    AgentIdentity(
        const std::string& agent_id,
        const SignatureKeyPair& sig_keypair,
        const EncryptionKeyPair& enc_keypair
    );

    /**
     * @brief Get file path for signature key storage
     */
    static std::filesystem::path get_signature_key_path(
        const std::string& agent_id,
        const std::filesystem::path& storage_dir
    );

    /**
     * @brief Get file path for encryption key storage
     */
    static std::filesystem::path get_encryption_key_path(
        const std::string& agent_id,
        const std::filesystem::path& storage_dir
    );
};

} // namespace nlitp
