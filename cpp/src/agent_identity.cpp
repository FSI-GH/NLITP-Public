/**
 * @file agent_identity.cpp
 * @brief Implementation of agent identity management
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Secure identity management with persistent key storage
 */

#include "nlitp/agent_identity.hpp"
#include "nlitp/security_config.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

using json = nlohmann::json;

namespace nlitp {

// ============================================================================
// Constructors
// ============================================================================

AgentIdentity::AgentIdentity(const std::string& agent_id)
    : agent_id_(agent_id)
    , signature_keypair_(AgentCrypto::generate_signature_keypair())
    , encryption_keypair_(AgentCrypto::generate_encryption_keypair())
{
}

AgentIdentity::AgentIdentity(
    const std::string& agent_id,
    const SignatureKeyPair& sig_keypair,
    const EncryptionKeyPair& enc_keypair
)
    : agent_id_(agent_id)
    , signature_keypair_(sig_keypair)
    , encryption_keypair_(enc_keypair)
{
}

// ============================================================================
// Persistent Storage
// ============================================================================

std::optional<AgentIdentity> AgentIdentity::load(
    const std::string& agent_id,
    const std::filesystem::path& storage_dir
) {
    try {
        // Get key file paths
        auto sig_path = get_signature_key_path(agent_id, storage_dir);
        auto enc_path = get_encryption_key_path(agent_id, storage_dir);

        // Check if files exist
        if (!std::filesystem::exists(sig_path) || !std::filesystem::exists(enc_path)) {
            return std::nullopt;
        }

        // Read signature key file
        std::ifstream sig_file(sig_path, std::ios::binary);
        if (!sig_file) {
            return std::nullopt;
        }

        SignatureKeyPair sig_keypair;
        sig_file.read(reinterpret_cast<char*>(sig_keypair.public_key.data()),
                     sig_keypair.public_key.size());
        sig_file.read(reinterpret_cast<char*>(sig_keypair.secret_key.data()),
                     sig_keypair.secret_key.size());
        sig_file.close();

        // Read encryption key file
        std::ifstream enc_file(enc_path, std::ios::binary);
        if (!enc_file) {
            return std::nullopt;
        }

        EncryptionKeyPair enc_keypair;
        enc_file.read(reinterpret_cast<char*>(enc_keypair.public_key.data()),
                     enc_keypair.public_key.size());
        enc_file.read(reinterpret_cast<char*>(enc_keypair.secret_key.data()),
                     enc_keypair.secret_key.size());
        enc_file.close();

        // Create identity from loaded keys
        return AgentIdentity(agent_id, sig_keypair, enc_keypair);

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool AgentIdentity::save(const std::filesystem::path& storage_dir) const {
    try {
        // Create storage directory if it doesn't exist
        if (!std::filesystem::exists(storage_dir)) {
            std::filesystem::create_directories(storage_dir);
        }

        // Get key file paths
        auto sig_path = get_signature_key_path(agent_id_, storage_dir);
        auto enc_path = get_encryption_key_path(agent_id_, storage_dir);

        // Write signature key file
        std::ofstream sig_file(sig_path, std::ios::binary | std::ios::trunc);
        if (!sig_file) {
            return false;
        }

        sig_file.write(reinterpret_cast<const char*>(signature_keypair_.public_key.data()),
                      signature_keypair_.public_key.size());
        sig_file.write(reinterpret_cast<const char*>(signature_keypair_.secret_key.data()),
                      signature_keypair_.secret_key.size());
        sig_file.close();

        // Set restrictive permissions (owner read/write only)
#ifndef _WIN32
        std::filesystem::permissions(sig_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace);
#endif

        // Write encryption key file
        std::ofstream enc_file(enc_path, std::ios::binary | std::ios::trunc);
        if (!enc_file) {
            return false;
        }

        enc_file.write(reinterpret_cast<const char*>(encryption_keypair_.public_key.data()),
                      encryption_keypair_.public_key.size());
        enc_file.write(reinterpret_cast<const char*>(encryption_keypair_.secret_key.data()),
                      encryption_keypair_.secret_key.size());
        enc_file.close();

        // Set restrictive permissions (owner read/write only)
#ifndef _WIN32
        std::filesystem::permissions(enc_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace);
#endif

        return true;

    } catch (const std::exception&) {
        return false;
    }
}

bool AgentIdentity::remove(
    const std::string& agent_id,
    const std::filesystem::path& storage_dir
) {
    try {
        auto sig_path = get_signature_key_path(agent_id, storage_dir);
        auto enc_path = get_encryption_key_path(agent_id, storage_dir);

        bool removed_sig = false;
        bool removed_enc = false;

        if (std::filesystem::exists(sig_path)) {
            removed_sig = std::filesystem::remove(sig_path);
        }

        if (std::filesystem::exists(enc_path)) {
            removed_enc = std::filesystem::remove(enc_path);
        }

        return removed_sig || removed_enc;

    } catch (const std::exception&) {
        return false;
    }
}

// ============================================================================
// Identity Information
// ============================================================================

std::string AgentIdentity::get_agent_id() const {
    return agent_id_;
}

std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> AgentIdentity::get_signature_public_key() const {
    return signature_keypair_.public_key;
}

std::array<uint8_t, crypto_box_PUBLICKEYBYTES> AgentIdentity::get_encryption_public_key() const {
    return encryption_keypair_.public_key;
}

std::string AgentIdentity::get_signature_public_key_b64() const {
    std::vector<uint8_t> key_vec(
        signature_keypair_.public_key.begin(),
        signature_keypair_.public_key.end()
    );
    return AgentCrypto::bytes_to_base64(key_vec);
}

std::string AgentIdentity::get_encryption_public_key_b64() const {
    std::vector<uint8_t> key_vec(
        encryption_keypair_.public_key.begin(),
        encryption_keypair_.public_key.end()
    );
    return AgentCrypto::bytes_to_base64(key_vec);
}

// ============================================================================
// Cryptographic Operations
// ============================================================================

std::vector<uint8_t> AgentIdentity::sign(const std::vector<uint8_t>& message) const {
    return AgentCrypto::sign_message(message, signature_keypair_.secret_key);
}

bool AgentIdentity::verify(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature,
    const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& peer_public_key
) {
    return AgentCrypto::verify_signature(message, signature, peer_public_key);
}

std::optional<SharedSecret> AgentIdentity::key_exchange(
    const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& peer_public_key
) const {
    return AgentCrypto::key_exchange(encryption_keypair_.secret_key, peer_public_key);
}

// ============================================================================
// Serialization
// ============================================================================

std::string AgentIdentity::to_json() const {
    json j;

    j["agent_id"] = agent_id_;

    // Signature keys (base64 encoded)
    std::vector<uint8_t> sig_pub(signature_keypair_.public_key.begin(),
                                 signature_keypair_.public_key.end());
    std::vector<uint8_t> sig_sec(signature_keypair_.secret_key.begin(),
                                 signature_keypair_.secret_key.end());

    j["signature_public_key"] = AgentCrypto::bytes_to_base64(sig_pub);
    j["signature_secret_key"] = AgentCrypto::bytes_to_base64(sig_sec);

    // Encryption keys (base64 encoded)
    std::vector<uint8_t> enc_pub(encryption_keypair_.public_key.begin(),
                                 encryption_keypair_.public_key.end());
    std::vector<uint8_t> enc_sec(encryption_keypair_.secret_key.begin(),
                                 encryption_keypair_.secret_key.end());

    j["encryption_public_key"] = AgentCrypto::bytes_to_base64(enc_pub);
    j["encryption_secret_key"] = AgentCrypto::bytes_to_base64(enc_sec);

    return j.dump(2);
}

std::optional<AgentIdentity> AgentIdentity::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        // Extract agent ID
        std::string agent_id = j["agent_id"];

        // Decode signature keys
        auto sig_pub_opt = AgentCrypto::base64_to_bytes(j["signature_public_key"]);
        auto sig_sec_opt = AgentCrypto::base64_to_bytes(j["signature_secret_key"]);

        if (!sig_pub_opt || !sig_sec_opt) {
            return std::nullopt;
        }

        // Decode encryption keys
        auto enc_pub_opt = AgentCrypto::base64_to_bytes(j["encryption_public_key"]);
        auto enc_sec_opt = AgentCrypto::base64_to_bytes(j["encryption_secret_key"]);

        if (!enc_pub_opt || !enc_sec_opt) {
            return std::nullopt;
        }

        // Verify key sizes
        if (sig_pub_opt->size() != crypto_sign_PUBLICKEYBYTES ||
            sig_sec_opt->size() != crypto_sign_SECRETKEYBYTES ||
            enc_pub_opt->size() != crypto_box_PUBLICKEYBYTES ||
            enc_sec_opt->size() != crypto_box_SECRETKEYBYTES) {
            return std::nullopt;
        }

        // Create keypairs
        SignatureKeyPair sig_keypair;
        std::copy(sig_pub_opt->begin(), sig_pub_opt->end(), sig_keypair.public_key.begin());
        std::copy(sig_sec_opt->begin(), sig_sec_opt->end(), sig_keypair.secret_key.begin());

        EncryptionKeyPair enc_keypair;
        std::copy(enc_pub_opt->begin(), enc_pub_opt->end(), enc_keypair.public_key.begin());
        std::copy(enc_sec_opt->begin(), enc_sec_opt->end(), enc_keypair.secret_key.begin());

        return AgentIdentity(agent_id, sig_keypair, enc_keypair);

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// Private Helper Functions
// ============================================================================

std::filesystem::path AgentIdentity::get_signature_key_path(
    const std::string& agent_id,
    const std::filesystem::path& storage_dir
) {
    std::string filename = agent_id + "_signature.key";
    return storage_dir / filename;
}

std::filesystem::path AgentIdentity::get_encryption_key_path(
    const std::string& agent_id,
    const std::filesystem::path& storage_dir
) {
    std::string filename = agent_id + "_encryption.key";
    return storage_dir / filename;
}

} // namespace nlitp
