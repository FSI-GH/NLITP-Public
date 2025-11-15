/**
 * @file agent_crypto.hpp
 * @brief Cryptographic operations for NLITP agents
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Provides Ed25519 signatures, X25519 key exchange, and ChaCha20-Poly1305 encryption.
 */

#pragma once

#include <array>
#include <vector>
#include <string>
#include <optional>
#include <sodium.h>

namespace nlitp {

/**
 * @brief Ed25519 signature key pair
 */
struct SignatureKeyPair {
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> public_key;
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> secret_key;
};

/**
 * @brief X25519 encryption key pair
 */
struct EncryptionKeyPair {
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> public_key;
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> secret_key;
};

/**
 * @brief Shared secret from key exchange
 */
struct SharedSecret {
    std::array<uint8_t, crypto_box_BEFORENMBYTES> key;
};

/**
 * @brief AgentCrypto - Cryptographic operations for agents
 *
 * Thread-safe cryptographic primitives using libsodium.
 * All methods are const and stateless (except key generation).
 */
class AgentCrypto {
public:
    /**
     * @brief Initialize libsodium (call once at startup)
     * @return true if initialization successful, false otherwise
     */
    static bool initialize();

    // ========================================================================
    // Key Generation
    // ========================================================================

    /**
     * @brief Generate Ed25519 signature key pair
     * @return SignatureKeyPair with public and secret keys
     */
    static SignatureKeyPair generate_signature_keypair();

    /**
     * @brief Generate X25519 encryption key pair
     * @return EncryptionKeyPair with public and secret keys
     */
    static EncryptionKeyPair generate_encryption_keypair();

    // ========================================================================
    // Digital Signatures (Ed25519)
    // ========================================================================

    /**
     * @brief Sign a message with Ed25519
     * @param message Message to sign
     * @param secret_key Secret signing key
     * @return Signature (64 bytes)
     */
    static std::vector<uint8_t> sign_message(
        const std::vector<uint8_t>& message,
        const std::array<uint8_t, crypto_sign_SECRETKEYBYTES>& secret_key
    );

    /**
     * @brief Verify Ed25519 signature
     * @param message Original message
     * @param signature Signature to verify (64 bytes)
     * @param public_key Public key of signer
     * @return true if signature is valid, false otherwise
     */
    static bool verify_signature(
        const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& signature,
        const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& public_key
    );

    // ========================================================================
    // Key Exchange (X25519 ECDH)
    // ========================================================================

    /**
     * @brief Perform X25519 key exchange to derive shared secret
     * @param our_secret_key Our X25519 secret key
     * @param their_public_key Their X25519 public key
     * @return SharedSecret for symmetric encryption
     */
    static std::optional<SharedSecret> key_exchange(
        const std::array<uint8_t, crypto_box_SECRETKEYBYTES>& our_secret_key,
        const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& their_public_key
    );

    // ========================================================================
    // Encryption (ChaCha20-Poly1305 AEAD)
    // ========================================================================

    /**
     * @brief Encrypt message with ChaCha20-Poly1305
     * @param plaintext Message to encrypt
     * @param shared_secret Shared secret from key exchange
     * @param nonce Unique nonce (12 bytes) - must never be reused with same key
     * @return Ciphertext with authentication tag appended
     */
    static std::optional<std::vector<uint8_t>> encrypt(
        const std::vector<uint8_t>& plaintext,
        const SharedSecret& shared_secret,
        const std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_NPUBBYTES>& nonce
    );

    /**
     * @brief Decrypt message with ChaCha20-Poly1305
     * @param ciphertext Encrypted message with authentication tag
     * @param shared_secret Shared secret from key exchange
     * @param nonce Nonce used for encryption (12 bytes)
     * @return Decrypted plaintext, or std::nullopt if authentication fails
     */
    static std::optional<std::vector<uint8_t>> decrypt(
        const std::vector<uint8_t>& ciphertext,
        const SharedSecret& shared_secret,
        const std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_NPUBBYTES>& nonce
    );

    // ========================================================================
    // Utility Functions
    // ========================================================================

    /**
     * @brief Generate cryptographically secure random nonce
     * @return Random nonce (12 bytes)
     */
    static std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_NPUBBYTES> generate_nonce();

    /**
     * @brief Generate cryptographically secure random bytes
     * @param size Number of random bytes to generate
     * @return Vector of random bytes
     */
    static std::vector<uint8_t> generate_random_bytes(size_t size);

    /**
     * @brief Constant-time comparison of byte arrays (prevents timing attacks)
     * @param a First byte array
     * @param b Second byte array
     * @return true if arrays are equal, false otherwise
     */
    static bool constant_time_compare(
        const std::vector<uint8_t>& a,
        const std::vector<uint8_t>& b
    );

    /**
     * @brief Convert bytes to hexadecimal string
     * @param bytes Input bytes
     * @return Hexadecimal string representation
     */
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);

    /**
     * @brief Convert bytes to base64 string
     * @param bytes Input bytes
     * @return Base64 string representation
     */
    static std::string bytes_to_base64(const std::vector<uint8_t>& bytes);

    /**
     * @brief Convert hexadecimal string to bytes
     * @param hex Hexadecimal string
     * @return Decoded bytes, or std::nullopt if invalid
     */
    static std::optional<std::vector<uint8_t>> hex_to_bytes(const std::string& hex);

    /**
     * @brief Convert base64 string to bytes
     * @param base64 Base64 string
     * @return Decoded bytes, or std::nullopt if invalid
     */
    static std::optional<std::vector<uint8_t>> base64_to_bytes(const std::string& base64);

    /**
     * @brief Securely zero memory (prevents compiler optimization from removing)
     * @param data Pointer to memory to zero
     * @param size Size of memory region
     */
    static void secure_zero(void* data, size_t size);
};

} // namespace nlitp
