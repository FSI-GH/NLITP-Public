/**
 * @file agent_crypto.cpp
 * @brief Implementation of cryptographic operations for NLITP agents
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * - Ed25519: Digital signatures (128-bit security)
 * - X25519: Key exchange (ECDH)
 * - ChaCha20-Poly1305: AEAD cipher
 * - libsodium: Industry-standard implementation
 */

#include "nlitp/agent_crypto.hpp"
#include <stdexcept>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace nlitp {

// ============================================================================
// Initialization
// ============================================================================

bool AgentCrypto::initialize() {
    // Initialize libsodium (safe to call multiple times)
    if (sodium_init() < 0) {
        return false;
    }
    return true;
}

// ============================================================================
// Key Generation
// ============================================================================

SignatureKeyPair AgentCrypto::generate_signature_keypair() {
    SignatureKeyPair keypair;

    // Generate Ed25519 key pair
    crypto_sign_keypair(
        keypair.public_key.data(),
        keypair.secret_key.data()
    );

    return keypair;
}

EncryptionKeyPair AgentCrypto::generate_encryption_keypair() {
    EncryptionKeyPair keypair;

    // Generate X25519 key pair
    crypto_box_keypair(
        keypair.public_key.data(),
        keypair.secret_key.data()
    );

    return keypair;
}

// ============================================================================
// Digital Signatures (Ed25519)
// ============================================================================

std::vector<uint8_t> AgentCrypto::sign_message(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, crypto_sign_SECRETKEYBYTES>& secret_key
) {
    // Allocate signature buffer
    std::vector<uint8_t> signature(crypto_sign_BYTES);

    // Sign the message (detached signature)
    unsigned long long signature_len;
    crypto_sign_detached(
        signature.data(),
        &signature_len,
        message.data(),
        message.size(),
        secret_key.data()
    );

    // Resize to actual signature length (should always be crypto_sign_BYTES)
    signature.resize(signature_len);

    return signature;
}

bool AgentCrypto::verify_signature(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature,
    const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& public_key
) {
    // Signature must be exactly 64 bytes
    if (signature.size() != crypto_sign_BYTES) {
        return false;
    }

    // Verify detached signature
    int result = crypto_sign_verify_detached(
        signature.data(),
        message.data(),
        message.size(),
        public_key.data()
    );

    return result == 0;
}

// ============================================================================
// Key Exchange (X25519 ECDH)
// ============================================================================

std::optional<SharedSecret> AgentCrypto::key_exchange(
    const std::array<uint8_t, crypto_box_SECRETKEYBYTES>& our_secret_key,
    const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& their_public_key
) {
    SharedSecret shared;

    // Compute shared secret via X25519 ECDH
    int result = crypto_box_beforenm(
        shared.key.data(),
        their_public_key.data(),
        our_secret_key.data()
    );

    if (result != 0) {
        return std::nullopt;
    }

    return shared;
}

// ============================================================================
// Encryption (ChaCha20-Poly1305 AEAD)
// ============================================================================

std::optional<std::vector<uint8_t>> AgentCrypto::encrypt(
    const std::vector<uint8_t>& plaintext,
    const SharedSecret& shared_secret,
    const std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_NPUBBYTES>& nonce
) {
    // Allocate ciphertext buffer (plaintext + authentication tag)
    std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);

    unsigned long long ciphertext_len;

    // Encrypt with ChaCha20-Poly1305 (IETF variant)
    int result = crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(),
        &ciphertext_len,
        plaintext.data(),
        plaintext.size(),
        nullptr,  // No additional data
        0,
        nullptr,  // No secret nonce
        nonce.data(),
        shared_secret.key.data()
    );

    if (result != 0) {
        return std::nullopt;
    }

    // Resize to actual ciphertext length
    ciphertext.resize(ciphertext_len);

    return ciphertext;
}

std::optional<std::vector<uint8_t>> AgentCrypto::decrypt(
    const std::vector<uint8_t>& ciphertext,
    const SharedSecret& shared_secret,
    const std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_NPUBBYTES>& nonce
) {
    // Ciphertext must be at least as long as the authentication tag
    if (ciphertext.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) {
        return std::nullopt;
    }

    // Allocate plaintext buffer (ciphertext - authentication tag)
    std::vector<uint8_t> plaintext(ciphertext.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);

    unsigned long long plaintext_len;

    // Decrypt with ChaCha20-Poly1305 (IETF variant)
    // This will fail if authentication tag doesn't match (tampering detected)
    int result = crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext.data(),
        &plaintext_len,
        nullptr,  // No secret nonce
        ciphertext.data(),
        ciphertext.size(),
        nullptr,  // No additional data
        0,
        nonce.data(),
        shared_secret.key.data()
    );

    if (result != 0) {
        // Authentication failed - message was tampered with
        return std::nullopt;
    }

    // Resize to actual plaintext length
    plaintext.resize(plaintext_len);

    return plaintext;
}

// ============================================================================
// Utility Functions
// ============================================================================

std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_NPUBBYTES> AgentCrypto::generate_nonce() {
    std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_NPUBBYTES> nonce;
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

std::vector<uint8_t> AgentCrypto::generate_random_bytes(size_t size) {
    std::vector<uint8_t> bytes(size);
    randombytes_buf(bytes.data(), size);
    return bytes;
}

bool AgentCrypto::constant_time_compare(
    const std::vector<uint8_t>& a,
    const std::vector<uint8_t>& b
) {
    // Must be same length
    if (a.size() != b.size()) {
        return false;
    }

    // Use libsodium's constant-time comparison to prevent timing attacks
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string AgentCrypto::bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (uint8_t byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

std::string AgentCrypto::bytes_to_base64(const std::vector<uint8_t>& bytes) {
    // Calculate base64 encoded length
    size_t base64_len = sodium_base64_encoded_len(
        bytes.size(),
        sodium_base64_VARIANT_ORIGINAL
    );

    // Allocate buffer for base64 string
    std::vector<char> base64(base64_len);

    // Encode to base64
    sodium_bin2base64(
        base64.data(),
        base64.size(),
        bytes.data(),
        bytes.size(),
        sodium_base64_VARIANT_ORIGINAL
    );

    return std::string(base64.data());
}

std::optional<std::vector<uint8_t>> AgentCrypto::hex_to_bytes(const std::string& hex) {
    // Hex string must have even length
    if (hex.length() % 2 != 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);

        try {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
            bytes.push_back(byte);
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    return bytes;
}

std::optional<std::vector<uint8_t>> AgentCrypto::base64_to_bytes(const std::string& base64) {
    // Calculate maximum decoded length
    size_t max_decoded_len = base64.length();

    // Allocate buffer for decoded bytes
    std::vector<uint8_t> bytes(max_decoded_len);

    size_t decoded_len;
    const char* end_ptr;

    // Decode from base64
    int result = sodium_base642bin(
        bytes.data(),
        bytes.size(),
        base64.c_str(),
        base64.length(),
        nullptr,  // No ignore characters
        &decoded_len,
        &end_ptr,
        sodium_base64_VARIANT_ORIGINAL
    );

    if (result != 0) {
        return std::nullopt;
    }

    // Resize to actual decoded length
    bytes.resize(decoded_len);

    return bytes;
}

void AgentCrypto::secure_zero(void* data, size_t size) {
    // Use libsodium's secure memzero (prevents compiler optimization from removing)
    sodium_memzero(data, size);
}

} // namespace nlitp
