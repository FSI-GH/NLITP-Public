/**
 * @file test_agent_crypto.cpp
 * @brief Comprehensive unit tests for AgentCrypto
 *
 * Tests all cryptographic operations including:
 * - Key generation (Ed25519, X25519)
 * - Digital signatures (Ed25519)
 * - Key exchange (X25519 ECDH)
 * - Encryption/decryption (ChaCha20-Poly1305)
 * - Utility functions (encoding, constant-time comparison)
 * - Security edge cases and error handling
 * - Thread safety
 */

#include <gtest/gtest.h>
#include "nlitp/agent_crypto.hpp"
#include <thread>
#include <vector>
#include <algorithm>

using namespace nlitp;

// Test fixture for AgentCrypto tests
class AgentCryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize libsodium once for all tests
        ASSERT_TRUE(AgentCrypto::initialize());
    }
};

// ============================================================================
// Initialization Tests
// ============================================================================

TEST_F(AgentCryptoTest, InitializeSuccess) {
    // Should succeed on multiple calls
    EXPECT_TRUE(AgentCrypto::initialize());
    EXPECT_TRUE(AgentCrypto::initialize());
}

// ============================================================================
// Key Generation Tests
// ============================================================================

TEST_F(AgentCryptoTest, GenerateSignatureKeypair) {
    auto keypair = AgentCrypto::generate_signature_keypair();

    // Check key sizes
    EXPECT_EQ(keypair.public_key.size(), crypto_sign_PUBLICKEYBYTES);
    EXPECT_EQ(keypair.secret_key.size(), crypto_sign_SECRETKEYBYTES);

    // Verify keys are not all zeros
    bool public_not_zero = std::any_of(keypair.public_key.begin(),
                                       keypair.public_key.end(),
                                       [](uint8_t b) { return b != 0; });
    bool secret_not_zero = std::any_of(keypair.secret_key.begin(),
                                       keypair.secret_key.end(),
                                       [](uint8_t b) { return b != 0; });
    EXPECT_TRUE(public_not_zero);
    EXPECT_TRUE(secret_not_zero);
}

TEST_F(AgentCryptoTest, GenerateSignatureKeypairUniqueness) {
    auto keypair1 = AgentCrypto::generate_signature_keypair();
    auto keypair2 = AgentCrypto::generate_signature_keypair();

    // Different keypairs should have different keys
    EXPECT_NE(keypair1.public_key, keypair2.public_key);
    EXPECT_NE(keypair1.secret_key, keypair2.secret_key);
}

TEST_F(AgentCryptoTest, GenerateEncryptionKeypair) {
    auto keypair = AgentCrypto::generate_encryption_keypair();

    // Check key sizes
    EXPECT_EQ(keypair.public_key.size(), crypto_box_PUBLICKEYBYTES);
    EXPECT_EQ(keypair.secret_key.size(), crypto_box_SECRETKEYBYTES);

    // Verify keys are not all zeros
    bool public_not_zero = std::any_of(keypair.public_key.begin(),
                                       keypair.public_key.end(),
                                       [](uint8_t b) { return b != 0; });
    bool secret_not_zero = std::any_of(keypair.secret_key.begin(),
                                       keypair.secret_key.end(),
                                       [](uint8_t b) { return b != 0; });
    EXPECT_TRUE(public_not_zero);
    EXPECT_TRUE(secret_not_zero);
}

TEST_F(AgentCryptoTest, GenerateEncryptionKeypairUniqueness) {
    auto keypair1 = AgentCrypto::generate_encryption_keypair();
    auto keypair2 = AgentCrypto::generate_encryption_keypair();

    // Different keypairs should have different keys
    EXPECT_NE(keypair1.public_key, keypair2.public_key);
    EXPECT_NE(keypair1.secret_key, keypair2.secret_key);
}

// ============================================================================
// Digital Signature Tests (Ed25519)
// ============================================================================

TEST_F(AgentCryptoTest, SignAndVerifyMessage) {
    auto keypair = AgentCrypto::generate_signature_keypair();
    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    // Sign message
    auto signature = AgentCrypto::sign_message(message, keypair.secret_key);

    // Verify signature
    EXPECT_TRUE(AgentCrypto::verify_signature(message, signature, keypair.public_key));
}

TEST_F(AgentCryptoTest, SignatureSize) {
    auto keypair = AgentCrypto::generate_signature_keypair();
    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    auto signature = AgentCrypto::sign_message(message, keypair.secret_key);

    EXPECT_EQ(signature.size(), crypto_sign_BYTES);
}

TEST_F(AgentCryptoTest, VerifyInvalidSignature) {
    auto keypair = AgentCrypto::generate_signature_keypair();
    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    auto signature = AgentCrypto::sign_message(message, keypair.secret_key);

    // Modify signature
    signature[0] ^= 0xFF;

    // Should fail verification
    EXPECT_FALSE(AgentCrypto::verify_signature(message, signature, keypair.public_key));
}

TEST_F(AgentCryptoTest, VerifyModifiedMessage) {
    auto keypair = AgentCrypto::generate_signature_keypair();
    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    auto signature = AgentCrypto::sign_message(message, keypair.secret_key);

    // Modify message
    message[0] ^= 0xFF;

    // Should fail verification
    EXPECT_FALSE(AgentCrypto::verify_signature(message, signature, keypair.public_key));
}

TEST_F(AgentCryptoTest, VerifyWrongPublicKey) {
    auto keypair1 = AgentCrypto::generate_signature_keypair();
    auto keypair2 = AgentCrypto::generate_signature_keypair();
    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    auto signature = AgentCrypto::sign_message(message, keypair1.secret_key);

    // Try to verify with wrong public key
    EXPECT_FALSE(AgentCrypto::verify_signature(message, signature, keypair2.public_key));
}

TEST_F(AgentCryptoTest, SignEmptyMessage) {
    auto keypair = AgentCrypto::generate_signature_keypair();
    std::vector<uint8_t> empty_message;

    auto signature = AgentCrypto::sign_message(empty_message, keypair.secret_key);

    // Should still produce valid signature
    EXPECT_EQ(signature.size(), crypto_sign_BYTES);
    EXPECT_TRUE(AgentCrypto::verify_signature(empty_message, signature, keypair.public_key));
}

TEST_F(AgentCryptoTest, SignLargeMessage) {
    auto keypair = AgentCrypto::generate_signature_keypair();
    std::vector<uint8_t> large_message(1024 * 1024, 0x42); // 1 MB

    auto signature = AgentCrypto::sign_message(large_message, keypair.secret_key);

    EXPECT_EQ(signature.size(), crypto_sign_BYTES);
    EXPECT_TRUE(AgentCrypto::verify_signature(large_message, signature, keypair.public_key));
}

// ============================================================================
// Key Exchange Tests (X25519 ECDH)
// ============================================================================

TEST_F(AgentCryptoTest, KeyExchangeSuccess) {
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();

    // Alice computes shared secret with Bob's public key
    auto alice_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);

    // Bob computes shared secret with Alice's public key
    auto bob_secret = AgentCrypto::key_exchange(bob_keypair.secret_key, alice_keypair.public_key);

    // Both should compute same shared secret
    ASSERT_TRUE(alice_secret.has_value());
    ASSERT_TRUE(bob_secret.has_value());
    EXPECT_EQ(alice_secret->key, bob_secret->key);
}

TEST_F(AgentCryptoTest, KeyExchangeSharedSecretSize) {
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();

    auto shared_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);

    ASSERT_TRUE(shared_secret.has_value());
    EXPECT_EQ(shared_secret->key.size(), crypto_box_BEFORENMBYTES);
}

TEST_F(AgentCryptoTest, KeyExchangeDifferentPeers) {
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();
    auto charlie_keypair = AgentCrypto::generate_encryption_keypair();

    // Alice-Bob shared secret
    auto alice_bob = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);

    // Alice-Charlie shared secret
    auto alice_charlie = AgentCrypto::key_exchange(alice_keypair.secret_key, charlie_keypair.public_key);

    // Should be different
    ASSERT_TRUE(alice_bob.has_value());
    ASSERT_TRUE(alice_charlie.has_value());
    EXPECT_NE(alice_bob->key, alice_charlie->key);
}

// ============================================================================
// Encryption/Decryption Tests (ChaCha20-Poly1305)
// ============================================================================

TEST_F(AgentCryptoTest, EncryptDecryptSuccess) {
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();

    auto shared_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);
    ASSERT_TRUE(shared_secret.has_value());

    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5, 6, 7, 8};
    auto nonce = AgentCrypto::generate_nonce();

    // Encrypt
    auto ciphertext = AgentCrypto::encrypt(plaintext, *shared_secret, nonce);
    ASSERT_TRUE(ciphertext.has_value());

    // Decrypt
    auto decrypted = AgentCrypto::decrypt(*ciphertext, *shared_secret, nonce);
    ASSERT_TRUE(decrypted.has_value());

    EXPECT_EQ(plaintext, *decrypted);
}

TEST_F(AgentCryptoTest, EncryptedSizeLargerThanPlaintext) {
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();

    auto shared_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);
    ASSERT_TRUE(shared_secret.has_value());

    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    auto nonce = AgentCrypto::generate_nonce();

    auto ciphertext = AgentCrypto::encrypt(plaintext, *shared_secret, nonce);
    ASSERT_TRUE(ciphertext.has_value());

    // Ciphertext should include authentication tag
    EXPECT_GT(ciphertext->size(), plaintext.size());
}

TEST_F(AgentCryptoTest, DecryptModifiedCiphertext) {
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();

    auto shared_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);
    ASSERT_TRUE(shared_secret.has_value());

    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    auto nonce = AgentCrypto::generate_nonce();

    auto ciphertext = AgentCrypto::encrypt(plaintext, *shared_secret, nonce);
    ASSERT_TRUE(ciphertext.has_value());

    // Tamper with ciphertext
    (*ciphertext)[0] ^= 0xFF;

    // Decryption should fail (authentication failure)
    auto decrypted = AgentCrypto::decrypt(*ciphertext, *shared_secret, nonce);
    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AgentCryptoTest, DecryptWrongNonce) {
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();

    auto shared_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);
    ASSERT_TRUE(shared_secret.has_value());

    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    auto nonce = AgentCrypto::generate_nonce();

    auto ciphertext = AgentCrypto::encrypt(plaintext, *shared_secret, nonce);
    ASSERT_TRUE(ciphertext.has_value());

    // Use wrong nonce for decryption
    auto wrong_nonce = AgentCrypto::generate_nonce();
    auto decrypted = AgentCrypto::decrypt(*ciphertext, *shared_secret, wrong_nonce);
    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AgentCryptoTest, DecryptWrongSharedSecret) {
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();
    auto eve_keypair = AgentCrypto::generate_encryption_keypair();

    auto alice_bob_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);
    auto alice_eve_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, eve_keypair.public_key);
    ASSERT_TRUE(alice_bob_secret.has_value());
    ASSERT_TRUE(alice_eve_secret.has_value());

    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    auto nonce = AgentCrypto::generate_nonce();

    // Alice encrypts for Bob
    auto ciphertext = AgentCrypto::encrypt(plaintext, *alice_bob_secret, nonce);
    ASSERT_TRUE(ciphertext.has_value());

    // Eve tries to decrypt with wrong shared secret
    auto decrypted = AgentCrypto::decrypt(*ciphertext, *alice_eve_secret, nonce);
    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AgentCryptoTest, EncryptEmptyMessage) {
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();

    auto shared_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);
    ASSERT_TRUE(shared_secret.has_value());

    std::vector<uint8_t> empty_plaintext;
    auto nonce = AgentCrypto::generate_nonce();

    auto ciphertext = AgentCrypto::encrypt(empty_plaintext, *shared_secret, nonce);
    ASSERT_TRUE(ciphertext.has_value());

    auto decrypted = AgentCrypto::decrypt(*ciphertext, *shared_secret, nonce);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, empty_plaintext);
}

TEST_F(AgentCryptoTest, EncryptLargeMessage) {
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();

    auto shared_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);
    ASSERT_TRUE(shared_secret.has_value());

    // 1 MB message
    std::vector<uint8_t> large_plaintext(1024 * 1024);
    for (size_t i = 0; i < large_plaintext.size(); i++) {
        large_plaintext[i] = static_cast<uint8_t>(i % 256);
    }

    auto nonce = AgentCrypto::generate_nonce();

    auto ciphertext = AgentCrypto::encrypt(large_plaintext, *shared_secret, nonce);
    ASSERT_TRUE(ciphertext.has_value());

    auto decrypted = AgentCrypto::decrypt(*ciphertext, *shared_secret, nonce);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, large_plaintext);
}

// ============================================================================
// Nonce Generation Tests
// ============================================================================

TEST_F(AgentCryptoTest, GenerateNonceSize) {
    auto nonce = AgentCrypto::generate_nonce();
    EXPECT_EQ(nonce.size(), crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
}

TEST_F(AgentCryptoTest, GenerateNonceUniqueness) {
    auto nonce1 = AgentCrypto::generate_nonce();
    auto nonce2 = AgentCrypto::generate_nonce();

    // Nonces should be different
    EXPECT_NE(nonce1, nonce2);
}

TEST_F(AgentCryptoTest, GenerateRandomBytesSize) {
    size_t sizes[] = {0, 1, 16, 32, 64, 128, 256, 1024};

    for (size_t size : sizes) {
        auto random_bytes = AgentCrypto::generate_random_bytes(size);
        EXPECT_EQ(random_bytes.size(), size);
    }
}

TEST_F(AgentCryptoTest, GenerateRandomBytesUniqueness) {
    auto bytes1 = AgentCrypto::generate_random_bytes(32);
    auto bytes2 = AgentCrypto::generate_random_bytes(32);

    EXPECT_NE(bytes1, bytes2);
}

// ============================================================================
// Constant-Time Comparison Tests
// ============================================================================

TEST_F(AgentCryptoTest, ConstantTimeCompareEqual) {
    std::vector<uint8_t> a = {1, 2, 3, 4, 5};
    std::vector<uint8_t> b = {1, 2, 3, 4, 5};

    EXPECT_TRUE(AgentCrypto::constant_time_compare(a, b));
}

TEST_F(AgentCryptoTest, ConstantTimeCompareNotEqual) {
    std::vector<uint8_t> a = {1, 2, 3, 4, 5};
    std::vector<uint8_t> b = {1, 2, 3, 4, 6};

    EXPECT_FALSE(AgentCrypto::constant_time_compare(a, b));
}

TEST_F(AgentCryptoTest, ConstantTimeCompareDifferentSizes) {
    std::vector<uint8_t> a = {1, 2, 3};
    std::vector<uint8_t> b = {1, 2, 3, 4};

    EXPECT_FALSE(AgentCrypto::constant_time_compare(a, b));
}

TEST_F(AgentCryptoTest, ConstantTimeCompareEmpty) {
    std::vector<uint8_t> a;
    std::vector<uint8_t> b;

    EXPECT_TRUE(AgentCrypto::constant_time_compare(a, b));
}

// ============================================================================
// Encoding Tests (Hex, Base64)
// ============================================================================

TEST_F(AgentCryptoTest, BytesToHex) {
    std::vector<uint8_t> bytes = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    std::string hex = AgentCrypto::bytes_to_hex(bytes);

    EXPECT_EQ(hex, "0123456789abcdef");
}

TEST_F(AgentCryptoTest, HexToBytes) {
    std::string hex = "0123456789abcdef";
    auto bytes = AgentCrypto::hex_to_bytes(hex);

    ASSERT_TRUE(bytes.has_value());

    std::vector<uint8_t> expected = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    EXPECT_EQ(*bytes, expected);
}

TEST_F(AgentCryptoTest, HexRoundTrip) {
    std::vector<uint8_t> original = AgentCrypto::generate_random_bytes(32);
    std::string hex = AgentCrypto::bytes_to_hex(original);
    auto decoded = AgentCrypto::hex_to_bytes(hex);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, original);
}

TEST_F(AgentCryptoTest, HexInvalidCharacters) {
    std::string invalid_hex = "0123456789GGGGGG";
    auto bytes = AgentCrypto::hex_to_bytes(invalid_hex);

    EXPECT_FALSE(bytes.has_value());
}

TEST_F(AgentCryptoTest, HexOddLength) {
    std::string odd_hex = "012345";
    auto bytes = AgentCrypto::hex_to_bytes(odd_hex);

    // Should handle gracefully (implementation dependent)
    EXPECT_FALSE(bytes.has_value());
}

TEST_F(AgentCryptoTest, Base64RoundTrip) {
    std::vector<uint8_t> original = AgentCrypto::generate_random_bytes(32);
    std::string base64 = AgentCrypto::bytes_to_base64(original);
    auto decoded = AgentCrypto::base64_to_bytes(base64);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, original);
}

TEST_F(AgentCryptoTest, Base64EmptyInput) {
    std::vector<uint8_t> empty;
    std::string base64 = AgentCrypto::bytes_to_base64(empty);
    auto decoded = AgentCrypto::base64_to_bytes(base64);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, empty);
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(AgentCryptoTest, ConcurrentKeyGeneration) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<SignatureKeyPair> keypairs(num_threads);

    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back([&keypairs, i]() {
            keypairs[i] = AgentCrypto::generate_signature_keypair();
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All keypairs should be unique
    for (int i = 0; i < num_threads; i++) {
        for (int j = i + 1; j < num_threads; j++) {
            EXPECT_NE(keypairs[i].public_key, keypairs[j].public_key);
        }
    }
}

TEST_F(AgentCryptoTest, ConcurrentSignAndVerify) {
    const int num_threads = 10;
    auto keypair = AgentCrypto::generate_signature_keypair();
    std::vector<std::thread> threads;
    std::vector<bool> results(num_threads);

    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back([&keypair, &results, i]() {
            std::vector<uint8_t> message = {static_cast<uint8_t>(i)};
            auto signature = AgentCrypto::sign_message(message, keypair.secret_key);
            results[i] = AgentCrypto::verify_signature(message, signature, keypair.public_key);
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All verifications should succeed
    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}

TEST_F(AgentCryptoTest, ConcurrentEncryptDecrypt) {
    const int num_threads = 10;
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();
    auto shared_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);
    ASSERT_TRUE(shared_secret.has_value());

    std::vector<std::thread> threads;
    std::vector<bool> results(num_threads);

    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back([&shared_secret, &results, i]() {
            std::vector<uint8_t> plaintext = {static_cast<uint8_t>(i)};
            auto nonce = AgentCrypto::generate_nonce();
            auto ciphertext = AgentCrypto::encrypt(plaintext, *shared_secret, nonce);
            if (!ciphertext.has_value()) {
                results[i] = false;
                return;
            }
            auto decrypted = AgentCrypto::decrypt(*ciphertext, *shared_secret, nonce);
            results[i] = decrypted.has_value() && (*decrypted == plaintext);
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All operations should succeed
    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}

// ============================================================================
// Security Tests
// ============================================================================

TEST_F(AgentCryptoTest, SecureZeroMemory) {
    std::vector<uint8_t> sensitive_data(32, 0xFF);

    AgentCrypto::secure_zero(sensitive_data.data(), sensitive_data.size());

    // All bytes should be zero
    for (uint8_t byte : sensitive_data) {
        EXPECT_EQ(byte, 0);
    }
}

TEST_F(AgentCryptoTest, NonceReusePrevention) {
    // This test documents that nonce reuse is dangerous
    auto alice_keypair = AgentCrypto::generate_encryption_keypair();
    auto bob_keypair = AgentCrypto::generate_encryption_keypair();

    auto shared_secret = AgentCrypto::key_exchange(alice_keypair.secret_key, bob_keypair.public_key);
    ASSERT_TRUE(shared_secret.has_value());

    auto nonce = AgentCrypto::generate_nonce();

    std::vector<uint8_t> plaintext1 = {1, 2, 3};
    std::vector<uint8_t> plaintext2 = {4, 5, 6};

    // Both encryptions use same nonce (BAD PRACTICE - for testing only)
    auto ciphertext1 = AgentCrypto::encrypt(plaintext1, *shared_secret, nonce);
    auto ciphertext2 = AgentCrypto::encrypt(plaintext2, *shared_secret, nonce);

    ASSERT_TRUE(ciphertext1.has_value());
    ASSERT_TRUE(ciphertext2.has_value());

    // Ciphertexts should be different even with same nonce (but this reveals info)
    EXPECT_NE(*ciphertext1, *ciphertext2);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
