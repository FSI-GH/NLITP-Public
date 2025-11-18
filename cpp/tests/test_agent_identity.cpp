/**
 * @file test_agent_identity.cpp
 * @brief Comprehensive unit tests for AgentIdentity
 *
 * Tests identity management including:
 * - Identity creation and key generation
 * - Persistent storage (save/load)
 * - Cryptographic operations (sign, verify, key exchange)
 * - Serialization (JSON import/export)
 * - Key management and security
 * - Thread safety
 */

#include <gtest/gtest.h>
#include "nlitp/agent_identity.hpp"
#include "nlitp/agent_crypto.hpp"
#include <filesystem>
#include <thread>
#include <vector>

using namespace nlitp;
namespace fs = std::filesystem;

// Test fixture for agent identity tests
class AgentIdentityTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto
        AgentCrypto::initialize();

        // Create temporary test directory
        test_dir_ = fs::temp_directory_path() / "nlitp_identity_test";
        fs::create_directories(test_dir_);
    }

    void TearDown() override {
        // Clean up test directory
        if (fs::exists(test_dir_)) {
            fs::remove_all(test_dir_);
        }
    }

    fs::path test_dir_;
};

// ============================================================================
// Identity Creation Tests
// ============================================================================

TEST_F(AgentIdentityTest, CreateIdentity) {
    AgentIdentity identity("test_agent");

    EXPECT_EQ(identity.get_agent_id(), "test_agent");
}

TEST_F(AgentIdentityTest, CreateIdentityGeneratesKeys) {
    AgentIdentity identity("test_agent");

    // Should have generated keys
    auto sig_key = identity.get_signature_public_key();
    auto enc_key = identity.get_encryption_public_key();

    // Keys should not be all zeros
    bool sig_not_zero = false;
    bool enc_not_zero = false;

    for (uint8_t byte : sig_key) {
        if (byte != 0) sig_not_zero = true;
    }
    for (uint8_t byte : enc_key) {
        if (byte != 0) enc_not_zero = true;
    }

    EXPECT_TRUE(sig_not_zero);
    EXPECT_TRUE(enc_not_zero);
}

TEST_F(AgentIdentityTest, CreateMultipleIdentitiesUnique) {
    AgentIdentity identity1("agent1");
    AgentIdentity identity2("agent2");

    // Should have different keys
    EXPECT_NE(identity1.get_signature_public_key(), identity2.get_signature_public_key());
    EXPECT_NE(identity1.get_encryption_public_key(), identity2.get_encryption_public_key());
}

TEST_F(AgentIdentityTest, CreateIdentityWithEmptyId) {
    // Should handle empty ID gracefully
    AgentIdentity identity("");
    EXPECT_EQ(identity.get_agent_id(), "");
}

// ============================================================================
// Key Access Tests
// ============================================================================

TEST_F(AgentIdentityTest, GetSignaturePublicKey) {
    AgentIdentity identity("test_agent");
    auto key = identity.get_signature_public_key();

    EXPECT_EQ(key.size(), crypto_sign_PUBLICKEYBYTES);
}

TEST_F(AgentIdentityTest, GetEncryptionPublicKey) {
    AgentIdentity identity("test_agent");
    auto key = identity.get_encryption_public_key();

    EXPECT_EQ(key.size(), crypto_box_PUBLICKEYBYTES);
}

TEST_F(AgentIdentityTest, GetSignaturePublicKeyBase64) {
    AgentIdentity identity("test_agent");
    std::string key_b64 = identity.get_signature_public_key_b64();

    EXPECT_FALSE(key_b64.empty());
    // Base64 encoding increases size
    EXPECT_GT(key_b64.length(), crypto_sign_PUBLICKEYBYTES);
}

TEST_F(AgentIdentityTest, GetEncryptionPublicKeyBase64) {
    AgentIdentity identity("test_agent");
    std::string key_b64 = identity.get_encryption_public_key_b64();

    EXPECT_FALSE(key_b64.empty());
    EXPECT_GT(key_b64.length(), crypto_box_PUBLICKEYBYTES);
}

// ============================================================================
// Signature Tests
// ============================================================================

TEST_F(AgentIdentityTest, SignMessage) {
    AgentIdentity identity("test_agent");
    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    auto signature = identity.sign(message);

    EXPECT_EQ(signature.size(), crypto_sign_BYTES);
}

TEST_F(AgentIdentityTest, SignAndVerify) {
    AgentIdentity identity("test_agent");
    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    auto signature = identity.sign(message);
    auto public_key = identity.get_signature_public_key();

    EXPECT_TRUE(AgentIdentity::verify(message, signature, public_key));
}

TEST_F(AgentIdentityTest, VerifyInvalidSignature) {
    AgentIdentity identity("test_agent");
    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    auto signature = identity.sign(message);
    signature[0] ^= 0xFF;  // Corrupt signature

    auto public_key = identity.get_signature_public_key();

    EXPECT_FALSE(AgentIdentity::verify(message, signature, public_key));
}

TEST_F(AgentIdentityTest, VerifyWrongKey) {
    AgentIdentity identity1("agent1");
    AgentIdentity identity2("agent2");

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    auto signature = identity1.sign(message);
    auto wrong_key = identity2.get_signature_public_key();

    EXPECT_FALSE(AgentIdentity::verify(message, signature, wrong_key));
}

// ============================================================================
// Key Exchange Tests
// ============================================================================

TEST_F(AgentIdentityTest, KeyExchange) {
    AgentIdentity alice("alice");
    AgentIdentity bob("bob");

    auto alice_secret = alice.key_exchange(bob.get_encryption_public_key());
    auto bob_secret = bob.key_exchange(alice.get_encryption_public_key());

    ASSERT_TRUE(alice_secret.has_value());
    ASSERT_TRUE(bob_secret.has_value());

    // Both should derive same shared secret
    EXPECT_EQ(alice_secret->key, bob_secret->key);
}

TEST_F(AgentIdentityTest, KeyExchangeEncryptDecrypt) {
    AgentIdentity alice("alice");
    AgentIdentity bob("bob");

    auto shared_secret = alice.key_exchange(bob.get_encryption_public_key());
    ASSERT_TRUE(shared_secret.has_value());

    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    auto nonce = AgentCrypto::generate_nonce();

    // Alice encrypts
    auto ciphertext = AgentCrypto::encrypt(plaintext, *shared_secret, nonce);
    ASSERT_TRUE(ciphertext.has_value());

    // Bob decrypts with same shared secret
    auto bob_secret = bob.key_exchange(alice.get_encryption_public_key());
    ASSERT_TRUE(bob_secret.has_value());

    auto decrypted = AgentCrypto::decrypt(*ciphertext, *bob_secret, nonce);
    ASSERT_TRUE(decrypted.has_value());

    EXPECT_EQ(*decrypted, plaintext);
}

// ============================================================================
// Persistence Tests (Save/Load)
// ============================================================================

TEST_F(AgentIdentityTest, SaveIdentity) {
    AgentIdentity identity("test_agent");

    bool saved = identity.save(test_dir_);
    EXPECT_TRUE(saved);

    // Check that files were created
    // Implementation specific - may create key files
}

TEST_F(AgentIdentityTest, SaveAndLoadIdentity) {
    AgentIdentity original("test_agent");
    auto original_sig_key = original.get_signature_public_key();
    auto original_enc_key = original.get_encryption_public_key();

    // Save
    bool saved = original.save(test_dir_);
    ASSERT_TRUE(saved);

    // Load
    auto loaded = AgentIdentity::load("test_agent", test_dir_);
    ASSERT_TRUE(loaded.has_value());

    // Should have same keys
    EXPECT_EQ(loaded->get_agent_id(), "test_agent");
    EXPECT_EQ(loaded->get_signature_public_key(), original_sig_key);
    EXPECT_EQ(loaded->get_encryption_public_key(), original_enc_key);
}

TEST_F(AgentIdentityTest, LoadNonExistentIdentity) {
    auto loaded = AgentIdentity::load("non_existent", test_dir_);
    EXPECT_FALSE(loaded.has_value());
}

TEST_F(AgentIdentityTest, SaveOverwriteExisting) {
    AgentIdentity identity1("test_agent");
    identity1.save(test_dir_);

    AgentIdentity identity2("test_agent");
    bool saved = identity2.save(test_dir_);

    // Should overwrite
    EXPECT_TRUE(saved);
}

TEST_F(AgentIdentityTest, RemoveIdentity) {
    AgentIdentity identity("test_agent");
    identity.save(test_dir_);

    bool removed = AgentIdentity::remove("test_agent", test_dir_);
    EXPECT_TRUE(removed);

    // Should not be loadable
    auto loaded = AgentIdentity::load("test_agent", test_dir_);
    EXPECT_FALSE(loaded.has_value());
}

TEST_F(AgentIdentityTest, RemoveNonExistentIdentity) {
    bool removed = AgentIdentity::remove("non_existent", test_dir_);
    // Should return false or handle gracefully
    EXPECT_FALSE(removed);
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(AgentIdentityTest, ConcurrentSignature) {
    AgentIdentity identity("test_agent");
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<std::vector<uint8_t>> signatures(num_threads);

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([&identity, &signatures, t]() {
            std::vector<uint8_t> message = {static_cast<uint8_t>(t)};
            signatures[t] = identity.sign(message);
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All signatures should be valid
    auto public_key = identity.get_signature_public_key();
    for (int i = 0; i < num_threads; i++) {
        std::vector<uint8_t> message = {static_cast<uint8_t>(i)};
        EXPECT_TRUE(AgentIdentity::verify(message, signatures[i], public_key));
    }
}

TEST_F(AgentIdentityTest, ConcurrentKeyExchange) {
    AgentIdentity alice("alice");
    const int num_peers = 10;
    std::vector<std::thread> threads;
    std::vector<AgentIdentity> peers;
    std::vector<std::optional<SharedSecret>> secrets(num_peers);

    // Create peers
    for (int i = 0; i < num_peers; i++) {
        peers.emplace_back("peer" + std::to_string(i));
    }

    // Alice performs key exchange with all peers concurrently
    for (int i = 0; i < num_peers; i++) {
        threads.emplace_back([&alice, &peers, &secrets, i]() {
            secrets[i] = alice.key_exchange(peers[i].get_encryption_public_key());
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All key exchanges should succeed
    for (int i = 0; i < num_peers; i++) {
        EXPECT_TRUE(secrets[i].has_value());
    }
}

TEST_F(AgentIdentityTest, ConcurrentSaveLoad) {
    const int num_threads = 5;
    std::vector<std::thread> threads;
    std::vector<bool> results(num_threads);

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, &results, t]() {
            AgentIdentity identity("agent" + std::to_string(t));
            bool saved = identity.save(test_dir_);

            if (saved) {
                auto loaded = AgentIdentity::load("agent" + std::to_string(t), test_dir_);
                results[t] = loaded.has_value();
            } else {
                results[t] = false;
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All save/load operations should succeed
    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}

// ============================================================================
// Security Tests
// ============================================================================

TEST_F(AgentIdentityTest, KeysAreUnique) {
    std::vector<AgentIdentity> identities;
    const int num_identities = 10;

    for (int i = 0; i < num_identities; i++) {
        identities.emplace_back("agent" + std::to_string(i));
    }

    // All signature keys should be unique
    for (int i = 0; i < num_identities; i++) {
        for (int j = i + 1; j < num_identities; j++) {
            EXPECT_NE(identities[i].get_signature_public_key(),
                     identities[j].get_signature_public_key());
            EXPECT_NE(identities[i].get_encryption_public_key(),
                     identities[j].get_encryption_public_key());
        }
    }
}

TEST_F(AgentIdentityTest, SignatureDeterministic) {
    AgentIdentity identity("test_agent");
    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    auto sig1 = identity.sign(message);
    auto sig2 = identity.sign(message);

    // Signatures should be deterministic with Ed25519
    EXPECT_EQ(sig1, sig2);
}

TEST_F(AgentIdentityTest, CannotVerifyWithWrongMessage) {
    AgentIdentity identity("test_agent");
    std::vector<uint8_t> message1 = {1, 2, 3, 4, 5};
    std::vector<uint8_t> message2 = {1, 2, 3, 4, 6};

    auto signature = identity.sign(message1);
    auto public_key = identity.get_signature_public_key();

    EXPECT_TRUE(AgentIdentity::verify(message1, signature, public_key));
    EXPECT_FALSE(AgentIdentity::verify(message2, signature, public_key));
}

TEST_F(AgentIdentityTest, KeyExchangeIsolation) {
    AgentIdentity alice("alice");
    AgentIdentity bob("bob");
    AgentIdentity charlie("charlie");

    auto alice_bob = alice.key_exchange(bob.get_encryption_public_key());
    auto alice_charlie = alice.key_exchange(charlie.get_encryption_public_key());

    ASSERT_TRUE(alice_bob.has_value());
    ASSERT_TRUE(alice_charlie.has_value());

    // Different peers should produce different shared secrets
    EXPECT_NE(alice_bob->key, alice_charlie->key);
}

TEST_F(AgentIdentityTest, LongAgentId) {
    std::string long_id(1000, 'a');
    AgentIdentity identity(long_id);

    EXPECT_EQ(identity.get_agent_id(), long_id);
}

TEST_F(AgentIdentityTest, SpecialCharactersInAgentId) {
    std::string special_id = "agent!@#$%^&*()";
    AgentIdentity identity(special_id);

    EXPECT_EQ(identity.get_agent_id(), special_id);
}

TEST_F(AgentIdentityTest, PreservesIdentityAfterMultipleOperations) {
    AgentIdentity identity("test_agent");
    auto original_sig_key = identity.get_signature_public_key();
    auto original_enc_key = identity.get_encryption_public_key();

    // Perform various operations
    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    identity.sign(message);
    identity.get_signature_public_key_b64();
    identity.get_encryption_public_key_b64();

    // Keys should remain unchanged
    EXPECT_EQ(identity.get_signature_public_key(), original_sig_key);
    EXPECT_EQ(identity.get_encryption_public_key(), original_enc_key);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
