/**
 * @file test_message_types.cpp
 * @brief Comprehensive unit tests for message types and serialization
 *
 * Tests message serialization including:
 * - Message type conversion
 * - JSON serialization/deserialization
 * - All message payload types
 * - Message validation
 * - Edge cases and error handling
 */

#include <gtest/gtest.h>
#include "nlitp/message_types.hpp"
#include "nlitp/agent_crypto.hpp"
#include <thread>
#include <vector>

using namespace nlitp;

// Test fixture for message types tests
class MessageTypesTest : public ::testing::Test {
protected:
    void SetUp() override {
        AgentCrypto::initialize();
    }
};

// ============================================================================
// MessageType Enum Tests
// ============================================================================

TEST_F(MessageTypesTest, MessageTypeToString) {
    EXPECT_EQ(MessageHelpers::message_type_to_string(MessageType::DISCOVERY_ANNOUNCE), "DISCOVERY_ANNOUNCE");
    EXPECT_EQ(MessageHelpers::message_type_to_string(MessageType::SESSION_REQUEST), "SESSION_REQUEST");
    EXPECT_EQ(MessageHelpers::message_type_to_string(MessageType::FILE_OFFER), "FILE_OFFER");
    EXPECT_EQ(MessageHelpers::message_type_to_string(MessageType::PING), "PING");
}

TEST_F(MessageTypesTest, StringToMessageType) {
    auto type = MessageHelpers::string_to_message_type("DISCOVERY_ANNOUNCE");
    ASSERT_TRUE(type.has_value());
    EXPECT_EQ(*type, MessageType::DISCOVERY_ANNOUNCE);
}

TEST_F(MessageTypesTest, StringToMessageTypeInvalid) {
    auto type = MessageHelpers::string_to_message_type("INVALID_TYPE");
    EXPECT_FALSE(type.has_value());
}

TEST_F(MessageTypesTest, MessageTypeRoundTrip) {
    MessageType types[] = {
        MessageType::DISCOVERY_ANNOUNCE,
        MessageType::SESSION_REQUEST,
        MessageType::FILE_OFFER,
        MessageType::TRUST_OBSERVATION,
        MessageType::GATEKEEPER_REGISTER,
        MessageType::PING
    };

    for (MessageType type : types) {
        std::string str = MessageHelpers::message_type_to_string(type);
        auto converted = MessageHelpers::string_to_message_type(str);
        ASSERT_TRUE(converted.has_value());
        EXPECT_EQ(*converted, type);
    }
}

// ============================================================================
// Message ID Generation Tests
// ============================================================================

TEST_F(MessageTypesTest, GenerateMessageId) {
    std::string msg_id = MessageHelpers::generate_message_id(
        "sender123", 1234567890, "nonce123"
    );

    EXPECT_EQ(msg_id.length(), 64);  // SHA-256 hex
}

TEST_F(MessageTypesTest, GenerateMessageIdUniqueness) {
    std::string msg_id1 = MessageHelpers::generate_message_id(
        "sender1", 1234567890, "nonce1"
    );
    std::string msg_id2 = MessageHelpers::generate_message_id(
        "sender1", 1234567890, "nonce2"
    );

    EXPECT_NE(msg_id1, msg_id2);
}

TEST_F(MessageTypesTest, GetCurrentTimestamp) {
    uint64_t timestamp1 = MessageHelpers::get_current_timestamp();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    uint64_t timestamp2 = MessageHelpers::get_current_timestamp();

    EXPECT_GT(timestamp2, timestamp1);
}

// ============================================================================
// Message Validation Tests
// ============================================================================

TEST_F(MessageTypesTest, ValidateMessageSizeValid) {
    EXPECT_TRUE(MessageHelpers::validate_message_size(1024));
    EXPECT_TRUE(MessageHelpers::validate_message_size(1024 * 1024));
}

TEST_F(MessageTypesTest, ValidateMessageSizeTooLarge) {
    EXPECT_FALSE(MessageHelpers::validate_message_size(20 * 1024 * 1024));  // > 10MB
}

TEST_F(MessageTypesTest, ValidateMessageSizeZero) {
    EXPECT_TRUE(MessageHelpers::validate_message_size(0));
}

TEST_F(MessageTypesTest, ValidateFileSizeValid) {
    EXPECT_TRUE(MessageHelpers::validate_file_size(1024 * 1024));
}

TEST_F(MessageTypesTest, ValidateFileSizeTooLarge) {
    EXPECT_FALSE(MessageHelpers::validate_file_size(100ULL * 1024 * 1024));  // > 50MB
}

// ============================================================================
// Base Message Tests
// ============================================================================

TEST_F(MessageTypesTest, MessageToJson) {
    Message msg;
    msg.type = MessageType::PING;
    msg.message_id = "test_id_123";
    msg.timestamp = 1234567890;
    msg.sender_id = "sender1";
    msg.recipient_id = "recipient1";
    msg.signature = {1, 2, 3, 4};
    msg.payload = {5, 6, 7, 8};

    std::string json = msg.to_json();

    EXPECT_FALSE(json.empty());
    EXPECT_NE(json.find("PING"), std::string::npos);
    EXPECT_NE(json.find("sender1"), std::string::npos);
}

TEST_F(MessageTypesTest, MessageFromJson) {
    Message original;
    original.type = MessageType::PING;
    original.message_id = "test_id_123";
    original.timestamp = 1234567890;
    original.sender_id = "sender1";
    original.recipient_id = "recipient1";
    original.signature = {1, 2, 3, 4};
    original.payload = {5, 6, 7, 8};

    std::string json = original.to_json();
    auto parsed = Message::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->type, MessageType::PING);
    EXPECT_EQ(parsed->sender_id, "sender1");
    EXPECT_EQ(parsed->recipient_id, "recipient1");
}

TEST_F(MessageTypesTest, MessageRoundTrip) {
    Message original;
    original.type = MessageType::SESSION_MESSAGE;
    original.message_id = "msg_id_abc";
    original.timestamp = MessageHelpers::get_current_timestamp();
    original.sender_id = "alice";
    original.recipient_id = "bob";
    original.signature = AgentCrypto::generate_random_bytes(64);
    original.payload = AgentCrypto::generate_random_bytes(256);

    std::string json = original.to_json();
    auto parsed = Message::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->type, original.type);
    EXPECT_EQ(parsed->message_id, original.message_id);
    EXPECT_EQ(parsed->timestamp, original.timestamp);
    EXPECT_EQ(parsed->sender_id, original.sender_id);
    EXPECT_EQ(parsed->recipient_id, original.recipient_id);
    EXPECT_EQ(parsed->signature, original.signature);
    EXPECT_EQ(parsed->payload, original.payload);
}

TEST_F(MessageTypesTest, MessageFromInvalidJson) {
    auto parsed = Message::from_json("invalid json");
    EXPECT_FALSE(parsed.has_value());
}

TEST_F(MessageTypesTest, MessageFromEmptyJson) {
    auto parsed = Message::from_json("");
    EXPECT_FALSE(parsed.has_value());
}

// ============================================================================
// DiscoveryAnnounce Tests
// ============================================================================

TEST_F(MessageTypesTest, DiscoveryAnnounceToJson) {
    DiscoveryAnnounce announce;
    announce.agent_id = "agent123";
    announce.host = "192.168.1.100";
    announce.port = 12345;
    announce.public_key_sign = AgentCrypto::generate_random_bytes(32);
    announce.public_key_enc = AgentCrypto::generate_random_bytes(32);
    announce.capabilities["protocol"] = "NLITPv8";

    std::string json = announce.to_json();

    EXPECT_FALSE(json.empty());
    EXPECT_NE(json.find("agent123"), std::string::npos);
}

TEST_F(MessageTypesTest, DiscoveryAnnounceRoundTrip) {
    DiscoveryAnnounce original;
    original.agent_id = "agent456";
    original.host = "10.0.0.1";
    original.port = 54321;
    original.public_key_sign = AgentCrypto::generate_random_bytes(32);
    original.public_key_enc = AgentCrypto::generate_random_bytes(32);
    original.capabilities["version"] = "8.0";

    std::string json = original.to_json();
    auto parsed = DiscoveryAnnounce::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->agent_id, original.agent_id);
    EXPECT_EQ(parsed->host, original.host);
    EXPECT_EQ(parsed->port, original.port);
}

// ============================================================================
// SessionRequest Tests
// ============================================================================

TEST_F(MessageTypesTest, SessionRequestToJson) {
    SessionRequest request;
    request.session_id = "session_abc";
    request.ephemeral_key = AgentCrypto::generate_random_bytes(32);
    request.nonce = AgentCrypto::generate_random_bytes(12);

    std::string json = request.to_json();

    EXPECT_FALSE(json.empty());
    EXPECT_NE(json.find("session_abc"), std::string::npos);
}

TEST_F(MessageTypesTest, SessionRequestRoundTrip) {
    SessionRequest original;
    original.session_id = "session_xyz";
    original.ephemeral_key = AgentCrypto::generate_random_bytes(32);
    original.nonce = AgentCrypto::generate_random_bytes(12);

    std::string json = original.to_json();
    auto parsed = SessionRequest::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->session_id, original.session_id);
    EXPECT_EQ(parsed->ephemeral_key, original.ephemeral_key);
    EXPECT_EQ(parsed->nonce, original.nonce);
}

// ============================================================================
// SessionAccept Tests
// ============================================================================

TEST_F(MessageTypesTest, SessionAcceptRoundTrip) {
    SessionAccept original;
    original.session_id = "session_123";
    original.ephemeral_key = AgentCrypto::generate_random_bytes(32);
    original.nonce = AgentCrypto::generate_random_bytes(12);

    std::string json = original.to_json();
    auto parsed = SessionAccept::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->session_id, original.session_id);
}

// ============================================================================
// SessionMessage Tests
// ============================================================================

TEST_F(MessageTypesTest, SessionMessageRoundTrip) {
    SessionMessage original;
    original.session_id = "active_session";
    original.encrypted_data = AgentCrypto::generate_random_bytes(1024);
    original.nonce = AgentCrypto::generate_random_bytes(12);

    std::string json = original.to_json();
    auto parsed = SessionMessage::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->session_id, original.session_id);
    EXPECT_EQ(parsed->encrypted_data, original.encrypted_data);
}

// ============================================================================
// FileOffer Tests
// ============================================================================

TEST_F(MessageTypesTest, FileOfferToJson) {
    FileOffer offer;
    offer.file_id = "file_abc123";
    offer.filename = "document.pdf";
    offer.file_size = 1024 * 1024;
    offer.file_hash = AgentCrypto::generate_random_bytes(32);
    offer.mime_type = "application/pdf";

    std::string json = offer.to_json();

    EXPECT_FALSE(json.empty());
    EXPECT_NE(json.find("document.pdf"), std::string::npos);
}

TEST_F(MessageTypesTest, FileOfferRoundTrip) {
    FileOffer original;
    original.file_id = "file_xyz789";
    original.filename = "image.png";
    original.file_size = 2048;
    original.file_hash = AgentCrypto::generate_random_bytes(32);
    original.mime_type = "image/png";

    std::string json = original.to_json();
    auto parsed = FileOffer::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->file_id, original.file_id);
    EXPECT_EQ(parsed->filename, original.filename);
    EXPECT_EQ(parsed->file_size, original.file_size);
}

// ============================================================================
// FileChunk Tests
// ============================================================================

TEST_F(MessageTypesTest, FileChunkRoundTrip) {
    FileChunk original;
    original.file_id = "file_123";
    original.chunk_number = 5;
    original.total_chunks = 100;
    original.data = AgentCrypto::generate_random_bytes(8192);
    original.chunk_hash = AgentCrypto::generate_random_bytes(32);

    std::string json = original.to_json();
    auto parsed = FileChunk::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->file_id, original.file_id);
    EXPECT_EQ(parsed->chunk_number, original.chunk_number);
    EXPECT_EQ(parsed->total_chunks, original.total_chunks);
    EXPECT_EQ(parsed->data, original.data);
}

// ============================================================================
// TrustObservation Tests
// ============================================================================

TEST_F(MessageTypesTest, TrustObservationToJson) {
    TrustObservationMsg obs;
    obs.peer_id = "peer_abc";
    obs.trust_score = 0.85;
    obs.wisdom_score = 0.90;
    obs.verified = true;
    obs.observation = "Reliable communication";

    std::string json = obs.to_json();

    EXPECT_FALSE(json.empty());
    EXPECT_NE(json.find("peer_abc"), std::string::npos);
}

TEST_F(MessageTypesTest, TrustObservationRoundTrip) {
    TrustObservationMsg original;
    original.peer_id = "peer_xyz";
    original.trust_score = 0.75;
    original.wisdom_score = 0.80;
    original.verified = false;
    original.observation = "Occasional timeouts";

    std::string json = original.to_json();
    auto parsed = TrustObservationMsg::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->peer_id, original.peer_id);
    EXPECT_DOUBLE_EQ(parsed->trust_score, original.trust_score);
    EXPECT_DOUBLE_EQ(parsed->wisdom_score, original.wisdom_score);
    EXPECT_EQ(parsed->verified, original.verified);
}

// ============================================================================
// GatekeeperRegister Tests
// ============================================================================

TEST_F(MessageTypesTest, GatekeeperRegisterRoundTrip) {
    GatekeeperRegister original;
    original.scu_id = "scu_123";
    original.cluster_id = "cluster_A";
    original.public_key_sign = AgentCrypto::generate_random_bytes(32);
    original.public_key_enc = AgentCrypto::generate_random_bytes(32);

    std::string json = original.to_json();
    auto parsed = GatekeeperRegister::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->scu_id, original.scu_id);
    EXPECT_EQ(parsed->cluster_id, original.cluster_id);
}

// ============================================================================
// GatekeeperRoute Tests
// ============================================================================

TEST_F(MessageTypesTest, GatekeeperRouteRoundTrip) {
    GatekeeperRoute original;
    original.source_scu = "scu_1";
    original.destination_scu = "scu_2";
    original.destination_cluster = "cluster_B";
    original.encrypted_payload = AgentCrypto::generate_random_bytes(512);
    original.requires_sanitization = true;

    std::string json = original.to_json();
    auto parsed = GatekeeperRoute::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->source_scu, original.source_scu);
    EXPECT_EQ(parsed->destination_scu, original.destination_scu);
    EXPECT_EQ(parsed->requires_sanitization, original.requires_sanitization);
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

TEST_F(MessageTypesTest, EmptyFieldsInMessage) {
    Message msg;
    msg.type = MessageType::PING;
    msg.message_id = "";
    msg.timestamp = 0;
    msg.sender_id = "";
    msg.recipient_id = "";

    std::string json = msg.to_json();
    auto parsed = Message::from_json(json);

    ASSERT_TRUE(parsed.has_value());
}

TEST_F(MessageTypesTest, VeryLargePayload) {
    Message msg;
    msg.type = MessageType::SESSION_MESSAGE;
    msg.message_id = "large_msg";
    msg.timestamp = MessageHelpers::get_current_timestamp();
    msg.sender_id = "sender";
    msg.recipient_id = "recipient";
    msg.payload = AgentCrypto::generate_random_bytes(1024 * 1024);  // 1MB

    std::string json = msg.to_json();

    EXPECT_FALSE(json.empty());
}

TEST_F(MessageTypesTest, SpecialCharactersInStrings) {
    DiscoveryAnnounce announce;
    announce.agent_id = "agent!@#$%^&*()";
    announce.host = "host:with:colons";
    announce.port = 12345;

    std::string json = announce.to_json();
    auto parsed = DiscoveryAnnounce::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->agent_id, announce.agent_id);
}

TEST_F(MessageTypesTest, UnicodeInObservation) {
    TrustObservationMsg obs;
    obs.peer_id = "peer1";
    obs.trust_score = 0.8;
    obs.wisdom_score = 0.9;
    obs.verified = true;
    obs.observation = "Test with émojis  and ünïcödé";

    std::string json = obs.to_json();
    auto parsed = TrustObservationMsg::from_json(json);

    ASSERT_TRUE(parsed.has_value());
}

TEST_F(MessageTypesTest, ZeroValues) {
    FileOffer offer;
    offer.file_id = "zero_test";
    offer.filename = "empty.txt";
    offer.file_size = 0;  // Zero-size file

    std::string json = offer.to_json();
    auto parsed = FileOffer::from_json(json);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->file_size, 0);
}

TEST_F(MessageTypesTest, MaxValues) {
    FileChunk chunk;
    chunk.file_id = "max_test";
    chunk.chunk_number = std::numeric_limits<uint64_t>::max();
    chunk.total_chunks = std::numeric_limits<uint64_t>::max();

    std::string json = chunk.to_json();
    auto parsed = FileChunk::from_json(json);

    ASSERT_TRUE(parsed.has_value());
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(MessageTypesTest, ConcurrentMessageSerialization) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<std::string> jsons(num_threads);

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([&jsons, t]() {
            Message msg;
            msg.type = MessageType::PING;
            msg.message_id = "msg_" + std::to_string(t);
            msg.timestamp = MessageHelpers::get_current_timestamp();
            msg.sender_id = "sender_" + std::to_string(t);
            msg.recipient_id = "recipient";
            jsons[t] = msg.to_json();
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All serializations should succeed
    for (const auto& json : jsons) {
        EXPECT_FALSE(json.empty());
    }
}

TEST_F(MessageTypesTest, ConcurrentMessageDeserialization) {
    // Pre-create JSON strings
    std::vector<std::string> jsons;
    for (int i = 0; i < 10; i++) {
        Message msg;
        msg.type = MessageType::PING;
        msg.message_id = "msg_" + std::to_string(i);
        msg.timestamp = MessageHelpers::get_current_timestamp();
        msg.sender_id = "sender";
        msg.recipient_id = "recipient";
        jsons.push_back(msg.to_json());
    }

    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<bool> results(num_threads);

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([&jsons, &results, t]() {
            auto parsed = Message::from_json(jsons[t]);
            results[t] = parsed.has_value();
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All deserializations should succeed
    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}

TEST_F(MessageTypesTest, ConcurrentMessageIdGeneration) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<std::string> msg_ids(num_threads);

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([&msg_ids, t]() {
            msg_ids[t] = MessageHelpers::generate_message_id(
                "sender", MessageHelpers::get_current_timestamp(), "nonce_" + std::to_string(t)
            );
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All IDs should be unique
    std::set<std::string> unique_ids(msg_ids.begin(), msg_ids.end());
    EXPECT_EQ(unique_ids.size(), num_threads);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
