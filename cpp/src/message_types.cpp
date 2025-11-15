/**
 * @file message_types.cpp
 * @brief Implementation of message types and serialization
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright � 2025 Fortified Solutions Inc.
 *
 */

#include "nlitp/message_types.hpp"
#include "nlitp/agent_crypto.hpp"
#include "nlitp/security_config.hpp"
#include "nlitp/replay_protection.hpp"
#include <nlohmann/json.hpp>
#include <chrono>

using json = nlohmann::json;

namespace nlitp {

// ============================================================================
// Message Type String Conversion
// ============================================================================

std::string MessageHelpers::message_type_to_string(MessageType type) {
    switch (type) {
        case MessageType::DISCOVERY_ANNOUNCE: return "DISCOVERY_ANNOUNCE";
        case MessageType::DISCOVERY_QUERY: return "DISCOVERY_QUERY";
        case MessageType::DISCOVERY_RESPONSE: return "DISCOVERY_RESPONSE";
        case MessageType::SESSION_REQUEST: return "SESSION_REQUEST";
        case MessageType::SESSION_ACCEPT: return "SESSION_ACCEPT";
        case MessageType::SESSION_REJECT: return "SESSION_REJECT";
        case MessageType::SESSION_MESSAGE: return "SESSION_MESSAGE";
        case MessageType::SESSION_CLOSE: return "SESSION_CLOSE";
        case MessageType::FILE_OFFER: return "FILE_OFFER";
        case MessageType::FILE_ACCEPT: return "FILE_ACCEPT";
        case MessageType::FILE_REJECT: return "FILE_REJECT";
        case MessageType::FILE_CHUNK: return "FILE_CHUNK";
        case MessageType::FILE_COMPLETE: return "FILE_COMPLETE";
        case MessageType::TRUST_OBSERVATION: return "TRUST_OBSERVATION";
        case MessageType::TRUST_QUERY: return "TRUST_QUERY";
        case MessageType::TRUST_RESPONSE: return "TRUST_RESPONSE";
        case MessageType::GATEKEEPER_REGISTER: return "GATEKEEPER_REGISTER";
        case MessageType::GATEKEEPER_ROUTE: return "GATEKEEPER_ROUTE";
        case MessageType::GATEKEEPER_BLOCK: return "GATEKEEPER_BLOCK";
        case MessageType::GATEKEEPER_SANITIZE: return "GATEKEEPER_SANITIZE";
        case MessageType::PING: return "PING";
        case MessageType::PONG: return "PONG";
        case MessageType::HEARTBEAT: return "HEARTBEAT";
        default: return "UNKNOWN";
    }
}

std::optional<MessageType> MessageHelpers::string_to_message_type(const std::string& str) {
    if (str == "DISCOVERY_ANNOUNCE") return MessageType::DISCOVERY_ANNOUNCE;
    if (str == "DISCOVERY_QUERY") return MessageType::DISCOVERY_QUERY;
    if (str == "DISCOVERY_RESPONSE") return MessageType::DISCOVERY_RESPONSE;
    if (str == "SESSION_REQUEST") return MessageType::SESSION_REQUEST;
    if (str == "SESSION_ACCEPT") return MessageType::SESSION_ACCEPT;
    if (str == "SESSION_REJECT") return MessageType::SESSION_REJECT;
    if (str == "SESSION_MESSAGE") return MessageType::SESSION_MESSAGE;
    if (str == "SESSION_CLOSE") return MessageType::SESSION_CLOSE;
    if (str == "FILE_OFFER") return MessageType::FILE_OFFER;
    if (str == "FILE_ACCEPT") return MessageType::FILE_ACCEPT;
    if (str == "FILE_REJECT") return MessageType::FILE_REJECT;
    if (str == "FILE_CHUNK") return MessageType::FILE_CHUNK;
    if (str == "FILE_COMPLETE") return MessageType::FILE_COMPLETE;
    if (str == "TRUST_OBSERVATION") return MessageType::TRUST_OBSERVATION;
    if (str == "TRUST_QUERY") return MessageType::TRUST_QUERY;
    if (str == "TRUST_RESPONSE") return MessageType::TRUST_RESPONSE;
    if (str == "GATEKEEPER_REGISTER") return MessageType::GATEKEEPER_REGISTER;
    if (str == "GATEKEEPER_ROUTE") return MessageType::GATEKEEPER_ROUTE;
    if (str == "GATEKEEPER_BLOCK") return MessageType::GATEKEEPER_BLOCK;
    if (str == "GATEKEEPER_SANITIZE") return MessageType::GATEKEEPER_SANITIZE;
    if (str == "PING") return MessageType::PING;
    if (str == "PONG") return MessageType::PONG;
    if (str == "HEARTBEAT") return MessageType::HEARTBEAT;
    return std::nullopt;
}

// ============================================================================
// Message Helpers
// ============================================================================

std::string MessageHelpers::generate_message_id(
    const std::string& sender_id,
    uint64_t timestamp,
    const std::string& nonce
) {
    return MessageReplayProtection::generate_message_id(sender_id, timestamp, nonce);
}

uint64_t MessageHelpers::get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

bool MessageHelpers::validate_message_size(size_t size) {
    return size > 0 && size <= security::MAX_MESSAGE_SIZE;
}

bool MessageHelpers::validate_file_size(uint64_t size) {
    return size > 0 && size <= security::MAX_FILE_SIZE;
}

// ============================================================================
// Base Message Serialization
// ============================================================================

std::string Message::to_json() const {
    try {
        json j;
        j["type"] = MessageHelpers::message_type_to_string(type);
        j["message_id"] = message_id;
        j["timestamp"] = timestamp;
        j["sender_id"] = sender_id;
        j["recipient_id"] = recipient_id;
        j["signature"] = AgentCrypto::bytes_to_base64(signature);
        j["payload"] = AgentCrypto::bytes_to_base64(payload);

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<Message> Message::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        Message msg;

        // Parse message type
        std::string type_str = j["type"];
        auto type_opt = MessageHelpers::string_to_message_type(type_str);
        if (!type_opt) {
            return std::nullopt;
        }
        msg.type = *type_opt;

        // Parse fields
        msg.message_id = j["message_id"];
        msg.timestamp = j["timestamp"];
        msg.sender_id = j["sender_id"];
        msg.recipient_id = j["recipient_id"];

        // Parse signature
        auto sig_opt = AgentCrypto::base64_to_bytes(j["signature"]);
        if (!sig_opt) {
            return std::nullopt;
        }
        msg.signature = *sig_opt;

        // Parse payload
        auto payload_opt = AgentCrypto::base64_to_bytes(j["payload"]);
        if (!payload_opt) {
            return std::nullopt;
        }
        msg.payload = *payload_opt;

        return msg;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// DiscoveryAnnounce
// ============================================================================

std::string DiscoveryAnnounce::to_json() const {
    try {
        json j;
        j["agent_id"] = agent_id;
        j["host"] = host;
        j["port"] = port;
        j["public_key_sign"] = AgentCrypto::bytes_to_base64(public_key_sign);
        j["public_key_enc"] = AgentCrypto::bytes_to_base64(public_key_enc);
        j["capabilities"] = capabilities;

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<DiscoveryAnnounce> DiscoveryAnnounce::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        DiscoveryAnnounce announce;
        announce.agent_id = j["agent_id"];
        announce.host = j["host"];
        announce.port = j["port"];

        auto sign_key_opt = AgentCrypto::base64_to_bytes(j["public_key_sign"]);
        auto enc_key_opt = AgentCrypto::base64_to_bytes(j["public_key_enc"]);

        if (!sign_key_opt || !enc_key_opt) {
            return std::nullopt;
        }

        announce.public_key_sign = *sign_key_opt;
        announce.public_key_enc = *enc_key_opt;
        announce.capabilities = j["capabilities"].get<std::map<std::string, std::string>>();

        return announce;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// DiscoveryQuery
// ============================================================================

std::string DiscoveryQuery::to_json() const {
    try {
        json j;
        j["target_agent_id"] = target_agent_id;
        j["require_capabilities"] = require_capabilities;
        j["required_capabilities"] = required_capabilities;

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<DiscoveryQuery> DiscoveryQuery::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        DiscoveryQuery query;
        query.target_agent_id = j.value("target_agent_id", "");
        query.require_capabilities = j.value("require_capabilities", false);
        query.required_capabilities = j.value("required_capabilities",
            std::map<std::string, std::string>());

        return query;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// DiscoveryResponse
// ============================================================================

std::string DiscoveryResponse::to_json() const {
    try {
        json j;
        j["agent_id"] = agent_id;
        j["host"] = host;
        j["port"] = port;
        j["public_key_sign"] = AgentCrypto::bytes_to_base64(public_key_sign);
        j["public_key_enc"] = AgentCrypto::bytes_to_base64(public_key_enc);
        j["capabilities"] = capabilities;
        j["available"] = available;

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<DiscoveryResponse> DiscoveryResponse::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        DiscoveryResponse response;
        response.agent_id = j["agent_id"];
        response.host = j["host"];
        response.port = j["port"];

        auto sign_key_opt = AgentCrypto::base64_to_bytes(j["public_key_sign"]);
        auto enc_key_opt = AgentCrypto::base64_to_bytes(j["public_key_enc"]);

        if (!sign_key_opt || !enc_key_opt) {
            return std::nullopt;
        }

        response.public_key_sign = *sign_key_opt;
        response.public_key_enc = *enc_key_opt;
        response.capabilities = j["capabilities"].get<std::map<std::string, std::string>>();
        response.available = j.value("available", true);

        return response;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// SessionRequest
// ============================================================================

std::string SessionRequest::to_json() const {
    try {
        json j;
        j["session_id"] = session_id;
        j["ephemeral_key"] = AgentCrypto::bytes_to_base64(ephemeral_key);
        j["nonce"] = AgentCrypto::bytes_to_base64(nonce);

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<SessionRequest> SessionRequest::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        SessionRequest req;
        req.session_id = j["session_id"];

        auto key_opt = AgentCrypto::base64_to_bytes(j["ephemeral_key"]);
        auto nonce_opt = AgentCrypto::base64_to_bytes(j["nonce"]);

        if (!key_opt || !nonce_opt) {
            return std::nullopt;
        }

        req.ephemeral_key = *key_opt;
        req.nonce = *nonce_opt;

        return req;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// SessionAccept
// ============================================================================

std::string SessionAccept::to_json() const {
    try {
        json j;
        j["session_id"] = session_id;
        j["ephemeral_key"] = AgentCrypto::bytes_to_base64(ephemeral_key);
        j["nonce"] = AgentCrypto::bytes_to_base64(nonce);

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<SessionAccept> SessionAccept::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        SessionAccept accept;
        accept.session_id = j["session_id"];

        auto key_opt = AgentCrypto::base64_to_bytes(j["ephemeral_key"]);
        auto nonce_opt = AgentCrypto::base64_to_bytes(j["nonce"]);

        if (!key_opt || !nonce_opt) {
            return std::nullopt;
        }

        accept.ephemeral_key = *key_opt;
        accept.nonce = *nonce_opt;

        return accept;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// SessionMessage
// ============================================================================

std::string SessionMessage::to_json() const {
    try {
        json j;
        j["session_id"] = session_id;
        j["encrypted_data"] = AgentCrypto::bytes_to_base64(encrypted_data);
        j["nonce"] = AgentCrypto::bytes_to_base64(nonce);

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<SessionMessage> SessionMessage::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        SessionMessage msg;
        msg.session_id = j["session_id"];

        auto data_opt = AgentCrypto::base64_to_bytes(j["encrypted_data"]);
        auto nonce_opt = AgentCrypto::base64_to_bytes(j["nonce"]);

        if (!data_opt || !nonce_opt) {
            return std::nullopt;
        }

        msg.encrypted_data = *data_opt;
        msg.nonce = *nonce_opt;

        return msg;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// FileOffer
// ============================================================================

std::string FileOffer::to_json() const {
    try {
        json j;
        j["file_id"] = file_id;
        j["filename"] = filename;
        j["file_size"] = file_size;
        j["file_hash"] = AgentCrypto::bytes_to_base64(file_hash);
        j["mime_type"] = mime_type;

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<FileOffer> FileOffer::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        FileOffer offer;
        offer.file_id = j["file_id"];
        offer.filename = j["filename"];
        offer.file_size = j["file_size"];
        offer.mime_type = j["mime_type"];

        auto hash_opt = AgentCrypto::base64_to_bytes(j["file_hash"]);
        if (!hash_opt) {
            return std::nullopt;
        }

        offer.file_hash = *hash_opt;

        // Validate file size
        if (!MessageHelpers::validate_file_size(offer.file_size)) {
            return std::nullopt;
        }

        return offer;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// FileChunk
// ============================================================================

std::string FileChunk::to_json() const {
    try {
        json j;
        j["file_id"] = file_id;
        j["chunk_number"] = chunk_number;
        j["total_chunks"] = total_chunks;
        j["data"] = AgentCrypto::bytes_to_base64(data);
        j["chunk_hash"] = AgentCrypto::bytes_to_base64(chunk_hash);

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<FileChunk> FileChunk::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        FileChunk chunk;
        chunk.file_id = j["file_id"];
        chunk.chunk_number = j["chunk_number"];
        chunk.total_chunks = j["total_chunks"];

        auto data_opt = AgentCrypto::base64_to_bytes(j["data"]);
        auto hash_opt = AgentCrypto::base64_to_bytes(j["chunk_hash"]);

        if (!data_opt || !hash_opt) {
            return std::nullopt;
        }

        chunk.data = *data_opt;
        chunk.chunk_hash = *hash_opt;

        return chunk;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// TrustObservationMsg
// ============================================================================

std::string TrustObservationMsg::to_json() const {
    try {
        json j;
        j["peer_id"] = peer_id;
        j["trust_score"] = trust_score;
        j["wisdom_score"] = wisdom_score;
        j["verified"] = verified;
        j["observation"] = observation;

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<TrustObservationMsg> TrustObservationMsg::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        TrustObservationMsg msg;
        msg.peer_id = j["peer_id"];
        msg.trust_score = j["trust_score"];
        msg.wisdom_score = j["wisdom_score"];
        msg.verified = j["verified"];
        msg.observation = j["observation"];

        // Validate scores
        if (msg.trust_score < 0.0 || msg.trust_score > 1.0 ||
            msg.wisdom_score < 0.0 || msg.wisdom_score > 1.0) {
            return std::nullopt;
        }

        return msg;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// GatekeeperRegister
// ============================================================================

std::string GatekeeperRegister::to_json() const {
    try {
        json j;
        j["scu_id"] = scu_id;
        j["cluster_id"] = cluster_id;
        j["public_key_sign"] = AgentCrypto::bytes_to_base64(public_key_sign);
        j["public_key_enc"] = AgentCrypto::bytes_to_base64(public_key_enc);

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<GatekeeperRegister> GatekeeperRegister::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        GatekeeperRegister reg;
        reg.scu_id = j["scu_id"];
        reg.cluster_id = j["cluster_id"];

        auto sign_key_opt = AgentCrypto::base64_to_bytes(j["public_key_sign"]);
        auto enc_key_opt = AgentCrypto::base64_to_bytes(j["public_key_enc"]);

        if (!sign_key_opt || !enc_key_opt) {
            return std::nullopt;
        }

        reg.public_key_sign = *sign_key_opt;
        reg.public_key_enc = *enc_key_opt;

        return reg;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ============================================================================
// GatekeeperRoute
// ============================================================================

std::string GatekeeperRoute::to_json() const {
    try {
        json j;
        j["source_scu"] = source_scu;
        j["destination_scu"] = destination_scu;
        j["destination_cluster"] = destination_cluster;
        j["encrypted_payload"] = AgentCrypto::bytes_to_base64(encrypted_payload);
        j["requires_sanitization"] = requires_sanitization;

        return j.dump();
    } catch (const std::exception&) {
        return "{}";
    }
}

std::optional<GatekeeperRoute> GatekeeperRoute::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);

        GatekeeperRoute route;
        route.source_scu = j["source_scu"];
        route.destination_scu = j["destination_scu"];
        route.destination_cluster = j["destination_cluster"];
        route.requires_sanitization = j["requires_sanitization"];

        auto payload_opt = AgentCrypto::base64_to_bytes(j["encrypted_payload"]);
        if (!payload_opt) {
            return std::nullopt;
        }

        route.encrypted_payload = *payload_opt;

        return route;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

} // namespace nlitp
