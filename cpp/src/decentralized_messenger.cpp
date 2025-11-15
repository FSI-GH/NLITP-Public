/**
 * @file decentralized_messenger.cpp
 * @brief Implementation of decentralized P2P messaging
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Thread-safe P2P messaging with encryption
 */

#include "nlitp/decentralized_messenger.hpp"
#include "nlitp/utilities.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>

namespace nlitp {

// ============================================================================
// Constants
// ============================================================================

constexpr size_t MAX_UDP_PACKET_SIZE = 65507;
constexpr size_t MAX_TCP_MESSAGE_SIZE = 10485760; // 10 MB
constexpr uint64_t SESSION_TIMEOUT_SECONDS = 3600; // 1 hour
constexpr uint64_t TRANSFER_TIMEOUT_SECONDS = 600; // 10 minutes
constexpr int MAX_MESSAGE_RETRIES = 3;

// ============================================================================
// Constructor and Destructor
// ============================================================================

DecentralizedMessenger::DecentralizedMessenger(
    std::shared_ptr<AgentIdentity> identity,
    uint16_t listen_port,
    size_t max_connections,
    size_t chunk_size
)
    : identity_(std::move(identity))
    , io_context_()
    , udp_socket_(nullptr)
    , tcp_acceptor_(nullptr)
    , listen_port_(listen_port)
    , max_connections_(max_connections)
    , chunk_size_(chunk_size)
    , rate_limiter_(100.0, 200.0)  // 100 msg/s, burst 200
    , replay_protection_(std::chrono::seconds(60))
    , running_(false)
{
    utilities::log_info("DecentralizedMessenger created for agent: " + identity_->get_agent_id());
}

DecentralizedMessenger::~DecentralizedMessenger() {
    stop();
    utilities::log_info("DecentralizedMessenger destroyed");
}

// ============================================================================
// Lifecycle Management
// ============================================================================

bool DecentralizedMessenger::start() {
    if (running_.exchange(true)) {
        utilities::log_warn("DecentralizedMessenger already running");
        return false;
    }

    try {
        // Initialize UDP socket
        udp_socket_ = std::make_unique<asio::ip::udp::socket>(
            io_context_,
            asio::ip::udp::endpoint(asio::ip::udp::v4(), listen_port_)
        );
        listen_port_ = udp_socket_->local_endpoint().port();

        // Initialize TCP acceptor
        tcp_acceptor_ = std::make_unique<asio::ip::tcp::acceptor>(
            io_context_,
            asio::ip::tcp::endpoint(asio::ip::tcp::v4(), listen_port_)
        );

        utilities::log_info("DecentralizedMessenger listening on port " + std::to_string(listen_port_));

        // Start async operations
        start_udp_receive();
        start_tcp_accept();

        // Start worker threads
        size_t num_threads = std::max<size_t>(2, std::thread::hardware_concurrency());
        for (size_t i = 0; i < num_threads; ++i) {
            worker_threads_.emplace_back([this]() {
                try {
                    io_context_.run();
                } catch (const std::exception& e) {
                    utilities::log_error("Worker thread error: " + std::string(e.what()));
                }
            });
        }

        // Start message queue processor
        worker_threads_.emplace_back([this]() {
            while (running_) {
                process_message_queue();
                cleanup_expired_sessions();
                cleanup_stale_transfers();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });

        utilities::log_info("DecentralizedMessenger started with " + std::to_string(worker_threads_.size()) + " threads");
        return true;

    } catch (const std::exception& e) {
        utilities::log_error("Failed to start DecentralizedMessenger: " + std::string(e.what()));
        running_ = false;
        return false;
    }
}

void DecentralizedMessenger::stop() {
    if (!running_.exchange(false)) {
        return;
    }

    utilities::log_info("Stopping DecentralizedMessenger...");

    // Close all sessions
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (const auto& [peer_id, session] : sessions_) {
            close_session(session.session_id);
        }
        sessions_.clear();
    }

    // Stop I/O context
    io_context_.stop();

    // Join worker threads
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();

    // Close sockets
    if (udp_socket_ && udp_socket_->is_open()) {
        udp_socket_->close();
    }
    if (tcp_acceptor_ && tcp_acceptor_->is_open()) {
        tcp_acceptor_->close();
    }

    utilities::log_info("DecentralizedMessenger stopped");
}

bool DecentralizedMessenger::is_running() const {
    return running_;
}

uint16_t DecentralizedMessenger::get_listen_port() const {
    return listen_port_;
}

// ============================================================================
// Session Management
// ============================================================================

std::optional<std::string> DecentralizedMessenger::request_session(
    const std::string& peer_id,
    const std::string& peer_host,
    uint16_t peer_port,
    const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& peer_enc_key
) {
    if (!running_) {
        utilities::log_error("Cannot request session: messenger not running");
        return std::nullopt;
    }

    try {
        // Generate session ID
        std::string session_id = generate_session_id(peer_id);

        // Generate ephemeral keypair for this session
        auto ephemeral_keypair = AgentCrypto::generate_encryption_keypair();

        // Perform key exchange
        auto shared_secret_opt = AgentCrypto::key_exchange(
            ephemeral_keypair.secret_key,
            peer_enc_key
        );

        if (!shared_secret_opt) {
            utilities::log_error("Key exchange failed for session request");
            return std::nullopt;
        }

        // Create session request payload
        SessionRequest request;
        request.session_id = session_id;
        request.ephemeral_key = std::vector<uint8_t>(
            ephemeral_keypair.public_key.begin(),
            ephemeral_keypair.public_key.end()
        );
        request.nonce = AgentCrypto::generate_random_bytes(16);

        // Create message
        auto payload_json = request.to_json();
        std::vector<uint8_t> payload(payload_json.begin(), payload_json.end());
        Message message = create_message(MessageType::SESSION_REQUEST, payload, peer_id);

        // Store pending session
        {
            std::lock_guard<std::mutex> lock(pending_sessions_mutex_);
            Session pending_session;
            pending_session.session_id = session_id;
            pending_session.peer_id = peer_id;
            pending_session.peer_host = peer_host;
            pending_session.peer_port = peer_port;
            pending_session.shared_secret = *shared_secret_opt;
            pending_session.peer_enc_key = peer_enc_key;
            pending_session.established_time = MessageHelpers::get_current_timestamp();
            pending_session.last_activity = pending_session.established_time;
            pending_session.is_initiator = true;
            pending_sessions_[session_id] = pending_session;
        }

        // Send session request
        if (send_tcp_message(message, peer_host, peer_port)) {
            utilities::log_info("Session request sent to " + peer_id + " (session: " + session_id + ")");
            return session_id;
        } else {
            std::lock_guard<std::mutex> lock(pending_sessions_mutex_);
            pending_sessions_.erase(session_id);
            return std::nullopt;
        }

    } catch (const std::exception& e) {
        utilities::log_error("Failed to request session: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool DecentralizedMessenger::accept_session(const std::string& session_id) {
    std::lock_guard<std::mutex> pending_lock(pending_sessions_mutex_);

    auto it = pending_sessions_.find(session_id);
    if (it == pending_sessions_.end()) {
        utilities::log_error("Session not found: " + session_id);
        return false;
    }

    Session session = it->second;
    pending_sessions_.erase(it);

    try {
        // Generate our ephemeral keypair
        auto ephemeral_keypair = AgentCrypto::generate_encryption_keypair();

        // Create session accept payload
        SessionAccept accept;
        accept.session_id = session_id;
        accept.ephemeral_key = std::vector<uint8_t>(
            ephemeral_keypair.public_key.begin(),
            ephemeral_keypair.public_key.end()
        );
        accept.nonce = AgentCrypto::generate_random_bytes(16);

        // Create message
        auto payload_json = accept.to_json();
        std::vector<uint8_t> payload(payload_json.begin(), payload_json.end());
        Message message = create_message(MessageType::SESSION_ACCEPT, payload, session.peer_id);

        // Send acceptance
        if (send_tcp_message(message, session.peer_host, session.peer_port)) {
            // Move to active sessions
            std::lock_guard<std::mutex> sessions_lock(sessions_mutex_);
            sessions_[session.peer_id] = session;

            utilities::log_info("Session accepted: " + session_id);

            // Notify callback
            if (session_callback_) {
                session_callback_(session_id, session.peer_id, true);
            }

            return true;
        }

        return false;

    } catch (const std::exception& e) {
        utilities::log_error("Failed to accept session: " + std::string(e.what()));
        return false;
    }
}

bool DecentralizedMessenger::reject_session(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(pending_sessions_mutex_);

    auto it = pending_sessions_.find(session_id);
    if (it == pending_sessions_.end()) {
        return false;
    }

    Session session = it->second;
    pending_sessions_.erase(it);

    try {
        // Create rejection message
        std::vector<uint8_t> payload;
        Message message = create_message(MessageType::SESSION_REJECT, payload, session.peer_id);

        send_tcp_message(message, session.peer_host, session.peer_port);
        utilities::log_info("Session rejected: " + session_id);

        // Notify callback
        if (session_callback_) {
            session_callback_(session_id, session.peer_id, false);
        }

        return true;

    } catch (const std::exception& e) {
        utilities::log_error("Failed to reject session: " + std::string(e.what()));
        return false;
    }
}

bool DecentralizedMessenger::close_session(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    // Find session by ID
    auto it = std::find_if(sessions_.begin(), sessions_.end(),
        [&session_id](const auto& pair) {
            return pair.second.session_id == session_id;
        });

    if (it == sessions_.end()) {
        return false;
    }

    Session session = it->second;
    sessions_.erase(it);

    try {
        // Create close message
        std::vector<uint8_t> payload;
        Message message = create_message(MessageType::SESSION_CLOSE, payload, session.peer_id);

        send_tcp_message(message, session.peer_host, session.peer_port);
        utilities::log_info("Session closed: " + session_id);

        // Notify callback
        if (session_callback_) {
            session_callback_(session_id, session.peer_id, false);
        }

        return true;

    } catch (const std::exception& e) {
        utilities::log_error("Failed to close session: " + std::string(e.what()));
        return false;
    }
}

std::optional<Session> DecentralizedMessenger::get_session(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    auto it = sessions_.find(peer_id);
    if (it == sessions_.end()) {
        return std::nullopt;
    }

    return it->second;
}

std::vector<Session> DecentralizedMessenger::get_all_sessions() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    std::vector<Session> result;
    result.reserve(sessions_.size());

    for (const auto& [peer_id, session] : sessions_) {
        result.push_back(session);
    }

    return result;
}

// ============================================================================
// Messaging
// ============================================================================

std::optional<std::string> DecentralizedMessenger::send_message(
    const std::string& peer_id,
    const std::vector<uint8_t>& payload
) {
    return send_message_typed(peer_id, MessageType::SESSION_MESSAGE, payload);
}

std::optional<std::string> DecentralizedMessenger::send_message_typed(
    const std::string& peer_id,
    MessageType message_type,
    const std::vector<uint8_t>& payload
) {
    if (!running_) {
        utilities::log_error("Cannot send message: messenger not running");
        return std::nullopt;
    }

    // Get session
    std::optional<Session> session_opt;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(peer_id);
        if (it == sessions_.end()) {
            utilities::log_error("No active session with peer: " + peer_id);
            return std::nullopt;
        }
        session_opt = it->second;
    }

    Session& session = *session_opt;

    try {
        // Encrypt payload
        auto encrypted_opt = encrypt_session_message(payload, session);
        if (!encrypted_opt) {
            utilities::log_error("Failed to encrypt message");
            return std::nullopt;
        }

        // Create session message payload
        SessionMessage session_msg;
        session_msg.session_id = session.session_id;
        session_msg.encrypted_data = *encrypted_opt;
        session_msg.nonce = AgentCrypto::generate_random_bytes(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

        // Serialize to JSON
        auto payload_json = session_msg.to_json();
        std::vector<uint8_t> final_payload(payload_json.begin(), payload_json.end());

        // Create message
        Message message = create_message(message_type, final_payload, peer_id);

        // Send via TCP
        if (send_tcp_message(message, session.peer_host, session.peer_port)) {
            // Update last activity
            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                auto it = sessions_.find(peer_id);
                if (it != sessions_.end()) {
                    it->second.last_activity = MessageHelpers::get_current_timestamp();
                }
            }

            return message.message_id;
        }

        return std::nullopt;

    } catch (const std::exception& e) {
        utilities::log_error("Failed to send message: " + std::string(e.what()));
        return std::nullopt;
    }
}

std::optional<std::string> DecentralizedMessenger::broadcast_message(
    MessageType message_type,
    const std::vector<uint8_t>& payload,
    uint16_t port
) {
    if (!running_) {
        utilities::log_error("Cannot broadcast message: messenger not running");
        return std::nullopt;
    }

    try {
        // Create message
        Message message = create_message(message_type, payload, "");

        // Send broadcast
        asio::ip::udp::endpoint broadcast_endpoint(
            asio::ip::address_v4::broadcast(),
            port
        );

        auto message_json = message.to_json();
        std::vector<uint8_t> message_data(message_json.begin(), message_json.end());

        udp_socket_->send_to(asio::buffer(message_data), broadcast_endpoint);

        utilities::log_info("Broadcast message sent (type: " +
            MessageHelpers::message_type_to_string(message_type) + ")");

        return message.message_id;

    } catch (const std::exception& e) {
        utilities::log_error("Failed to broadcast message: " + std::string(e.what()));
        return std::nullopt;
    }
}

// ============================================================================
// File Transfer
// ============================================================================

std::optional<std::string> DecentralizedMessenger::send_file(
    const std::string& peer_id,
    const std::string& filename
) {
    if (!running_) {
        utilities::log_error("Cannot send file: messenger not running");
        return std::nullopt;
    }

    try {
        // Read file
        auto file_data_opt = utilities::read_file_binary(filename);
        if (!file_data_opt) {
            utilities::log_error("Failed to read file: " + filename);
            return std::nullopt;
        }

        const auto& file_data = *file_data_opt;

        // Calculate hash
        auto hash_opt = utilities::calculate_file_hash(filename);
        if (!hash_opt) {
            utilities::log_error("Failed to calculate file hash");
            return std::nullopt;
        }

        auto hash_bytes_opt = AgentCrypto::hex_to_bytes(*hash_opt);
        if (!hash_bytes_opt) {
            return std::nullopt;
        }

        // Generate file ID
        std::string file_id = generate_file_id(filename);

        // Create file offer
        FileOffer offer;
        offer.file_id = file_id;
        offer.filename = std::filesystem::path(filename).filename().string();
        offer.file_size = file_data.size();
        offer.file_hash = *hash_bytes_opt;
        offer.mime_type = "application/octet-stream";

        // Send offer
        auto payload_json = offer.to_json();
        std::vector<uint8_t> payload(payload_json.begin(), payload_json.end());

        auto message_id = send_message_typed(peer_id, MessageType::FILE_OFFER, payload);
        if (!message_id) {
            return std::nullopt;
        }

        // Create transfer state
        {
            std::lock_guard<std::mutex> lock(transfers_mutex_);
            FileTransfer transfer;
            transfer.file_id = file_id;
            transfer.filename = filename;
            transfer.file_size = file_data.size();
            transfer.file_hash = *hash_bytes_opt;
            transfer.bytes_transferred = 0;
            transfer.total_chunks = (file_data.size() + chunk_size_ - 1) / chunk_size_;
            transfer.is_sender = true;
            transfer.start_time = std::chrono::steady_clock::now();

            // Split into chunks
            for (size_t i = 0; i < transfer.total_chunks; ++i) {
                size_t offset = i * chunk_size_;
                size_t chunk_sz = std::min(chunk_size_, file_data.size() - offset);
                std::vector<uint8_t> chunk(
                    file_data.begin() + offset,
                    file_data.begin() + offset + chunk_sz
                );
                transfer.chunks.push_back(std::move(chunk));
            }

            file_transfers_[file_id] = std::move(transfer);
        }

        utilities::log_info("File offer sent: " + filename + " (file_id: " + file_id + ")");
        return file_id;

    } catch (const std::exception& e) {
        utilities::log_error("Failed to send file: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool DecentralizedMessenger::accept_file(const std::string& file_id, const std::string& save_path) {
    std::lock_guard<std::mutex> lock(transfers_mutex_);

    auto it = file_transfers_.find(file_id);
    if (it == file_transfers_.end()) {
        utilities::log_error("File transfer not found: " + file_id);
        return false;
    }

    // Store save path
    it->second.filename = save_path;

    // Send acceptance (implementation would send FILE_ACCEPT message)
    utilities::log_info("File transfer accepted: " + file_id);
    return true;
}

bool DecentralizedMessenger::reject_file(const std::string& file_id) {
    std::lock_guard<std::mutex> lock(transfers_mutex_);

    auto it = file_transfers_.find(file_id);
    if (it == file_transfers_.end()) {
        return false;
    }

    file_transfers_.erase(it);
    utilities::log_info("File transfer rejected: " + file_id);
    return true;
}

std::optional<double> DecentralizedMessenger::get_file_progress(const std::string& file_id) const {
    std::lock_guard<std::mutex> lock(transfers_mutex_);

    auto it = file_transfers_.find(file_id);
    if (it == file_transfers_.end()) {
        return std::nullopt;
    }

    if (it->second.file_size == 0) {
        return 1.0;
    }

    return static_cast<double>(it->second.bytes_transferred) / it->second.file_size;
}

// ============================================================================
// Callbacks
// ============================================================================

void DecentralizedMessenger::set_message_callback(MessageCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    message_callback_ = std::move(callback);
}

void DecentralizedMessenger::set_session_callback(SessionCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    session_callback_ = std::move(callback);
}

void DecentralizedMessenger::set_file_progress_callback(FileProgressCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    file_progress_callback_ = std::move(callback);
}

// ============================================================================
// Statistics
// ============================================================================

size_t DecentralizedMessenger::get_active_session_count() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return sessions_.size();
}

size_t DecentralizedMessenger::get_queue_size() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return message_queue_.size();
}

size_t DecentralizedMessenger::get_active_transfer_count() const {
    std::lock_guard<std::mutex> lock(transfers_mutex_);
    return file_transfers_.size();
}

// ============================================================================
// Private Methods - Network I/O
// ============================================================================

void DecentralizedMessenger::start_udp_receive() {
    auto buffer = std::make_shared<std::vector<uint8_t>>(MAX_UDP_PACKET_SIZE);
    auto sender_endpoint = std::make_shared<asio::ip::udp::endpoint>();

    udp_socket_->async_receive_from(
        asio::buffer(*buffer),
        *sender_endpoint,
        [this, buffer, sender_endpoint](const asio::error_code& error, std::size_t bytes_transferred) {
            handle_udp_receive(error, bytes_transferred, buffer, sender_endpoint);
        }
    );
}

void DecentralizedMessenger::start_tcp_accept() {
    auto socket = std::make_shared<asio::ip::tcp::socket>(io_context_);

    tcp_acceptor_->async_accept(
        *socket,
        [this, socket](const asio::error_code& error) {
            handle_tcp_accept(error, socket);
        }
    );
}

void DecentralizedMessenger::handle_udp_receive(
    const asio::error_code& error,
    std::size_t bytes_transferred,
    std::shared_ptr<std::vector<uint8_t>> buffer,
    std::shared_ptr<asio::ip::udp::endpoint> sender_endpoint
) {
    if (!error && bytes_transferred > 0) {
        try {
            // Parse message
            std::string message_json(buffer->begin(), buffer->begin() + bytes_transferred);
            auto message_opt = Message::from_json(message_json);

            if (message_opt) {
                std::string sender_host = sender_endpoint->address().to_string();
                uint16_t sender_port = sender_endpoint->port();
                process_message(*message_opt, sender_host, sender_port);
            }
        } catch (const std::exception& e) {
            utilities::log_error("Failed to process UDP message: " + std::string(e.what()));
        }
    }

    // Continue receiving
    if (running_) {
        start_udp_receive();
    }
}

void DecentralizedMessenger::handle_tcp_accept(
    const asio::error_code& error,
    std::shared_ptr<asio::ip::tcp::socket> socket
) {
    if (!error) {
        // Handle connection in separate thread
        auto buffer = std::make_shared<std::vector<uint8_t>>(MAX_TCP_MESSAGE_SIZE);
        handle_tcp_receive(socket, buffer);
    }

    // Continue accepting
    if (running_) {
        start_tcp_accept();
    }
}

void DecentralizedMessenger::handle_tcp_receive(
    std::shared_ptr<asio::ip::tcp::socket> socket,
    std::shared_ptr<std::vector<uint8_t>> buffer
) {
    socket->async_read_some(
        asio::buffer(*buffer),
        [this, socket, buffer](const asio::error_code& error, std::size_t bytes_transferred) {
            if (!error && bytes_transferred > 0) {
                try {
                    // Parse message
                    std::string message_json(buffer->begin(), buffer->begin() + bytes_transferred);
                    auto message_opt = Message::from_json(message_json);

                    if (message_opt) {
                        std::string sender_host = socket->remote_endpoint().address().to_string();
                        uint16_t sender_port = socket->remote_endpoint().port();
                        process_message(*message_opt, sender_host, sender_port);
                    }
                } catch (const std::exception& e) {
                    utilities::log_error("Failed to process TCP message: " + std::string(e.what()));
                }
            }
        }
    );
}

// ============================================================================
// Private Methods - Message Processing
// ============================================================================

void DecentralizedMessenger::process_message(
    const Message& message,
    const std::string& sender_host,
    uint16_t sender_port
) {
    // Rate limiting
    if (!rate_limiter_.allow_message(message.sender_id)) {
        utilities::log_warn("Rate limit exceeded for peer: " + message.sender_id);
        return;
    }

    // Replay protection
    if (!replay_protection_.validate_message(message.message_id, message.timestamp)) {
        utilities::log_warn("Replay attack detected: " + message.message_id);
        return;
    }

    // Process based on message type
    switch (message.type) {
        case MessageType::SESSION_REQUEST: {
            std::string payload_str(message.payload.begin(), message.payload.end());
            auto request = SessionRequest::from_json(payload_str);
            if (request) {
                process_session_request(*request, message, sender_host, sender_port);
            }
            break;
        }

        case MessageType::SESSION_ACCEPT: {
            std::string payload_str(message.payload.begin(), message.payload.end());
            auto accept = SessionAccept::from_json(payload_str);
            if (accept) {
                process_session_accept(*accept, message);
            }
            break;
        }

        case MessageType::SESSION_MESSAGE: {
            std::string payload_str(message.payload.begin(), message.payload.end());
            auto session_msg = SessionMessage::from_json(payload_str);
            if (session_msg) {
                process_session_message(*session_msg, message);
            }
            break;
        }

        case MessageType::FILE_OFFER: {
            std::string payload_str(message.payload.begin(), message.payload.end());
            auto offer = FileOffer::from_json(payload_str);
            if (offer) {
                process_file_offer(*offer, message);
            }
            break;
        }

        case MessageType::FILE_CHUNK: {
            std::string payload_str(message.payload.begin(), message.payload.end());
            auto chunk = FileChunk::from_json(payload_str);
            if (chunk) {
                process_file_chunk(*chunk, message);
            }
            break;
        }

        default:
            // Invoke callback for all messages
            if (message_callback_) {
                message_callback_(message);
            }
            break;
    }
}

void DecentralizedMessenger::process_session_request(
    const SessionRequest& request,
    const Message& message,
    const std::string& sender_host,
    uint16_t sender_port
) {
    utilities::log_info("Session request received from " + message.sender_id);

    // Store as pending session
    std::lock_guard<std::mutex> lock(pending_sessions_mutex_);

    Session pending_session;
    pending_session.session_id = request.session_id;
    pending_session.peer_id = message.sender_id;
    pending_session.peer_host = sender_host;
    pending_session.peer_port = sender_port;
    pending_session.established_time = MessageHelpers::get_current_timestamp();
    pending_session.last_activity = pending_session.established_time;
    pending_session.is_initiator = false;

    // Copy ephemeral key
    if (request.ephemeral_key.size() == crypto_box_PUBLICKEYBYTES) {
        std::copy(request.ephemeral_key.begin(), request.ephemeral_key.end(),
                  pending_session.peer_enc_key.begin());
    }

    pending_sessions_[request.session_id] = pending_session;

    // Notify callback
    if (session_callback_) {
        session_callback_(request.session_id, message.sender_id, false);
    }
}

void DecentralizedMessenger::process_session_accept(
    const SessionAccept& accept,
    const Message& message
) {
    utilities::log_info("Session accept received from " + message.sender_id);

    // Move from pending to active
    std::lock_guard<std::mutex> pending_lock(pending_sessions_mutex_);
    std::lock_guard<std::mutex> sessions_lock(sessions_mutex_);

    auto it = pending_sessions_.find(accept.session_id);
    if (it != pending_sessions_.end()) {
        sessions_[message.sender_id] = it->second;
        pending_sessions_.erase(it);

        // Notify callback
        if (session_callback_) {
            session_callback_(accept.session_id, message.sender_id, true);
        }
    }
}

void DecentralizedMessenger::process_session_message(
    const SessionMessage& session_msg,
    const Message& message
) {
    // Find session
    std::optional<Session> session_opt = get_session(message.sender_id);
    if (!session_opt) {
        utilities::log_warn("No session found for message from " + message.sender_id);
        return;
    }

    // Decrypt message
    auto decrypted_opt = decrypt_session_message(
        session_msg.encrypted_data,
        session_msg.nonce,
        *session_opt
    );

    if (decrypted_opt) {
        // Update activity
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            auto it = sessions_.find(message.sender_id);
            if (it != sessions_.end()) {
                it->second.last_activity = MessageHelpers::get_current_timestamp();
            }
        }

        // Invoke callback
        if (message_callback_) {
            message_callback_(message);
        }
    }
}

void DecentralizedMessenger::process_file_offer(
    const FileOffer& offer,
    const Message& message
) {
    utilities::log_info("File offer received: " + offer.filename + " (" +
                       utilities::format_file_size(offer.file_size) + ")");

    // Store transfer state
    std::lock_guard<std::mutex> lock(transfers_mutex_);

    FileTransfer transfer;
    transfer.file_id = offer.file_id;
    transfer.filename = offer.filename;
    transfer.file_size = offer.file_size;
    transfer.file_hash = offer.file_hash;
    transfer.bytes_transferred = 0;
    transfer.total_chunks = 0;
    transfer.is_sender = false;
    transfer.start_time = std::chrono::steady_clock::now();

    file_transfers_[offer.file_id] = std::move(transfer);

    // Notify callback
    if (message_callback_) {
        message_callback_(message);
    }
}

void DecentralizedMessenger::process_file_chunk(
    const FileChunk& chunk,
    const Message& message
) {
    std::lock_guard<std::mutex> lock(transfers_mutex_);

    auto it = file_transfers_.find(chunk.file_id);
    if (it == file_transfers_.end()) {
        utilities::log_warn("Unknown file transfer: " + chunk.file_id);
        return;
    }

    // Store chunk
    if (chunk.chunk_number < it->second.chunks.size()) {
        it->second.chunks[chunk.chunk_number] = chunk.data;
        it->second.bytes_transferred += chunk.data.size();

        // Notify progress
        if (file_progress_callback_) {
            file_progress_callback_(
                chunk.file_id,
                it->second.bytes_transferred,
                it->second.file_size
            );
        }
    }
}

void DecentralizedMessenger::process_file_complete(
    const std::string& file_id,
    const Message& message
) {
    utilities::log_info("File transfer complete: " + file_id);

    // Notify callback
    if (message_callback_) {
        message_callback_(message);
    }
}

// ============================================================================
// Private Methods - Message Sending
// ============================================================================

bool DecentralizedMessenger::send_udp_message(
    const Message& message,
    const std::string& host,
    uint16_t port
) {
    try {
        asio::ip::udp::endpoint endpoint(
            asio::ip::address::from_string(host),
            port
        );

        auto message_json = message.to_json();
        std::vector<uint8_t> message_data(message_json.begin(), message_json.end());

        if (message_data.size() > MAX_UDP_PACKET_SIZE) {
            utilities::log_error("Message too large for UDP");
            return false;
        }

        udp_socket_->send_to(asio::buffer(message_data), endpoint);
        return true;

    } catch (const std::exception& e) {
        utilities::log_error("Failed to send UDP message: " + std::string(e.what()));
        return false;
    }
}

bool DecentralizedMessenger::send_tcp_message(
    const Message& message,
    const std::string& host,
    uint16_t port
) {
    try {
        asio::ip::tcp::socket socket(io_context_);
        asio::ip::tcp::endpoint endpoint(
            asio::ip::address::from_string(host),
            port
        );

        socket.connect(endpoint);

        auto message_json = message.to_json();
        std::vector<uint8_t> message_data(message_json.begin(), message_json.end());

        asio::write(socket, asio::buffer(message_data));
        return true;

    } catch (const std::exception& e) {
        utilities::log_error("Failed to send TCP message: " + std::string(e.what()));
        return false;
    }
}

void DecentralizedMessenger::queue_message(
    const Message& message,
    const std::string& host,
    uint16_t port,
    bool use_tcp
) {
    std::lock_guard<std::mutex> lock(queue_mutex_);

    QueuedMessage queued;
    queued.message = message;
    queued.destination_host = host;
    queued.destination_port = port;
    queued.use_tcp = use_tcp;
    queued.retry_count = 0;

    message_queue_.push(std::move(queued));
}

void DecentralizedMessenger::process_message_queue() {
    std::lock_guard<std::mutex> lock(queue_mutex_);

    if (message_queue_.empty()) {
        return;
    }

    QueuedMessage queued = message_queue_.front();
    message_queue_.pop();

    bool success = queued.use_tcp ?
        send_tcp_message(queued.message, queued.destination_host, queued.destination_port) :
        send_udp_message(queued.message, queued.destination_host, queued.destination_port);

    if (!success && queued.retry_count < MAX_MESSAGE_RETRIES) {
        queued.retry_count++;
        message_queue_.push(std::move(queued));
    }
}

// ============================================================================
// Private Methods - Encryption
// ============================================================================

std::optional<std::vector<uint8_t>> DecentralizedMessenger::encrypt_session_message(
    const std::vector<uint8_t>& plaintext,
    const Session& session
) {
    auto nonce = AgentCrypto::generate_nonce();
    return AgentCrypto::encrypt(plaintext, session.shared_secret, nonce);
}

std::optional<std::vector<uint8_t>> DecentralizedMessenger::decrypt_session_message(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& nonce_vec,
    const Session& session
) {
    if (nonce_vec.size() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
        return std::nullopt;
    }

    std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_NPUBBYTES> nonce;
    std::copy(nonce_vec.begin(), nonce_vec.end(), nonce.begin());

    return AgentCrypto::decrypt(ciphertext, session.shared_secret, nonce);
}

// ============================================================================
// Private Methods - Utilities
// ============================================================================

Message DecentralizedMessenger::create_message(
    MessageType type,
    const std::vector<uint8_t>& payload,
    const std::string& recipient_id
) {
    Message message;
    message.type = type;
    message.timestamp = MessageHelpers::get_current_timestamp();
    message.sender_id = identity_->get_agent_id();
    message.recipient_id = recipient_id;
    message.payload = payload;

    // Generate message ID
    std::string nonce = utilities::generate_uuid();
    message.message_id = MessageHelpers::generate_message_id(
        message.sender_id,
        message.timestamp,
        nonce
    );

    // Sign message
    std::vector<uint8_t> message_data(payload.begin(), payload.end());
    message.signature = identity_->sign(message_data);

    return message;
}

std::string DecentralizedMessenger::generate_session_id(const std::string& peer_id) {
    std::string data = identity_->get_agent_id() + peer_id +
                      std::to_string(MessageHelpers::get_current_timestamp()) +
                      utilities::generate_uuid();
    return MessageReplayProtection::generate_message_id(data, MessageHelpers::get_current_timestamp(), "");
}

std::string DecentralizedMessenger::generate_file_id(const std::string& filename) {
    std::string data = filename + std::to_string(MessageHelpers::get_current_timestamp()) +
                      utilities::generate_uuid();
    return MessageReplayProtection::generate_message_id(data, MessageHelpers::get_current_timestamp(), "");
}

void DecentralizedMessenger::cleanup_expired_sessions() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);

    uint64_t now = MessageHelpers::get_current_timestamp();
    auto it = sessions_.begin();

    while (it != sessions_.end()) {
        if (now - it->second.last_activity > SESSION_TIMEOUT_SECONDS) {
            utilities::log_info("Session expired: " + it->second.session_id);
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

void DecentralizedMessenger::cleanup_stale_transfers() {
    std::lock_guard<std::mutex> lock(transfers_mutex_);

    auto now = std::chrono::steady_clock::now();
    auto it = file_transfers_.begin();

    while (it != file_transfers_.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.start_time
        ).count();

        if (elapsed > TRANSFER_TIMEOUT_SECONDS) {
            utilities::log_info("File transfer timeout: " + it->first);
            it = file_transfers_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace nlitp
