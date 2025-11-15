/**
 * @file agent_node.cpp
 * @brief Implementation of main SCU agent orchestrator
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright � 2025 Fortified Solutions Inc.
 *
 * Integrates all NLITP subsystems into cohesive agent node
 */

#include "nlitp/agent_node.hpp"
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <fstream>

namespace nlitp {

using namespace nlitp::utilities;
using namespace nlitp::security;

// ============================================================================
// Constructor and Destructor
// ============================================================================

AgentNode::AgentNode(
    const std::string& agent_id,
    const std::string& data_dir,
    uint16_t discovery_port,
    bool auto_accept_sessions
)
    : agent_id_(agent_id)
    , data_dir_(data_dir.empty() ? get_data_directory() : std::filesystem::path(data_dir))
    , discovery_port_(discovery_port)
    , auto_accept_sessions_(auto_accept_sessions)
    , running_(false)
    , messages_sent_(0)
    , messages_received_(0)
    , bytes_sent_(0)
    , bytes_received_(0)
    , allocated_port_(0)
{
    log_info("AgentNode: Initializing agent '" + agent_id_ + "'");

    // Validate agent ID
    if (!validate_identifier(agent_id_)) {
        throw std::invalid_argument("Invalid agent ID: " + agent_id_);
    }
}

AgentNode::~AgentNode() {
    if (running_) {
        log_warn("AgentNode: Destructor called while still running, forcing stop");
        stop();
    }
    log_info("AgentNode: Destroyed");
}

// ============================================================================
// Lifecycle Management
// ============================================================================

bool AgentNode::start() {
    if (running_) {
        log_warn("AgentNode: Already running");
        return false;
    }

    log_info("AgentNode: Starting agent node...");

    try {
        // Initialize data directory
        if (!initialize_data_directory()) {
            log_error("AgentNode: Failed to initialize data directory");
            return false;
        }

        // Load or create identity
        if (!initialize_identity()) {
            log_error("AgentNode: Failed to initialize identity");
            return false;
        }

        // Initialize subsystems
        if (!initialize_subsystems()) {
            log_error("AgentNode: Failed to initialize subsystems");
            return false;
        }

        // Start discovery service
        if (!discovery_->start_discovery_listener()) {
            log_error("AgentNode: Failed to start discovery service");
            return false;
        }
        log_info("AgentNode: Discovery service started");

        // Start messenger
        if (!messenger_->start()) {
            log_error("AgentNode: Failed to start messenger");
            discovery_->stop();
            return false;
        }
        log_info("AgentNode: Messenger started on port " + std::to_string(allocated_port_));

        // Create work guard to keep io_context running
        work_guard_ = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
            io_context_.get_executor()
        );

        // Start worker threads for ASIO
        size_t num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 2;

        log_info("AgentNode: Starting " + std::to_string(num_threads) + " worker threads");
        for (size_t i = 0; i < num_threads; ++i) {
            worker_threads_.emplace_back([this]() {
                try {
                    io_context_.run();
                } catch (const std::exception& e) {
                    log_error("AgentNode: Worker thread exception: " + std::string(e.what()));
                }
            });
        }

        // Mark as running and record start time
        running_ = true;
        start_time_ = std::chrono::steady_clock::now();

        // Send initial announcement
        announce();

        log_info("AgentNode: Started successfully");
        print_status();

        return true;

    } catch (const std::exception& e) {
        log_error("AgentNode: Exception during start: " + std::string(e.what()));
        return false;
    }
}

void AgentNode::stop() {
    if (!running_) {
        log_warn("AgentNode: Not running");
        return;
    }

    log_info("AgentNode: Stopping agent node...");
    running_ = false;

    try {
        // Stop discovery
        if (discovery_) {
            discovery_->stop_discovery_listener();
            log_info("AgentNode: Discovery service stopped");
        }

        // Stop messenger
        if (messenger_) {
            messenger_->stop();
            log_info("AgentNode: Messenger stopped");
        }

        // Stop ASIO work
        work_guard_.reset();
        io_context_.stop();

        // Wait for worker threads
        for (auto& thread : worker_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        worker_threads_.clear();

        // Release allocated port
        if (port_allocator_ && allocated_port_ != 0) {
            port_allocator_->release(allocated_port_);
            log_info("AgentNode: Released port " + std::to_string(allocated_port_));
        }

        log_info("AgentNode: Stopped successfully");
        print_status();

    } catch (const std::exception& e) {
        log_error("AgentNode: Exception during stop: " + std::string(e.what()));
    }
}

void AgentNode::run() {
    if (!running_) {
        log_error("AgentNode: Cannot run - not started");
        return;
    }

    log_info("AgentNode: Entering main event loop (Ctrl+C to stop)");

    // Main event loop - just wait for signals
    while (running_) {
        try {
            // Sleep for a bit and perform maintenance tasks
            std::this_thread::sleep_for(std::chrono::seconds(30));

            // Cleanup stale peers
            size_t removed = cleanup_stale_peers();
            if (removed > 0) {
                log_info("AgentNode: Removed " + std::to_string(removed) + " stale peers");
            }

            // Re-announce presence
            announce();

        } catch (const std::exception& e) {
            log_error("AgentNode: Exception in main loop: " + std::string(e.what()));
        }
    }

    log_info("AgentNode: Exited main event loop");
}

bool AgentNode::is_running() const {
    return running_;
}

std::string AgentNode::get_agent_id() const {
    return agent_id_;
}

uint16_t AgentNode::get_port() const {
    return allocated_port_;
}

// ============================================================================
// Peer Discovery and Management
// ============================================================================

std::vector<PeerConnection> AgentNode::get_peers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    std::vector<PeerConnection> result;
    result.reserve(peers_.size());

    for (const auto& [peer_id, peer] : peers_) {
        result.push_back(*peer);
    }

    return result;
}

std::shared_ptr<PeerConnection> AgentNode::get_peer(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    auto it = peers_.find(peer_id);
    if (it != peers_.end()) {
        return it->second;
    }

    return nullptr;
}

bool AgentNode::announce() {
    if (!running_ || !discovery_) {
        return false;
    }

    try {
        std::map<std::string, std::string> capabilities;
        capabilities["role"] = "scu";
        capabilities["version"] = "8.0";

        bool success = discovery_->announce_presence(capabilities);
        if (success) {
            log_debug("AgentNode: Announced presence to network");
        }
        return success;
    } catch (const std::exception& e) {
        log_error("AgentNode: Failed to announce: " + std::string(e.what()));
        return false;
    }
}

// ============================================================================
// Messaging
// ============================================================================

bool AgentNode::send_message(const std::string& peer_id, const std::string& content) {
    if (!running_ || !messenger_) {
        log_error("AgentNode: Cannot send message - not running");
        return false;
    }

    try {
        // Get peer info
        auto peer = get_peer(peer_id);
        if (!peer) {
            log_error("AgentNode: Unknown peer: " + peer_id);
            return false;
        }

        // Check trust score
        if (!is_peer_trusted(peer_id)) {
            log_warn("AgentNode: Peer " + peer_id + " is not trusted");
            // Still allow sending, but log warning
        }

        // Convert content to bytes
        std::vector<uint8_t> payload(content.begin(), content.end());

        // Send via messenger
        auto message_id = messenger_->send_message(peer_id, payload);
        if (!message_id) {
            log_error("AgentNode: Failed to send message to " + peer_id);
            return false;
        }

        // Update statistics
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            messages_sent_++;
            bytes_sent_ += content.size();
        }

        log_info("AgentNode: Sent message to " + peer_id + " (" + std::to_string(content.size()) + " bytes)");
        return true;

    } catch (const std::exception& e) {
        log_error("AgentNode: Exception sending message: " + std::string(e.what()));
        return false;
    }
}

bool AgentNode::send_file(const std::string& peer_id, const std::string& file_path) {
    if (!running_ || !messenger_) {
        log_error("AgentNode: Cannot send file - not running");
        return false;
    }

    try {
        // Validate file path
        std::filesystem::path path(file_path);
        if (!std::filesystem::exists(path)) {
            log_error("AgentNode: File not found: " + file_path);
            return false;
        }

        if (!std::filesystem::is_regular_file(path)) {
            log_error("AgentNode: Not a regular file: " + file_path);
            return false;
        }

        // Check file size
        auto file_size = std::filesystem::file_size(path);
        if (file_size > MAX_FILE_SIZE) {
            log_error("AgentNode: File too large: " + std::to_string(file_size) + " bytes");
            return false;
        }

        // Get peer info
        auto peer = get_peer(peer_id);
        if (!peer) {
            log_error("AgentNode: Unknown peer: " + peer_id);
            return false;
        }

        // Send via messenger
        auto file_id = messenger_->send_file(peer_id, file_path);
        if (!file_id) {
            log_error("AgentNode: Failed to initiate file transfer to " + peer_id);
            return false;
        }

        log_info("AgentNode: Initiated file transfer to " + peer_id + ": " + path.filename().string());
        return true;

    } catch (const std::exception& e) {
        log_error("AgentNode: Exception sending file: " + std::string(e.what()));
        return false;
    }
}

void AgentNode::on_message_received(std::function<void(const std::string&, const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    message_callback_ = callback;
}

void AgentNode::on_file_received(std::function<void(const std::string&, const std::string&, const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    file_callback_ = callback;
}

// ============================================================================
// Trust Management
// ============================================================================

bool AgentNode::record_trust_observation(
    const std::string& peer_id,
    double trust_score,
    bool verified,
    const std::string& observation
) {
    if (!trust_ledger_) {
        log_error("AgentNode: Trust ledger not initialized");
        return false;
    }

    try {
        // Validate trust score
        if (trust_score < 0.0 || trust_score > 1.0) {
            log_error("AgentNode: Invalid trust score: " + std::to_string(trust_score));
            return false;
        }

        bool success = trust_ledger_->record_observation(
            agent_id_,
            peer_id,
            trust_score,
            verified,
            observation
        );

        if (success) {
            log_info("AgentNode: Recorded trust observation for " + peer_id + ": " + std::to_string(trust_score));
        } else {
            log_error("AgentNode: Failed to record trust observation for " + peer_id);
        }

        return success;

    } catch (const std::exception& e) {
        log_error("AgentNode: Exception recording trust: " + std::string(e.what()));
        return false;
    }
}

double AgentNode::get_trust_score(const std::string& peer_id) const {
    if (!trust_ledger_) {
        return 0.5; // Neutral trust
    }

    try {
        return trust_ledger_->calculate_trust_score(peer_id);
    } catch (const std::exception& e) {
        log_error("AgentNode: Exception getting trust score: " + std::string(e.what()));
        return 0.5;
    }
}

std::optional<PeerStats> AgentNode::get_peer_trust_stats(const std::string& peer_id) const {
    if (!trust_ledger_) {
        return std::nullopt;
    }

    try {
        return trust_ledger_->get_peer_stats(peer_id);
    } catch (const std::exception& e) {
        log_error("AgentNode: Exception getting peer stats: " + std::string(e.what()));
        return std::nullopt;
    }
}

// ============================================================================
// Session Management
// ============================================================================

bool AgentNode::request_session(const std::string& peer_id) {
    if (!running_ || !messenger_) {
        log_error("AgentNode: Cannot request session - not running");
        return false;
    }

    try {
        // Get peer info
        auto peer = get_peer(peer_id);
        if (!peer) {
            log_error("AgentNode: Unknown peer: " + peer_id);
            return false;
        }

        // Get peer's encryption key from discovery
        auto discovered_peer_opt = discovery_->get_peer(peer_id);
        if (!discovered_peer_opt) {
            log_error("AgentNode: Peer not discovered: " + peer_id);
            return false;
        }

        // Use the key directly (it's already an array)
        const auto& peer_enc_key = discovered_peer_opt->public_key_enc;

        // Request session
        auto session_id = messenger_->request_session(peer_id, peer->host, peer->port, peer_enc_key);
        if (!session_id) {
            log_error("AgentNode: Failed to request session with " + peer_id);
            return false;
        }

        log_info("AgentNode: Requested session with " + peer_id);
        return true;

    } catch (const std::exception& e) {
        log_error("AgentNode: Exception requesting session: " + std::string(e.what()));
        return false;
    }
}

bool AgentNode::close_session(const std::string& peer_id) {
    if (!messenger_) {
        return false;
    }

    try {
        // Get session
        auto session = messenger_->get_session(peer_id);
        if (!session) {
            log_warn("AgentNode: No active session with " + peer_id);
            return false;
        }

        bool success = messenger_->close_session(session->session_id);
        if (success) {
            log_info("AgentNode: Closed session with " + peer_id);

            // Update peer connection
            std::lock_guard<std::mutex> lock(peers_mutex_);
            auto it = peers_.find(peer_id);
            if (it != peers_.end()) {
                it->second->has_active_session = false;
            }
        }

        return success;

    } catch (const std::exception& e) {
        log_error("AgentNode: Exception closing session: " + std::string(e.what()));
        return false;
    }
}

size_t AgentNode::get_active_session_count() const {
    if (!messenger_) {
        return 0;
    }

    try {
        return messenger_->get_active_session_count();
    } catch (const std::exception& e) {
        log_error("AgentNode: Exception getting session count: " + std::string(e.what()));
        return 0;
    }
}

// ============================================================================
// Statistics and Monitoring
// ============================================================================

AgentNodeStats AgentNode::get_stats() const {
    AgentNodeStats stats{};

    std::lock_guard<std::mutex> lock(stats_mutex_);

    stats.active_peers = get_peers().size();
    stats.active_sessions = messenger_ ? messenger_->get_active_session_count() : 0;
    stats.active_transfers = messenger_ ? messenger_->get_active_transfer_count() : 0;
    stats.messages_sent = messages_sent_;
    stats.messages_received = messages_received_;
    stats.bytes_sent = bytes_sent_;
    stats.bytes_received = bytes_received_;
    stats.uptime_seconds = get_uptime();

    return stats;
}

uint64_t AgentNode::get_uptime() const {
    if (!running_) {
        return 0;
    }

    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_);
    return duration.count();
}

void AgentNode::print_status() const {
    auto stats = get_stats();

    std::cout << "\nTPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPW\n";
    std::cout << "Q              NLITPv8 Agent Node Status                        Q\n";
    std::cout << "`PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPc\n";
    std::cout << "Q Agent ID:         " << std::left << std::setw(43) << agent_id_ << " Q\n";
    std::cout << "Q Port:             " << std::left << std::setw(43) << allocated_port_ << " Q\n";
    std::cout << "Q Status:           " << std::left << std::setw(43) << (running_ ? "RUNNING" : "STOPPED") << " Q\n";
    std::cout << "Q Uptime:           " << std::left << std::setw(43) << format_duration(stats.uptime_seconds) << " Q\n";
    std::cout << "`PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPc\n";
    std::cout << "Q Active Peers:     " << std::left << std::setw(43) << stats.active_peers << " Q\n";
    std::cout << "Q Active Sessions:  " << std::left << std::setw(43) << stats.active_sessions << " Q\n";
    std::cout << "Q File Transfers:   " << std::left << std::setw(43) << stats.active_transfers << " Q\n";
    std::cout << "`PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPc\n";
    std::cout << "Q Messages Sent:    " << std::left << std::setw(43) << stats.messages_sent << " Q\n";
    std::cout << "Q Messages Recv:    " << std::left << std::setw(43) << stats.messages_received << " Q\n";
    std::cout << "Q Bytes Sent:       " << std::left << std::setw(43) << format_file_size(stats.bytes_sent) << " Q\n";
    std::cout << "Q Bytes Recv:       " << std::left << std::setw(43) << format_file_size(stats.bytes_received) << " Q\n";
    std::cout << "ZPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP]\n\n";
}

// ============================================================================
// Private Methods - Initialization
// ============================================================================

bool AgentNode::initialize_data_directory() {
    try {
        // Create main data directory
        if (!std::filesystem::exists(data_dir_)) {
            std::filesystem::create_directories(data_dir_);
            log_info("AgentNode: Created data directory: " + data_dir_.string());
        }

        // Create subdirectories
        auto keys_dir = data_dir_ / "keys";
        auto db_dir = data_dir_ / "database";
        auto files_dir = data_dir_ / "received";
        auto logs_dir = data_dir_ / "logs";

        for (const auto& dir : {keys_dir, db_dir, files_dir, logs_dir}) {
            if (!std::filesystem::exists(dir)) {
                std::filesystem::create_directories(dir);
                log_info("AgentNode: Created directory: " + dir.string());
            }
        }

        return true;

    } catch (const std::exception& e) {
        log_error("AgentNode: Failed to initialize data directory: " + std::string(e.what()));
        return false;
    }
}

bool AgentNode::initialize_identity() {
    try {
        auto keys_dir = data_dir_ / "keys";

        // Try to load existing identity
        auto identity = AgentIdentity::load(agent_id_, keys_dir);

        if (identity) {
            log_info("AgentNode: Loaded existing identity");
            identity_ = std::make_shared<AgentIdentity>(*identity);
        } else {
            // Create new identity
            log_info("AgentNode: Creating new identity");
            identity_ = std::make_shared<AgentIdentity>(agent_id_);

            // Save to disk
            if (!identity_->save(keys_dir)) {
                log_error("AgentNode: Failed to save identity");
                return false;
            }
            log_info("AgentNode: Saved new identity to " + keys_dir.string());
        }

        log_info("AgentNode: Identity initialized for " + identity_->get_agent_id());
        return true;

    } catch (const std::exception& e) {
        log_error("AgentNode: Failed to initialize identity: " + std::string(e.what()));
        return false;
    }
}

bool AgentNode::initialize_subsystems() {
    try {
        // Initialize port allocator
        port_allocator_ = std::make_unique<PortAllocator>(PORT_RANGE_START, PORT_RANGE_END);

        // Allocate a port
        auto port_opt = port_allocator_->allocate();
        if (!port_opt) {
            log_error("AgentNode: Failed to allocate port");
            return false;
        }
        allocated_port_ = *port_opt;
        log_info("AgentNode: Allocated port " + std::to_string(allocated_port_));

        // Initialize trust ledger
        auto db_path = get_database_path();
        trust_ledger_ = std::make_unique<TrustLedger>(db_path, agent_id_);
        log_info("AgentNode: Initialized trust ledger: " + db_path);

        // Initialize rate limiter
        rate_limiter_ = std::make_unique<RateLimiter>(RATE_LIMIT_PER_SECOND, RATE_LIMIT_BURST);
        log_info("AgentNode: Initialized rate limiter");

        // Initialize replay protection
        replay_protection_ = std::make_unique<MessageReplayProtection>(REPLAY_WINDOW);
        log_info("AgentNode: Initialized replay protection");

        // Initialize messenger
        messenger_ = std::make_shared<DecentralizedMessenger>(identity_, allocated_port_);

        // Set messenger callbacks
        messenger_->set_message_callback([this](const Message& msg) {
            handle_message_received(msg);
        });

        messenger_->set_session_callback([this](const std::string& sid, const std::string& pid, bool success) {
            handle_session_event(sid, pid, success);
        });

        messenger_->set_file_progress_callback([this](const std::string& fid, uint64_t xfer, uint64_t total) {
            handle_file_progress(fid, xfer, total);
        });

        log_info("AgentNode: Initialized messenger");

        // Initialize discovery
        discovery_ = std::make_unique<AgentDiscovery>(
            identity_,
            io_context_,
            discovery_port_
        );

        // Set discovery callback
        discovery_->set_peer_discovered_callback([this](const PeerInfo& peer) {
            handle_peer_discovered(peer);
        });

        log_info("AgentNode: Initialized discovery service");

        return true;

    } catch (const std::exception& e) {
        log_error("AgentNode: Failed to initialize subsystems: " + std::string(e.what()));
        return false;
    }
}

// ============================================================================
// Private Methods - Event Handlers
// ============================================================================

void AgentNode::handle_peer_discovered(const PeerInfo& peer) {
    log_info("AgentNode: Discovered peer: " + peer.agent_id + " at " + peer.host + ":" + std::to_string(peer.port));

    // Update peer connection info
    update_peer_connection(peer);

    // Auto-request session if enabled
    if (auto_accept_sessions_) {
        request_session(peer.agent_id);
    }
}

void AgentNode::handle_message_received(const Message& message) {
    try {
        // Update statistics
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            messages_received_++;
            bytes_received_ += message.payload.size();
        }

        // Rate limiting check
        if (rate_limiter_ && !rate_limiter_->allow_message(message.sender_id)) {
            log_warn("AgentNode: Rate limit exceeded for " + message.sender_id);
            return;
        }

        // Replay protection check
        if (replay_protection_ && !replay_protection_->validate_message(message.message_id, message.timestamp)) {
            log_warn("AgentNode: Replay attack detected from " + message.sender_id);
            return;
        }

        log_info("AgentNode: Received message from " + message.sender_id + " (" + std::to_string(message.payload.size()) + " bytes)");

        // Call user callback if set
        std::lock_guard<std::mutex> lock(callback_mutex_);
        if (message_callback_) {
            std::string content(message.payload.begin(), message.payload.end());
            message_callback_(message.sender_id, content);
        }

    } catch (const std::exception& e) {
        log_error("AgentNode: Exception handling message: " + std::string(e.what()));
    }
}

void AgentNode::handle_session_event(const std::string& session_id, const std::string& peer_id, bool success) {
    if (success) {
        log_info("AgentNode: Session established with " + peer_id);

        // Update peer connection
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = peers_.find(peer_id);
        if (it != peers_.end()) {
            it->second->has_active_session = true;
        }
    } else {
        log_warn("AgentNode: Session failed with " + peer_id);
    }
}

void AgentNode::handle_file_progress(const std::string& file_id, uint64_t bytes_transferred, uint64_t total_bytes) {
    double progress = (double)bytes_transferred / (double)total_bytes * 100.0;
    log_debug("AgentNode: File transfer " + file_id + ": " + std::to_string((int)progress) + "%");
}

// ============================================================================
// Private Methods - Utilities
// ============================================================================

void AgentNode::update_peer_connection(const PeerInfo& peer) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    auto now = std::chrono::steady_clock::now();
    auto last_seen = std::chrono::duration_cast<std::chrono::seconds>(now - peer.last_seen).count();

    auto it = peers_.find(peer.agent_id);
    if (it != peers_.end()) {
        // Update existing peer
        it->second->host = peer.host;
        it->second->port = peer.port;
        it->second->last_seen = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    } else {
        // Add new peer
        auto connection = std::make_shared<PeerConnection>();
        connection->agent_id = peer.agent_id;
        connection->host = peer.host;
        connection->port = peer.port;
        connection->trust_score = get_trust_score(peer.agent_id);
        connection->has_active_session = false;
        connection->last_seen = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

        peers_[peer.agent_id] = connection;
    }
}

size_t AgentNode::cleanup_stale_peers() {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    auto timeout = 300; // 5 minutes

    size_t removed = 0;
    for (auto it = peers_.begin(); it != peers_.end();) {
        if ((now - it->second->last_seen) > timeout) {
            log_debug("AgentNode: Removing stale peer: " + it->first);
            it = peers_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }

    return removed;
}

bool AgentNode::is_peer_trusted(const std::string& peer_id) const {
    double trust_score = get_trust_score(peer_id);
    return trust_score >= 0.5; // Neutral or better
}

std::string AgentNode::get_database_path() const {
    auto db_dir = data_dir_ / "database";
    auto db_file = db_dir / (agent_id_ + "_trust.db");
    return db_file.string();
}

std::string AgentNode::get_received_files_dir() const {
    auto files_dir = data_dir_ / "received";
    return files_dir.string();
}

} // namespace nlitp
