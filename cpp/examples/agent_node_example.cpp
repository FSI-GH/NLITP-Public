/**
 * @file agent_node_example.cpp
 * @brief Example CLI application using AgentNode
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Demonstrates basic AgentNode usage:
 * - Start agent with identity
 * - Discover peers
 * - Send messages
 * - Send files
 * - Record trust observations
 */

#include "nlitp/agent_node.hpp"
#include "nlitp/utilities.hpp"
#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <thread>

using namespace nlitp;
using namespace nlitp::utilities;

// Global agent node pointer for signal handler
static std::atomic<nlitp::AgentNode*> g_agent_node(nullptr);
static std::atomic<bool> g_shutdown(false);

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    std::cout << "\n\nReceived signal " << signal << ", shutting down...\n";
    g_shutdown = true;

    auto* node = g_agent_node.load();
    if (node) {
        node->stop();
    }
}

// Print usage information
void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <agent_id> [data_dir]\n\n";
    std::cout << "Arguments:\n";
    std::cout << "  agent_id    Unique agent identifier (alphanumeric, max 64 chars)\n";
    std::cout << "  data_dir    Data directory (optional, default: ~/.nlitp)\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " alice\n";
    std::cout << "  " << program_name << " bob /tmp/bob_data\n\n";
}

// Print help menu
void print_help() {
    std::cout << "\n╗\n";
    std::cout << "                    NLITPv8 Agent Commands                     \n";
    std::cout << "╣\n";
    std::cout << " help                - Show this help menu                      \n";
    std::cout << " status              - Show agent status                        \n";
    std::cout << " peers               - List discovered peers                    \n";
    std::cout << " announce            - Broadcast presence to network            \n";
    std::cout << " msg <peer> <text>   - Send message to peer                     \n";
    std::cout << " file <peer> <path>  - Send file to peer                        \n";
    std::cout << " trust <peer> <0-1>  - Record trust observation                 \n";
    std::cout << " session <peer>      - Request encrypted session                \n";
    std::cout << " close <peer>        - Close session with peer                  \n";
    std::cout << " quit / exit         - Shutdown agent                           \n";
    std::cout << "╝\n\n";
}

// List all discovered peers
void list_peers(AgentNode& node) {
    auto peers = node.get_peers();

    if (peers.empty()) {
        std::cout << "No peers discovered yet.\n";
        return;
    }

    std::cout << "\n╗\n";
    std::cout << "                     Discovered Peers                           \n";
    std::cout << "╣\n";

    for (const auto& peer : peers) {
        std::cout << " Agent ID:  " << std::left << std::setw(49) << peer.agent_id << "\n";
        std::cout << " Address:   " << std::left << std::setw(49)
                  << (peer.host + ":" + std::to_string(peer.port)) << "\n";
        std::cout << " Trust:     " << std::left << std::setw(49)
                  << std::to_string(peer.trust_score) << "\n";
        std::cout << " Session:   " << std::left << std::setw(49)
                  << (peer.has_active_session ? "Active" : "None") << "\n";
        std::cout << "────────────────────────────────────────────────────────────────╢\n";
    }

    std::cout << "╝\n\n";
}

// Handle user commands
bool handle_command(AgentNode& node, const std::string& command_line) {
    if (command_line.empty()) {
        return true;
    }

    std::istringstream iss(command_line);
    std::string cmd;
    iss >> cmd;

    if (cmd == "help" || cmd == "h" || cmd == "?") {
        print_help();
    }
    else if (cmd == "status") {
        node.print_status();
    }
    else if (cmd == "peers") {
        list_peers(node);
    }
    else if (cmd == "announce") {
        if (node.announce()) {
            std::cout << "[OK] Announced presence to network\n";
        } else {
            std::cout << "[FAIL] Failed to announce presence\n";
        }
    }
    else if (cmd == "msg") {
        std::string peer_id, message;
        iss >> peer_id;
        std::getline(iss, message);

        if (peer_id.empty() || message.empty()) {
            std::cout << "Usage: msg <peer_id> <message>\n";
        } else {
            // Trim leading whitespace from message
            message.erase(0, message.find_first_not_of(" \t"));

            if (node.send_message(peer_id, message)) {
                std::cout << "[OK] Message sent to " << peer_id << "\n";
            } else {
                std::cout << "[FAIL] Failed to send message to " << peer_id << "\n";
            }
        }
    }
    else if (cmd == "file") {
        std::string peer_id, file_path;
        iss >> peer_id >> file_path;

        if (peer_id.empty() || file_path.empty()) {
            std::cout << "Usage: file <peer_id> <file_path>\n";
        } else {
            if (node.send_file(peer_id, file_path)) {
                std::cout << "[OK] File transfer initiated to " << peer_id << "\n";
            } else {
                std::cout << "[FAIL] Failed to send file to " << peer_id << "\n";
            }
        }
    }
    else if (cmd == "trust") {
        std::string peer_id;
        double trust_score;
        iss >> peer_id >> trust_score;

        if (peer_id.empty() || iss.fail()) {
            std::cout << "Usage: trust <peer_id> <score_0_to_1>\n";
        } else {
            if (node.record_trust_observation(peer_id, trust_score, true, "Manual observation")) {
                std::cout << "[OK] Trust observation recorded for " << peer_id << ": " << trust_score << "\n";
            } else {
                std::cout << "[FAIL] Failed to record trust observation\n";
            }
        }
    }
    else if (cmd == "session") {
        std::string peer_id;
        iss >> peer_id;

        if (peer_id.empty()) {
            std::cout << "Usage: session <peer_id>\n";
        } else {
            if (node.request_session(peer_id)) {
                std::cout << "[OK] Session request sent to " << peer_id << "\n";
            } else {
                std::cout << "[FAIL] Failed to request session with " << peer_id << "\n";
            }
        }
    }
    else if (cmd == "close") {
        std::string peer_id;
        iss >> peer_id;

        if (peer_id.empty()) {
            std::cout << "Usage: close <peer_id>\n";
        } else {
            if (node.close_session(peer_id)) {
                std::cout << "[OK] Session closed with " << peer_id << "\n";
            } else {
                std::cout << "[FAIL] Failed to close session with " << peer_id << "\n";
            }
        }
    }
    else if (cmd == "quit" || cmd == "exit") {
        return false;
    }
    else {
        std::cout << "Unknown command: " << cmd << "\n";
        std::cout << "Type 'help' for available commands\n";
    }

    return true;
}

int main(int argc, char* argv[]) {
    // Parse command line arguments
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string agent_id = argv[1];
    std::string data_dir = (argc >= 3) ? argv[2] : "";

    // Initialize logging
    initialize_logging("", LogLevel::INFO);

    std::cout << "\n╗\n";
    std::cout << "            NLITPv8 Agent Node - CLI Example                   \n";
    std::cout << "         Next Level Intelligence Transport Protocol v8          \n";
    std::cout << "              Copyright © 2025 Fortified Solutions Inc.         \n";
    std::cout << "╝\n\n";

    try {
        // Create agent node
        std::cout << "Initializing agent '" << agent_id << "'...\n";
        AgentNode node(agent_id, data_dir);

        // Set up signal handlers for graceful shutdown
        g_agent_node.store(&node);
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        // Set up message callback
        node.on_message_received([](const std::string& peer_id, const std::string& content) {
            std::cout << "\n>>> Message from " << peer_id << ": " << content << "\n> ";
            std::cout.flush();
        });

        // Set up file callback
        node.on_file_received([](const std::string& peer_id, const std::string& file_path, const std::string& filename) {
            std::cout << "\n>>> File received from " << peer_id << ": " << filename
                      << " saved to " << file_path << "\n> ";
            std::cout.flush();
        });

        // Start the agent node
        std::cout << "Starting agent node...\n";
        if (!node.start()) {
            std::cerr << "Failed to start agent node\n";
            return 1;
        }

        // Start background thread for event loop
        std::thread event_loop([&node]() {
            node.run();
        });

        // Print initial help
        print_help();

        // Command loop
        std::string line;
        while (!g_shutdown && std::cout << "> " && std::getline(std::cin, line)) {
            if (!handle_command(node, line)) {
                break;
            }
        }

        // Shutdown
        std::cout << "\nShutting down agent node...\n";
        g_shutdown = true;
        node.stop();

        if (event_loop.joinable()) {
            event_loop.join();
        }

        std::cout << "Agent node stopped successfully\n";

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
