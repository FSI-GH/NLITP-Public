/**
 * @file agent_example.cpp
 * @brief Simple agent example - Basic peer discovery and messaging
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Demonstrates minimal agent usage:
 * - Initialize agent identity
 * - Discover peers on local network
 * - Send simple message
 */

#include "nlitp/agent_node.hpp"
#include <iostream>
#include <thread>
#include <chrono>

using namespace nlitp;
using namespace std::chrono_literals;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <agent_id>\n";
        std::cerr << "Example: " << argv[0] << " alice\n";
        return 1;
    }

    std::string agent_id = argv[1];
    std::string data_dir = argc >= 3 ? argv[2] : "";

    try {
        std::cout << "\n=== NLITPv8 Simple Agent Example ===\n\n";

        // Create agent node
        std::cout << "Creating agent: " << agent_id << "\n";
        AgentNode agent(agent_id, data_dir);

        // Start agent
        std::cout << "Starting agent...\n";
        agent.start();

        // Get agent info
        std::cout << "\nAgent Info:\n";
        std::cout << "  ID:        " << agent.get_agent_id() << "\n";
        std::cout << "  Port:      " << agent.get_port() << "\n\n";

        // Announce presence
        std::cout << "Broadcasting presence to network...\n";
        agent.announce();

        // Wait for peer discovery
        std::cout << "Waiting for peer discovery (5 seconds)...\n";
        std::this_thread::sleep_for(5s);

        // List discovered peers
        auto peers = agent.get_peers();
        std::cout << "\nDiscovered " << peers.size() << " peer(s):\n";

        if (peers.empty()) {
            std::cout << "  (No peers found on local network)\n";
        } else {
            for (const auto& peer : peers) {
                std::cout << "  - " << peer.agent_id
                          << " (" << peer.host << ":" << peer.port << ")"
                          << " [trust: " << peer.trust_score << "]\n";
            }

            // Send message to first peer
            const auto& first_peer = peers[0];
            std::cout << "\nSending test message to " << first_peer.agent_id << "...\n";

            std::string message_content = "Hello from " + agent_id;
            agent.send_message(first_peer.agent_id, message_content);
            std::cout << "Message sent.\n";
        }

        // Shutdown
        std::cout << "\nShutting down agent...\n";
        agent.stop();
        std::cout << "Agent stopped successfully.\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
