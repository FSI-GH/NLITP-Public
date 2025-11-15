/**
 * @file mesh_demo.cpp
 * @brief Mesh network demonstration - Multiple agents communicating
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Demonstrates mesh networking:
 * - Launch multiple agent nodes
 * - Peer discovery across mesh
 * - Message broadcasting
 * - Trust network visualization
 */

#include "nlitp/agent_node.hpp"
#include "nlitp/utilities.hpp"
#include <iostream>
#include <vector>
#include <memory>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include <iomanip>

using namespace nlitp;
using namespace std::chrono_literals;

// Global shutdown flag
static std::atomic<bool> g_shutdown(false);

void signal_handler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down mesh...\n";
    g_shutdown = true;
}

void print_mesh_status(const std::vector<std::unique_ptr<AgentNode>>& agents) {
    std::cout << "\n╗\n";
    std::cout << "                  Mesh Network Status                     \n";
    std::cout << "╣\n";

    for (const auto& agent : agents) {
        auto info = agent->get_info();
        auto peers = agent->get_peers();

        std::cout << " Agent: " << std::left << std::setw(46) << info.agent_id << "\n";
        std::cout << "   Peers:   " << std::left << std::setw(44) << peers.size() << "\n";

        if (!peers.empty()) {
            std::cout << "   Connected to:                                       \n";
            for (const auto& peer : peers) {
                std::string peer_info = "    - " + peer.agent_id +
                                       " [trust: " + std::to_string(peer.trust_score).substr(0, 4) + "]";
                std::cout << "   " << std::left << std::setw(52) << peer_info << "\n";
            }
        }
        std::cout << "──────────────────────────────────────────────────────────╢\n";
    }
    std::cout << "╝\n\n";
}

int main(int argc, char** argv) {
    // Handle Ctrl+C
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        std::cout << "╗\n";
        std::cout << "        NLITPv8 Mesh Network Demonstration               \n";
        std::cout << "      (Press Ctrl+C to stop)                              \n";
        std::cout << "╝\n\n";

        // Create mesh of 3 agents
        std::vector<std::unique_ptr<AgentNode>> agents;
        std::vector<std::string> agent_ids = {"alpha", "beta", "gamma"};

        std::cout << "Creating mesh with " << agent_ids.size() << " agents...\n";

        for (const auto& id : agent_ids) {
            std::cout << "  - Initializing agent: " << id << "\n";
            agents.push_back(std::make_unique<AgentNode>(id, ""));
        }

        // Start all agents
        std::cout << "\nStarting all agents...\n";
        for (auto& agent : agents) {
            agent->start();
        }

        // Let them discover each other
        std::cout << "Waiting for peer discovery...\n";
        std::this_thread::sleep_for(3s);

        // Announce all agents
        std::cout << "Broadcasting presence...\n";
        for (auto& agent : agents) {
            agent->announce();
        }

        std::this_thread::sleep_for(2s);

        // Show mesh status
        print_mesh_status(agents);

        // Broadcast a message from first agent
        std::cout << "Broadcasting message from " << agent_ids[0] << "...\n";
        std::vector<uint8_t> broadcast_msg(
            std::string("Hello mesh network!").begin(),
            std::string("Hello mesh network!").end()
        );

        auto peers = agents[0]->get_peers();
        for (const auto& peer : peers) {
            agents[0]->send_message(peer.agent_id, broadcast_msg);
        }

        std::cout << "Message sent to " << peers.size() << " peer(s).\n\n";

        // Run for 30 seconds or until interrupted
        std::cout << "Mesh running... (will auto-stop in 30 seconds)\n";
        for (int i = 0; i < 30 && !g_shutdown; ++i) {
            std::this_thread::sleep_for(1s);

            // Print status every 10 seconds
            if ((i + 1) % 10 == 0) {
                print_mesh_status(agents);
            }
        }

        // Shutdown all agents
        std::cout << "\nShutting down mesh...\n";
        for (auto& agent : agents) {
            agent->stop();
        }

        std::cout << "Mesh network stopped successfully.\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
