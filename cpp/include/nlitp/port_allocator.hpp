/**
 * @file port_allocator.hpp
 * @brief Thread-safe network port allocation
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Allocates unique network ports for agents from configurable range.
 * - Thread-safe allocation
 * - Port reuse tracking
 * - Automatic cleanup of released ports
 * - Collision avoidance
 */

#pragma once

#include <cstdint>
#include <set>
#include <mutex>
#include <optional>

namespace nlitp {

/**
 * @brief PortAllocator - Thread-safe network port allocation
 *
 * Manages allocation of network ports from a configurable range.
 * Prevents port collisions by tracking allocated ports.
 *
 * Default range: 11000-61000 (50,000 ports available)
 */
class PortAllocator {
public:
    /**
     * @brief Construct port allocator with configurable range
     * @param start_port First port in allocation range (default: 11000)
     * @param end_port Last port in allocation range (default: 61000)
     */
    explicit PortAllocator(
        uint16_t start_port = 11000,
        uint16_t end_port = 61000
    );

    /**
     * @brief Destructor
     */
    ~PortAllocator() = default;

    // Disable copy and move (singleton pattern recommended)
    PortAllocator(const PortAllocator&) = delete;
    PortAllocator& operator=(const PortAllocator&) = delete;
    PortAllocator(PortAllocator&&) = delete;
    PortAllocator& operator=(PortAllocator&&) = delete;

    /**
     * @brief Allocate next available port
     * @return Port number if successful, std::nullopt if no ports available
     */
    std::optional<uint16_t> allocate();

    /**
     * @brief Allocate specific port if available
     * @param port Desired port number
     * @return true if port was allocated, false if already in use or out of range
     */
    bool allocate_specific(uint16_t port);

    /**
     * @brief Release allocated port back to pool
     * @param port Port number to release
     * @return true if port was released, false if port was not allocated
     */
    bool release(uint16_t port);

    /**
     * @brief Check if port is allocated
     * @param port Port number to check
     * @return true if port is allocated, false otherwise
     */
    bool is_allocated(uint16_t port) const;

    /**
     * @brief Get number of allocated ports
     * @return Count of currently allocated ports
     */
    size_t get_allocated_count() const;

    /**
     * @brief Get number of available ports
     * @return Count of available ports in range
     */
    size_t get_available_count() const;

    /**
     * @brief Get total port range size
     * @return Total number of ports in allocation range
     */
    size_t get_total_count() const;

    /**
     * @brief Check if any ports are available
     * @return true if ports available, false if all allocated
     */
    bool has_available_ports() const;

    /**
     * @brief Reset allocator (release all ports)
     */
    void reset();

private:
    /// Start of port allocation range
    uint16_t start_port_;

    /// End of port allocation range
    uint16_t end_port_;

    /// Next port to try for allocation (round-robin)
    uint16_t next_port_;

    /// Set of currently allocated ports
    std::set<uint16_t> allocated_ports_;

    /// Mutex for thread-safe access
    mutable std::mutex mutex_;

    /**
     * @brief Check if port is within valid range
     * @param port Port number to check
     * @return true if port is in range, false otherwise
     */
    bool is_in_range(uint16_t port) const;
};

} // namespace nlitp
