/**
 * @file port_allocator.cpp
 * @brief Implementation of thread-safe port allocation
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Thread-safe port allocation with collision avoidance
 */

#include "nlitp/port_allocator.hpp"

namespace nlitp {

// ============================================================================
// Constructor
// ============================================================================

PortAllocator::PortAllocator(uint16_t start_port, uint16_t end_port)
    : start_port_(start_port)
    , end_port_(end_port)
    , next_port_(start_port)
{
    // Validate port range
    if (start_port_ >= end_port_) {
        throw std::invalid_argument("start_port must be less than end_port");
    }
}

// ============================================================================
// Port Allocation
// ============================================================================

std::optional<uint16_t> PortAllocator::allocate() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if any ports available
    if (allocated_ports_.size() >= get_total_count()) {
        return std::nullopt;
    }

    // Try to allocate starting from next_port_
    uint16_t attempts = 0;
    uint16_t max_attempts = end_port_ - start_port_ + 1;

    while (attempts < max_attempts) {
        // Check if current port is available
        if (allocated_ports_.find(next_port_) == allocated_ports_.end()) {
            // Port is available, allocate it
            uint16_t allocated_port = next_port_;
            allocated_ports_.insert(allocated_port);

            // Move to next port (round-robin)
            next_port_++;
            if (next_port_ > end_port_) {
                next_port_ = start_port_;
            }

            return allocated_port;
        }

        // Port is already allocated, try next one
        next_port_++;
        if (next_port_ > end_port_) {
            next_port_ = start_port_;
        }

        attempts++;
    }

    // No available ports found
    return std::nullopt;
}

bool PortAllocator::allocate_specific(uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if port is in valid range
    if (!is_in_range(port)) {
        return false;
    }

    // Check if port is already allocated
    if (allocated_ports_.find(port) != allocated_ports_.end()) {
        return false;
    }

    // Allocate the port
    allocated_ports_.insert(port);
    return true;
}

// ============================================================================
// Port Release
// ============================================================================

bool PortAllocator::release(uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if port is allocated
    auto it = allocated_ports_.find(port);
    if (it == allocated_ports_.end()) {
        return false;
    }

    // Release the port
    allocated_ports_.erase(it);
    return true;
}

// ============================================================================
// Query Functions
// ============================================================================

bool PortAllocator::is_allocated(uint16_t port) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return allocated_ports_.find(port) != allocated_ports_.end();
}

size_t PortAllocator::get_allocated_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return allocated_ports_.size();
}

size_t PortAllocator::get_available_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return get_total_count() - allocated_ports_.size();
}

size_t PortAllocator::get_total_count() const {
    return static_cast<size_t>(end_port_ - start_port_ + 1);
}

bool PortAllocator::has_available_ports() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return allocated_ports_.size() < get_total_count();
}

// ============================================================================
// Management Functions
// ============================================================================

void PortAllocator::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    allocated_ports_.clear();
    next_port_ = start_port_;
}

// ============================================================================
// Private Helper Functions
// ============================================================================

bool PortAllocator::is_in_range(uint16_t port) const {
    return port >= start_port_ && port <= end_port_;
}

} // namespace nlitp
