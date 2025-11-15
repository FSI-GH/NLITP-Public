/**
 * @file test_port_allocator.cpp
 * @brief Comprehensive unit tests for PortAllocator
 *
 * Tests port allocation including:
 * - Port allocation and release
 * - Range management
 * - Port exhaustion handling
 * - Thread safety
 * - Edge cases
 */

#include <gtest/gtest.h>
#include "nlitp/port_allocator.hpp"
#include <thread>
#include <vector>
#include <set>

using namespace nlitp;

// Test fixture for port allocator tests
class PortAllocatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        allocator_ = std::make_unique<PortAllocator>();
    }

    void TearDown() override {
        allocator_.reset();
    }

    std::unique_ptr<PortAllocator> allocator_;
};

// ============================================================================
// Basic Allocation Tests
// ============================================================================

TEST_F(PortAllocatorTest, AllocatePort) {
    auto port = allocator_->allocate();
    ASSERT_TRUE(port.has_value());
    EXPECT_GE(*port, 11000);
    EXPECT_LE(*port, 61000);
}

TEST_F(PortAllocatorTest, AllocateMultiplePorts) {
    auto port1 = allocator_->allocate();
    auto port2 = allocator_->allocate();
    auto port3 = allocator_->allocate();

    ASSERT_TRUE(port1.has_value());
    ASSERT_TRUE(port2.has_value());
    ASSERT_TRUE(port3.has_value());

    // All ports should be different
    EXPECT_NE(*port1, *port2);
    EXPECT_NE(*port2, *port3);
    EXPECT_NE(*port1, *port3);
}

TEST_F(PortAllocatorTest, AllocateSpecificPort) {
    uint16_t desired_port = 12000;

    bool allocated = allocator_->allocate_specific(desired_port);
    EXPECT_TRUE(allocated);

    // Should be marked as allocated
    EXPECT_TRUE(allocator_->is_allocated(desired_port));
}

TEST_F(PortAllocatorTest, AllocateSpecificPortTwice) {
    uint16_t desired_port = 12000;

    EXPECT_TRUE(allocator_->allocate_specific(desired_port));
    EXPECT_FALSE(allocator_->allocate_specific(desired_port));  // Already allocated
}

TEST_F(PortAllocatorTest, AllocateSpecificOutOfRange) {
    EXPECT_FALSE(allocator_->allocate_specific(10000));  // Below range
    EXPECT_FALSE(allocator_->allocate_specific(65000));  // Above range
}

// ============================================================================
// Release Tests
// ============================================================================

TEST_F(PortAllocatorTest, ReleasePort) {
    auto port = allocator_->allocate();
    ASSERT_TRUE(port.has_value());

    bool released = allocator_->release(*port);
    EXPECT_TRUE(released);

    // Should not be allocated anymore
    EXPECT_FALSE(allocator_->is_allocated(*port));
}

TEST_F(PortAllocatorTest, ReleaseAndReallocate) {
    auto port = allocator_->allocate();
    ASSERT_TRUE(port.has_value());
    uint16_t port_num = *port;

    allocator_->release(port_num);

    // Should be able to allocate the same port again
    bool reallocated = allocator_->allocate_specific(port_num);
    EXPECT_TRUE(reallocated);
}

TEST_F(PortAllocatorTest, ReleaseUnallocatedPort) {
    bool released = allocator_->release(12000);
    EXPECT_FALSE(released);  // Not allocated
}

TEST_F(PortAllocatorTest, ReleasePortTwice) {
    auto port = allocator_->allocate();
    ASSERT_TRUE(port.has_value());

    EXPECT_TRUE(allocator_->release(*port));
    EXPECT_FALSE(allocator_->release(*port));  // Already released
}

// ============================================================================
// Query Tests
// ============================================================================

TEST_F(PortAllocatorTest, IsAllocatedUnallocatedPort) {
    EXPECT_FALSE(allocator_->is_allocated(12000));
}

TEST_F(PortAllocatorTest, IsAllocatedAfterAllocation) {
    auto port = allocator_->allocate();
    ASSERT_TRUE(port.has_value());

    EXPECT_TRUE(allocator_->is_allocated(*port));
}

TEST_F(PortAllocatorTest, IsAllocatedAfterRelease) {
    auto port = allocator_->allocate();
    ASSERT_TRUE(port.has_value());

    allocator_->release(*port);

    EXPECT_FALSE(allocator_->is_allocated(*port));
}

TEST_F(PortAllocatorTest, GetAllocatedCountEmpty) {
    EXPECT_EQ(allocator_->get_allocated_count(), 0);
}

TEST_F(PortAllocatorTest, GetAllocatedCountGrows) {
    allocator_->allocate();
    EXPECT_EQ(allocator_->get_allocated_count(), 1);

    allocator_->allocate();
    EXPECT_EQ(allocator_->get_allocated_count(), 2);

    allocator_->allocate();
    EXPECT_EQ(allocator_->get_allocated_count(), 3);
}

TEST_F(PortAllocatorTest, GetAllocatedCountAfterRelease) {
    auto port1 = allocator_->allocate();
    auto port2 = allocator_->allocate();

    EXPECT_EQ(allocator_->get_allocated_count(), 2);

    allocator_->release(*port1);

    EXPECT_EQ(allocator_->get_allocated_count(), 1);
}

TEST_F(PortAllocatorTest, GetAvailableCount) {
    size_t initial_available = allocator_->get_available_count();
    EXPECT_GT(initial_available, 0);

    allocator_->allocate();

    size_t after_alloc = allocator_->get_available_count();
    EXPECT_EQ(after_alloc, initial_available - 1);
}

TEST_F(PortAllocatorTest, GetTotalCount) {
    size_t total = allocator_->get_total_count();
    EXPECT_EQ(total, 50001);  // 11000 to 61000 inclusive

    size_t allocated = allocator_->get_allocated_count();
    size_t available = allocator_->get_available_count();

    EXPECT_EQ(allocated + available, total);
}

TEST_F(PortAllocatorTest, HasAvailablePorts) {
    EXPECT_TRUE(allocator_->has_available_ports());
}

// ============================================================================
// Range Configuration Tests
// ============================================================================

TEST_F(PortAllocatorTest, CustomPortRange) {
    auto custom_allocator = std::make_unique<PortAllocator>(20000, 20100);

    auto port = custom_allocator->allocate();
    ASSERT_TRUE(port.has_value());
    EXPECT_GE(*port, 20000);
    EXPECT_LE(*port, 20100);
}

TEST_F(PortAllocatorTest, CustomRangeTotalCount) {
    auto custom_allocator = std::make_unique<PortAllocator>(20000, 20100);

    EXPECT_EQ(custom_allocator->get_total_count(), 101);  // 20000 to 20100 inclusive
}

TEST_F(PortAllocatorTest, SmallPortRange) {
    auto small_allocator = std::make_unique<PortAllocator>(30000, 30005);

    EXPECT_EQ(small_allocator->get_total_count(), 6);

    // Allocate all ports
    for (int i = 0; i < 6; i++) {
        EXPECT_TRUE(small_allocator->allocate().has_value());
    }

    // Should be exhausted
    EXPECT_FALSE(small_allocator->allocate().has_value());
}

TEST_F(PortAllocatorTest, SinglePortRange) {
    auto single_allocator = std::make_unique<PortAllocator>(40000, 40000);

    EXPECT_EQ(single_allocator->get_total_count(), 1);

    auto port = single_allocator->allocate();
    ASSERT_TRUE(port.has_value());
    EXPECT_EQ(*port, 40000);

    // Second allocation should fail
    EXPECT_FALSE(single_allocator->allocate().has_value());
}

// ============================================================================
// Exhaustion Tests
// ============================================================================

TEST_F(PortAllocatorTest, ExhaustSmallRange) {
    auto small_allocator = std::make_unique<PortAllocator>(50000, 50010);

    std::vector<uint16_t> allocated_ports;

    // Allocate all available ports
    while (auto port = small_allocator->allocate()) {
        allocated_ports.push_back(*port);
    }

    EXPECT_EQ(allocated_ports.size(), 11);  // 50000 to 50010 inclusive
    EXPECT_FALSE(small_allocator->has_available_ports());

    // Release one port
    small_allocator->release(allocated_ports[0]);

    // Should be able to allocate again
    EXPECT_TRUE(small_allocator->allocate().has_value());
}

TEST_F(PortAllocatorTest, AllocateWhenExhausted) {
    auto tiny_allocator = std::make_unique<PortAllocator>(60000, 60001);

    // Allocate both ports
    auto port1 = tiny_allocator->allocate();
    auto port2 = tiny_allocator->allocate();

    ASSERT_TRUE(port1.has_value());
    ASSERT_TRUE(port2.has_value());

    // Third allocation should fail
    auto port3 = tiny_allocator->allocate();
    EXPECT_FALSE(port3.has_value());
}

// ============================================================================
// Reset Tests
// ============================================================================

TEST_F(PortAllocatorTest, Reset) {
    // Allocate some ports
    allocator_->allocate();
    allocator_->allocate();
    allocator_->allocate();

    EXPECT_GT(allocator_->get_allocated_count(), 0);

    allocator_->reset();

    EXPECT_EQ(allocator_->get_allocated_count(), 0);
    EXPECT_EQ(allocator_->get_available_count(), allocator_->get_total_count());
}

TEST_F(PortAllocatorTest, ResetAndReallocate) {
    auto port1 = allocator_->allocate();
    ASSERT_TRUE(port1.has_value());

    allocator_->reset();

    // Should be able to allocate again (might be same port)
    auto port2 = allocator_->allocate();
    ASSERT_TRUE(port2.has_value());
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(PortAllocatorTest, ConcurrentAllocation) {
    const int num_threads = 10;
    const int allocations_per_thread = 100;
    std::vector<std::thread> threads;
    std::vector<std::vector<uint16_t>> allocated_ports(num_threads);

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, &allocated_ports, t, allocations_per_thread]() {
            for (int i = 0; i < allocations_per_thread; i++) {
                auto port = allocator_->allocate();
                if (port.has_value()) {
                    allocated_ports[t].push_back(*port);
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Collect all allocated ports
    std::set<uint16_t> all_ports;
    for (const auto& ports : allocated_ports) {
        all_ports.insert(ports.begin(), ports.end());
    }

    // All ports should be unique
    size_t total_allocated = 0;
    for (const auto& ports : allocated_ports) {
        total_allocated += ports.size();
    }

    EXPECT_EQ(all_ports.size(), total_allocated);
}

TEST_F(PortAllocatorTest, ConcurrentAllocationSpecific) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<bool> results(num_threads);

    uint16_t base_port = 12000;

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, &results, t, base_port]() {
            // Each thread tries to allocate a unique port
            results[t] = allocator_->allocate_specific(base_port + t);
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All allocations should succeed (different ports)
    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}

TEST_F(PortAllocatorTest, ConcurrentAllocationSamePort) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<bool> results(num_threads);

    uint16_t contested_port = 13000;

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, &results, t, contested_port]() {
            // All threads try to allocate same port
            results[t] = allocator_->allocate_specific(contested_port);
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Only one thread should succeed
    int success_count = 0;
    for (bool result : results) {
        if (result) success_count++;
    }

    EXPECT_EQ(success_count, 1);
}

TEST_F(PortAllocatorTest, ConcurrentAllocateAndRelease) {
    const int num_threads = 10;
    std::vector<std::thread> threads;

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this]() {
            for (int i = 0; i < 50; i++) {
                auto port = allocator_->allocate();
                if (port.has_value()) {
                    // Immediately release
                    allocator_->release(*port);
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All ports should be released
    EXPECT_EQ(allocator_->get_allocated_count(), 0);
}

TEST_F(PortAllocatorTest, ConcurrentQuery) {
    // Pre-allocate some ports
    std::vector<uint16_t> ports;
    for (int i = 0; i < 10; i++) {
        auto port = allocator_->allocate();
        if (port.has_value()) {
            ports.push_back(*port);
        }
    }

    const int num_threads = 10;
    std::vector<std::thread> threads;

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([this, &ports]() {
            for (int i = 0; i < 100; i++) {
                allocator_->get_allocated_count();
                allocator_->get_available_count();
                allocator_->has_available_ports();
                for (uint16_t port : ports) {
                    allocator_->is_allocated(port);
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Should not crash
    EXPECT_EQ(allocator_->get_allocated_count(), ports.size());
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F(PortAllocatorTest, AllocatePort0) {
    EXPECT_FALSE(allocator_->allocate_specific(0));
}

TEST_F(PortAllocatorTest, AllocatePort1) {
    EXPECT_FALSE(allocator_->allocate_specific(1));
}

TEST_F(PortAllocatorTest, AllocateMaxPort) {
    EXPECT_FALSE(allocator_->allocate_specific(65535));
}

TEST_F(PortAllocatorTest, ReleasePort0) {
    EXPECT_FALSE(allocator_->release(0));
}

TEST_F(PortAllocatorTest, IsAllocatedOutOfRange) {
    EXPECT_FALSE(allocator_->is_allocated(1000));
    EXPECT_FALSE(allocator_->is_allocated(65000));
}

TEST_F(PortAllocatorTest, MultipleResets) {
    allocator_->allocate();
    allocator_->reset();
    allocator_->reset();
    allocator_->reset();

    EXPECT_EQ(allocator_->get_allocated_count(), 0);
}

TEST_F(PortAllocatorTest, AllocateAllInSmallRange) {
    auto small_allocator = std::make_unique<PortAllocator>(55000, 55005);

    std::set<uint16_t> allocated;
    while (auto port = small_allocator->allocate()) {
        allocated.insert(*port);
    }

    EXPECT_EQ(allocated.size(), 6);

    // Verify all ports in range were allocated
    for (uint16_t port = 55000; port <= 55005; port++) {
        EXPECT_TRUE(allocated.count(port) > 0);
    }
}

TEST_F(PortAllocatorTest, RoundRobinAllocation) {
    auto small_allocator = std::make_unique<PortAllocator>(56000, 56009);

    std::vector<uint16_t> first_round;
    for (int i = 0; i < 10; i++) {
        auto port = small_allocator->allocate();
        ASSERT_TRUE(port.has_value());
        first_round.push_back(*port);
    }

    // Release all
    for (uint16_t port : first_round) {
        small_allocator->release(port);
    }

    // Allocate again - might follow round-robin pattern
    std::vector<uint16_t> second_round;
    for (int i = 0; i < 10; i++) {
        auto port = small_allocator->allocate();
        ASSERT_TRUE(port.has_value());
        second_round.push_back(*port);
    }

    // All ports should be valid
    for (uint16_t port : second_round) {
        EXPECT_GE(port, 56000);
        EXPECT_LE(port, 56009);
    }
}

TEST_F(PortAllocatorTest, InvalidRangeStartGreaterThanEnd) {
    // Constructor should handle invalid range
    // This might throw or set a default range - implementation dependent
    // Test that it doesn't crash
    try {
        auto invalid_allocator = std::make_unique<PortAllocator>(60000, 50000);
        // If it doesn't throw, it should at least be usable
        EXPECT_GE(invalid_allocator->get_total_count(), 0);
    } catch (...) {
        // Exception is acceptable for invalid input
        SUCCEED();
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
