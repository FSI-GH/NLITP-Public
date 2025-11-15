# NLITPv8 Test Suite
# Google Test Framework

cmake_minimum_required(VERSION 3.20)

# Fetch Google Test
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Enable testing
enable_testing()
include(GoogleTest)

# Test executables
set(TEST_TARGETS
    test_agent_crypto
    test_security_config
    test_replay_protection
    test_rate_limiter
    test_agent_identity
    test_port_allocator
    test_trust_ledger
    test_message_types
)

# Create test executables
add_executable(test_agent_crypto test_agent_crypto.cpp)
add_executable(test_security_config test_security_config.cpp)
add_executable(test_replay_protection test_replay_protection.cpp)
add_executable(test_rate_limiter test_rate_limiter.cpp)
add_executable(test_agent_identity test_agent_identity.cpp)
add_executable(test_port_allocator test_port_allocator.cpp)
add_executable(test_trust_ledger test_trust_ledger.cpp)
add_executable(test_message_types test_message_types.cpp)

# Link all tests against nlitp8 library and Google Test
foreach(TEST_TARGET ${TEST_TARGETS})
    target_link_libraries(${TEST_TARGET}
        PRIVATE
            nlitp8
            GTest::gtest
            GTest::gtest_main
            Threads::Threads
    )

    # Discover tests for CTest integration
    gtest_discover_tests(${TEST_TARGET}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        PROPERTIES
            LABELS "unit"
    )
endforeach()

# Add custom target to run all tests
add_custom_target(run_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --verbose
    DEPENDS ${TEST_TARGETS}
    COMMENT "Running all NLITP unit tests..."
)

# Add custom target for coverage (if gcov/lcov available)
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT MSVC)
    add_custom_target(coverage
        COMMAND lcov --directory . --zerocounters
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        COMMAND lcov --directory . --capture --output-file coverage.info
        COMMAND lcov --remove coverage.info '/usr/*' '*/test/*' '*/external/*' --output-file coverage.info.cleaned
        COMMAND genhtml coverage.info.cleaned --output-directory coverage_report
        DEPENDS ${TEST_TARGETS}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Generating code coverage report..."
    )
endif()

# Print test configuration
message(STATUS "")
message(STATUS "Test Configuration:")
message(STATUS "  Google Test:       ${googletest_VERSION}")
message(STATUS "  Test Targets:      ${TEST_TARGETS}")
message(STATUS "  Coverage:          ${CMAKE_BUILD_TYPE} == Debug")
message(STATUS "")
