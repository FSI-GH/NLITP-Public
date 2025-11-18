# NLITPv8 - C++ Implementation
# Cross-Platform: macOS 15+, Linux (Ubuntu 22+), Windows 10+/Server 2016+

cmake_minimum_required(VERSION 3.20)
project(NLITPv8 VERSION 8.0.0 LANGUAGES CXX)

# C++20 standard required for modern features
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler warnings (strict)
if(MSVC)
    add_compile_options(/W4 /WX /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Security flags
if(NOT MSVC)
    add_compile_options(
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIE
    )
    if(NOT APPLE)
        # Linux-only linker flags
        add_link_options(
            -Wl,-z,relro
            -Wl,-z,now
            -pie
        )
    else()
        # macOS linker flags
        add_link_options(-Wl,-pie)
    endif()
endif()

# Platform detection
if(APPLE)
    set(NLITP_PLATFORM "macOS")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "15.0")
elseif(UNIX)
    set(NLITP_PLATFORM "Linux")
elseif(WIN32)
    set(NLITP_PLATFORM "Windows")
    add_definitions(-DNOMINMAX -DWIN32_LEAN_AND_MEAN)
endif()

message(STATUS "Building NLITPv8 for ${NLITP_PLATFORM}")

# Dependencies
find_package(Threads REQUIRED)

# libsodium for cryptography (Ed25519, X25519, ChaCha20-Poly1305)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.18)

# SQLite3 for database
find_package(SQLite3 REQUIRED)

# Optional: OpenSSL for additional crypto (backup)
find_package(OpenSSL)

# asio for async networking (header-only)
find_path(ASIO_INCLUDE_DIR asio.hpp)
if(NOT ASIO_INCLUDE_DIR)
    message(STATUS "Downloading asio...")
    include(FetchContent)
    FetchContent_Declare(
        asio
        URL https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-28-0.tar.gz
    )
    FetchContent_MakeAvailable(asio)
    set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include)
endif()

# nlohmann/json for JSON parsing
find_package(nlohmann_json 3.11.0)
if(NOT nlohmann_json_FOUND)
    message(STATUS "Downloading nlohmann/json...")
    include(FetchContent)
    FetchContent_Declare(
        json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    )
    FetchContent_MakeAvailable(json)
endif()

# spdlog for logging
find_package(spdlog)
if(NOT spdlog_FOUND)
    message(STATUS "Downloading spdlog...")
    include(FetchContent)
    FetchContent_Declare(
        spdlog
        URL https://github.com/gabime/spdlog/archive/refs/tags/v1.12.0.tar.gz
    )
    FetchContent_MakeAvailable(spdlog)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
    ${SQLite3_INCLUDE_DIRS}
    ${ASIO_INCLUDE_DIR}
)

# Link directories (critical for pkg-config found libraries on macOS)
link_directories(${SODIUM_LIBRARY_DIRS})

# Library source files
set(NLITP_SOURCES
    src/security_config.cpp
    src/agent_crypto.cpp
    src/agent_identity.cpp
    src/port_allocator.cpp
    src/trust_ledger.cpp
    src/message_types.cpp
    src/replay_protection.cpp
    src/rate_limiter.cpp
    src/agent_discovery.cpp
    src/decentralized_messenger.cpp
    src/agent_node.cpp
    src/utilities.cpp
)

# Main library
add_library(nlitp8 STATIC ${NLITP_SOURCES})

target_link_libraries(nlitp8
    PUBLIC
        Threads::Threads
        ${SODIUM_LIBRARIES}
        SQLite::SQLite3
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        OpenSSL::Crypto
)

target_compile_definitions(nlitp8
    PUBLIC
        ASIO_STANDALONE
        ASIO_NO_DEPRECATED
    PRIVATE
        NLITP_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        NLITP_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        NLITP_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)

# Examples
add_executable(nlitp_agent_example examples/agent_example.cpp)
target_link_libraries(nlitp_agent_example nlitp8)

add_executable(nlitp_mesh_demo examples/mesh_demo.cpp)
target_link_libraries(nlitp_mesh_demo nlitp8)

# Tests
enable_testing()
add_subdirectory(tests)

# Installation
install(TARGETS nlitp8
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/nlitp
    DESTINATION include
    FILES_MATCHING PATTERN "*.hpp"
)

# Package config
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/NLITPv8ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/NLITPv8ConfigVersion.cmake"
    DESTINATION lib/cmake/NLITPv8
)

# Print configuration
message(STATUS "")
message(STATUS "NLITPv8 Configuration:")
message(STATUS "  Platform:          ${NLITP_PLATFORM}")
message(STATUS "  C++ Standard:      ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type:        ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install Prefix:    ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  libsodium:         ${SODIUM_VERSION}")
message(STATUS "  SQLite3:           ${SQLite3_VERSION}")
message(STATUS "")
