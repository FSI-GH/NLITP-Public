/**
 * @file utilities.cpp
 * @brief Implementation of common utility functions for NLITP
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 */

#include "nlitp/utilities.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <thread>
#include <random>
#include <cstring>

// Platform-specific includes for networking
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <ifaddrs.h>
#endif

// OpenSSL for SHA-256
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace nlitp {
namespace utilities {

namespace {
    // Global logger instance
    std::shared_ptr<spdlog::logger> g_logger;

    // Convert LogLevel to spdlog level
    spdlog::level::level_enum to_spdlog_level(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG:    return spdlog::level::debug;
            case LogLevel::INFO:     return spdlog::level::info;
            case LogLevel::WARN:     return spdlog::level::warn;
            case LogLevel::ERROR:    return spdlog::level::err;
            case LogLevel::CRITICAL: return spdlog::level::critical;
            default:                 return spdlog::level::info;
        }
    }
}

// ============================================================================
// LOGGING FUNCTIONS
// ============================================================================

void initialize_logging(const std::string& log_file, LogLevel level) {
    try {
        std::vector<spdlog::sink_ptr> sinks;

        // Console sink (colored)
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(to_spdlog_level(level));
        sinks.push_back(console_sink);

        // File sink (rotating, 10MB per file, 3 files max)
        if (!log_file.empty()) {
            auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                log_file, 1024 * 1024 * 10, 3);
            file_sink->set_level(to_spdlog_level(level));
            sinks.push_back(file_sink);
        }

        // Create logger
        g_logger = std::make_shared<spdlog::logger>("nlitp", sinks.begin(), sinks.end());
        g_logger->set_level(to_spdlog_level(level));
        g_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");

        // Register as default logger
        spdlog::set_default_logger(g_logger);

    } catch (const spdlog::spdlog_ex& ex) {
        fprintf(stderr, "Log initialization failed: %s\n", ex.what());
    }
}

void log(LogLevel level, const std::string& message) {
    if (!g_logger) {
        initialize_logging();
    }

    switch (level) {
        case LogLevel::DEBUG:    g_logger->debug(message); break;
        case LogLevel::INFO:     g_logger->info(message); break;
        case LogLevel::WARN:     g_logger->warn(message); break;
        case LogLevel::ERROR:    g_logger->error(message); break;
        case LogLevel::CRITICAL: g_logger->critical(message); break;
    }
}

void log_debug(const std::string& message) {
    log(LogLevel::DEBUG, message);
}

void log_info(const std::string& message) {
    log(LogLevel::INFO, message);
}

void log_warn(const std::string& message) {
    log(LogLevel::WARN, message);
}

void log_error(const std::string& message) {
    log(LogLevel::ERROR, message);
}

void log_critical(const std::string& message) {
    log(LogLevel::CRITICAL, message);
}

// ============================================================================
// TIME/DATE FORMATTING FUNCTIONS
// ============================================================================

std::string format_timestamp(uint64_t timestamp) {
    std::time_t time = static_cast<std::time_t>(timestamp);
    std::tm tm_buf;

#ifdef _WIN32
    gmtime_s(&tm_buf, &time);
#else
    gmtime_r(&time, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string format_current_time() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::system_clock::to_time_t(now);
    return format_timestamp(static_cast<uint64_t>(timestamp));
}

std::string format_file_size(uint64_t size) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double size_d = static_cast<double>(size);

    while (size_d >= 1024.0 && unit_index < 4) {
        size_d /= 1024.0;
        unit_index++;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size_d << " " << units[unit_index];
    return oss.str();
}

std::string format_duration(uint64_t seconds) {
    uint64_t hours = seconds / 3600;
    uint64_t minutes = (seconds % 3600) / 60;
    uint64_t secs = seconds % 60;

    std::ostringstream oss;
    bool has_output = false;

    if (hours > 0) {
        oss << hours << "h";
        has_output = true;
    }
    if (minutes > 0 || (has_output && secs > 0)) {
        if (has_output) oss << " ";
        oss << minutes << "m";
        has_output = true;
    }
    if (secs > 0 || !has_output) {
        if (has_output) oss << " ";
        oss << secs << "s";
    }

    return oss.str();
}

// ============================================================================
// FILE I/O FUNCTIONS
// ============================================================================

std::optional<std::string> read_file(const std::string& file_path) {
    try {
        std::ifstream file(file_path, std::ios::in);
        if (!file.is_open()) {
            log_error("Failed to open file for reading: " + file_path);
            return std::nullopt;
        }

        std::ostringstream content;
        content << file.rdbuf();
        return content.str();

    } catch (const std::exception& ex) {
        log_error("Exception reading file " + file_path + ": " + ex.what());
        return std::nullopt;
    }
}

std::optional<std::vector<uint8_t>> read_file_binary(const std::string& file_path) {
    try {
        std::ifstream file(file_path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            log_error("Failed to open file for binary reading: " + file_path);
            return std::nullopt;
        }

        auto size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            log_error("Failed to read binary file: " + file_path);
            return std::nullopt;
        }

        return buffer;

    } catch (const std::exception& ex) {
        log_error("Exception reading binary file " + file_path + ": " + ex.what());
        return std::nullopt;
    }
}

bool write_file(const std::string& file_path, const std::string& content) {
    try {
        // Create parent directories if needed
        std::filesystem::path path(file_path);
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }

        std::ofstream file(file_path, std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            log_error("Failed to open file for writing: " + file_path);
            return false;
        }

        file << content;
        return file.good();

    } catch (const std::exception& ex) {
        log_error("Exception writing file " + file_path + ": " + ex.what());
        return false;
    }
}

bool write_file_binary(const std::string& file_path, const std::vector<uint8_t>& content) {
    try {
        // Create parent directories if needed
        std::filesystem::path path(file_path);
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }

        std::ofstream file(file_path, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            log_error("Failed to open file for binary writing: " + file_path);
            return false;
        }

        file.write(reinterpret_cast<const char*>(content.data()), content.size());
        return file.good();

    } catch (const std::exception& ex) {
        log_error("Exception writing binary file " + file_path + ": " + ex.what());
        return false;
    }
}

std::optional<std::string> calculate_file_hash(const std::string& file_path) {
    try {
        auto content = read_file_binary(file_path);
        if (!content) {
            return std::nullopt;
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(content->data(), content->size(), hash);

        std::ostringstream oss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(hash[i]);
        }

        return oss.str();

    } catch (const std::exception& ex) {
        log_error("Exception calculating file hash for " + file_path + ": " + ex.what());
        return std::nullopt;
    }
}

// ============================================================================
// STRING MANIPULATION FUNCTIONS
// ============================================================================

std::vector<std::string> split_string(const std::string& str, char delimiter) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;

    while (std::getline(ss, item, delimiter)) {
        result.push_back(item);
    }

    return result;
}

std::string trim_string(const std::string& str) {
    auto start = std::find_if_not(str.begin(), str.end(),
        [](unsigned char ch) { return std::isspace(ch); });

    auto end = std::find_if_not(str.rbegin(), str.rend(),
        [](unsigned char ch) { return std::isspace(ch); }).base();

    return (start < end) ? std::string(start, end) : std::string();
}

std::string to_lowercase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return result;
}

std::string to_uppercase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return std::toupper(c); });
    return result;
}

bool starts_with(const std::string& str, const std::string& prefix) {
    if (prefix.length() > str.length()) {
        return false;
    }
    return str.compare(0, prefix.length(), prefix) == 0;
}

bool ends_with(const std::string& str, const std::string& suffix) {
    if (suffix.length() > str.length()) {
        return false;
    }
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

// ============================================================================
// ENVIRONMENT/NETWORK FUNCTIONS
// ============================================================================

std::string get_env(const std::string& name, const std::string& default_value) {
    const char* value = std::getenv(name.c_str());
    return value ? std::string(value) : default_value;
}

std::string get_hostname() {
    char hostname[256];

#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
    int result = gethostname(hostname, sizeof(hostname));
    WSACleanup();
    if (result != 0) {
        return "unknown";
    }
#else
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        return "unknown";
    }
#endif

    return std::string(hostname);
}

std::vector<std::string> get_local_ip_addresses() {
    std::vector<std::string> addresses;

#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return addresses;
    }

    ULONG buffer_size = 15000;
    PIP_ADAPTER_ADDRESSES adapter_addresses = nullptr;

    do {
        adapter_addresses = (IP_ADAPTER_ADDRESSES*)malloc(buffer_size);
        if (!adapter_addresses) break;

        DWORD result = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, adapter_addresses, &buffer_size);

        if (result == ERROR_BUFFER_OVERFLOW) {
            free(adapter_addresses);
            adapter_addresses = nullptr;
        } else if (result == NO_ERROR) {
            break;
        } else {
            free(adapter_addresses);
            adapter_addresses = nullptr;
            break;
        }
    } while (true);

    if (adapter_addresses) {
        for (PIP_ADAPTER_ADDRESSES adapter = adapter_addresses; adapter; adapter = adapter->Next) {
            for (PIP_ADAPTER_UNICAST_ADDRESS address = adapter->FirstUnicastAddress;
                 address; address = address->Next) {
                char ip[INET6_ADDRSTRLEN];

                if (address->Address.lpSockaddr->sa_family == AF_INET) {
                    inet_ntop(AF_INET,
                        &((struct sockaddr_in*)address->Address.lpSockaddr)->sin_addr,
                        ip, sizeof(ip));
                    addresses.push_back(std::string(ip));
                } else if (address->Address.lpSockaddr->sa_family == AF_INET6) {
                    inet_ntop(AF_INET6,
                        &((struct sockaddr_in6*)address->Address.lpSockaddr)->sin6_addr,
                        ip, sizeof(ip));
                    addresses.push_back(std::string(ip));
                }
            }
        }
        free(adapter_addresses);
    }

    WSACleanup();

#else
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        return addresses;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;

        int family = ifa->ifa_addr->sa_family;

        if (family == AF_INET || family == AF_INET6) {
            char host[NI_MAXHOST];

            int result = getnameinfo(ifa->ifa_addr,
                (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);

            if (result == 0) {
                addresses.push_back(std::string(host));
            }
        }
    }

    freeifaddrs(ifaddr);
#endif

    return addresses;
}

// ============================================================================
// OTHER UTILITY FUNCTIONS
// ============================================================================

void sleep_ms(uint64_t milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

std::string generate_random_string(size_t length) {
    static const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    static std::random_device rd;
    static std::mt19937 generator(rd());
    static std::uniform_int_distribution<> distribution(0, sizeof(charset) - 2);

    std::string result;
    result.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        result += charset[distribution(generator)];
    }

    return result;
}

std::string generate_uuid() {
    static std::random_device rd;
    static std::mt19937 generator(rd());
    static std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);

    uint32_t data[4];
    for (int i = 0; i < 4; ++i) {
        data[i] = dist(generator);
    }

    // Set version (4) and variant bits according to RFC 4122
    data[1] = (data[1] & 0xFFFF0FFF) | 0x00004000; // Version 4
    data[2] = (data[2] & 0x3FFFFFFF) | 0x80000000; // Variant 10

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    oss << std::setw(8) << data[0] << "-";
    oss << std::setw(4) << (data[1] >> 16) << "-";
    oss << std::setw(4) << (data[1] & 0xFFFF) << "-";
    oss << std::setw(4) << (data[2] >> 16) << "-";
    oss << std::setw(4) << (data[2] & 0xFFFF);
    oss << std::setw(8) << data[3];

    return oss.str();
}

} // namespace utilities
} // namespace nlitp
