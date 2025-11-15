/**
 * @file utilities.hpp
 * @brief Common utility functions for NLITP
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 * Utility functions used throughout NLITP:
 * - Logging and error reporting
 * - Time and date formatting
 * - String manipulation
 * - File I/O helpers
 * - Network helpers
 */

#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <optional>

namespace nlitp {
namespace utilities {

/**
 * @brief Log levels for NLITP logging
 */
enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR,
    CRITICAL
};

/**
 * @brief Initialize logging system
 * @param log_file Path to log file (empty for stdout only)
 * @param level Minimum log level to output
 */
void initialize_logging(const std::string& log_file = "", LogLevel level = LogLevel::INFO);

/**
 * @brief Log a message with specified level
 * @param level Log level
 * @param message Message to log
 */
void log(LogLevel level, const std::string& message);

/**
 * @brief Log debug message
 * @param message Message to log
 */
void log_debug(const std::string& message);

/**
 * @brief Log info message
 * @param message Message to log
 */
void log_info(const std::string& message);

/**
 * @brief Log warning message
 * @param message Message to log
 */
void log_warn(const std::string& message);

/**
 * @brief Log error message
 * @param message Message to log
 */
void log_error(const std::string& message);

/**
 * @brief Log critical message
 * @param message Message to log
 */
void log_critical(const std::string& message);

/**
 * @brief Format timestamp as ISO 8601 string
 * @param timestamp Unix timestamp (seconds since epoch)
 * @return Formatted string (e.g., "2025-11-10T15:30:45Z")
 */
std::string format_timestamp(uint64_t timestamp);

/**
 * @brief Format timestamp for current time
 * @return Formatted string for current time
 */
std::string format_current_time();

/**
 * @brief Format file size in human-readable format
 * @param size Size in bytes
 * @return Formatted string (e.g., "1.5 MB", "3.2 GB")
 */
std::string format_file_size(uint64_t size);

/**
 * @brief Format duration in human-readable format
 * @param seconds Duration in seconds
 * @return Formatted string (e.g., "2h 15m 30s")
 */
std::string format_duration(uint64_t seconds);

/**
 * @brief Read entire file into string
 * @param file_path Path to file
 * @return File contents or std::nullopt if error
 */
std::optional<std::string> read_file(const std::string& file_path);

/**
 * @brief Read entire file into byte vector
 * @param file_path Path to file
 * @return File contents or std::nullopt if error
 */
std::optional<std::vector<uint8_t>> read_file_binary(const std::string& file_path);

/**
 * @brief Write string to file
 * @param file_path Path to file
 * @param content Content to write
 * @return true if successful, false otherwise
 */
bool write_file(const std::string& file_path, const std::string& content);

/**
 * @brief Write byte vector to file
 * @param file_path Path to file
 * @param content Content to write
 * @return true if successful, false otherwise
 */
bool write_file_binary(const std::string& file_path, const std::vector<uint8_t>& content);

/**
 * @brief Calculate SHA-256 hash of file
 * @param file_path Path to file
 * @return SHA-256 hash as hex string, or std::nullopt if error
 */
std::optional<std::string> calculate_file_hash(const std::string& file_path);

/**
 * @brief Split string by delimiter
 * @param str String to split
 * @param delimiter Delimiter character
 * @return Vector of split strings
 */
std::vector<std::string> split_string(const std::string& str, char delimiter);

/**
 * @brief Trim whitespace from string
 * @param str String to trim
 * @return Trimmed string
 */
std::string trim_string(const std::string& str);

/**
 * @brief Convert string to lowercase
 * @param str String to convert
 * @return Lowercase string
 */
std::string to_lowercase(const std::string& str);

/**
 * @brief Convert string to uppercase
 * @param str String to convert
 * @return Uppercase string
 */
std::string to_uppercase(const std::string& str);

/**
 * @brief Check if string starts with prefix
 * @param str String to check
 * @param prefix Prefix to check for
 * @return true if starts with prefix, false otherwise
 */
bool starts_with(const std::string& str, const std::string& prefix);

/**
 * @brief Check if string ends with suffix
 * @param str String to check
 * @param suffix Suffix to check for
 * @return true if ends with suffix, false otherwise
 */
bool ends_with(const std::string& str, const std::string& suffix);

/**
 * @brief Get environment variable value
 * @param name Environment variable name
 * @param default_value Default value if not set
 * @return Environment variable value or default
 */
std::string get_env(const std::string& name, const std::string& default_value = "");

/**
 * @brief Get hostname of current machine
 * @return Hostname or "unknown" if unable to determine
 */
std::string get_hostname();

/**
 * @brief Get IP addresses of current machine
 * @return Vector of IP address strings
 */
std::vector<std::string> get_local_ip_addresses();

/**
 * @brief Sleep for specified milliseconds
 * @param milliseconds Duration to sleep
 */
void sleep_ms(uint64_t milliseconds);

/**
 * @brief Generate random alphanumeric string
 * @param length Length of string to generate
 * @return Random string
 */
std::string generate_random_string(size_t length);

/**
 * @brief Generate UUID v4 string
 * @return UUID string (e.g., "550e8400-e29b-41d4-a716-446655440000")
 */
std::string generate_uuid();

} // namespace utilities
} // namespace nlitp
