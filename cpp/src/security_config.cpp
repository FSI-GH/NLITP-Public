/**
 * @file security_config.cpp
 * @brief Implementation of security configuration and validation functions
 *
 * NLITPv8 - Next Level Intelligence Transport Protocol v8
 * Copyright © 2025 Fortified Solutions Inc.
 *
 */

#include "nlitp/security_config.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <regex>

namespace nlitp {
namespace security {

// ============================================================================
// ============================================================================

std::filesystem::path get_data_directory() {
    // Check for environment variable NLITP_DATA_DIR
    const char* env_data_dir = std::getenv("NLITP_DATA_DIR");

    if (env_data_dir != nullptr && std::strlen(env_data_dir) > 0) {
        // Use environment-specified directory
        std::filesystem::path data_dir(env_data_dir);

        // Create directory if it doesn't exist
        if (!std::filesystem::exists(data_dir)) {
            std::filesystem::create_directories(data_dir);
        }

        return data_dir;
    }

    // Default: /opt/fsi/var/nlitp
#ifdef _WIN32
    std::filesystem::path default_dir = "C:\\ProgramData\\FSI\\NLITP";
#else
    std::filesystem::path default_dir = "/opt/fsi/var/nlitp";
#endif

    // Create directory if it doesn't exist
    if (!std::filesystem::exists(default_dir)) {
        std::filesystem::create_directories(default_dir);
    }

    return default_dir;
}

std::filesystem::path get_received_directory() {
    std::filesystem::path received_dir = get_data_directory() / "received";

    // Create directory if it doesn't exist
    if (!std::filesystem::exists(received_dir)) {
        std::filesystem::create_directories(received_dir);
    }

    return received_dir;
}

std::filesystem::path get_database_directory() {
    std::filesystem::path db_dir = get_data_directory() / "db";

    // Create directory if it doesn't exist
    if (!std::filesystem::exists(db_dir)) {
        std::filesystem::create_directories(db_dir);
    }

    return db_dir;
}

std::filesystem::path get_log_directory() {
    std::filesystem::path log_dir = get_data_directory() / "logs";

    // Create directory if it doesn't exist
    if (!std::filesystem::exists(log_dir)) {
        std::filesystem::create_directories(log_dir);
    }

    return log_dir;
}

// ============================================================================
// ============================================================================

bool validate_identifier(const std::string& identifier, size_t max_length) {
    // Check length
    if (identifier.empty() || identifier.length() > max_length) {
        return false;
    }

    // Validate characters: alphanumeric + underscore + hyphen only
    // This prevents shell injection and other attacks
    for (char c : identifier) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
            return false;
        }
    }

    return true;
}

bool validate_user_input(const std::string& input, size_t max_length) {
    // Check length
    if (input.empty() || input.length() > max_length) {
        return false;
    }

    // Validate characters: alphanumeric + safe punctuation only
    // Disallow shell metacharacters: ; & | ` $ ( ) { } [ ] < > \ " '
    const std::string dangerous_chars = ";|&`$(){}[]<>\\\"'";

    for (char c : input) {
        // Allow alphanumeric
        if (std::isalnum(static_cast<unsigned char>(c))) {
            continue;
        }

        // Allow safe punctuation and whitespace
        if (c == ' ' || c == '.' || c == ',' || c == ':' || c == '-' || c == '_' || c == '/') {
            continue;
        }

        // Check if dangerous character
        if (dangerous_chars.find(c) != std::string::npos) {
            return false;
        }

        // Disallow control characters
        if (std::iscntrl(static_cast<unsigned char>(c))) {
            return false;
        }
    }

    return true;
}

std::string sanitize_filename(const std::string& filename, const std::string& extension) {
    // Start with original filename
    std::string sanitized = filename;

    // Remove any directory separators (path traversal prevention)
    sanitized.erase(
        std::remove_if(sanitized.begin(), sanitized.end(),
            [](char c) { return c == '/' || c == '\\'; }),
        sanitized.end()
    );

    // Remove any null bytes
    sanitized.erase(
        std::remove(sanitized.begin(), sanitized.end(), '\0'),
        sanitized.end()
    );

    // Remove leading/trailing whitespace
    auto start = sanitized.find_first_not_of(" \t\r\n");
    auto end = sanitized.find_last_not_of(" \t\r\n");

    if (start == std::string::npos) {
        // String is all whitespace
        sanitized = "untitled";
    } else {
        sanitized = sanitized.substr(start, end - start + 1);
    }

    // Replace dangerous characters with underscores
    const std::string dangerous_chars = "<>:\"|?*;";
    for (char& c : sanitized) {
        if (dangerous_chars.find(c) != std::string::npos) {
            c = '_';
        }
    }

    // Ensure filename is not empty after sanitization
    if (sanitized.empty()) {
        sanitized = "untitled";
    }

    // Truncate to maximum filename length (leave room for extension)
    if (sanitized.length() > MAX_FILENAME_LENGTH - extension.length()) {
        sanitized = sanitized.substr(0, MAX_FILENAME_LENGTH - extension.length());
    }

    // Add extension if not already present
    if (!extension.empty()) {
        // Convert to lowercase for comparison
        std::string lower_sanitized = sanitized;
        std::string lower_extension = extension;

        std::transform(lower_sanitized.begin(), lower_sanitized.end(),
                      lower_sanitized.begin(), ::tolower);
        std::transform(lower_extension.begin(), lower_extension.end(),
                      lower_extension.begin(), ::tolower);

        // Check if extension already present
        if (lower_sanitized.length() < lower_extension.length() ||
            lower_sanitized.substr(lower_sanitized.length() - lower_extension.length()) != lower_extension) {
            // Extension not present, add it
            sanitized += extension;
        }
    }

    return sanitized;
}

bool is_safe_path(const std::filesystem::path& path, const std::filesystem::path& base_dir) {
    try {
        // Resolve to canonical paths (resolves .., symlinks, etc.)
        std::filesystem::path canonical_path = std::filesystem::weakly_canonical(path);
        std::filesystem::path canonical_base = std::filesystem::weakly_canonical(base_dir);

        // Convert to strings for comparison
        std::string path_str = canonical_path.string();
        std::string base_str = canonical_base.string();

        // Ensure base_str ends with separator for proper prefix matching
        if (!base_str.empty() && base_str.back() != std::filesystem::path::preferred_separator) {
            base_str += std::filesystem::path::preferred_separator;
        }

        // Check if path starts with base directory
        if (path_str.find(base_str) != 0) {
            return false;
        }

        // Additional check: count directory separators to detect traversal attempts
        // If canonical path is outside base, it failed the check
        auto relative = std::filesystem::relative(canonical_path, canonical_base);

        // Check if relative path starts with ".." (traversal detected)
        if (!relative.empty() && relative.string().find("..") == 0) {
            return false;
        }

        return true;

    } catch (const std::filesystem::filesystem_error&) {
        // If path resolution fails, consider it unsafe
        return false;
    }
}

} // namespace security
} // namespace nlitp
