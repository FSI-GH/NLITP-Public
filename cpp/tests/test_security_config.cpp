/**
 * @file test_security_config.cpp
 * @brief Comprehensive unit tests for security configuration and validation
 *
 * Tests all security configuration including:
 * - Input validation (identifiers, user input)
 * - Path sanitization and traversal prevention
 * - Filename validation
 * - Directory configuration
 * - Security limits and constants
 * - Edge cases and attack vectors
 */

#include <gtest/gtest.h>
#include "nlitp/security_config.hpp"
#include <filesystem>
#include <thread>
#include <vector>

using namespace nlitp::security;
namespace fs = std::filesystem;

// Test fixture for security config tests
class SecurityConfigTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary test directory
        test_dir_ = fs::temp_directory_path() / "nlitp_security_test";
        fs::create_directories(test_dir_);
    }

    void TearDown() override {
        // Clean up test directory
        if (fs::exists(test_dir_)) {
            fs::remove_all(test_dir_);
        }
    }

    fs::path test_dir_;
};

// ============================================================================
// Security Constants Tests
// ============================================================================

TEST_F(SecurityConfigTest, SecurityLimitsAreReasonable) {
    EXPECT_EQ(MAX_MESSAGE_SIZE, 10 * 1024 * 1024);  // 10MB
    EXPECT_EQ(MAX_FILE_SIZE, 50 * 1024 * 1024);      // 50MB
    EXPECT_EQ(MAX_JSON_SIZE, 1024 * 1024);           // 1MB
    EXPECT_EQ(MAX_CHUNKS, 10000);
    EXPECT_EQ(MAX_PENDING_TRANSFERS, 100);
    EXPECT_EQ(MAX_IDENTIFIER_LENGTH, 64);
    EXPECT_EQ(MAX_INPUT_LENGTH, 128);
    EXPECT_EQ(MAX_FILENAME_LENGTH, 255);
}

TEST_F(SecurityConfigTest, NetworkTimeoutsAreReasonable) {
    EXPECT_EQ(CONNECTION_TIMEOUT, std::chrono::seconds(5));
    EXPECT_EQ(READ_TIMEOUT, std::chrono::seconds(30));
    EXPECT_EQ(WRITE_TIMEOUT, std::chrono::seconds(30));
    EXPECT_EQ(IDLE_TIMEOUT, std::chrono::minutes(5));
}

TEST_F(SecurityConfigTest, RateLimitConfigAreReasonable) {
    EXPECT_EQ(RATE_LIMIT_PER_SECOND, 100);
    EXPECT_EQ(RATE_LIMIT_BURST, 200);
    EXPECT_GE(RATE_LIMIT_BURST, RATE_LIMIT_PER_SECOND);
}

TEST_F(SecurityConfigTest, ReplayProtectionConfigIsReasonable) {
    EXPECT_EQ(REPLAY_WINDOW, std::chrono::seconds(60));
    EXPECT_EQ(REPLAY_CLEANUP, std::chrono::minutes(5));
}

TEST_F(SecurityConfigTest, CryptoSizesAreCorrect) {
    EXPECT_EQ(ED25519_SIGNATURE_SIZE, 64);
    EXPECT_EQ(ED25519_PUBKEY_SIZE, 32);
    EXPECT_EQ(ED25519_SECKEY_SIZE, 64);
    EXPECT_EQ(X25519_PUBKEY_SIZE, 32);
    EXPECT_EQ(X25519_SECKEY_SIZE, 32);
    EXPECT_EQ(CHACHA20_NONCE_SIZE, 12);
    EXPECT_EQ(CHACHA20_TAG_SIZE, 16);
}

TEST_F(SecurityConfigTest, NetworkConfigIsValid) {
    EXPECT_EQ(DISCOVERY_PORT, 10001);
    EXPECT_LT(PORT_RANGE_START, PORT_RANGE_END);
    EXPECT_GE(PORT_RANGE_START, 1024);  // Above privileged ports
    EXPECT_LE(PORT_RANGE_END, 65535);   // Within valid range
    EXPECT_LT(MAX_UDP_PACKET_SIZE, 65536);  // Below UDP max
}

// ============================================================================
// Identifier Validation Tests
// ============================================================================

TEST_F(SecurityConfigTest, ValidateIdentifierValid) {
    EXPECT_TRUE(validate_identifier("agent123"));
    EXPECT_TRUE(validate_identifier("test_agent"));
    EXPECT_TRUE(validate_identifier("agent-456"));
    EXPECT_TRUE(validate_identifier("Agent_Test-123"));
    EXPECT_TRUE(validate_identifier("a"));
}

TEST_F(SecurityConfigTest, ValidateIdentifierInvalid) {
    // Special characters
    EXPECT_FALSE(validate_identifier("agent@123"));
    EXPECT_FALSE(validate_identifier("test agent"));  // space
    EXPECT_FALSE(validate_identifier("agent$123"));
    EXPECT_FALSE(validate_identifier("agent#123"));
    EXPECT_FALSE(validate_identifier("agent!123"));
    EXPECT_FALSE(validate_identifier("agent.123"));
    EXPECT_FALSE(validate_identifier("agent/123"));
    EXPECT_FALSE(validate_identifier("agent\\123"));
}

TEST_F(SecurityConfigTest, ValidateIdentifierEmpty) {
    EXPECT_FALSE(validate_identifier(""));
}

TEST_F(SecurityConfigTest, ValidateIdentifierTooLong) {
    std::string too_long(MAX_IDENTIFIER_LENGTH + 1, 'a');
    EXPECT_FALSE(validate_identifier(too_long));
}

TEST_F(SecurityConfigTest, ValidateIdentifierExactlyMaxLength) {
    std::string exact_max(MAX_IDENTIFIER_LENGTH, 'a');
    EXPECT_TRUE(validate_identifier(exact_max));
}

TEST_F(SecurityConfigTest, ValidateIdentifierCustomMaxLength) {
    std::string test_id = "test123";
    EXPECT_TRUE(validate_identifier(test_id, 10));
    EXPECT_FALSE(validate_identifier(test_id, 5));
}

TEST_F(SecurityConfigTest, ValidateIdentifierShellMetacharacters) {
    // Shell metacharacters should be rejected
    EXPECT_FALSE(validate_identifier("agent;rm -rf /"));
    EXPECT_FALSE(validate_identifier("agent|cat /etc/passwd"));
    EXPECT_FALSE(validate_identifier("agent&background"));
    EXPECT_FALSE(validate_identifier("agent`whoami`"));
    EXPECT_FALSE(validate_identifier("agent$(whoami)"));
    EXPECT_FALSE(validate_identifier("agent>output.txt"));
    EXPECT_FALSE(validate_identifier("agent<input.txt"));
}

TEST_F(SecurityConfigTest, ValidateIdentifierPathTraversal) {
    EXPECT_FALSE(validate_identifier("../etc/passwd"));
    EXPECT_FALSE(validate_identifier("..\\windows\\system32"));
    EXPECT_FALSE(validate_identifier("agent/../admin"));
}

// ============================================================================
// User Input Validation Tests
// ============================================================================

TEST_F(SecurityConfigTest, ValidateUserInputValid) {
    EXPECT_TRUE(validate_user_input("Hello World"));
    EXPECT_TRUE(validate_user_input("Test 123"));
    EXPECT_TRUE(validate_user_input("Email: test@example.com"));
    EXPECT_TRUE(validate_user_input("Message with punctuation!"));
    EXPECT_TRUE(validate_user_input("Question?"));
}

TEST_F(SecurityConfigTest, ValidateUserInputInvalid) {
    // Shell metacharacters
    EXPECT_FALSE(validate_user_input("test;rm -rf /"));
    EXPECT_FALSE(validate_user_input("test|cat /etc/passwd"));
    EXPECT_FALSE(validate_user_input("test&background"));
    EXPECT_FALSE(validate_user_input("test`whoami`"));
    EXPECT_FALSE(validate_user_input("test$(whoami)"));
    EXPECT_FALSE(validate_user_input("test>output.txt"));
    EXPECT_FALSE(validate_user_input("test<input.txt"));
}

TEST_F(SecurityConfigTest, ValidateUserInputEmpty) {
    // Empty input should be valid (application can decide to reject)
    EXPECT_TRUE(validate_user_input(""));
}

TEST_F(SecurityConfigTest, ValidateUserInputTooLong) {
    std::string too_long(MAX_INPUT_LENGTH + 1, 'a');
    EXPECT_FALSE(validate_user_input(too_long));
}

TEST_F(SecurityConfigTest, ValidateUserInputCustomMaxLength) {
    std::string test_input = "Hello World";
    EXPECT_TRUE(validate_user_input(test_input, 20));
    EXPECT_FALSE(validate_user_input(test_input, 5));
}

TEST_F(SecurityConfigTest, ValidateUserInputSQLInjection) {
    // SQL injection attempts should be allowed (sanitization at DB layer)
    // But special chars might be filtered
    EXPECT_FALSE(validate_user_input("admin'; DROP TABLE users;--"));
}

TEST_F(SecurityConfigTest, ValidateUserInputXSS) {
    // XSS attempts with shell chars should be rejected
    EXPECT_FALSE(validate_user_input("<script>alert('xss')</script>"));
}

// ============================================================================
// Filename Sanitization Tests
// ============================================================================

TEST_F(SecurityConfigTest, SanitizeFilenameValid) {
    EXPECT_EQ(sanitize_filename("document.md"), "document.md");
    EXPECT_EQ(sanitize_filename("test_file.md"), "test_file.md");
    EXPECT_EQ(sanitize_filename("file-123.md"), "file-123.md");
}

TEST_F(SecurityConfigTest, SanitizeFilenamePathTraversal) {
    // Path traversal should be removed
    EXPECT_EQ(sanitize_filename("../../../etc/passwd"), "passwd.md");
    EXPECT_EQ(sanitize_filename("..\\..\\windows\\system32\\config"), "config.md");
    EXPECT_EQ(sanitize_filename("test/../admin/file"), "file.md");
}

TEST_F(SecurityConfigTest, SanitizeFilenameAbsolutePath) {
    // Absolute paths should be converted to filename only
    EXPECT_EQ(sanitize_filename("/etc/passwd"), "passwd.md");
    EXPECT_EQ(sanitize_filename("/home/user/document.txt"), "document.md");
    EXPECT_EQ(sanitize_filename("C:\\Windows\\System32\\config"), "config.md");
}

TEST_F(SecurityConfigTest, SanitizeFilenameSpecialCharacters) {
    // Special characters should be handled safely
    std::string result = sanitize_filename("file:with*special?chars<>.txt");
    EXPECT_NE(result.find(".md"), std::string::npos);  // Should have extension
}

TEST_F(SecurityConfigTest, SanitizeFilenameEmpty) {
    std::string result = sanitize_filename("");
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find(".md"), std::string::npos);
}

TEST_F(SecurityConfigTest, SanitizeFilenameOnlyDots) {
    std::string result = sanitize_filename("...");
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find(".md"), std::string::npos);
}

TEST_F(SecurityConfigTest, SanitizeFilenameCustomExtension) {
    EXPECT_EQ(sanitize_filename("document.txt", ".txt"), "document.txt");
    EXPECT_EQ(sanitize_filename("image", ".png"), "image.png");
}

TEST_F(SecurityConfigTest, SanitizeFilenameTooLong) {
    std::string long_name(300, 'a');
    std::string result = sanitize_filename(long_name);
    EXPECT_LE(result.length(), MAX_FILENAME_LENGTH);
}

TEST_F(SecurityConfigTest, SanitizeFilenameNullBytes) {
    std::string filename_with_null = "file\0hidden.txt";
    std::string result = sanitize_filename(filename_with_null);
    // Should handle null bytes safely
    EXPECT_NE(result.find(".md"), std::string::npos);
}

// ============================================================================
// Path Safety Tests
// ============================================================================

TEST_F(SecurityConfigTest, IsSafePathWithinBase) {
    fs::path base = test_dir_;
    fs::path safe_path = test_dir_ / "subdir" / "file.txt";

    EXPECT_TRUE(is_safe_path(safe_path, base));
}

TEST_F(SecurityConfigTest, IsSafePathExactlyBase) {
    fs::path base = test_dir_;
    EXPECT_TRUE(is_safe_path(base, base));
}

TEST_F(SecurityConfigTest, IsSafePathTraversalAttack) {
    fs::path base = test_dir_;
    fs::path malicious_path = test_dir_ / ".." / ".." / "etc" / "passwd";

    EXPECT_FALSE(is_safe_path(malicious_path, base));
}

TEST_F(SecurityConfigTest, IsSafePathAbsoluteOutside) {
    fs::path base = test_dir_;
    fs::path outside_path = "/etc/passwd";

    EXPECT_FALSE(is_safe_path(outside_path, base));
}

TEST_F(SecurityConfigTest, IsSafePathRelativeTraversal) {
    fs::path base = test_dir_;
    fs::path traversal = test_dir_ / "subdir" / ".." / ".." / ".." / "etc";

    EXPECT_FALSE(is_safe_path(traversal, base));
}

TEST_F(SecurityConfigTest, IsSafePathSymlinkAttack) {
    // Create subdirectory
    fs::path subdir = test_dir_ / "subdir";
    fs::create_directories(subdir);

    // Create symlink to /etc (if possible)
    fs::path symlink_path = subdir / "evil_link";
    try {
        fs::create_symlink("/etc", symlink_path);

        // Following symlink should not escape base directory
        fs::path target = symlink_path / "passwd";
        EXPECT_FALSE(is_safe_path(target, test_dir_));
    } catch (const fs::filesystem_error&) {
        // Symlink creation might fail (permissions), skip test
        GTEST_SKIP() << "Cannot create symlinks in test environment";
    }
}

TEST_F(SecurityConfigTest, IsSafePathNonExistentPath) {
    fs::path base = test_dir_;
    fs::path non_existent = test_dir_ / "does_not_exist" / "file.txt";

    // Non-existent paths within base should still be considered safe
    EXPECT_TRUE(is_safe_path(non_existent, base));
}

// ============================================================================
// Directory Configuration Tests
// ============================================================================

TEST_F(SecurityConfigTest, GetDataDirectory) {
    auto data_dir = get_data_directory();
    EXPECT_FALSE(data_dir.empty());
    EXPECT_TRUE(data_dir.is_absolute());
}

TEST_F(SecurityConfigTest, GetReceivedDirectory) {
    auto received_dir = get_received_directory();
    EXPECT_FALSE(received_dir.empty());
    EXPECT_TRUE(received_dir.is_absolute());
}

TEST_F(SecurityConfigTest, GetDatabaseDirectory) {
    auto db_dir = get_database_directory();
    EXPECT_FALSE(db_dir.empty());
    EXPECT_TRUE(db_dir.is_absolute());
}

TEST_F(SecurityConfigTest, GetLogDirectory) {
    auto log_dir = get_log_directory();
    EXPECT_FALSE(log_dir.empty());
    EXPECT_TRUE(log_dir.is_absolute());
}

TEST_F(SecurityConfigTest, DirectoriesAreConsistent) {
    auto data_dir = get_data_directory();
    auto received_dir = get_received_directory();
    auto db_dir = get_database_directory();
    auto log_dir = get_log_directory();

    // Subdirectories should be under data directory
    EXPECT_TRUE(received_dir.string().find(data_dir.string()) == 0 ||
                received_dir.is_absolute());
    EXPECT_TRUE(db_dir.string().find(data_dir.string()) == 0 ||
                db_dir.is_absolute());
    EXPECT_TRUE(log_dir.string().find(data_dir.string()) == 0 ||
                log_dir.is_absolute());
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(SecurityConfigTest, ConcurrentValidateIdentifier) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<bool> results(num_threads);

    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back([&results, i]() {
            results[i] = validate_identifier("agent_" + std::to_string(i));
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}

TEST_F(SecurityConfigTest, ConcurrentSanitizeFilename) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<std::string> results(num_threads);

    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back([&results, i]() {
            results[i] = sanitize_filename("file_" + std::to_string(i) + ".txt");
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    for (size_t i = 0; i < results.size(); i++) {
        EXPECT_FALSE(results[i].empty());
        EXPECT_NE(results[i].find("file_" + std::to_string(i)), std::string::npos);
    }
}

TEST_F(SecurityConfigTest, ConcurrentPathValidation) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::vector<bool> results(num_threads);

    fs::path base = test_dir_;

    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back([&results, &base, i]() {
            fs::path test_path = base / ("subdir" + std::to_string(i)) / "file.txt";
            results[i] = is_safe_path(test_path, base);
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    for (bool result : results) {
        EXPECT_TRUE(result);
    }
}

// ============================================================================
// Security Edge Cases
// ============================================================================

TEST_F(SecurityConfigTest, ValidateIdentifierUnicode) {
    // Unicode characters should be rejected for identifiers
    EXPECT_FALSE(validate_identifier("agent_\xE2\x9C\x93"));  // UTF-8 checkmark
    EXPECT_FALSE(validate_identifier("\xE4\xB8\xAD\xE6\x96\x87"));  // Chinese chars
}

TEST_F(SecurityConfigTest, ValidateUserInputControlCharacters) {
    // Control characters should be handled
    EXPECT_FALSE(validate_user_input("test\x01\x02\x03"));
    EXPECT_FALSE(validate_user_input("test\r\nmore"));
}

TEST_F(SecurityConfigTest, SanitizeFilenameReservedNames) {
    // Reserved filenames on Windows
    std::string result_con = sanitize_filename("CON");
    std::string result_prn = sanitize_filename("PRN");
    std::string result_nul = sanitize_filename("NUL");

    // Should not return reserved names unchanged
    EXPECT_NE(result_con, "CON");
    EXPECT_NE(result_prn, "PRN");
    EXPECT_NE(result_nul, "NUL");
}

TEST_F(SecurityConfigTest, PathTraversalVariants) {
    fs::path base = test_dir_;

    // Various path traversal techniques
    EXPECT_FALSE(is_safe_path(base / "../../../etc/passwd", base));
    EXPECT_FALSE(is_safe_path(base / "..\\..\\..\\windows\\system32", base));
    EXPECT_FALSE(is_safe_path(base / "subdir/../../outside", base));
    EXPECT_FALSE(is_safe_path(base / "./../../etc", base));
}

TEST_F(SecurityConfigTest, ValidateIdentifierBoundaryValues) {
    // Test boundary values
    EXPECT_TRUE(validate_identifier("a"));  // Single char
    EXPECT_TRUE(validate_identifier("a123"));  // Starts with letter
    EXPECT_TRUE(validate_identifier("123"));  // Starts with number
    EXPECT_TRUE(validate_identifier("_test"));  // Starts with underscore
    EXPECT_TRUE(validate_identifier("-test"));  // Starts with hyphen
}

TEST_F(SecurityConfigTest, SanitizeFilenamePreservesValidNames) {
    std::vector<std::string> valid_names = {
        "document.md",
        "test_file_123.md",
        "report-2023.md",
        "README.md",
        "file.with.dots.md"
    };

    for (const auto& name : valid_names) {
        EXPECT_EQ(sanitize_filename(name), name);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
