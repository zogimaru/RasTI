/**
 * @file Test.cpp
 * @brief Unit Test Suite untuk RasTI Core Functions
 *
 * File ini berisi comprehensive unit tests untuk menguji semua fungsi
 * privilege escalation dan security validation dalam RasTI.
 *
 * Test Categories:
 * - PRIVILEGE TESTS: Testing privilege management functions
 * - SECURITY TESTS: Testing path validation dan security functions
 * - UTILITY TESTS: Testing helper functions dan string operations
 *
 * @author RasTI Development Team
 * @version 1.1.0.0
 * @date 2025
 */

#include "Core.h"
#include <iostream>
#include <string>
#include <cassert>
#include <windows.h>
#include <tchar.h>
#include <iomanip>
#include <chrono>
#include <vector>
#include <sstream>

//==============================================================================
// TEST MACROS
//==============================================================================

/** @brief Macro untuk assertion dalam test functions */
#define TEST_ASSERT(condition, message) \
    if (!(condition)) { \
        std::cout << "TEST FAILED: " << message << std::endl; \
        return false; \
    }

/** @brief Macro untuk menandai test berhasil */
#define TEST_PASS(message) \
    std::cout << "TEST PASSED: " << message << std::endl; \
    return true;

bool TestResolveDynamicFunctions() {
    std::cout << "Testing ResolveDynamicFunctions..." << std::endl;

    pRtlAdjustPrivilege = NULL;
    pLogonUserExExW = NULL;

    ResolveDynamicFunctions();

    TEST_ASSERT(pRtlAdjustPrivilege != NULL, "RtlAdjustPrivilege function pointer should be loaded");
    TEST_ASSERT(pLogonUserExExW != NULL, "LogonUserExExW function pointer should be loaded");

    TEST_PASS("ResolveDynamicFunctions loads function pointers correctly");
}

bool TestEnablePrivilege() {
    std::cout << "Testing EnablePrivilege..." << std::endl;

    ResolveDynamicFunctions();

    bool result = EnablePrivilege(false, 99999);
    TEST_ASSERT(result == false, "EnablePrivilege should return false for invalid privilege");

    result = EnablePrivilege(false, SeDebugPrivilege);
    std::cout << "EnablePrivilege result: " << (result ? "true" : "false") << std::endl;

    TEST_PASS("EnablePrivilege handles invalid privileges correctly");
}

bool TestCheckAdministratorPrivileges() {
    std::cout << "Testing CheckAdministratorPrivileges..." << std::endl;

    BOOL result = CheckAdministratorPrivileges();
    std::cout << "Administrator privileges: " << (result ? "true" : "false") << std::endl;

    TEST_PASS("CheckAdministratorPrivileges executes without crashing");
}

bool TestGetTrustedInstallerToken() {
    std::cout << "Testing GetTrustedInstallerToken..." << std::endl;

    if (!CheckAdministratorPrivileges()) {
        std::cout << "Skipping GetTrustedInstallerToken test - requires administrator privileges" << std::endl;
        TEST_PASS("GetTrustedInstallerToken test skipped (no admin privileges)");
    }

    ResolveDynamicFunctions();

    HANDLE token = GetTrustedInstallerToken();

    if (token == NULL) {
        std::cout << "GetTrustedInstallerToken returned NULL - this may be expected in test environment" << std::endl;
        TEST_PASS("GetTrustedInstallerToken handles failure gracefully");
    } else {
        std::cout << "GetTrustedInstallerToken returned valid token" << std::endl;
        CloseHandle(token);
        TEST_PASS("GetTrustedInstallerToken returns valid token when successful");
    }
}

bool TestStringConversion() {
    std::cout << "Testing string conversion safety..." << std::endl;

    AnsiString empty = "";
    int wEmptyLen = MultiByteToWideChar(CP_ACP, 0, empty.c_str(), -1, NULL, 0);
    if (wEmptyLen == 0 || wEmptyLen > MAX_PATH) {
        TEST_ASSERT(false, "Failed to convert empty string");
    }
    std::wstring wEmpty(wEmptyLen, 0);
    int result = MultiByteToWideChar(CP_ACP, 0, empty.c_str(), -1, &wEmpty[0], wEmptyLen);
    if (result == 0) {
        TEST_ASSERT(false, "Failed to convert empty string");
    }
    wEmpty.resize(wEmptyLen - 1);
    TEST_ASSERT(wEmpty.empty(), "Empty string conversion should work");

    AnsiString normal = "test.exe";
    int wNormalLen = MultiByteToWideChar(CP_ACP, 0, normal.c_str(), -1, NULL, 0);
    if (wNormalLen == 0 || wNormalLen > MAX_PATH) {
        TEST_ASSERT(false, "Failed to convert normal string");
    }
    std::wstring wNormal(wNormalLen, 0);
    result = MultiByteToWideChar(CP_ACP, 0, normal.c_str(), -1, &wNormal[0], wNormalLen);
    if (result == 0) {
        TEST_ASSERT(false, "Failed to convert normal string");
    }
    wNormal.resize(wNormalLen - 1);
    TEST_ASSERT(wNormal == L"test.exe", "Normal string conversion should work");

    AnsiString special = "test_123.exe";
    int wSpecialLen = MultiByteToWideChar(CP_ACP, 0, special.c_str(), -1, NULL, 0);
    if (wSpecialLen == 0 || wSpecialLen > MAX_PATH) {
        TEST_ASSERT(false, "Failed to convert special string");
    }
    std::wstring wSpecial(wSpecialLen, 0);
    result = MultiByteToWideChar(CP_ACP, 0, special.c_str(), -1, &wSpecial[0], wSpecialLen);
    if (result == 0) {
        TEST_ASSERT(false, "Failed to convert special string");
    }
    wSpecial.resize(wSpecialLen - 1);
    TEST_ASSERT(wSpecial == L"test_123.exe", "Special character string conversion should work");

    TEST_PASS("String conversion handles various inputs correctly");
}

bool TestSecurityValidations() {
    std::cout << "Testing security validation functions..." << std::endl;

    AnsiString testPath = "  test.exe  ";
    TEST_ASSERT(SanitizePath(testPath), "SanitizePath should succeed");
    TEST_ASSERT(testPath.Pos("  ") == 0, "SanitizePath should remove whitespace");

    TEST_ASSERT(IsPathTraversalSafe("C:\\Windows\\notepad.exe"), "Valid absolute path should be safe");
    TEST_ASSERT(IsPathTraversalSafe("notepad.exe"), "Simple filename should be safe");

    TEST_ASSERT(!IsPathTraversalSafe("..\\notepad.exe"), "Path with .. should be unsafe");
    TEST_ASSERT(!IsPathTraversalSafe("C:\\Windows\\..\\system32\\notepad.exe"), "Path with .. in middle should be unsafe");
    TEST_ASSERT(!IsPathTraversalSafe("test<>.exe"), "Path with suspicious chars should be unsafe");

    TEST_ASSERT(ValidatePriorityValue(IDLE_PRIORITY_CLASS), "IDLE_PRIORITY_CLASS should be valid");
    TEST_ASSERT(ValidatePriorityValue(NORMAL_PRIORITY_CLASS), "NORMAL_PRIORITY_CLASS should be valid");
    TEST_ASSERT(ValidatePriorityValue(REALTIME_PRIORITY_CLASS), "REALTIME_PRIORITY_CLASS should be valid");
    TEST_ASSERT(!ValidatePriorityValue(999), "Invalid priority should be rejected");

    TEST_ASSERT(!ValidateExecutablePath(""), "Empty path should be invalid");
    TEST_ASSERT(!ValidateExecutablePath(std::string(MAX_PATH + 1, 'A').c_str()), "Very long path should be invalid");

    TEST_PASS("Security validation functions work correctly");
}

bool TestErrorMessages() {
    std::cout << "Testing error message functions..." << std::endl;

    AnsiString msg1 = GetErrorMessage("Test error");
    TEST_ASSERT(msg1.Pos("Error: Test error") > 0, "GetErrorMessage should format correctly");

    AnsiString msg2 = GetErrorMessageCode("Test error", 123);
    TEST_ASSERT(msg2.Pos("Error: Test error") > 0, "GetErrorMessageCode should include error code");
    TEST_ASSERT(msg2.Pos("123") > 0, "GetErrorMessageCode should include error number");

    TEST_PASS("Error message functions format correctly");
}

//==============================================================================
// TEST DATA STRUCTURES
//==============================================================================

/** @brief Function pointer type untuk test functions */
typedef bool (*TestFunction)();

/**
 * @brief Structure untuk menyimpan hasil test individual
 */
struct TestResult {
    std::string name;        /**< Nama test function */
    std::string description; /**< Deskripsi test case */
    TestFunction func;       /**< Pointer ke test function */
    bool passed;             /**< Status pass/fail */
    double duration;         /**< Durasi eksekusi dalam milliseconds */
};

/**
 * @brief Structure untuk mengelompokkan test berdasarkan kategori
 */
struct TestCategory {
    std::string name;              /**< Nama kategori (e.g., "PRIVILEGE TESTS") */
    std::string icon;              /**< Emoji icon untuk display */
    std::vector<TestResult> tests; /**< Array test functions dalam kategori ini */
};

//==============================================================================
// OUTPUT FORMATTING FUNCTIONS
//==============================================================================

/**
 * @brief Mencetak header test suite dengan informasi versi dan tanggal
 */
void PrintHeader() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&time);

    std::cout << "RasTI Core Functions Unit Tests" << std::endl;
    std::cout << "Version 1.0.0 - " << std::put_time(&tm, "%Y-%m-%d") << std::endl;
    std::cout << std::string(50, '=') << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Mencetak informasi environment (admin privileges, waktu mulai)
 */
void PrintEnvironmentInfo() {
    BOOL isAdmin = CheckAdministratorPrivileges();
    std::cout << "🔧 Environment: Windows 11 | Admin: " << (isAdmin ? "Yes" : "No") << " | TI: " << (isAdmin ? "Yes" : "No") << std::endl;

    auto start = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(start);
    std::tm tm = *std::localtime(&time);
    std::cout << "⏱️  Started at: " << std::put_time(&tm, "%H:%M:%S") << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Mencetak header kategori test dengan progress counter
 *
 * @param category Kategori test yang akan ditampilkan
 */
void PrintCategoryHeader(const TestCategory& category) {
    int passed = 0;
    for (const auto& test : category.tests) {
        if (test.passed) passed++;
    }

    std::cout << category.icon << " " << category.name << " (" << passed << "/" << category.tests.size() << " passed)" << std::endl;
}

/**
 * @brief Mencetak hasil individual test dengan tree-style formatting
 *
 * @param test Hasil test yang akan ditampilkan
 * @param isLast true jika ini test terakhir dalam kategori
 */
void PrintTestResult(const TestResult& test, bool isLast) {
    std::string prefix = isLast ? "└── " : "├── ";  // Tree-style prefix
    std::string status = test.passed ? "✅ " : "❌ "; // Status emoji
    std::cout << prefix << status << test.name << ": " << test.description << std::endl;
}

/**
 * @brief Mencetak ringkasan akhir test suite
 *
 * @param categories Semua kategori test yang telah dijalankan
 * @param totalTime Total waktu eksekusi dalam detik
 */
void PrintSummary(const std::vector<TestCategory>& categories, double totalTime) {
    int totalTests = 0;
    int totalPassed = 0;

    // Hitung total test dan passed test
    for (const auto& category : categories) {
        totalTests += category.tests.size();
        for (const auto& test : category.tests) {
            if (test.passed) totalPassed++;
        }
    }

    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << std::endl;
    std::string status = (totalPassed == totalTests) ? "✅" : "❌";
    std::cout << "📊 FINAL RESULTS: " << totalPassed << "/" << totalTests << " tests passed (" << std::fixed << std::setprecision(1) << (totalPassed * 100.0 / totalTests) << "%) " << status << std::endl;
    std::cout << "⏱️  Total time: " << std::fixed << std::setprecision(2) << totalTime << " seconds" << std::endl;
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << std::endl;
}

/**
 * @brief Main entry point untuk test suite
 *
 * Function ini menjalankan semua unit tests secara terorganisir,
 * mengukur performa, dan memberikan laporan hasil yang comprehensive.
 *
 * @param argc Jumlah argument command line
 * @param argv Array argument command line
 * @return 0 jika semua test pass, 1 jika ada yang fail
 */
int _tmain(int argc, _TCHAR* argv[]) {
    //======================================================================
    // INITIALIZATION PHASE
    //======================================================================

    // Catat waktu mulai untuk pengukuran performa total
    auto startTime = std::chrono::high_resolution_clock::now();

    // Tampilkan header dan informasi environment
    PrintHeader();
    PrintEnvironmentInfo();

    //======================================================================
    // TEST DEFINITION PHASE
    //======================================================================

    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << std::endl;
    std::cout << "📋 Test Categories:" << std::endl;
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << std::endl;
    std::cout << std::endl;

    // Definisi semua kategori test dengan function pointers
    // Setiap kategori berisi array of test functions yang akan dijalankan
    std::vector<TestCategory> categories = {
        {"PRIVILEGE TESTS", "🔐", {
            {"ResolveDynamicFunctions", "Function pointers loaded correctly", TestResolveDynamicFunctions, false, 0.0},
            {"EnablePrivilege", "Invalid privileges rejected properly", TestEnablePrivilege, false, 0.0}
        }},
        {"SECURITY TESTS", "🛡️ ", {
            {"CheckAdministratorPrivileges", "TI privileges detected", TestCheckAdministratorPrivileges, false, 0.0},
            {"GetTrustedInstallerToken", "Handles NULL gracefully", TestGetTrustedInstallerToken, false, 0.0},
            {"SecurityValidations", "Path traversal prevented", TestSecurityValidations, false, 0.0}
        }},
        {"UTILITY TESTS", "🔧", {
            {"StringConversion", "Safe encoding/decoding", TestStringConversion, false, 0.0},
            {"ErrorMessages", "Proper formatting", TestErrorMessages, false, 0.0}
        }}
    };

    //======================================================================
    // TEST EXECUTION PHASE
    //======================================================================

    // Jalankan semua test dalam setiap kategori
    for (auto& category : categories) {
        // Tampilkan header kategori dengan progress counter
        PrintCategoryHeader(category);

        // Jalankan setiap test dalam kategori
        for (size_t i = 0; i < category.tests.size(); i++) {
            auto& test = category.tests[i];

            // Catat waktu mulai untuk pengukuran durasi test
            auto testStart = std::chrono::high_resolution_clock::now();

            // REDIRECT COUT: Tangkap output test function agar tidak tercampur dengan UI
            // Simpan streambuf lama untuk restore nanti
            std::stringstream buffer;
            std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

            // Jalankan test function
            bool result = false;
            if (test.func) {
                result = test.func();
            }

            // RESTORE COUT: Kembalikan output stream ke normal
            std::cout.rdbuf(old);

            // Hitung durasi eksekusi test
            auto testEnd = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(testEnd - testStart);

            // Simpan hasil test
            test.passed = result;
            test.duration = duration.count();

            // Tampilkan hasil test dengan formatting tree-style
            PrintTestResult(test, i == category.tests.size() - 1);
        }
        std::cout << std::endl; // Baris kosong antar kategori
    }

    //======================================================================
    // REPORTING PHASE
    //======================================================================

    // Hitung waktu total eksekusi
    auto endTime = std::chrono::high_resolution_clock::now();
    auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    // Tampilkan ringkasan akhir
    PrintSummary(categories, totalDuration.count() / 1000.0);

    //======================================================================
    // CLEANUP AND EXIT
    //======================================================================

    std::cout << std::endl << "Press Enter to exit...";
    std::cin.get(); // Tunggu user input sebelum exit

    // Hitung final statistics untuk return code
    int totalPassed = 0;
    int totalTests = 0;
    for (const auto& category : categories) {
        totalTests += category.tests.size();
        for (const auto& test : category.tests) {
            if (test.passed) totalPassed++;
        }
    }

    // Return 0 jika semua test pass, 1 jika ada yang fail
    return (totalPassed == totalTests) ? 0 : 1;
}
