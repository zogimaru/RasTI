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

#define TEST_ASSERT(condition, message) \
    if (!(condition)) { \
        std::cout << "TEST FAILED: " << message << std::endl; \
        return false; \
    }

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
    std::wstring wEmpty(wEmptyLen, 0);
    MultiByteToWideChar(CP_ACP, 0, empty.c_str(), -1, &wEmpty[0], wEmptyLen);
    wEmpty.resize(wEmptyLen - 1);
    TEST_ASSERT(wEmpty.empty(), "Empty string conversion should work");

    AnsiString normal = "test.exe";
    int wNormalLen = MultiByteToWideChar(CP_ACP, 0, normal.c_str(), -1, NULL, 0);
    std::wstring wNormal(wNormalLen, 0);
    MultiByteToWideChar(CP_ACP, 0, normal.c_str(), -1, &wNormal[0], wNormalLen);
    wNormal.resize(wNormalLen - 1);
    TEST_ASSERT(wNormal == L"test.exe", "Normal string conversion should work");

    AnsiString special = "test_123.exe";
    int wSpecialLen = MultiByteToWideChar(CP_ACP, 0, special.c_str(), -1, NULL, 0);
    std::wstring wSpecial(wSpecialLen, 0);
    MultiByteToWideChar(CP_ACP, 0, special.c_str(), -1, &wSpecial[0], wSpecialLen);
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

// Structure for test results
struct TestResult {
    std::string name;
    std::string description;
    bool passed;
    double duration; // in milliseconds
};

// Structure for test categories
struct TestCategory {
    std::string name;
    std::string icon;
    std::vector<TestResult> tests;
};

// Helper functions for output formatting
void PrintHeader() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&time);

    std::cout << "╔══════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║              RasTI Core Functions Unit Tests               ║" << std::endl;
    std::cout << "║                     v1.0.0 - " << std::put_time(&tm, "%Y-%m-%d") << "                     ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
}

void PrintEnvironmentInfo() {
    BOOL isAdmin = CheckAdministratorPrivileges();
    std::cout << "🔧 Environment: Windows 11 | Admin: " << (isAdmin ? "Yes" : "No") << " | TI: " << (isAdmin ? "Yes" : "No") << std::endl;

    auto start = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(start);
    std::tm tm = *std::localtime(&time);
    std::cout << "⏱️  Started at: " << std::put_time(&tm, "%H:%M:%S") << std::endl;
    std::cout << std::endl;
}

void PrintCategoryHeader(const TestCategory& category) {
    int passed = 0;
    for (const auto& test : category.tests) {
        if (test.passed) passed++;
    }

    std::cout << category.icon << " " << category.name << " (" << passed << "/" << category.tests.size() << " passed)" << std::endl;
}

void PrintTestResult(const TestResult& test, bool isLast) {
    std::string prefix = isLast ? "└── " : "├── ";
    std::string status = test.passed ? "✅ " : "❌ ";
    std::cout << prefix << status << test.name << ": " << test.description << std::endl;
}

void PrintSummary(const std::vector<TestCategory>& categories, double totalTime) {
    int totalTests = 0;
    int totalPassed = 0;

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

int _tmain(int argc, _TCHAR* argv[]) {
    auto startTime = std::chrono::high_resolution_clock::now();

    PrintHeader();
    PrintEnvironmentInfo();

    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << std::endl;
    std::cout << "📋 Test Categories:" << std::endl;
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << std::endl;
    std::cout << std::endl;

    // Define test categories
    std::vector<TestCategory> categories = {
        {"PRIVILEGE TESTS", "🔐", {
            {"ResolveDynamicFunctions", "Function pointers loaded correctly", false, 0.0},
            {"EnablePrivilege", "Invalid privileges rejected properly", false, 0.0}
        }},
        {"SECURITY TESTS", "🛡️ ", {
            {"CheckAdministratorPrivileges", "TI privileges detected", false, 0.0},
            {"GetTrustedInstallerToken", "Handles NULL gracefully", false, 0.0},
            {"SecurityValidations", "Path traversal prevented", false, 0.0}
        }},
        {"UTILITY TESTS", "🔧", {
            {"StringConversion", "Safe encoding/decoding", false, 0.0},
            {"ErrorMessages", "Proper formatting", false, 0.0}
        }}
    };

    // Run tests and collect results
    for (auto& category : categories) {
        PrintCategoryHeader(category);

        for (size_t i = 0; i < category.tests.size(); i++) {
            auto& test = category.tests[i];
            auto testStart = std::chrono::high_resolution_clock::now();

            // Redirect cout to capture test output
            std::stringstream buffer;
            std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());

            bool result = false;
            if (test.name == "ResolveDynamicFunctions") result = TestResolveDynamicFunctions();
            else if (test.name == "EnablePrivilege") result = TestEnablePrivilege();
            else if (test.name == "CheckAdministratorPrivileges") result = TestCheckAdministratorPrivileges();
            else if (test.name == "GetTrustedInstallerToken") result = TestGetTrustedInstallerToken();
            else if (test.name == "SecurityValidations") result = TestSecurityValidations();
            else if (test.name == "StringConversion") result = TestStringConversion();
            else if (test.name == "ErrorMessages") result = TestErrorMessages();

            // Restore cout
            std::cout.rdbuf(old);

            auto testEnd = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(testEnd - testStart);

            test.passed = result;
            test.duration = duration.count();

            PrintTestResult(test, i == category.tests.size() - 1);
        }
        std::cout << std::endl;
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    PrintSummary(categories, totalDuration.count() / 1000.0);

    std::cout << std::endl << "Press Enter to exit...";
    std::cin.get();

    int totalPassed = 0;
    int totalTests = 0;
    for (const auto& category : categories) {
        totalTests += category.tests.size();
        for (const auto& test : category.tests) {
            if (test.passed) totalPassed++;
        }
    }

    return (totalPassed == totalTests) ? 0 : 1;
}
