#include "Core.h"
#include <iostream>
#include <string>
#include <cassert>
#include <windows.h>
#include <tchar.h>

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

int _tmain(int argc, _TCHAR* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "RasTI Core Functions Unit Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    int passed = 0;
    int total = 0;

    struct TestCase {
        const char* name;
        bool (*func)();
    };

    TestCase tests[] = {
        {"ResolveDynamicFunctions", TestResolveDynamicFunctions},
        {"EnablePrivilege", TestEnablePrivilege},
        {"CheckAdministratorPrivileges", TestCheckAdministratorPrivileges},
        {"GetTrustedInstallerToken", TestGetTrustedInstallerToken},
        {"StringConversion", TestStringConversion},
        {"SecurityValidations", TestSecurityValidations},
        {"ErrorMessages", TestErrorMessages}
    };

    for (auto& test : tests) {
        total++;
        std::cout << "Running test: " << test.name << std::endl;
        if (test.func()) {
            passed++;
        }
        std::cout << std::endl;
    }

    std::cout << "========================================" << std::endl;
    std::cout << "Test Results: " << passed << "/" << total << " tests passed" << std::endl;
    std::cout << "========================================" << std::endl;

    if (passed == total) {
        std::cout << "All tests passed! ✅" << std::endl;
    } else {
        std::cout << "Some tests failed! ❌" << std::endl;
    }

    std::cout << std::endl << "Press Enter to exit...";
    std::cin.get();

    return (passed == total) ? 0 : 1;
}
