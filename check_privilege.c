#include <windows.h>
#include <stdio.h>

// Function to print privilege name and state
void PrintPrivilege(LUID_AND_ATTRIBUTES la) {
    char buffer[256];
    DWORD bufferSize = sizeof(buffer);

    if (LookupPrivilegeName(NULL, &la.Luid, buffer, &bufferSize)) {
        printf("%s: %s\n", buffer, (la.Attributes & SE_PRIVILEGE_ENABLED) ? "Enabled" : "Disabled");
    }
}

int main() {
    HANDLE hToken;
    DWORD tokenInfoLength = 0;

    // Open the current process token with TOKEN_QUERY access
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        fprintf(stderr, "Failed to open process token. Error: %lu\n", GetLastError());
        return 1;
    }

    // First call to GetTokenInformation to get the buffer size needed
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tokenInfoLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        fprintf(stderr, "GetTokenInformation failed. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return 1;
    }

    PTOKEN_PRIVILEGES tokenPrivileges = (PTOKEN_PRIVILEGES)malloc(tokenInfoLength);

    // Second call to GetTokenInformation to get the privileges information
    if (GetTokenInformation(hToken, TokenPrivileges, tokenPrivileges, tokenInfoLength, &tokenInfoLength)) {
        printf("Privileges of the current process:\n");
        for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++) {
            PrintPrivilege(tokenPrivileges->Privileges[i]);
        }
    } else {
        fprintf(stderr, "GetTokenInformation failed. Error: %lu\n", GetLastError());
    }

    free(tokenPrivileges);
    CloseHandle(hToken);
    return 0;
}
