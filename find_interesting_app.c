#include <windows.h>
#include <stdio.h>
#include <aclapi.h>

void CheckPermissionsAndPrint(const char* directoryPath) {
    WIN32_FIND_DATA findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;
    char filePath[MAX_PATH];
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pACL = NULL;
    DWORD dwRes;
    PSID pSidOwner = NULL;
    BOOL bOwnerDefaulted;

    // Create a search path for files
    snprintf(filePath, MAX_PATH, "%s\\*", directoryPath);
    hFind = FindFirstFile(filePath, &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Unable to access directory %s\n", directoryPath);
        return;
    }

    do {
        if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
            snprintf(filePath, MAX_PATH, "%s\\%s", directoryPath, findData.cFileName);

            // Get the security descriptor for the file
            dwRes = GetNamedSecurityInfo(filePath, SE_FILE_OBJECT,
                                         OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                         &pSidOwner, NULL, &pACL, NULL, &pSD);
            if (dwRes == ERROR_SUCCESS) {
                TRUSTEE trustee;
                ACCESS_MASK accessRights = 0;
                BuildTrusteeWithSid(&trustee, pSidOwner);

                // Check access rights
                GetEffectiveRightsFromAcl(pACL, &trustee, &accessRights);

                // Check for write or full access
                if ((accessRights & (FILE_GENERIC_WRITE | FILE_ALL_ACCESS)) != 0) {
                    printf("Name: %s\nGranted Access: ", findData.cFileName);
                    if (accessRights & FILE_GENERIC_WRITE) printf("Write ");
                    if (accessRights & FILE_ALL_ACCESS) printf("Full");
                    printf("\n");
                }
                LocalFree(pSD);
            } else {
                printf("Failed to get security info for %s\n", filePath);
            }
        }
    } while (FindNextFile(hFind, &findData) != 0);

    dwError = GetLastError();
    FindClose(hFind);
    if (dwError != ERROR_NO_MORE_FILES) {
        printf("FindNextFile error. Error is %u\n", dwError);
    }
}

int main() {
    CheckPermissionsAndPrint("C:\\Program Files");
    CheckPermissionsAndPrint("C:\\Program Files (x86)");
    CheckPermissionsAndPrint("C:\\Windows");

    return 0;
}
