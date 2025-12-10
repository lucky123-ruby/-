#include "p2p_bot.h"
#include <stdio.h>
#include <chrono>

// 生成节点ID
void generate_node_id(char* node_id) {
    if (!node_id) {
        printf("[Node ID] Error: Passed pointer is null\n");
        return;
    }

    memset(node_id, 0, NODE_ID_STRING_SIZE + 1);

    HCRYPTPROV hProv = 0;
    unsigned char random_bytes[NODE_ID_BINARY_SIZE] = { 0 };

    printf("[Node ID] Starting to generate node ID...\n");

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        printf("[Node ID] Encryption context acquired successfully\n");

        if (CryptGenRandom(hProv, NODE_ID_BINARY_SIZE, random_bytes)) {
            printf("[Node ID] Random number generation successful\n");
            hex_encode(random_bytes, NODE_ID_BINARY_SIZE, node_id);
            CryptReleaseContext(hProv, 0);

            size_t generated_len = strlen(node_id);
            if (generated_len != NODE_ID_STRING_SIZE) {
                printf("[Node ID] Warning: Generated node ID has abnormal length: %zu (expected: %d)\n",
                    generated_len, NODE_ID_STRING_SIZE);
                printf("[Node ID] Using fallback method\n");
                srand((unsigned int)time(NULL));
                for (int i = 0; i < NODE_ID_BINARY_SIZE; i++) {
                    sprintf_s(node_id + (i * 2), 3, "%02X", rand() % 256);
                }
            }
            else {
                printf("[Node ID] Node ID generated successfully: %s\n", node_id);
            }
            return;
        }
        else {
            printf("[Node ID] Random number generation failed: %d\n", GetLastError());
            CryptReleaseContext(hProv, 0);
        }
    }
    else {
        printf("[Node ID] Failed to acquire encryption context: %d\n", GetLastError());
    }

    // Fallback method
    printf("[Node ID] Using fallback method to generate node ID\n");
    srand((unsigned int)time(NULL));
    for (int i = 0; i < NODE_ID_BINARY_SIZE; i++) {
        sprintf_s(node_id + (i * 2), 3, "%02X", rand() % 256);
    }

    // Verify fallback result
    if (strlen(node_id) != NODE_ID_STRING_SIZE) {
        printf("[Node ID] Critical error: Fallback method also generated node ID with abnormal length\n");
    }
    else {
        printf("[Node ID] Fallback method generated successfully: %s\n", node_id);
    }
}

// Generate message ID
void generate_message_id(char* message_id) {
    GUID guid;
    if (CoCreateGuid(&guid) == S_OK) {
        sprintf_s(message_id, 37, "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    }
    else {
        // Fallback solution: use timestamp and random numbers
        srand((unsigned int)time(NULL));
        sprintf_s(message_id, 37, "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            (unsigned long)time(NULL), rand() % 0xFFFF, rand() % 0xFFFF,
            rand() % 256, rand() % 256, rand() % 256, rand() % 256,
            rand() % 256, rand() % 256, rand() % 256, rand() % 256);
    }
}

// Get current timestamp
unsigned long long get_timestamp() {
    // Use C++11 chrono library (cross-platform compatible)
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

    // Convert to Unix timestamp (seconds)
    return (unsigned long long)(milliseconds / 1000);
}

// Alternative Windows-specific implementation
unsigned long long get_timestamp_win32() {
    FILETIME ft;
    ULARGE_INTEGER ull;

    GetSystemTimeAsFileTime(&ft);
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    // Convert to Unix timestamp (seconds from January 1, 1601 to January 1, 1970)
    return (ull.QuadPart / 10000000ULL) - 11644473600ULL;
}

// Hexadecimal encoding
void hex_encode(const unsigned char* data, unsigned int size, char* output) {
    if (!data || !output) {
        printf("[Hex Encode] Error: Input or output pointer is null\n");
        return;
    }

    // Calculate required output buffer size
    unsigned int required_size = size * 2;

    // Ensure output buffer is large enough
    if (required_size > KEY_STRING_SIZE) {
        printf("[Hex Encode] Error: Output buffer may be too small (%u > %d)\n",
            required_size, KEY_STRING_SIZE);
        return;
    }

    // Encode data
    for (unsigned int i = 0; i < size; i++) {
        sprintf_s(output + (i * 2), 3, "%02X", data[i]);
    }
    output[size * 2] = '\0';
}

// Hexadecimal decoding
int hex_decode(const char* hex, unsigned char* data, unsigned int max_size) {
    if (!hex || !data) {
        printf("[Hex Decode] Error: Input or output pointer is null\n");
        return 0;
    }

    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_size) {
        printf("[Hex Decode] Error: Invalid hex string length or buffer too small\n");
        return 0;
    }

    for (size_t i = 0; i < len / 2; i++) {
        unsigned int byte;
        if (sscanf_s(hex + (i * 2), "%2x", &byte) == 1) {
            data[i] = (unsigned char)byte;
        }
        else {
            printf("[Hex Decode] Error: Failed to parse hex string at position %zu\n", i * 2);
            return 0;
        }
    }

    return (int)(len / 2);
}

// Debug function: Check system status
void debug_system_status() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);

    printf("[Debug] System information:\n");
    printf("[Debug]   CPU cores: %d\n", sysInfo.dwNumberOfProcessors);
    printf("[Debug]   Total memory: %llu MB\n", memStatus.ullTotalPhys / (1024 * 1024));
    printf("[Debug]   Available memory: %llu MB\n", memStatus.ullAvailPhys / (1024 * 1024));
    printf("[Debug]   Memory usage: %lu%%\n", memStatus.dwMemoryLoad);
}

// Safe timestamp acquisition function
unsigned long long safe_get_timestamp() {
    __try {
        return get_timestamp();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[Security] Exception in get_timestamp(), using fallback solution\n");
        return get_timestamp_win32();
    }
}