#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define SALT_LEN 16
#define IV_LEN 12
#define TAG_LEN 16
#define KEY_LEN 32

// Encrypt plaintext with AES-256-GCM.
// ciphertext buffer must be at least plaintext_len + TAG_LEN bytes.
// ciphertext_len is updated with actual length (ciphertext + tag).
int encrypt_aes_gcm(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *iv, size_t iv_len,
                    unsigned char *ciphertext, size_t *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len;
    int ciphertext_len_tmp;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len_tmp = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len_tmp += len;

    // Get tag and append after ciphertext
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, ciphertext + ciphertext_len_tmp)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len_tmp += TAG_LEN;

    *ciphertext_len = ciphertext_len_tmp;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Decrypt ciphertext with AES-256-GCM.
// ciphertext_len includes the 16-byte tag at the end.
// plaintext buffer must be at least ciphertext_len bytes.
// plaintext_len updated with actual length.
int decrypt_aes_gcm(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *iv, size_t iv_len,
                    unsigned char *plaintext, size_t *plaintext_len) {
    if (ciphertext_len < TAG_LEN) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len;
    int plaintext_len_tmp;

    size_t actual_ciphertext_len = ciphertext_len - TAG_LEN;
    const unsigned char *tag = ciphertext + actual_ciphertext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)actual_ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len_tmp = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        // Authentication failure - tag mismatch
        return -1;
    }
    plaintext_len_tmp += len;

    *plaintext_len = plaintext_len_tmp;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// File-based encryption: reads input file, encrypts, writes output file.
// Output format: SALT (16 bytes) + IV (12 bytes) + CIPHERTEXT+TAG
int encrypt_file_aes_gcm(const char *input_path, const char *output_path, const char *password) {
    FILE *fin = fopen(input_path, "rb");
    if (!fin) {
        perror("fopen input");
        return -1;
    }

    FILE *fout = fopen(output_path, "wb");
    if (!fout) {
        perror("fopen output");
        fclose(fin);
        return -1;
    }

    unsigned char salt[SALT_LEN];
    if (RAND_bytes(salt, SALT_LEN) != 1) {
        fprintf(stderr, "Failed to generate salt\n");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    unsigned char key[KEY_LEN];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, 100000,
                           EVP_sha256(), KEY_LEN, key)) {
        fprintf(stderr, "Key derivation failed\n");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    unsigned char iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) {
        fprintf(stderr, "IV generation failed\n");
        fclose(fin);
        fclose(fout);
        return -1;
    }

    if (fwrite(salt, 1, SALT_LEN, fout) != SALT_LEN) goto err;
    if (fwrite(iv, 1, IV_LEN, fout) != IV_LEN) goto err;

    fseek(fin, 0, SEEK_END);
    long input_len = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    unsigned char *plaintext = malloc(input_len);
    if (!plaintext) goto err;

    if (fread(plaintext, 1, input_len, fin) != (size_t)input_len) {
        free(plaintext);
        goto err;
    }

    size_t ciphertext_len = input_len + TAG_LEN;
    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        free(plaintext);
        goto err;
    }

    if (encrypt_aes_gcm(plaintext, input_len, key, KEY_LEN, iv, IV_LEN, ciphertext, &ciphertext_len) != 0) {
        fprintf(stderr, "AES-GCM encryption failed\n");
        free(plaintext);
        free(ciphertext);
        goto err;
    }

    free(plaintext);

    if (fwrite(ciphertext, 1, ciphertext_len, fout) != ciphertext_len) {
        free(ciphertext);
        goto err;
    }

    free(ciphertext);

    fclose(fin);
    fclose(fout);
    return 0;

err:
    fclose(fin);
    fclose(fout);
    return -1;
}

// File-based decryption: reads input file, decrypts, writes output file.
// Expects input format: SALT(16) + IV(12) + CIPHERTEXT+TAG
int decrypt_file_aes_gcm(const char *input_path, const char *output_path, const char *password) {
    FILE *fin = fopen(input_path, "rb");
    if (!fin) {
        perror("fopen input");
        return -1;
    }

    FILE *fout = fopen(output_path, "wb");
    if (!fout) {
        perror("fopen output");
        fclose(fin);
        return -1;
    }

    unsigned char salt[SALT_LEN];
    unsigned char iv[IV_LEN];

    if (fread(salt, 1, SALT_LEN, fin) != SALT_LEN) goto err;
    if (fread(iv, 1, IV_LEN, fin) != IV_LEN) goto err;

    unsigned char key[KEY_LEN];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, 100000,
                           EVP_sha256(), KEY_LEN, key)) {
        fprintf(stderr, "Key derivation failed\n");
        goto err;
    }

    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    long ciphertext_len = file_size - SALT_LEN - IV_LEN;
    fseek(fin, SALT_LEN + IV_LEN, SEEK_SET);

    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) goto err;

    if (fread(ciphertext, 1, ciphertext_len, fin) != (size_t)ciphertext_len) {
        free(ciphertext);
        goto err;
    }

    size_t plaintext_len = ciphertext_len;
    unsigned char *plaintext = malloc(plaintext_len);
    if (!plaintext) {
        free(ciphertext);
        goto err;
    }

    if (decrypt_aes_gcm(ciphertext, ciphertext_len, key, KEY_LEN, iv, IV_LEN, plaintext, &plaintext_len) != 0) {
        free(ciphertext);
        free(plaintext);
        goto err;
    }

    free(ciphertext);

    if (fwrite(plaintext, 1, plaintext_len, fout) != plaintext_len) {
        free(plaintext);
        goto err;
    }

    free(plaintext);

    fclose(fin);
    fclose(fout);
    return 0;

err:
    fclose(fin);
    fclose(fout);
    return -1;
}
