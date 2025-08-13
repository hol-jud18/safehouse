#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

int encrypt_aes_gcm(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *aad, size_t aad_len,
                    unsigned char *ciphertext, size_t *ciphertext_len);

int decrypt_aes_gcm(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *aad, size_t aad_len,
                    unsigned char *plaintext, size_t *plaintext_len);

// New file-based API wrappers:
int encrypt_file_aes_gcm(const char *input_path, const char *output_path, const char *password);
int decrypt_file_aes_gcm(const char *input_path, const char *output_path, const char *password);

#endif
