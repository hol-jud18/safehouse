#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define SALT_LEN 16
#define IV_LEN 12
#define KEY_LEN 32
#define TAG_LEN 16

int derive_key(const char *password, const unsigned char *salt, unsigned char *key_out);
int encrypt_aes_gcm(const unsigned char *plaintext, size_t plaintext_len,
                    const char *password,
                    unsigned char *salt_out,
                    unsigned char *iv_out,
                    unsigned char *ciphertext_out,
                    unsigned char *tag_out);

int decrypt_aes_gcm(const unsigned char *ciphertext, size_t ciphertext_len,
                    const char *password,
                    const unsigned char *salt,
                    const unsigned char *iv,
                    const unsigned char *tag,
                    unsigned char *plaintext_out);

#endif
