/*** includes ***/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <openssl/sha.h>
#include "crypto.h"

/*** defines ***/
typedef struct {
    char *filepath;
    int encrypt;
    int decrypt;
    int store;
    int retrieve;
    char *algo;
    char *key; 
    char *salt;
    char *verify;
    char *output;
    int verbose;
} VaultOptions;

/*** constants ***/
static const char *HASH_DB = ".vault_hashes";

static void save_file_hash(const char *filepath, const char *hash_hex) {
    FILE *f = fopen(HASH_DB, "a");
    if (!f) { perror("fopen"); return; }
    fprintf(f, "%s:%s\n", filepath, hash_hex);
    fclose(f);
}

static char* get_saved_hash(const char *filepath) {
    FILE *f = fopen(HASH_DB, "r");
    if (!f) return NULL;
    static char hash[65];
    char line[512];
    char stored_file[256], stored_hash[65];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%255[^:]:%64s", stored_file, stored_hash) == 2) {
            if (strcmp(stored_file, filepath) == 0) {
                strcpy(hash, stored_hash);
                found = 1;
                //keep scanning so we keep the latest match
            }
        }
    }
    fclose(f);
    return found ? hash : NULL;
}


void info() {
    printf("Usage: vault <Path to File> [OPTIONS]\n\n");
    printf("Required:\n");
    printf("  <Path to File>        Path to the file to process\n\n");
    printf("Options:\n");
    printf("  --encrypt             Encrypt the file\n");
    printf("  --decrypt             Decrypt the file\n");
    printf("  --key <string>        Password for AES encryption/decryption (required)\n");
    printf("  --verify <hash>       Verify SHA256 hash of file\n");
    printf("  --output <file>       Output file path\n");
    printf("  --verbose             Enable detailed logging\n");
    printf("  --help, -h            Show this message\n");
}


char* strip_extension(const char* filename, const char* ext) {
    size_t len = strlen(filename);
    size_t ext_len = strlen(ext);
    if (len > ext_len && strcmp(filename + len - ext_len, ext) == 0) {
        char* result = malloc(len - ext_len + 1);
        if (!result) return NULL;
        strncpy(result, filename, len - ext_len);
        result[len - ext_len] = '\0';
        return result;
    }
    return strdup(filename);
}

int hash_file_sha256(const char *filename, unsigned char *digest) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        exit(1);
    }
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    unsigned char buf[4096];
    size_t read_len;
    while ((read_len = fread(buf, 1, sizeof(buf), fp)) > 0) {
        SHA256_Update(&ctx, buf, read_len);
    }
    SHA256_Final(digest, &ctx);
    fclose(fp);
    return 0;
}

void hash_to_hex(const unsigned char *hash, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", hash[i]);
    }
    out[len * 2] = '\0';
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        info();
        return 1;
    }

    VaultOptions opts = {0};
    opts.filepath = NULL;

    // Parse command line args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            info();
            return 0;
        } else if (strcmp(argv[i], "--encrypt") == 0) {
            opts.encrypt = 1;
        } else if (strcmp(argv[i], "--decrypt") == 0) {
            opts.decrypt = 1;
        } else if (strcmp(argv[i], "--store") == 0) {
            opts.store = 1;
        } else if (strcmp(argv[i], "--retrieve") == 0) {
            opts.retrieve = 1;
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            opts.key = argv[++i];
        } else if (strcmp(argv[i], "--verify") == 0 && i + 1 < argc) {
            opts.verify = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            opts.output = argv[++i];
        } else if (strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = 1;
        } else if (argv[i][0] != '-') {
            if (!opts.filepath) {
                opts.filepath = argv[i];
            } else {
                fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
                return 1;
            }
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    if (!opts.filepath) {
        fprintf(stderr, "Error: File path is required.\n\n");
        info();
        return 1;
    }
    if (opts.encrypt && opts.decrypt) {
        fprintf(stderr, "Error: Cannot use both --encrypt and --decrypt\n");
        return 1;
    }
    if (!opts.encrypt && !opts.decrypt && !opts.verify && !opts.store && !opts.retrieve) {
        fprintf(stderr, "Error: Must specify --encrypt or --decrypt or --verify or --store or --retrieve\n");
        return 1;
    }
    if ((opts.encrypt || opts.decrypt) && !opts.key) {
        fprintf(stderr, "Error: --key is required for encryption/decryption\n");
        return 1;
    }

    if (opts.verbose) {
        printf("File: %s\n", opts.filepath);
        if (opts.encrypt) printf("Mode: Encrypt (AES-256-GCM)\n");
        if (opts.decrypt) printf("Mode: Decrypt (AES-256-GCM)\n");
        printf("Verbose: ON\n");
    }

    // Verify hash if requested
    if (opts.verify) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        hash_file_sha256(opts.filepath, digest);

        char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
        hash_to_hex(digest, SHA256_DIGEST_LENGTH, hash_hex);

        if (opts.verbose) {
            printf("Computed SHA256: %s\n", hash_hex);
            printf("Verifying against: %s\n", opts.verify);
        }

        if (strcasecmp(hash_hex, opts.verify) == 0) {
            printf("Hash verified successfully\n");
        } else {
            fprintf(stderr, "Hashes do not match!\n");
            return 2;
        }
    }

    if (opts.encrypt) {
        char *out_path = opts.output;
        if (!out_path) {
            out_path = malloc(strlen(opts.filepath) + 7);
            if (!out_path) {
                fprintf(stderr, "Memory allocation failed\n");
                return 1;
            }
            sprintf(out_path, "%s.vault", opts.filepath);
        }
        if (encrypt_file_aes_gcm(opts.filepath, out_path, opts.key) != 0) {
            fprintf(stderr, "Encryption failed\n");
            if (!opts.output) free(out_path);
            return 1;
        }
        if (opts.verbose) printf("Encrypted file written to: %s\n", out_path);

        
        if (!opts.output) free(out_path);
    } else if (opts.decrypt) {
        char *out_path = opts.output;
        if (!out_path) {
            out_path = strip_extension(opts.filepath, ".vault");
            if (!out_path) {
                fprintf(stderr, "Memory allocation failed\n");
                return 1;
            }
        }
        if (decrypt_file_aes_gcm(opts.filepath, out_path, opts.key) != 0) {
            fprintf(stderr, "Decryption failed\n");
            if (!opts.output) free(out_path);
            return 1;
        }
        if (opts.verbose) printf("Decrypted file written to: %s\n", out_path);
        if (!opts.output) free(out_path);
    } else if (opts.store) {
        // hash plaintext file
        unsigned char digest[SHA256_DIGEST_LENGTH];
        if (hash_file_sha256(opts.filepath, digest) != 0) {
            fprintf(stderr, "Error hashing file\n");
            return 1;
        }
        char hash_hex[SHA256_DIGEST_LENGTH*2+1];
        hash_to_hex(digest, SHA256_DIGEST_LENGTH, hash_hex);

        //save hash locally so it can be compared later
        save_file_hash(opts.filepath, hash_hex);
        if (opts.verbose) printf("Saved hash for %s: %s\n", opts.filepath, hash_hex);

        //encrypt
        char out_path[512];
        snprintf(out_path, sizeof(out_path), "%s.vault", opts.filepath);
        if (encrypt_file_aes_gcm(opts.filepath, out_path, opts.key) != 0) {
            fprintf(stderr, "Error encrypting for store\n");
            return 1;
        }
        if (opts.verbose) printf("Encrypted to %s\n", out_path);

        //placeholder for future store logic


    } else if (opts.retrieve) {
        // Attempt to decrypt first, but don't exit before reporting integrity status.
        char out_path[512];
        snprintf(out_path, sizeof(out_path), "%s.decrypted", opts.filepath);
        int dec_rc = decrypt_file_aes_gcm(opts.filepath, out_path, opts.key);

        // Figure out original filename (without .vault) and fetch saved hash
        char *original_file = strip_extension(opts.filepath, ".vault");
        char *expected = get_saved_hash(original_file);

        if (dec_rc != 0) {
            // Could not decrypt, then the file must have been modified or an incorrect key was provided.
            if (expected) {
                fprintf(stderr,
                    "Integrity check NOT OK: could not decrypt '%s' (wrong key or file was modified).\n"
                    "Expected saved hash for original '%s' is %s, but actual could not be computed.\n",
                    opts.filepath, original_file, expected);
            } else {
                fprintf(stderr,
                    "Integrity check NOT OK: could not decrypt '%s' and no saved hash found for '%s'.\n",
                    opts.filepath, original_file);
            }
            free(original_file);
            return 1;
        }

        // If we decrypted, compute actual hash of the plaintext and compare
        unsigned char digest[SHA256_DIGEST_LENGTH];
        if (hash_file_sha256(out_path, digest) != 0) {
            fprintf(stderr, "Error hashing decrypted output\n");
            free(original_file);
            return 1;
        }
        char actual[SHA256_DIGEST_LENGTH*2+1];
        hash_to_hex(digest, SHA256_DIGEST_LENGTH, actual);

        if (!expected) {
            printf("No saved hash found for %s. Actual (decrypted) hash: %s\n", original_file, actual);
        } else if (strcmp(actual, expected) == 0) {
            printf("Integrity check OK for %s\n", out_path);
        } else {
            fprintf(stderr, "Integrity check NOT OK! Expected %s but got %s\n", expected, actual);
        }

        free(original_file);
    }

    return 0;
}
