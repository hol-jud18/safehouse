/*** includes ***/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

/*** defines ***/
typedef struct {
    char *filepath;
    int encrypt;
    int decrypt;
    char *algo;
    char *key; 
    char *salt;
    char *verify;
    char *output;
    int verbose;
} VaultOptions;


void info() {
    printf("Usage: vault <Path to File> [OPTIONS]\n\n");
    printf("Required:\n");
    printf("  <Path to File>        Path to the file to process\n\n");
    printf("Options:\n");
    printf("  --store               Store the file\n");
    printf("  --retrieve            Retrieve the file\n");
    printf("  --key <string>        Key for AES or custom algorithm (optional)\n");
    printf("  --salt <string>       Optional salt to strengthen hash\n");
    printf("  --verify <hash>       Compare file hash with given value\n");
    printf("  --output <file>       Specify output file name/path\n");
    printf("  --verbose             Enable detailed logging\n");
    printf("  --help, -h            Show this message\n");
}

unsigned char* read_file(const char *path, size_t *len_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    size_t len = ftell(fp);
    rewind(fp);

    unsigned char *buf = malloc(len);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    fread(buf, 1, len, fp);
    fclose(fp);
    *len_out = len;
    return buf;
}

void write_file(const char *path, unsigned char *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        perror("fopen - write");
        return;
    }
    fwrite(data, 1, len, fp);
    fclose(fp);
}

void hash_sha256(unsigned char *data, size_t len, unsigned char *digest) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(digest, &ctx);
}

void xor_encrypt(unsigned char *data, size_t len, const char *key) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

char* strip_extension(const char* filename, const char* ext) {
    size_t len = strlen(filename);
    size_t ext_len = strlen(ext);
    if (len > ext_len && strcmp(filename + len - ext_len, ext) == 0) {
        char* result = malloc(len - ext_len + 1);
        strncpy(result, filename, len - ext_len);
        result[len - ext_len] = '\0';
        return result;
    }
    return strdup(filename);
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

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            info();
            return 0;
        } else if (strcmp(argv[i], "--encrypt") == 0) {
            opts.encrypt = 1;
        } else if (strcmp(argv[i], "--decrypt") == 0) {
            opts.decrypt = 1;
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            opts.key = argv[++i];
        } else if (strcmp(argv[i], "--salt") == 0 && i + 1 < argc) {
            opts.salt = argv[++i];
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

    printf("File to process: %s\n", opts.filepath);
    if (opts.encrypt) printf("Encrypting using %s\n", opts.algo ? opts.algo : "default algorithm");
    if (opts.decrypt) printf("Decrypting using %s\n", opts.algo ? opts.algo : "default algorithm");
    if (opts.verbose) printf("Verbose mode is ON\n");

    size_t file_len;
    unsigned char *file_data = read_file(opts.filepath, &file_len);
    if (!file_data) {
        fprintf(stderr, "Failed to read input file.\n");
        return 1;
    }

    if (opts.verbose) printf("Read %zu bytes from file.\n", file_len);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    hash_sha256(file_data, file_len, hash);
    if (opts.verify) {
        char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
        hash_to_hex(hash, SHA256_DIGEST_LENGTH, hash_hex);

        if (opts.verbose) {
            printf("Computed SHA256 %s\n", hash_hex);
            printf("Verifying against: %s\n", opts.verify);
        }

        if (strcasecmp(hash_hex, opts.verify) == 0) {
            printf("Hash verified successfully\n");
        } else {
            printf("Hashes do not match!\n");
            return 2;
        }
    }

    if (opts.verbose) {
        printf("SHA256 hash: ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            printf("%02x", hash[i]);
        printf("\n");
    }

    if (opts.encrypt && opts.decrypt) {
        fprintf(stderr, "Error: Cannot use both --encrypt and --decrypt");
        return 1;
    }

    if (opts.encrypt || opts.decrypt) {
        if (!opts.key) {
            opts.key = "default";
            if (opts.verbose) printf("No key provided... Using default key.\n");
        }

        if (opts.verbose) {
            printf("%s data using XOR and key: %s\n", 
                opts.encrypt ? "Encrypting" : "Decrypting", opts.key);
        }

        xor_encrypt(file_data, file_len, opts.key);
    }

    char *out_path = opts.output;
    if (!out_path) {
        if (opts.decrypt) {
            out_path = strip_extension(opts.filepath, ".vault");
        } else {
            out_path = malloc(strlen(opts.filepath) + 7);
            sprintf(out_path, "%s.vault", opts.filepath);
        }
    }

    write_file(out_path, file_data, file_len);
    if (opts.verbose) printf("Encrypted data written to: %s\n", out_path);

    free(file_data);
    if (!opts.output) free(out_path);
}
