# Vaultmore

A secure file encryption and storage system built in C with a Python GTK GUI. Files are encrypted with AES-256-GCM and stored in a local vault, with SHA-256 integrity verification on every retrieval.

## Features

- **AES-256-GCM encryption** — authenticated encryption with a random salt and IV per file
- **PBKDF2-HMAC-SHA256 key derivation** — 100,000 iterations to derive keys from passwords
- **Integrity verification** — SHA-256 hashes are stored at vault time and checked on retrieval
- **Audit logging** — every operation is timestamped with username, hostname, and IP
- **GTK GUI** — browse the vault, retrieve files with a password dialog, and view the audit log

## Project Structure

```
vaultmore/
├── vault-command-utility/
│   ├── vaultmore.c     # CLI entry point and vault operations
│   ├── crypto.c        # AES-256-GCM encrypt/decrypt, PBKDF2, hashing
│   ├── crypto.h        # Crypto API header
│   ├── Makefile        # Build configuration (requires OpenSSL 3 via Homebrew)
│   └── vault-data/     # Encrypted files stored here
└── GUI/
    └── GUI.py          # GTK 3 GUI for browsing and retrieving vault files
```

## Requirements

- macOS with [Homebrew](https://brew.sh)
- OpenSSL 3: `brew install openssl@3`
- GCC and Make
- Python 3 with GTK 3 bindings (for the GUI)

## Build

```bash
cd vault-command-utility
make
```

To clean build artifacts:

```bash
make clean
```

## CLI Usage

```bash
./vault <file> --store --key <password>      # Encrypt and move file into the vault
./vault <file> --retrieve --key <password>   # Decrypt file from vault with integrity check
./vault <file> --encrypt --key <password>    # Encrypt file in place
./vault <file> --decrypt --key <password>    # Decrypt file in place
./vault <file> --verify <hash>               # Verify a file's SHA-256 hash
./vault --help                               # Show usage
```

## GUI Usage

```bash
cd GUI
python3 GUI.py
```

The GUI shows all files currently in the vault with their size and last-modified date. Select a file and click **Retrieve** to decrypt it with a password. The **Events** tab shows the full audit log.

## How It Works

1. **Store** — the file is encrypted with AES-256-GCM using a key derived from your password via PBKDF2. A random 16-byte salt and 12-byte IV are prepended to the ciphertext. The original file's SHA-256 hash is saved to `.vault_hashes` before encryption.
2. **Retrieve** — the vault file is decrypted, the resulting plaintext is hashed, and the hash is compared against the stored value. A mismatch indicates tampering.
3. **Logging** — each operation appends a record to `.vault_log` with the action, filename, timestamp, user, and host.
