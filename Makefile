OPENSSL_DIR := $(shell brew --prefix openssl@3)

CFLAGS := -Wall -Wextra -pedantic -std=c99 -I$(OPENSSL_DIR)/include
LDFLAGS := -L$(OPENSSL_DIR)/lib -lcrypto

vault: vaultmore.c
	$(CC) $(CFLAGS) vaultmore.c -o vault $(LDFLAGS)
