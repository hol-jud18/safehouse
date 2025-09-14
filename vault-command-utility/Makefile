OPENSSL_DIR := $(shell brew --prefix openssl@3)

CFLAGS := -Wall -Wextra -pedantic -std=c99 -I$(OPENSSL_DIR)/include
LDFLAGS := -L$(OPENSSL_DIR)/lib -lcrypto

SRC := vaultmore.c crypto.c
OBJ := $(SRC:.c=.o)

vault: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) vault
