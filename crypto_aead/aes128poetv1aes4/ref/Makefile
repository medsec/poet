CC=clang
CFLAGS=-W -Wall -Wextra -O3 -std=c99 -s

.PHONY: clean m32-test-poet all

all: test-poet test-encrypt poet-test-vectors

test-poet:
	touch crypto_aead.h
	$(CC) $(CFLAGS) -o $@ $@.c encrypt.c poet.c aes.c

test-encrypt:
	touch crypto_aead.h
	$(CC) $(CFLAGS) -o $@ $@.c encrypt.c poet.c aes.c

poet-test-vectors:
	touch crypto_aead.h
	$(CC) $(CFLAGS) -o $@ $@.c encrypt.c poet.c aes.c

m32-test-poet:
	$(CC) $(CFLAGS) -m32 -o $@ test-poet.c poet.c aes.c

clean:
	rm -f crypto_aead.h
	rm -f *.o *.gch 
	rm -f test-poet test-encrypt poet-test-vectors m32-test-poet
	rm -f *~

