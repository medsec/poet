CC=clang
CFLAGS=-W -Wall -Wextra -O3 -std=c99 -msse4.2 -mavx2 -maes
CSANITIZE_FLAGS=-W -Wall -Wextra -O1 -std=c99 -msse4.2 -mavx2 -maes -fsanitize=undefined -fsanitize=address -fsanitize=alignment -g3
DECRYPTFLAG = 

ifdef DEC
  DECRYPTFLAG=-DDECRYPT
endif

.PHONY: clean m32-test-poet

all: test-poet test-encrypt poet-test-vectors benchmark

test-poet:
	touch crypto_aead.h
	$(CC) $(CSANITIZE_FLAGS) -o $@ $@.c encrypt.c poet.c

test-encrypt:
	touch crypto_aead.h
	$(CC) $(CSANITIZE_FLAGS) -o $@ $@.c encrypt.c poet.c

poet-test-vectors:
	touch crypto_aead.h
	$(CC) $(CFLAGS) -o $@ $@.c encrypt.c poet.c

benchmark:
	touch crypto_aead.h
	$(CC) $(CFLAGS) $(DECRYPTFLAG) -o $@ $@.c encrypt.c poet.c

m32-test-poet:
	$(CC) $(CFLAGS) -m32 -o $@ test-poet.c poet.c

clean:
	rm -f crypto_aead.h
	rm -f *.o *.gch 
	rm -f test-poet test-encrypt poet-test-vectors m32-test-poet benchmark
	rm -f *~

