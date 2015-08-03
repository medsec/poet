#ifndef _POET_H_
#define _POET_H_

#include <stdint.h>
#include "aes.h"
#include "api.h"

// ---------------------------------------------------------------------

#define BLOCKLEN      CRYPTO_NPUBBYTES
#define BLOCKLEN_BITS CRYPTO_NPUBBYTES*8
#define KEYLEN        CRYPTO_KEYBYTES
#define KEYLEN_BITS   KEYLEN*8
#define TAGLEN        CRYPTO_ABYTES

#define SUCCESS 0
#define FAIL    1

// ---------------------------------------------------------------------

typedef unsigned char block[BLOCKLEN];
typedef int boolean;

// ---------------------------------------------------------------------

typedef struct {
  AES_KEY aes_enc;   // Expanded encryption key for the AES
  AES_KEY aes_dec;   // Expanded decryption key for the AES
  AES_KEY aes_axu; // Expanded key for the AXU hash function (top and bottom)
  block k;           // Block-cipher key
  block l;           // PMAC key
  block k_axu;       // Key for the AXU hash function (top and bottom)
  block x;           // Top-chaining value
  block y;           // Bottom-chaining value
  block tau;         // Result of the header-processing step
  uint64_t mlen;     // Message length
} poet_ctx_t;

// ---------------------------------------------------------------------

void keysetup_encrypt_only(poet_ctx_t *ctx, const unsigned char key[KEYLEN]);

void keysetup(poet_ctx_t *ctx, const unsigned char key[KEYLEN]);

void process_header(poet_ctx_t *ctx,
                    const unsigned char *header,
                    unsigned long long header_len);

void encrypt_final(poet_ctx_t *ctx,
                   const unsigned char *plaintext,
                   unsigned long long plen,
                   unsigned char *ciphertext,
                   unsigned char tag[TAGLEN]);

int decrypt_final(poet_ctx_t *ctx,
                  const unsigned char *ciphertext,
                  unsigned long long clen,
                  const unsigned char tag[TAGLEN],
                  unsigned char *plaintext);

// ---------------------------------------------------------------------

#endif //  _POET_H_
