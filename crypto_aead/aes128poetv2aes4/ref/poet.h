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

struct poet_ctx_t {
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
};

// ---------------------------------------------------------------------

void keysetup(struct poet_ctx_t *ctx, 
              const uint8_t key[KEYLEN]);

void process_header(struct poet_ctx_t *ctx, 
                    const uint8_t *header, 
                    uint64_t header_len);

void encrypt_final(struct poet_ctx_t *ctx, 
                   const uint8_t *plaintext, 
                   uint64_t plen, 
                   uint8_t *ciphertext, 
                   uint8_t tag[BLOCKLEN]);

int decrypt_final(struct poet_ctx_t *ctx, 
                  const uint8_t *ciphertext, 
                  uint64_t clen, 
                  const uint8_t tag[BLOCKLEN], 
                  uint8_t *plaintext);

// ---------------------------------------------------------------------

#endif //  _POET_H_
