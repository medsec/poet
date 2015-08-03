#ifndef _POET_H_
#define _POET_H_

#include <emmintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>
#include "api.h"

// ---------------------------------------------------------------------

#define BLOCKLEN      CRYPTO_NPUBBYTES
#define KEYLEN        CRYPTO_KEYBYTES
#define TAGLEN        CRYPTO_ABYTES
#define ROUNDS         10
#define ROUND_KEYS     11

typedef __m128i  AES_KEY[ROUND_KEYS];
typedef __m128i  AXU_KEY[ROUND_KEYS];

// ---------------------------------------------------------------------

typedef struct {
    AES_KEY aes_enc;   // Expanded encryption key for the AES
    AES_KEY aes_dec;   // Expanded decryption key for the AES
    AXU_KEY aes_axu;   // Expanded key for the AXU hash function (top and bottom)
    __m128i l;         // Masking key for the header-processing step
    __m128i x;         // Top-chaining value
    __m128i y;         // Bottom-chaining value
    __m128i tau;       // Result of the header-processing step
    unsigned long long mlen;     // Message length
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

#endif //  _POET_H_
