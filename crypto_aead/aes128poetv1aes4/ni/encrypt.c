#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "crypto_aead.h"
#include "poet.h"
#include "api.h"

// ---------------------------------------------------------------------

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec,
                        const unsigned char *npub,
                        const unsigned char *k)
{
    struct poet_ctx_t ctx;
    (void)nsec;

    if (clen) {
        *clen = mlen + CRYPTO_NPUBBYTES;
    }

    keysetup(&ctx, k);

    if (npub) {
        unsigned char *header = malloc((size_t)(adlen + CRYPTO_NPUBBYTES));
        memcpy(header, ad, adlen);
        memcpy(header + adlen, npub, CRYPTO_NPUBBYTES);
        process_header(&ctx, header, adlen + CRYPTO_NPUBBYTES);
        free(header);
    } else {
        process_header(&ctx, ad, adlen);
    }

    unsigned char *tag = c + mlen;
    encrypt_final(&ctx, m, mlen, c, tag);
    return 0;
}

// ---------------------------------------------------------------------

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec,
                        const unsigned char *c, unsigned long long clen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *npub,
                        const unsigned char *k)
{
    struct poet_ctx_t ctx;
    (void)nsec;

    unsigned char *header =  malloc((size_t)(adlen + CRYPTO_NPUBBYTES));
    unsigned char tag[CRYPTO_NPUBBYTES];

    if (clen < CRYPTO_NPUBBYTES) {
        return -1;
    }

    if (mlen) {
        *mlen = clen - CRYPTO_NPUBBYTES;
    }

    keysetup(&ctx, k);

    if (npub) {
        memcpy(tag, c + (clen - CRYPTO_NPUBBYTES), CRYPTO_NPUBBYTES);
        memcpy(header, ad, adlen);
        memcpy(header + adlen, npub, CRYPTO_NPUBBYTES);
        process_header(&ctx, header, adlen + CRYPTO_NPUBBYTES);
        free(header);
    } else {
        process_header(&ctx, ad, adlen);
    }
    
    return decrypt_final(&ctx, c, *mlen, tag, m);
}
