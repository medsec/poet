#include <stdio.h>
#include <string.h>
#include <emmintrin.h>
#include "poet.h"
#include "api.h"

// ---------------------------------------------------------------------

extern int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                               const unsigned char *m, unsigned long long mlen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *nsec,
                               const unsigned char *npub,
                               const unsigned char *k);

extern int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                               unsigned char *nsec,
                               const unsigned char *c, unsigned long long clen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *npub,
                               const unsigned char *k);

// ---------------------------------------------------------------------

static void store(const void *p, __m128i x)
{
    _mm_store_si128((__m128i*)p, x);
}

// ---------------------------------------------------------------------

static void print128(char* label, __m128i var)
{
    unsigned char val[BLOCKLEN];
    store((void*)val, var);
    printf("%s\n", label);
    int i;

    for (i = 0; i < BLOCKLEN; ++i)
    {
        printf("%02x ", val[i]);
    }

    puts("\n");
}

// ---------------------------------------------------------------------

static void print_hex(const char *message, const unsigned char *x, const int len)
{
    int i;
    puts(message);

    for (i = 0; i < len; i++)
    {
        if ((i != 0) && (i % 16 == 0)) puts("");
        printf("%02x ", x[i]);
    }

    printf("     %d (octets)\n\n", len);
}

// ---------------------------------------------------------------------

static void print_context(const struct poet_ctx_t *ctx)
{
    print128("K:   ", ctx->aes_enc[0]);
    print128("L:   ", ctx->l);
    print128("K_F: ", ctx->aes_axu[0]);
    print128("Tau: ", ctx->tau);
}

// ---------------------------------------------------------------------

static void test_output(const struct poet_ctx_t *ctx,
                        const unsigned char *k, const unsigned long long klen,
                        const unsigned char *h, const unsigned long long hlen,
                        const unsigned char *m, const unsigned long long mlen,
                        const unsigned char *c, const unsigned long long clen,
                        const unsigned char *t, const unsigned long long tlen)

{
    print_hex("SK: ", k, klen);
    print_context(ctx);
    print_hex("Header/Nonce: ", h, hlen);
    print_hex("Plaintext:", m, mlen);
    print_hex("Ciphertext:", c, clen);
    print_hex("Tag:", t, tlen);
    puts("\n\n");
}

// ---------------------------------------------------------------------

static int run_test(const unsigned char *k,
                    const unsigned char *h,
                    const unsigned long long hlen,
                    const unsigned char *expected_m,
                    unsigned long long mlen,
                    const unsigned char *expected_c,
                    const unsigned char *expected_t)
{
    struct poet_ctx_t ctx;
    unsigned char* c = (unsigned char*)malloc((size_t)mlen);
    unsigned char* m = (unsigned char*)malloc((size_t)mlen);
    unsigned long long clen = mlen;
    unsigned char t[TAGLEN];

    keysetup(&ctx, k);
    process_header(&ctx, h, hlen);
    encrypt_final(&ctx, expected_m, mlen, c, t);

    if (memcmp(expected_c, c, clen) || memcmp(expected_t, t, TAGLEN)) {
        test_output(&ctx, k, KEYLEN, h, hlen, expected_m, mlen, c, clen, t, TAGLEN);
        puts("Encryption produced incorrect result");
        free(m);
        free(c);
        return -1;
    }

    keysetup(&ctx, k);
    process_header(&ctx, h, hlen);

    const int result = decrypt_final(&ctx, c, clen, t, m);
    test_output(&ctx, k, KEYLEN, h, hlen, m, mlen, c, clen, t, TAGLEN);

    if (memcmp(expected_m, m, mlen)) {
        puts("Decryption produced incorrect result");
        free(m);
        free(c);
        return -1;
    }
    
    free(m);
    free(c);
    return result;
}

// ---------------------------------------------------------------------

static int test1()
{
    unsigned long long mlen = BLOCKLEN;
    const unsigned long long hlen = 0;
    const unsigned char k[KEYLEN] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    const unsigned char m[BLOCKLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const unsigned char c[BLOCKLEN] = {
        0x7a, 0x15, 0x53, 0xd4, 0x14, 0x78, 0xb2, 0x99,
        0x3a, 0x4c, 0x19, 0x70, 0xd2, 0x41, 0x04, 0x56
    };
    const unsigned char t[TAGLEN] = {
        0xdf, 0x9e, 0xeb, 0x7e, 0x56, 0x61, 0xa7, 0x8f,
        0x72, 0x93, 0xa1, 0xf4, 0x50, 0xab, 0x71, 0x37
    };

    return run_test(k, NULL, hlen, m, mlen, c, t);
}

// ---------------------------------------------------------------------

static int test2()
{
    unsigned long long mlen = 56;
    const unsigned long long hlen = BLOCKLEN;
    const unsigned char k[KEYLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const unsigned char h[BLOCKLEN] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    const unsigned char m[56] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe
    };
    const unsigned char c[56] = {
        0x4b, 0x43, 0x0f, 0x48, 0x03, 0xae, 0x40, 0xea, 
        0xa8, 0x95, 0x42, 0xbd, 0x44, 0x70, 0x81, 0x80, 
        0x46, 0x07, 0xd1, 0x57, 0x7a, 0xc0, 0xfd, 0x90, 
        0xa0, 0xb0, 0x53, 0xa4, 0xea, 0x4f, 0xc7, 0x66, 
        0xd8, 0xd6, 0x38, 0x4e, 0x83, 0xfa, 0xbc, 0x26, 
        0x5d, 0xbe, 0xee, 0x32, 0x6f, 0xb1, 0x0c, 0x9e, 
        0x9e, 0x63, 0xc1, 0xe0, 0x79, 0x22, 0x8b, 0xd5
    };
    const unsigned char t[TAGLEN] = {
        0x67, 0x5e, 0xfa, 0x65, 0x08, 0xea, 0x2e, 0xf3, 
        0xe8, 0x74, 0x46, 0xdb, 0x18, 0x0f, 0xff, 0x73
    };
    return run_test(k, h, hlen, m, mlen, c, t);
}

// ---------------------------------------------------------------------

static int test3()
{
    unsigned long long mlen = 0;
    const unsigned long long hlen = 24;
    const unsigned char k[KEYLEN] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    const unsigned char h[24] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe
    };
    const unsigned char t[TAGLEN] = {
        0x51, 0xad, 0x44, 0x5b, 0x59, 0xca, 0xbb, 0x77, 
        0x9e, 0xcc, 0x29, 0x8e, 0x18, 0x3e, 0x36, 0x7a
    };
    return run_test(k, h, hlen, NULL, mlen, NULL, t);
}

// ---------------------------------------------------------------------

static int test4()
{
    unsigned long long mlen = 52;
    const unsigned long long hlen = 24;
    const unsigned char k[KEYLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const unsigned char h[24] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe
    };
    const unsigned char m[52] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0xfe, 0xfe, 0xba, 0xbe
    };
    const unsigned char c[52] = {
        0x2a, 0x41, 0x1f, 0x68, 0xc7, 0x01, 0x7c, 0x54, 
        0x85, 0x2e, 0x64, 0x1c, 0x81, 0x02, 0xce, 0xa0, 
        0xe3, 0x59, 0xbc, 0xe5, 0x9f, 0x76, 0x59, 0x0c, 
        0x57, 0xc9, 0xc0, 0x4a, 0x98, 0x14, 0x63, 0x5b, 
        0x7d, 0xef, 0x80, 0x62, 0x5e, 0xec, 0x82, 0xe7, 
        0x66, 0x17, 0x4c, 0x72, 0x87, 0xe7, 0xd9, 0xd4, 
        0xa9, 0x9b, 0x6a, 0x36
    };
    const unsigned char t[TAGLEN] = {
        0x8b, 0x83, 0x74, 0xf0, 0x2b, 0xc6, 0xde, 0xa1, 
        0x98, 0xa9, 0x2a, 0x8b, 0x51, 0x3b, 0x60, 0x42
    };
    return run_test(k, h, hlen, m, mlen, c, t);
}

// ---------------------------------------------------------------------

static int test5()
{
    const char k[] = "Edgar Allan Poe.";
    const char h[] = "\"Seldom we find,\" says Solomon Don Dunce,\n\"Half an idea in the profoundest sonnet.\nThrough all the flimsy things we see at once\nAs easily as through a Naples bonnet-\nTrash of all trash!- how can a lady don it?\nYet heavier far than your Petrarchan stuff-\nOwl-downy nonsense that the faintest puff\nTwirls into trunk-paper the while you con it.\"\nAnd, veritably, Sol is right enough.\nThe general tuckermanities are arrant\nBubbles- ephemeral and so transparent-\nBut this is, now- you may depend upon it-\nStable, opaque, immortal- all by dint\nOf the dear names that he concealed within 't.";
    char m[] = "The noblest name in Allegory's page,\nThe hand that traced inexorable rage;\nA pleasing moralist whose page refined,\nDisplays the deepest knowledge of the mind;\nA tender poet of a foreign tongue,\n(Indited in the language that he sung.)\nA bard of brilliant but unlicensed page\nAt once the shame and glory of our age,\nThe prince of harmony and stirling sense,\nThe ancient dramatist of eminence,\nThe bard that paints imagination's powers,\nAnd him whose song revives departed hours,\nOnce more an ancient tragic bard recall,\nIn boldness of design surpassing all.\nThese names when rightly read, a name [make] known\nWhich gathers all their glories in its own.";

    const unsigned long long hlen = (unsigned long long)strlen(h);
    unsigned long long mlen = (unsigned long long)strlen(m);
    const unsigned char c[650] = {
        0x64, 0xd5, 0x7c, 0x66, 0x98, 0xda, 0x71, 0x5a, 
        0xd5, 0xa5, 0xb0, 0x50, 0xd4, 0x0b, 0x8d, 0xcd, 
        0x40, 0xfe, 0x97, 0x10, 0xa0, 0x52, 0xc7, 0x42, 
        0xa7, 0x1f, 0x11, 0x23, 0x44, 0x15, 0x54, 0x2a, 
        0x4d, 0x22, 0x6d, 0x87, 0xa6, 0x52, 0xc1, 0x2d, 
        0x34, 0x78, 0xac, 0x9c, 0xfa, 0x9f, 0x5e, 0x87, 
        0xe6, 0x05, 0x6a, 0xc5, 0x0c, 0x07, 0xe5, 0x09, 
        0x6a, 0x9f, 0xa8, 0x57, 0x10, 0xe4, 0x94, 0x3a, 
        0x8d, 0xa6, 0x80, 0xa0, 0x24, 0x93, 0x79, 0x85, 
        0xaa, 0xf0, 0x55, 0x3c, 0x63, 0xbf, 0xd4, 0x83, 
        0x7c, 0xdb, 0x2c, 0x54, 0x0b, 0x88, 0xe5, 0x1d, 
        0xff, 0x36, 0xe8, 0xdd, 0x5b, 0x9b, 0x79, 0x04, 
        0xc4, 0x95, 0x9e, 0xbc, 0xcb, 0xbf, 0xec, 0xef, 
        0x97, 0x3b, 0xcd, 0x2d, 0x5f, 0x73, 0xe4, 0xd4, 
        0xf2, 0xc3, 0xec, 0xd6, 0xa6, 0x16, 0x34, 0xf4, 
        0xfb, 0x46, 0x03, 0x36, 0x8d, 0xb4, 0xc0, 0xea, 
        0xaf, 0xf3, 0x62, 0xc3, 0xee, 0x19, 0x0b, 0x6e, 
        0xe1, 0xb0, 0xbd, 0x1f, 0xf2, 0x55, 0x9c, 0xde, 
        0xb7, 0xbf, 0xf7, 0x9b, 0xa4, 0x50, 0xb6, 0xae, 
        0x1b, 0xac, 0xf7, 0x6f, 0x09, 0x31, 0x12, 0x6c, 
        0x05, 0x56, 0x04, 0xb1, 0x35, 0xbe, 0x4d, 0xf0, 
        0xca, 0xc7, 0x0b, 0x9f, 0x55, 0x2f, 0xd6, 0x93, 
        0xad, 0xb3, 0x0d, 0x2a, 0x41, 0x31, 0x5b, 0x73, 
        0x48, 0x9b, 0x23, 0x70, 0x23, 0x7e, 0xa7, 0x51, 
        0xd5, 0x0a, 0x15, 0x1a, 0xda, 0x6b, 0xa2, 0xb0, 
        0xb6, 0xbd, 0x20, 0x66, 0xb5, 0xfd, 0x0b, 0xc2, 
        0x00, 0xbf, 0xdb, 0x3e, 0x03, 0x50, 0x22, 0x5d, 
        0x10, 0xbe, 0xfd, 0x8d, 0x35, 0x6f, 0x7b, 0x02, 
        0x2f, 0xb8, 0x50, 0x15, 0xcc, 0x1e, 0x22, 0xf8, 
        0x08, 0x7e, 0x2d, 0x9a, 0xce, 0x29, 0x0c, 0x02, 
        0x97, 0x12, 0x42, 0x15, 0x60, 0x9c, 0xc4, 0x52, 
        0x19, 0x6b, 0x0b, 0x46, 0x2d, 0xbd, 0x12, 0x2b, 
        0xaa, 0xd6, 0xac, 0x51, 0x8f, 0x3d, 0x12, 0x83, 
        0x07, 0x93, 0xac, 0xc5, 0xfd, 0xe4, 0xc1, 0x7a, 
        0xb1, 0x3e, 0xbd, 0x03, 0xa8, 0x87, 0x77, 0xe8, 
        0x60, 0x73, 0xbb, 0x34, 0x7a, 0x94, 0x1b, 0x93, 
        0x65, 0xa5, 0xc1, 0xfa, 0x1a, 0x44, 0x57, 0xde, 
        0xfb, 0xf7, 0xeb, 0xe2, 0x82, 0x12, 0x69, 0x49, 
        0x5f, 0x8c, 0x3d, 0x44, 0xc2, 0xaa, 0x93, 0xc9, 
        0x8e, 0xb8, 0x1c, 0x2c, 0x54, 0x5c, 0xd3, 0x72, 
        0xd4, 0x29, 0xa5, 0x8e, 0xde, 0x42, 0xca, 0x6c, 
        0xd4, 0xc9, 0x99, 0x73, 0xc7, 0x16, 0x47, 0x37, 
        0x89, 0x8e, 0xe9, 0x20, 0xda, 0x76, 0x12, 0xcd, 
        0x5b, 0x03, 0x87, 0x6a, 0x03, 0x2a, 0x34, 0x88, 
        0x46, 0xdb, 0x34, 0x47, 0x60, 0x2c, 0xcf, 0x5a, 
        0x58, 0xe7, 0xbc, 0xcb, 0x7c, 0xe1, 0xd5, 0x00, 
        0xdc, 0xe9, 0x48, 0x09, 0xfe, 0x09, 0x06, 0xbf, 
        0x78, 0x6d, 0xa3, 0x42, 0x1f, 0x97, 0x07, 0x83, 
        0x14, 0x76, 0x8d, 0xe1, 0x94, 0x29, 0x72, 0xdf, 
        0x80, 0xaa, 0x79, 0x08, 0x5c, 0x7c, 0x79, 0x49, 
        0x01, 0x09, 0xba, 0xfe, 0x18, 0x7e, 0x88, 0x5e, 
        0xfc, 0x12, 0x13, 0xcb, 0xb8, 0x4b, 0x3f, 0x83, 
        0x74, 0x9e, 0xe5, 0xec, 0x5a, 0x4e, 0xd0, 0xce, 
        0x92, 0xf0, 0xae, 0x6c, 0xae, 0x07, 0x84, 0x18, 
        0x0a, 0xc9, 0xf6, 0x57, 0xbd, 0x56, 0x95, 0xef, 
        0xa1, 0x98, 0x43, 0x6a, 0xe2, 0x84, 0x9e, 0x53, 
        0x78, 0x4e, 0x47, 0x5c, 0x01, 0x20, 0xb5, 0x71, 
        0x4e, 0xd3, 0xa1, 0x6f, 0x6d, 0x97, 0x98, 0xc9, 
        0xbb, 0xc5, 0xab, 0xdb, 0x83, 0x9b, 0xf6, 0x3d, 
        0x0e, 0xbd, 0x4f, 0x0b, 0x74, 0xb1, 0xdc, 0x84, 
        0xe8, 0x42, 0x83, 0x1c, 0x03, 0x19, 0x7e, 0x21, 
        0x0b, 0xa2, 0x23, 0xcc, 0x24, 0x1f, 0xe7, 0x78, 
        0x32, 0x0b, 0xa0, 0x87, 0x98, 0xc8, 0xf1, 0x28, 
        0x9a, 0x59, 0x75, 0x3f, 0x01, 0x0f, 0x9c, 0xc6, 
        0x6e, 0xc7, 0x26, 0x8a, 0x48, 0x62, 0xf0, 0x4e, 
        0xb1, 0xd6, 0x92, 0x61, 0x50, 0xec, 0xb4, 0x3c, 
        0x95, 0x8f, 0xcb, 0xd3, 0x33, 0xe1, 0xc3, 0xce, 
        0x32, 0xbe, 0xc9, 0x0a, 0x7f, 0x78, 0x89, 0x0b, 
        0x7f, 0xfd, 0x55, 0x3e, 0x99, 0x76, 0x0e, 0xac, 
        0xd8, 0xcc, 0x69, 0x14, 0x45, 0x44, 0x56, 0x7a, 
        0x57, 0xe0, 0x83, 0xe6, 0x50, 0x3a, 0x1a, 0xc1, 
        0x45, 0xe4, 0xdd, 0x42, 0x7a, 0xcf, 0x07, 0x66, 
        0xa5, 0xad, 0xe5, 0xc2, 0x5f, 0x07, 0x57, 0x38, 
        0xa9, 0xd9, 0x10, 0xde, 0x1f, 0xde, 0x1e, 0x3a, 
        0x63, 0xea, 0xf3, 0xa2, 0xe9, 0x44, 0xb8, 0xef, 
        0x88, 0xc7, 0x02, 0xec, 0x8c, 0x1f, 0x46, 0xd1, 
        0x20, 0x52, 0x20, 0x7d, 0x6e, 0x74, 0xfa, 0x60, 
        0x0c, 0x5e, 0x58, 0x2d, 0x91, 0x41, 0xc3, 0x41, 
        0x03, 0x58, 0x30, 0x99, 0x1a, 0x31, 0x67, 0x0e, 
        0xd1, 0xed, 0xce, 0x65, 0x63, 0xe9, 0xa4, 0x8f, 
        0x13, 0x39, 0x99, 0x79, 0xa7, 0xef, 0x23, 0xb1, 
        0x2b, 0xc1
    };
    const unsigned char t[TAGLEN] = {
        0xf4, 0xbf, 0x72, 0x7a, 0x2f, 0x10, 0xfe, 0x83, 
        0x9c, 0x79, 0xe1, 0x9e, 0xa0, 0xf3, 0x5d, 0xa2
    };
    return run_test((const unsigned char*)k, (const unsigned char*)h, hlen,
                    (unsigned char*)m, mlen, c, t);
}

// ---------------------------------------------------------------------

int main()
{
    int result = 0;
    result |= test1();
    result |= test3();
    result |= test2();
    result |= test4();
    result |= test5();

    if (result) {
        puts("Test result:  FAILED");
    } else {
        puts("Tests result: SUCCESS");
    }

    return 0;
}
