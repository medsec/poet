/*
// @author Eik List
// @last-modified 2015-09-01
// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
*/
#include <stdio.h>
#include <string.h>
#include "poet.h"
#include "api.h"

// ---------------------------------------------------------------------

static void print_hex(const char *message, 
                      const unsigned char *x, 
                      const size_t len)
{
    puts(message);

    for (size_t i = 0; i < len; i++) {
        if ((i != 0) && (i % 16 == 0)) puts("");
        printf("%02x ", x[i]);
    }

    printf("     %zu (octets)\n\n", len);
}

// ---------------------------------------------------------------------

#ifdef NI_ENABLED
#include <emmintrin.h>

// ---------------------------------------------------------------------

static void store(const unsigned char* p, __m128i x)
{
    _mm_store_si128((__m128i*)p, x);
}

// ---------------------------------------------------------------------

static void print128(char* label, __m128i var)
{
    unsigned char val[BLOCKLEN];
    store(val, var);
    printf("%s\n", label);
    
    for (size_t i = 0; i < BLOCKLEN; ++i) {
        printf("%02x ", val[i]);
    }

    puts("\n");
}

// ---------------------------------------------------------------------

static void print_context(const poet_ctx_t *ctx)
{
    print128("K:   ", ctx->aes_enc[0]);
    print128("L:   ", ctx->l);
    print128("K_F: ", ctx->aes_axu[0]);
    print128("Tau: ", ctx->tau);
}

#else

static void print_context(const poet_ctx_t *ctx)
{
    print_hex("K:", (const unsigned char*)ctx->k, BLOCKLEN);
    print_hex("L:", ctx->l, BLOCKLEN);
    print_hex("K_F:", (const unsigned char*)ctx->k_axu, BLOCKLEN);
    print_hex("Tau:", ctx->tau, TAGLEN);
}

#endif 

// ---------------------------------------------------------------------

static void test_output(const poet_ctx_t *ctx,
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
    poet_ctx_t ctx;
    unsigned char* c = (unsigned char*)malloc((size_t)mlen);
    unsigned char* m = (unsigned char*)malloc((size_t)mlen);
    unsigned long long clen = mlen;
    unsigned char t[TAGLEN];

    keysetup(&ctx, k);
    process_header(&ctx, h, hlen);
    encrypt_final(&ctx, expected_m, mlen, c, &clen, t);

    if (memcmp(expected_c, c, clen) || memcmp(expected_t, t, TAGLEN)) {
        test_output(&ctx, k, KEYLEN, h, hlen, expected_m, mlen, c, clen, t, TAGLEN);
        puts("Encryption produced incorrect result");
        free(m);
        free(c);
        return -1;
    }

    keysetup(&ctx, k);
    process_header(&ctx, h, hlen);

    const int result = decrypt_final(&ctx, c, clen, t, m, &mlen);
    test_output(&ctx, k, KEYLEN, h, hlen, m, mlen, c, clen, t, TAGLEN);

    if (memcmp(expected_m, m, mlen)) {
        puts("Decryption produced incorrect result");
        free(m);
        free(c);
        return -1;
    }
    
    if (result != 0) {
        puts("Verification failed");
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
        0x04, 0xa4, 0x10, 0x96, 0x64, 0xc2, 0x7c, 0x2f, 
        0xde, 0xb4, 0x8b, 0x57, 0x10, 0x76, 0x85, 0x12
    };
    const unsigned char t[TAGLEN] = {
        0xd1, 0x7a, 0xbb, 0x56, 0x8d, 0x44, 0xca, 0x71, 
        0xdc, 0xa5, 0x48, 0x21, 0x83, 0xb1, 0x9a, 0x24
    };
    return run_test(k, NULL, hlen, m, mlen, c, t);
}

// ---------------------------------------------------------------------

static int test2()
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
        0x6C, 0x9C, 0x5F, 0xB2, 0x52, 0x01, 0xF6, 0x3A, 
        0x10, 0x7C, 0x21, 0xB6, 0xF5, 0x23, 0x11, 0x36
    };
    return run_test(k, h, hlen, NULL, mlen, NULL, t);
}

// ---------------------------------------------------------------------

static int test3()
{
    unsigned long long mlen = 8;
    const unsigned long long hlen = BLOCKLEN;
    const unsigned char k[KEYLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const unsigned char h[BLOCKLEN] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    const unsigned char m[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    const unsigned char c[8] = {
        0x6b, 0x47, 0x46, 0x29, 0xfd, 0xfd, 0xa4, 0x1b
    };
    const unsigned char t[TAGLEN] = {
        0x44, 0x8d, 0xa9, 0xcd, 0x18, 0x62, 0x84, 0xa0, 
        0x2f, 0x38, 0xfb, 0x5c, 0xe8, 0xb3, 0x5f, 0xea
    };
    return run_test(k, h, hlen, m, mlen, c, t);
}

// ---------------------------------------------------------------------

static int test4()
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
        0x62, 0x57, 0x8c, 0x0a, 0xd6, 0x78, 0x52, 0xa2, 
        0xa9, 0xbe, 0xb0, 0x9e, 0x74, 0x58, 0xfe, 0x35, 
        0x32, 0xe9, 0x6e, 0xae, 0x67, 0x24, 0xe0, 0x0a, 
        0xde, 0xe6, 0x65, 0x92, 0xa0, 0xa9, 0x1f, 0x4e, 
        0xd6, 0x8c, 0x13, 0x8b, 0x13, 0x96, 0x05, 0x27, 
        0x96, 0x8c, 0x1f, 0x53, 0x87, 0xf3, 0x15, 0xb9, 
        0xbd, 0x27, 0x87, 0xe7, 0x1f, 0x29, 0x32, 0x3d
    };
    const unsigned char t[TAGLEN] = {
        0x33, 0x0b, 0xc6, 0x95, 0x73, 0xc8, 0x72, 0xc7, 
        0xc4, 0x30, 0x36, 0x6d, 0xd0, 0x5e, 0x75, 0xe4
    };
    return run_test(k, h, hlen, m, mlen, c, t);
}

// ---------------------------------------------------------------------

static int test5()
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
        0x34, 0x5f, 0xe2, 0xc7, 0xa5, 0x2d, 0x53, 0x2f, 
        0xe7, 0x0b, 0xa8, 0x3e, 0x2a, 0x14, 0x3b, 0x9f, 
        0x25, 0x0a, 0x20, 0x30, 0xa0, 0x06, 0x38, 0x75, 
        0xdb, 0xd9, 0x27, 0xd1, 0x6b, 0x95, 0xb2, 0x99, 
        0x7b, 0x11, 0x46, 0x57, 0xf7, 0x06, 0x68, 0x2c, 
        0xaa, 0xd1, 0x05, 0x9a, 0x26, 0x56, 0xb2, 0x51, 
        0x0d, 0x17, 0x5a, 0x92
    };
    const unsigned char t[TAGLEN] = {
        0xbc, 0x9b, 0x32, 0x43, 0x01, 0x9d, 0x0d, 0x5a, 
        0xbf, 0x22, 0xce, 0x9c, 0xa6, 0xdb, 0xb8, 0x33
    };
    return run_test(k, h, hlen, m, mlen, c, t);
}

// ---------------------------------------------------------------------

static int test6()
{
    const char k[] = "Edgar Allan Poe.";
    const char h[] = "\"Seldom we find,\" says Solomon Don Dunce,\n\"Half an idea in the profoundest sonnet.\nThrough all the flimsy things we see at once\nAs easily as through a Naples bonnet-\nTrash of all trash!- how can a lady don it?\nYet heavier far than your Petrarchan stuff-\nOwl-downy nonsense that the faintest puff\nTwirls into trunk-paper the while you con it.\"\nAnd, veritably, Sol is right enough.\nThe general tuckermanities are arrant\nBubbles- ephemeral and so transparent-\nBut this is, now- you may depend upon it-\nStable, opaque, immortal- all by dint\nOf the dear names that he concealed within 't.";
    char m[] = "The noblest name in Allegory's page,\nThe hand that traced inexorable rage;\nA pleasing moralist whose page refined,\nDisplays the deepest knowledge of the mind;\nA tender poet of a foreign tongue,\n(Indited in the language that he sung.)\nA bard of brilliant but unlicensed page\nAt once the shame and glory of our age,\nThe prince of harmony and stirling sense,\nThe ancient dramatist of eminence,\nThe bard that paints imagination's powers,\nAnd him whose song revives departed hours,\nOnce more an ancient tragic bard recall,\nIn boldness of design surpassing all.\nThese names when rightly read, a name [make] known\nWhich gathers all their glories in its own.";

    const unsigned long long hlen = (unsigned long long)strlen(h);
    unsigned long long mlen = (unsigned long long)strlen(m);
    const unsigned char c[650] = {
        0x28, 0xe0, 0x8c, 0xd2, 0xf6, 0xbe, 0x6b, 0x4b, 
        0x77, 0xec, 0x28, 0xb4, 0x2d, 0x7b, 0x73, 0x99, 
        0x1a, 0xfe, 0x27, 0xe5, 0xea, 0x9c, 0xe5, 0x2b, 
        0xfa, 0x01, 0x42, 0x5b, 0xc4, 0xaf, 0x1c, 0x77, 
        0x81, 0xa9, 0x46, 0x96, 0x36, 0x21, 0x2e, 0x08, 
        0x17, 0x11, 0xd2, 0xbf, 0x6c, 0xc1, 0x04, 0xe7, 
        0xac, 0xaa, 0xf3, 0xb5, 0x9c, 0x66, 0x22, 0x1d, 
        0x6c, 0xd5, 0x6a, 0x35, 0x2c, 0x34, 0x2d, 0x77, 
        0x63, 0x1a, 0xd2, 0xcf, 0x53, 0x86, 0xf1, 0xf6, 
        0x39, 0xc2, 0x99, 0xef, 0x7f, 0x77, 0x90, 0x32, 
        0xcb, 0xe3, 0x7e, 0x27, 0xc1, 0xeb, 0x7f, 0xed, 
        0x13, 0xeb, 0xb7, 0xa2, 0x20, 0x7c, 0x01, 0x40, 
        0x7e, 0x63, 0xf2, 0xdd, 0xc3, 0x55, 0x1a, 0x71, 
        0xfe, 0xbc, 0xce, 0x21, 0xdb, 0xf5, 0x24, 0x87, 
        0xbd, 0x8c, 0xb6, 0x81, 0x7f, 0xce, 0xe1, 0x25, 
        0x45, 0x0d, 0x28, 0x61, 0x44, 0x67, 0x65, 0x87, 
        0x17, 0x2c, 0xc2, 0xfa, 0x3c, 0x38, 0xe0, 0xbb, 
        0x59, 0x3d, 0x1f, 0xce, 0xf4, 0x66, 0xc5, 0x26, 
        0xef, 0x2b, 0xe3, 0x2e, 0xdf, 0x5d, 0x25, 0xc7, 
        0xef, 0x1c, 0xa9, 0xec, 0x44, 0x49, 0x9b, 0xfb, 
        0xd6, 0x86, 0xf4, 0xcf, 0x08, 0xc0, 0x3e, 0xc1, 
        0x65, 0xab, 0x54, 0x6e, 0xc7, 0x00, 0xda, 0xbb, 
        0x88, 0xae, 0xff, 0xd3, 0xf0, 0x36, 0xdc, 0x95, 
        0x1b, 0x70, 0x9e, 0x87, 0xd3, 0x94, 0xbb, 0xed, 
        0x77, 0xab, 0x2c, 0x85, 0x90, 0xac, 0x71, 0x98, 
        0x79, 0xb4, 0xcf, 0x98, 0xa9, 0x40, 0xc0, 0x03, 
        0xdb, 0xc9, 0x96, 0xe4, 0x67, 0x09, 0x96, 0x13, 
        0x1d, 0x89, 0xa5, 0x04, 0xb5, 0x1f, 0xd2, 0xd9, 
        0x7b, 0x2a, 0x70, 0x77, 0x41, 0x05, 0x7f, 0xfa, 
        0xe9, 0x9d, 0xaf, 0xc2, 0x8a, 0x38, 0xbb, 0xc9, 
        0x75, 0x82, 0x66, 0x5a, 0x78, 0x3c, 0x4b, 0x6a, 
        0xc3, 0x90, 0x03, 0xa8, 0x08, 0xa5, 0xda, 0xd7, 
        0xab, 0xa3, 0x99, 0xe9, 0x2e, 0x28, 0xc7, 0x76, 
        0x14, 0x3c, 0x3e, 0xd5, 0x21, 0x08, 0xac, 0xa9, 
        0x45, 0xc9, 0xe2, 0x22, 0x68, 0xa8, 0xaa, 0xcf, 
        0x92, 0xe3, 0xc4, 0x83, 0x23, 0x8e, 0x5f, 0x37, 
        0x67, 0xd9, 0x9a, 0xa5, 0xf8, 0xd7, 0x35, 0xaf, 
        0xaf, 0xf5, 0xac, 0xe9, 0x03, 0xde, 0xab, 0x14, 
        0x33, 0xff, 0x5b, 0x5d, 0x85, 0xbd, 0xc6, 0xbc, 
        0xb9, 0x98, 0x81, 0xf8, 0xd1, 0x0c, 0x05, 0x5c, 
        0x28, 0xc2, 0x95, 0xe0, 0x17, 0x30, 0x5f, 0x08, 
        0x01, 0x19, 0xcc, 0xbd, 0x57, 0xe1, 0x26, 0xc5, 
        0x5d, 0x47, 0xad, 0x67, 0x87, 0xf9, 0xbe, 0x51, 
        0x3d, 0x86, 0x17, 0x11, 0x6e, 0x47, 0x09, 0x93, 
        0x48, 0xa6, 0x99, 0x80, 0xcf, 0xd6, 0x0a, 0xb1, 
        0xf5, 0x10, 0x28, 0x77, 0x16, 0xf5, 0xa6, 0x16, 
        0x9c, 0x3e, 0xcb, 0x4e, 0x80, 0xb2, 0x05, 0xae, 
        0xb9, 0xe1, 0x2f, 0xa9, 0x6d, 0x8f, 0xd9, 0x7c, 
        0x88, 0x4b, 0xa4, 0x31, 0xf7, 0xe9, 0x24, 0x15, 
        0xfd, 0xd1, 0xea, 0xde, 0x69, 0x1b, 0x91, 0x59, 
        0xe1, 0xce, 0xcc, 0x2d, 0xca, 0x25, 0x30, 0xbe, 
        0xbb, 0x48, 0x47, 0x21, 0x0b, 0x96, 0x40, 0xef, 
        0xcd, 0xc4, 0xb5, 0x19, 0xb0, 0xb8, 0xe7, 0xb6, 
        0x14, 0x9e, 0xdd, 0xe6, 0xee, 0xc8, 0x84, 0x91, 
        0x97, 0x2b, 0xfa, 0x63, 0xb7, 0xda, 0xf9, 0x10, 
        0x68, 0x19, 0x42, 0x04, 0x96, 0x72, 0xed, 0x99, 
        0xf8, 0x08, 0xd6, 0xa0, 0x3c, 0xb2, 0xd6, 0x06, 
        0x25, 0xf9, 0xa3, 0xfe, 0x9e, 0xc5, 0x8c, 0x2d, 
        0x6c, 0xc5, 0x3b, 0x18, 0x35, 0x24, 0x06, 0x20, 
        0xe9, 0x30, 0x68, 0xaf, 0x75, 0xf8, 0xd1, 0x99, 
        0xd4, 0x09, 0xf1, 0xab, 0x5d, 0xcf, 0xc7, 0x00, 
        0x11, 0x8e, 0x75, 0x0b, 0x59, 0x06, 0x82, 0x0b, 
        0x41, 0x48, 0x09, 0xab, 0x9d, 0x37, 0x8c, 0x64, 
        0x37, 0x7e, 0xb9, 0xcb, 0xfe, 0x18, 0xa7, 0xdf, 
        0x31, 0xd3, 0x28, 0xe4, 0xe1, 0x70, 0xf5, 0x04, 
        0xf2, 0xc5, 0xec, 0x23, 0x8c, 0xb1, 0x5d, 0x8c, 
        0xe8, 0x81, 0x90, 0x38, 0x8d, 0x88, 0x98, 0x8b, 
        0x19, 0xd1, 0x51, 0x8b, 0xa0, 0x84, 0xac, 0x95, 
        0x62, 0x06, 0xdd, 0x7c, 0xaf, 0xa7, 0xd8, 0x94, 
        0x7a, 0x92, 0xa5, 0xf7, 0x95, 0x89, 0x9d, 0xd9, 
        0xe8, 0xcd, 0xfd, 0x40, 0x9a, 0x89, 0x2a, 0x4d, 
        0xcf, 0xc5, 0xb6, 0xbf, 0xb8, 0xf8, 0xf1, 0x4f, 
        0xb8, 0xa0, 0x71, 0xd2, 0xa1, 0xb0, 0x83, 0xdd, 
        0xe2, 0xed, 0x82, 0x18, 0x42, 0x2b, 0x04, 0xa7, 
        0xf3, 0x2b, 0x62, 0x06, 0x2f, 0xe4, 0x4a, 0xf2, 
        0x3f, 0x33, 0x1b, 0x33, 0x6d, 0x6c, 0x3b, 0x4c, 
        0xb9, 0xb6, 0x75, 0xf9, 0xad, 0xdd, 0xbd, 0x64, 
        0xbe, 0x55, 0x46, 0xa4, 0x59, 0xc8, 0x2b, 0x93, 
        0x4f, 0xed, 0x32, 0x2e, 0x3a, 0x42, 0x6c, 0xdc, 
        0xe0, 0xd4, 0xb4, 0x87, 0x55, 0x04, 0x65, 0x49, 
        0xb3, 0xa1, 0x9d, 0x38, 0x8f, 0xb0, 0x65, 0x7a, 
        0xbe, 0x31
    };
    const unsigned char t[TAGLEN] = {
        0xa4, 0x48, 0x62, 0x82, 0xd7, 0xd9, 0xf0, 0x88, 
        0x72, 0xd8, 0xf7, 0x0f, 0x97, 0x05, 0x6b, 0x61
    };
    return run_test((const unsigned char*)k, (const unsigned char*)h, hlen,
                    (unsigned char*)m, mlen, c, t);
}

// ---------------------------------------------------------------------

int main()
{
    int result = 0;
    result |= test1();
    result |= test2();
    result |= test3();
    result |= test4();
    result |= test5();
    result |= test6();

    if (result) {
        puts("Test result:  FAILED");
    } else {
        puts("Tests result: SUCCESS");
    }

    return 0;
}