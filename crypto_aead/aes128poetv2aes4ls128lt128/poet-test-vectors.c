/*
// @author Eik List and Christian Forler
// @last-modified 2016-08-04
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

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec,
                        const unsigned char *npub,
                        const unsigned char *k);

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec,
                        const unsigned char *c, unsigned long long clen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *npub,
                        const unsigned char *k);

// ---------------------------------------------------------------------

static void print_hex(const char *message, 
                      const unsigned char *x, 
                      const size_t len)
{
    puts(message);
    const size_t clamped_len = (len <= 1024) ? len : 1024;

    for (size_t i = 0; i < clamped_len; i++) {
        if ((i != 0) && (i % 16 == 0)) puts("");
        printf("%02x ", x[i]);
    }

    if (clamped_len == len) {
        printf("     %zu (octets)\n\n", len);
    } else {
        printf("     %zu/%zu (octets)\n\n", clamped_len, len);
    }
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

static unsigned char* generate_multi_part_message(
    const size_t num_full_parts, 
    const size_t num_bytes_in_final_part, 
    const unsigned long num_blocks_in_part, 
    unsigned long long* num_bytes) 
{
    *num_bytes = num_bytes_in_final_part
        + (num_full_parts * num_blocks_in_part * BLOCKLEN);
    unsigned char* message = (unsigned char*)malloc(*num_bytes);

    for (size_t i = 0; i < *num_bytes; i++) {
        message[i] = i & 0xFF;
    }
    
    return message;
}

// ---------------------------------------------------------------------

static unsigned char* read_from_file(const char* path, 
                                     unsigned long long* num_bytes) { 
    FILE* f = fopen(path, "r");

    if (f == NULL) {
        *num_bytes = 0;
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    int fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    unsigned char* string = (unsigned char*)malloc(fsize + 1);

    fread(string, fsize, 1, f);
    fclose(f);
    string[fsize] = 0;
    *num_bytes = fsize;
    return string;
}

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
                    const unsigned long long expected_clen, 
                    const unsigned char *expected_t)
{
    poet_ctx_t ctx;
    const unsigned long long expected_mlen = mlen;
    unsigned char* c = (expected_clen == 0) ? 
        NULL : (unsigned char*)malloc((size_t)expected_clen);
    unsigned char* m = (mlen == 0) ? 
        NULL : (unsigned char*)malloc((size_t)mlen);
    unsigned char t[TAGLEN];
    unsigned long long clen;

    keysetup(&ctx, k);
    process_header(&ctx, h, hlen);
    encrypt_final(&ctx, expected_m, mlen, c, &clen, t);

    if (clen != expected_clen) {
        printf("Expected ciphertext length %llu, but was %llu bytes \n", 
            expected_clen, clen);
    }

    if (memcmp(expected_c, c, expected_clen)
        || memcmp(expected_t, t, TAGLEN)) {
        test_output(&ctx, k, KEYLEN, h, hlen, expected_m, mlen, 
            c, expected_clen, t, TAGLEN);
        puts("Encryption produced incorrect result");
        free(m);
        free(c);
        return -1;
    }

    keysetup(&ctx, k);
    process_header(&ctx, h, hlen);

    const int result = decrypt_final(&ctx, c, clen, t, m, &mlen);

    if (mlen != expected_mlen) {
        printf("Expected plaintext length %llu, but was %llu bytes \n", 
            expected_mlen, mlen);
    }

    test_output(&ctx, k, KEYLEN, h, hlen, m, mlen, c, expected_clen, t, TAGLEN);

    if (memcmp(expected_m, m, expected_mlen)) {
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
    const unsigned long long clen = BLOCKLEN;
    const unsigned long long hlen = 0;
    const unsigned char k[KEYLEN] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    const unsigned char m[BLOCKLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const unsigned char c[BLOCKLEN] = {
        0x6C, 0xAE, 0xC4, 0x40, 0x53, 0xEF, 0x03, 0x7A, 
        0xCD, 0x13, 0x01, 0x39, 0x06, 0xAF, 0xDF, 0xF9
    };
    const unsigned char t[TAGLEN] = {
        0x82, 0xC5, 0x94, 0xF1, 0x2B, 0x15, 0xB1, 0x6E, 
        0x31, 0x72, 0x45, 0xDC, 0x8F, 0x9D, 0xBC, 0x67
    };
    return run_test(k, NULL, hlen, m, mlen, c, clen, t);
}

// ---------------------------------------------------------------------

static int test2()
{
    unsigned long long mlen = 0;
    const unsigned long long clen = 0;
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
        0x56, 0xF4, 0x88, 0xE4, 0x1E, 0xE3, 0x28, 0x6B, 
        0xE8, 0xB6, 0xE8, 0x35, 0xC1, 0x05, 0xD5, 0x71
    };
    return run_test(k, h, hlen, NULL, mlen, NULL, clen, t);
}

// ---------------------------------------------------------------------

static int test3()
{
    unsigned long long mlen = 8;
    const unsigned long long clen = 8;
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
        0x15, 0x7C, 0x7A, 0x82, 0x87, 0xEE, 0xD8, 0x31
    };
    const unsigned char t[TAGLEN] = {
        0xED, 0x33, 0xF1, 0x70, 0x1F, 0x53, 0x6B, 0x7E, 
        0xC9, 0xB8, 0x7E, 0xB5, 0x04, 0x86, 0x2F, 0x7C
    };
    return run_test(k, h, hlen, m, mlen, c, clen, t);
}

// ---------------------------------------------------------------------

static int test4()
{
    unsigned long long mlen = 56;
    const unsigned long long clen = 56;
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
        0xDA, 0xE2, 0x78, 0xD4, 0x32, 0x74, 0xD7, 0x8D, 
        0x81, 0x6A, 0x33, 0x28, 0xCB, 0x96, 0xBD, 0xFD, 
        0x97, 0xB0, 0x29, 0x34, 0x1E, 0x73, 0x0C, 0x0D, 
        0xA3, 0xA9, 0x32, 0x8E, 0x8F, 0x9B, 0x21, 0x2C, 
        0x6B, 0x3B, 0xB0, 0x5A, 0x19, 0x11, 0x87, 0x7D, 
        0x7A, 0x7C, 0xD8, 0x99, 0x9C, 0x99, 0x3C, 0xEB, 
        0x1C, 0xE9, 0x96, 0xE9, 0xDC, 0xC8, 0x20, 0x50
    };
    const unsigned char t[TAGLEN] = {
        0x38, 0xBD, 0x98, 0x8B, 0x87, 0xC5, 0x10, 0x85, 
        0x58, 0xA3, 0xF9, 0x24, 0xA7, 0xAE, 0x51, 0x72
    };
    return run_test(k, h, hlen, m, mlen, c, clen, t);
}

// ---------------------------------------------------------------------

static int test5()
{
    unsigned long long mlen = 52;
    const unsigned long long clen = 52;
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
        0xCE, 0x4F, 0x04, 0xF8, 0xC4, 0x42, 0x70, 0xC9, 
        0x57, 0xBF, 0x24, 0xFC, 0xDA, 0x43, 0xB3, 0x6E, 
        0xF5, 0x43, 0xBD, 0xD5, 0xF5, 0x82, 0xA9, 0x71, 
        0x09, 0xFB, 0xE8, 0xAD, 0xFD, 0x1A, 0x67, 0x52, 
        0xD2, 0xFF, 0x67, 0x34, 0x02, 0xB2, 0xCE, 0x1C, 
        0x74, 0x38, 0xF1, 0x23, 0xC0, 0x1C, 0xD9, 0xC6, 
        0xAD, 0xC3, 0x33, 0x9E
    };
    const unsigned char t[TAGLEN] = {
        0x3B, 0x48, 0xC8, 0xD1, 0x1A, 0xCB, 0x57, 0x67, 
        0xAB, 0xBF, 0x3D, 0xDF, 0x28, 0x56, 0xA4, 0x00
    };
    return run_test(k, h, hlen, m, mlen, c, clen, t);
}

// ---------------------------------------------------------------------

static int test6()
{
    const char k[] = "Edgar Allan Poe.";
    const char h[] = "\"Seldom we find,\" says Solomon Don Dunce,\n\"Half an idea in the profoundest sonnet.\nThrough all the flimsy things we see at once\nAs easily as through a Naples bonnet-\nTrash of all trash!- how can a lady don it?\nYet heavier far than your Petrarchan stuff-\nOwl-downy nonsense that the faintest puff\nTwirls into trunk-paper the while you con it.\"\nAnd, veritably, Sol is right enough.\nThe general tuckermanities are arrant\nBubbles- ephemeral and so transparent-\nBut this is, now- you may depend upon it-\nStable, opaque, immortal- all by dint\nOf the dear names that he concealed within 't.";
    char m[] = "The noblest name in Allegory's page,\nThe hand that traced inexorable rage;\nA pleasing moralist whose page refined,\nDisplays the deepest knowledge of the mind;\nA tender poet of a foreign tongue,\n(Indited in the language that he sung.)\nA bard of brilliant but unlicensed page\nAt once the shame and glory of our age,\nThe prince of harmony and stirling sense,\nThe ancient dramatist of eminence,\nThe bard that paints imagination's powers,\nAnd him whose song revives departed hours,\nOnce more an ancient tragic bard recall,\nIn boldness of design surpassing all.\nThese names when rightly read, a name [make] known\nWhich gathers all their glories in its own.";

    const unsigned long long hlen = (unsigned long long)strlen(h);
    unsigned long long mlen = (unsigned long long)strlen(m);
    const unsigned long long clen = 650;
    const unsigned char c[650] = {
        0x3B, 0x7A, 0xDB, 0xAD, 0x02, 0x44, 0x45, 0xCA, 
        0x09, 0xD9, 0x67, 0xE2, 0x2B, 0x58, 0xC4, 0x57, 
        0x96, 0x60, 0x70, 0xB8, 0xF4, 0xF0, 0x08, 0x6A, 
        0x9F, 0x17, 0x55, 0x87, 0xEE, 0x57, 0xD7, 0xAE, 
        0x68, 0x61, 0x78, 0x11, 0x87, 0x57, 0x8C, 0xCA, 
        0x06, 0x49, 0x33, 0xD2, 0x0C, 0x4A, 0x0F, 0xCC, 
        0xDF, 0x44, 0xA9, 0xE9, 0x8F, 0xB8, 0x9B, 0x93, 
        0xFE, 0x3E, 0xA9, 0x0A, 0xD9, 0xA8, 0x95, 0x4C, 
        0x73, 0xCA, 0x3C, 0xA7, 0x70, 0x3A, 0x59, 0xB4, 
        0x4A, 0x0B, 0x25, 0xA0, 0x34, 0xCD, 0x99, 0xEE, 
        0x3F, 0x86, 0x41, 0x4E, 0x67, 0xF6, 0x4E, 0xAD, 
        0x0B, 0xC2, 0x46, 0x9A, 0xF9, 0x25, 0xE1, 0x00, 
        0xE8, 0x44, 0x26, 0xC5, 0x70, 0x5B, 0x1A, 0x76, 
        0x33, 0xA5, 0x0A, 0x78, 0xE5, 0x64, 0x86, 0xED, 
        0xFB, 0xFF, 0x23, 0xCF, 0xCB, 0x77, 0x7C, 0xBA, 
        0x3C, 0x03, 0x2B, 0xA8, 0x9E, 0xE0, 0x93, 0xA3, 
        0xCA, 0xC9, 0x96, 0xDA, 0x56, 0x3E, 0x7C, 0x8F, 
        0xA2, 0xF5, 0x47, 0x77, 0xD9, 0xF5, 0xE0, 0x56, 
        0xF8, 0x98, 0x07, 0x03, 0x32, 0x0D, 0x06, 0xE0, 
        0x1F, 0x7D, 0xCC, 0xDA, 0xF1, 0xCE, 0xCB, 0x94, 
        0xE8, 0x6F, 0xCA, 0x0F, 0x60, 0xFF, 0x3E, 0xAD, 
        0xF8, 0x05, 0x4D, 0xDD, 0xB3, 0xC5, 0x9E, 0x09, 
        0x89, 0x2F, 0x06, 0x35, 0xC0, 0xCB, 0x10, 0xBF, 
        0x08, 0x7C, 0xFC, 0x13, 0xBD, 0x31, 0x40, 0x93, 
        0xEF, 0x66, 0x0A, 0xD7, 0x0C, 0x6C, 0x29, 0x31, 
        0xD4, 0x66, 0xE9, 0x44, 0x67, 0x0F, 0x1F, 0xD5, 
        0x85, 0x6F, 0xF4, 0xD1, 0xAD, 0xD1, 0x4D, 0x5A, 
        0x0A, 0x63, 0xFB, 0xD4, 0xD9, 0xCB, 0x5E, 0x5A, 
        0x2A, 0x4C, 0xB8, 0x63, 0xC3, 0x8F, 0x02, 0xEC, 
        0xBC, 0x03, 0x6F, 0xB4, 0x72, 0xC2, 0x7C, 0x89, 
        0xA6, 0x49, 0xAB, 0xB3, 0x69, 0xC7, 0xD8, 0xA2, 
        0x37, 0x75, 0xFD, 0x07, 0x3E, 0x5D, 0x63, 0x64, 
        0x32, 0x70, 0x5F, 0x8C, 0x49, 0x9E, 0x76, 0x40, 
        0x10, 0x85, 0x3F, 0x9C, 0xB0, 0x9F, 0x02, 0xDF, 
        0xAC, 0x7E, 0xED, 0x3B, 0x69, 0xE0, 0xB8, 0x41, 
        0xEA, 0xB8, 0xD9, 0xED, 0xB9, 0x0E, 0x83, 0xE2, 
        0x18, 0x1C, 0x4C, 0xEF, 0xC6, 0x9C, 0x20, 0x5E, 
        0xAE, 0xD8, 0x79, 0xF9, 0xAF, 0x9E, 0xC6, 0x1A, 
        0xD9, 0x7E, 0xAD, 0x9B, 0x07, 0x06, 0xB0, 0x04, 
        0x3A, 0x01, 0x38, 0xF0, 0x72, 0xB9, 0x19, 0x5D, 
        0xEB, 0x72, 0x3B, 0xB9, 0xAA, 0xD3, 0xA0, 0x4B, 
        0xF3, 0xB6, 0xB7, 0x49, 0xF8, 0x7E, 0x84, 0xE3, 
        0x76, 0xA2, 0x1D, 0xFA, 0x43, 0x41, 0x21, 0x7D, 
        0x78, 0x7B, 0xF9, 0x1B, 0x9A, 0xC1, 0x59, 0x65, 
        0x0D, 0x30, 0x34, 0x32, 0x87, 0x53, 0x40, 0x4C, 
        0xC8, 0x86, 0x3D, 0xBC, 0x01, 0xBB, 0xF1, 0xEC, 
        0xE5, 0x2E, 0xF5, 0xAF, 0x61, 0xC3, 0x0E, 0x51, 
        0xD6, 0x0E, 0x62, 0x2C, 0x44, 0x2C, 0x72, 0x0C, 
        0x76, 0x1C, 0xBE, 0xE6, 0x26, 0xDD, 0x02, 0x1C, 
        0xB6, 0x9B, 0xD8, 0xAF, 0x21, 0xFE, 0xE1, 0x09, 
        0xCA, 0x9B, 0xD1, 0x51, 0x4A, 0x9A, 0x3F, 0x01, 
        0xB1, 0x9C, 0xD2, 0x77, 0x50, 0x1A, 0x68, 0x6E, 
        0x1A, 0x28, 0x63, 0x9E, 0xF5, 0x81, 0x36, 0x76, 
        0xB9, 0xA6, 0xF6, 0x0B, 0x75, 0xA5, 0x82, 0x42, 
        0x74, 0x4D, 0xEF, 0x33, 0x0E, 0x67, 0xDA, 0x03, 
        0x5F, 0x8B, 0x34, 0x0A, 0xCC, 0x3C, 0xF8, 0xD2, 
        0xB6, 0xAD, 0xDA, 0x3F, 0x27, 0xCB, 0x34, 0x6D, 
        0x87, 0x34, 0x25, 0x4D, 0x05, 0x8A, 0xDF, 0xFD, 
        0x22, 0x9C, 0xDE, 0xCB, 0x61, 0x68, 0xF0, 0x1F, 
        0xC1, 0xDC, 0xE6, 0xD0, 0xFE, 0x49, 0x24, 0xEB, 
        0xC8, 0x71, 0xF0, 0x59, 0xC1, 0xCD, 0x7E, 0xEB, 
        0x0D, 0xC6, 0x80, 0x41, 0x7F, 0x38, 0x8E, 0xC2, 
        0x53, 0x82, 0xBF, 0x13, 0x82, 0x8C, 0x67, 0x6D, 
        0x0A, 0xE6, 0x9A, 0x00, 0xC1, 0xD1, 0x24, 0xCE, 
        0xBA, 0x27, 0xD3, 0x3F, 0xBF, 0x6C, 0x2A, 0x78, 
        0x67, 0xBD, 0x27, 0x2B, 0xF3, 0x24, 0x46, 0x88, 
        0x97, 0x2D, 0x59, 0x04, 0x2F, 0x9A, 0x84, 0xE4, 
        0x60, 0xE5, 0x8E, 0x13, 0x00, 0xCD, 0xB7, 0x79, 
        0x77, 0xB7, 0x23, 0xD4, 0x62, 0x68, 0x93, 0x16, 
        0x40, 0x7D, 0x82, 0x90, 0xF6, 0xEB, 0xF4, 0x3C, 
        0x6F, 0x37, 0xC0, 0x8B, 0xD8, 0x8B, 0xB4, 0xE9, 
        0x2C, 0xC3, 0x04, 0x2D, 0x51, 0x6D, 0x6F, 0xEE, 
        0xBC, 0xFD, 0xEA, 0xE6, 0x34, 0xE8, 0x0A, 0xA6, 
        0x1E, 0xC0, 0xFA, 0xF7, 0x0D, 0xCA, 0xFB, 0x64, 
        0xEB, 0x62, 0x04, 0xDB, 0x19, 0xD7, 0xB8, 0xCB, 
        0x89, 0x28, 0x98, 0xF1, 0x7C, 0x26, 0xF4, 0xD7, 
        0xED, 0x39, 0x94, 0xBF, 0x81, 0xF2, 0x38, 0xCB, 
        0x00, 0xB8, 0xCC, 0x6A, 0xD3, 0x7B, 0xEF, 0x9F, 
        0x17, 0xC3, 0xFD, 0x9C, 0x16, 0x19, 0x26, 0x28, 
        0xB7, 0x16, 0x39, 0x2C, 0x3A, 0x66, 0x41, 0x4A, 
        0x79, 0xF4, 0x99, 0xD1, 0x67, 0x13, 0xB9, 0xE6, 
        0x55, 0x1E
    };
    const unsigned char t[TAGLEN] = {
        0x1C, 0x1D, 0xA2, 0xD8, 0xF5, 0xA5, 0x5F, 0x2D, 
        0xA1, 0xAC, 0x91, 0x14, 0xF4, 0x11, 0x8F, 0xA7
    };
    return run_test((const unsigned char*)k, (const unsigned char*)h, hlen,
                    (unsigned char*)m, mlen, c, clen, t);
}

// ---------------------------------------------------------------------

static int test7()
{
    unsigned long long mlen = 2*BLOCKLEN;
    const unsigned long long clen = mlen;
    const unsigned long long hlen = 0;
    const unsigned char k[KEYLEN] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    const unsigned char m[2*BLOCKLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const unsigned char c[2*BLOCKLEN] = {
        0xe1, 0x84, 0x6e, 0x43, 0x83, 0x53, 0x8e, 0xb6, 
        0xa0, 0xa4, 0x2a, 0xc3, 0x4a, 0x48, 0x05, 0x51, 
        0x0a, 0xbc, 0x9d, 0x0f, 0x1c, 0x1b, 0xab, 0x3a, 
        0x90, 0xef, 0x8b, 0x99, 0xf2, 0x43, 0x2c, 0x17
    };
    const unsigned char t[TAGLEN] = {
        0x44, 0xbb, 0x7b, 0x8d, 0xb4, 0x53, 0x34, 0xe1, 
        0xf7, 0x92, 0xea, 0x42, 0xbc, 0x54, 0xce, 0x40
    };
    return run_test(k, NULL, hlen, m, mlen, c, clen, t);
}

// ---------------------------------------------------------------------

static int test8()
{
    unsigned long long mlen = 3*BLOCKLEN;
    const unsigned long long clen = mlen;
    const unsigned long long hlen = 0;
    const unsigned char k[KEYLEN] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    const unsigned char m[3*BLOCKLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const unsigned char c[3*BLOCKLEN] = {
        0xe1, 0x84, 0x6e, 0x43, 0x83, 0x53, 0x8e, 0xb6, 
        0xa0, 0xa4, 0x2a, 0xc3, 0x4a, 0x48, 0x05, 0x51, 
        0x98, 0x49, 0x83, 0xdc, 0x58, 0x3b, 0x98, 0xfc, 
        0xbb, 0x65, 0x8a, 0xa5, 0x3d, 0xa1, 0x2a, 0xec, 
        0x8c, 0x0b, 0x20, 0x41, 0x3d, 0xbd, 0x45, 0x21, 
        0x05, 0xf6, 0x29, 0x59, 0x2b, 0x13, 0xae, 0x34
    };
    const unsigned char t[TAGLEN] = {
        0xfa, 0xb5, 0xe0, 0x5b, 0xb9, 0xab, 0x13, 0x1b, 
        0x8d, 0x7c, 0x83, 0xf4, 0xb0, 0x8f, 0xbf, 0x9a
    };
    return run_test(k, NULL, hlen, m, mlen, c, clen, t);
}

// ---------------------------------------------------------------------

static int test9()
{
    unsigned long long mlen = 4*BLOCKLEN;
    const unsigned long long clen = mlen;
    const unsigned long long hlen = 2*BLOCKLEN;
    const unsigned char k[KEYLEN] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    const unsigned char h[2*BLOCKLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const unsigned char m[4*BLOCKLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const unsigned char c[4*BLOCKLEN] = {
        0x7a, 0xd5, 0xa9, 0x02, 0x3a, 0x54, 0x39, 0xb3, 
        0x16, 0x19, 0x62, 0x5e, 0x34, 0x67, 0x1b, 0xb8, 
        0x9d, 0xb9, 0x48, 0x0c, 0x76, 0xed, 0xa4, 0xcc, 
        0x84, 0x00, 0xce, 0x95, 0x97, 0x4c, 0xb7, 0x4c, 
        0xb7, 0xf5, 0x62, 0x98, 0xaa, 0xf5, 0x37, 0x0c, 
        0x15, 0xf0, 0xb8, 0x44, 0x02, 0x99, 0x58, 0x1f, 
        0xbf, 0x8c, 0x4b, 0xd2, 0x3d, 0xf0, 0x6c, 0x27, 
        0xd3, 0x5e, 0x3e, 0x2b, 0x09, 0x61, 0xd7, 0x8a
    };
    const unsigned char t[TAGLEN] = {
        0x0e, 0x2c, 0x3d, 0x9a, 0xfa, 0x5d, 0xe5, 0x3c, 
        0x9b, 0xb1, 0xda, 0x59, 0xf9, 0xb5, 0xef, 0xf9
    };
    return run_test(k, h, hlen, m, mlen, c, clen, t);
}

// ---------------------------------------------------------------------

static int test10()
{
    unsigned long long mlen = 35;
    const unsigned long long clen = mlen;
    const unsigned long long hlen = 28;
    const unsigned char k[KEYLEN] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    const unsigned char h[28] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb
    };
    const unsigned char m[35] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 
        0x00, 0x11, 0x22
    };
    const unsigned char c[35] = {
        0xe4, 0x50, 0xb4, 0x6d, 0x61, 0x57, 0xb9, 0xd7, 
        0xaa, 0xc2, 0xec, 0x3f, 0x7b, 0xe9, 0xdb, 0xcb, 
        0xfd, 0xcf, 0x85, 0x32, 0xc0, 0xb2, 0xbd, 0x1c, 
        0x8c, 0x95, 0x55, 0xf3, 0xff, 0xf8, 0x89, 0x4d, 
        0x4a, 0x35, 0xf5
    };
    const unsigned char t[TAGLEN] = {
        0x27, 0x66, 0x73, 0x37, 0x88, 0x25, 0xeb, 0x66, 
        0x09, 0x89, 0x7e, 0x67, 0xf5, 0x95, 0xf2, 0x0f
    };
    return run_test(k, h, hlen, m, mlen, c, clen, t);
}

// ---------------------------------------------------------------------

static void fill(unsigned char* buffer, const size_t n) {
    for (size_t i = 0; i < n; ++i) {
        buffer[i] = i & 0xFF;
    }
}

// ---------------------------------------------------------------------

static int tests_from_supercop() {
    static const size_t MAXTEST_BYTES = 4096;
    static const size_t INTERMEDIATE_TAG_BYTES = 
        INTERMEDIATE_TAGLEN * MAXTEST_BYTES / PARTLEN;

    unsigned char* c = (unsigned char*)malloc((size_t)MAXTEST_BYTES + 
        INTERMEDIATE_TAG_BYTES +
        CRYPTO_ABYTES);
    unsigned char* a = (unsigned char*)malloc((size_t)MAXTEST_BYTES);
    unsigned char* m = (unsigned char*)malloc((size_t)MAXTEST_BYTES);

    unsigned char k[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    unsigned char* nsec = 0;

    unsigned long long alen;
    unsigned long long clen;
    unsigned long long mlen;

    int result = 0;
    fill(k, CRYPTO_KEYBYTES);
    fill(npub, CRYPTO_NPUBBYTES);
    
    for (size_t i = 0; i <= MAXTEST_BYTES; ++i) {
        mlen = i;
        alen = i;
        clen = i + CRYPTO_ABYTES;

        fill(a, alen);
        fill(m, mlen);

        crypto_aead_encrypt(
            c, &clen, m, mlen, a, alen, nsec, npub, k
        );

        const int current_result = crypto_aead_decrypt(
            m, &mlen, nsec, c, clen, a, alen, npub, k
        );
        result |= current_result;

        if (current_result) {
            printf("crypto_aead_decrypt returned %d at %zu\n", current_result, i);
        }
    }

    free(a);
    free(c);
    free(m);

    return result;
}

// ---------------------------------------------------------------------

static int test2Parts0()
{
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
    unsigned long long mlen;
    unsigned char* m = generate_multi_part_message(2, 0, NUM_BLOCKS_PER_PART, &mlen);
    unsigned long long clen;
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes4_128_128_2_0.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0x63, 0xD9, 0x19, 0xA9, 0xCD, 0x4A, 0xC1, 0x19, 
        0xA9, 0x75, 0x6A, 0x79, 0xCC, 0xB0, 0x3F, 0xF0
    };

    const int result = run_test(k, h, hlen, m, mlen, c, clen, t);
    free(m);
    free(c);
    return result;
}

// ---------------------------------------------------------------------

static int test2Parts1()
{
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
    unsigned long long mlen;
    unsigned char* m = generate_multi_part_message(2, 1, NUM_BLOCKS_PER_PART, &mlen);
    unsigned long long clen;
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes4_128_128_2_1.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0x3B, 0x5E, 0xAF, 0x59, 0x25, 0xD9, 0xA6, 0xBB, 
        0x84, 0x3B, 0x61, 0xF2, 0x93, 0x5B, 0xC4, 0x41
    };
    const int result = run_test(k, h, hlen, m, mlen, c, clen, t);
    free(m);
    free(c);
    return result;
}

// ---------------------------------------------------------------------

static int test2PartsFull()
{
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
    unsigned long long mlen;
    unsigned char* m = generate_multi_part_message(2, NUM_BLOCKS_PER_PART, NUM_BLOCKS_PER_PART, &mlen);
    unsigned long long clen;
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes4_128_128_2_full.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0xC8, 0x55, 0xE3, 0x8A, 0xE3, 0x67, 0x79, 0x92, 
        0x2D, 0xAE, 0x67, 0x80, 0x7F, 0x97, 0x73, 0xC0
    };
    const int result = run_test(k, h, hlen, m, mlen, c, clen, t);
    free(m);
    free(c);
    return result;
}

// ---------------------------------------------------------------------

static int test16Parts0()
{
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
    unsigned long long mlen;
    unsigned char* m = generate_multi_part_message(16, 0, NUM_BLOCKS_PER_PART, &mlen);
    unsigned long long clen;
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes4_128_128_16_0.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0xBA, 0x08, 0x6E, 0x6B, 0xF7, 0xC6, 0xF8, 0xD2, 
        0xF7, 0x82, 0x39, 0x1A, 0xF2, 0x36, 0x46, 0x71
    };
    const int result = run_test(k, h, hlen, m, mlen, c, clen, t);
    free(m);
    free(c);
    return result;
}

// ---------------------------------------------------------------------

static int test16Parts1()
{
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
    unsigned long long mlen;
    unsigned char* m = generate_multi_part_message(16, 1, NUM_BLOCKS_PER_PART, &mlen);
    unsigned long long clen;
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes4_128_128_16_1.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0xD7, 0x8A, 0x47, 0x65, 0xE6, 0x64, 0x9E, 0x95, 
        0x08, 0x39, 0x37, 0xC9, 0x09, 0xDC, 0xC1, 0xF1
    };
    const int result = run_test(k, h, hlen, m, mlen, c, clen, t);
    free(m);
    free(c);
    return result;
}

// ---------------------------------------------------------------------

static int test16PartsFull()
{
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
    unsigned long long mlen;
    unsigned char* m = generate_multi_part_message(16, NUM_BLOCKS_PER_PART, NUM_BLOCKS_PER_PART, &mlen);
    unsigned long long clen;
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes4_128_128_16_full.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0x6D, 0xD1, 0xB6, 0x38, 0xA5, 0xC2, 0xC7, 0x23, 
        0x33, 0xB0, 0x88, 0x02, 0xF3, 0x55, 0x88, 0xA4
    };
    const int result = run_test(k, h, hlen, m, mlen, c, clen, t);
    free(m);
    free(c);
    return result;
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
    result |= test7();
    result |= test8();
    result |= test9();
    result |= test10();
    result |= tests_from_supercop();

    result |= test2Parts0();
    result |= test2Parts1();
    result |= test2PartsFull();
    result |= test16Parts0();
    result |= test16Parts1();
    result |= test16PartsFull();

    if (result) {
        puts("Test result:  FAILED");
    } else {
        puts("Tests result: SUCCESS");
    }

    return 0;
}
