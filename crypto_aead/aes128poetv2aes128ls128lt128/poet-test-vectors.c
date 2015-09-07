/*
// @author Eik List and Christian Forler
// @last-modified 2015-09-06
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
        0x7A, 0x98, 0xFD, 0xD8, 0x7A, 0xDB, 0x2F, 0x3B, 
        0xB4, 0x53, 0xCC, 0xD9, 0xD7, 0x92, 0xFE, 0xFA
    };
    const unsigned char t[TAGLEN] = {
        0x19, 0xDA, 0xF2, 0x51, 0x42, 0xBB, 0x49, 0x52, 
        0x41, 0x8F, 0xD6, 0xD5, 0xEC, 0xD0, 0x67, 0xD6
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
        0x3B, 0xE6, 0x7F, 0x6B, 0x41, 0x95, 0xBD, 0x2B, 
        0xC9, 0x8C, 0x46, 0x36, 0x33, 0xF1, 0xCA, 0x8D
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
        0x51, 0x10, 0x90, 0x80, 0x07, 0x36, 0xF5, 0x64
    };
    const unsigned char t[TAGLEN] = {
        0x28, 0x56, 0xA8, 0xE5, 0x31, 0x88, 0x33, 0x33, 
        0x40, 0xBA, 0x39, 0x52, 0xFF, 0x52, 0x5C, 0x62
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
        0xFB, 0x49, 0x02, 0x58, 0x11, 0x99, 0xC0, 0x0D, 
        0x44, 0xD2, 0x97, 0x14, 0xAC, 0x11, 0x25, 0x52, 
        0x74, 0x08, 0xD8, 0xA9, 0xB3, 0xF2, 0xF1, 0xD8, 
        0x0C, 0xAC, 0x69, 0xCA, 0x9A, 0x43, 0xDF, 0xC5, 
        0xE1, 0x0B, 0x09, 0x28, 0xF7, 0xF8, 0x20, 0x2B, 
        0xD4, 0x03, 0x13, 0x55, 0x8B, 0xC7, 0x7D, 0x56, 
        0x15, 0xCC, 0xE5, 0x46, 0x19, 0x6D, 0xE5, 0x64
    };
    const unsigned char t[TAGLEN] = {
        0x16, 0x64, 0x22, 0x25, 0xE3, 0x4E, 0x58, 0x51, 
        0xA8, 0x09, 0x9B, 0x68, 0x73, 0xE0, 0x54, 0x9F
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
        0x56, 0xFD, 0x4D, 0xFD, 0xB1, 0xE8, 0xB8, 0x03, 
        0xAE, 0x06, 0xE1, 0x18, 0x44, 0xE5, 0x26, 0x2F, 
        0x6C, 0x1B, 0xD6, 0x28, 0x05, 0x17, 0x42, 0x59, 
        0x87, 0xDB, 0xE3, 0x78, 0x14, 0x4E, 0xBD, 0xFD, 
        0x88, 0x60, 0x10, 0xE4, 0x18, 0xB2, 0x23, 0x66, 
        0xA5, 0x0D, 0x1E, 0x8F, 0x3B, 0x12, 0xCB, 0x74, 
        0x0A, 0xB4, 0xA4, 0x92
    };
    const unsigned char t[TAGLEN] = {
        0x82, 0xC9, 0x6E, 0xFB, 0xA5, 0xE8, 0xDE, 0x78, 
        0x91, 0xCD, 0xCC, 0xA9, 0xCA, 0x03, 0xBD, 0x94
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
        0x04, 0x6F, 0x2D, 0x93, 0x69, 0xB2, 0x76, 0x10, 
        0xF8, 0xB3, 0x27, 0x5D, 0x77, 0x56, 0x42, 0x04, 
        0x07, 0x7B, 0x0D, 0x95, 0xDC, 0x69, 0xAD, 0x43, 
        0xB4, 0x27, 0x84, 0xB7, 0x38, 0x3D, 0xAA, 0xCE, 
        0x0C, 0x02, 0x4F, 0x97, 0x80, 0x5C, 0x05, 0x1C, 
        0x40, 0x4D, 0x2E, 0xD0, 0x07, 0x4E, 0xE9, 0x94, 
        0x1A, 0x7E, 0xA8, 0x21, 0xD2, 0xC0, 0xB4, 0x0F, 
        0xD9, 0x05, 0xA5, 0xB2, 0xD6, 0x72, 0xD7, 0x60, 
        0x32, 0x5D, 0x2A, 0x6B, 0xD5, 0xA6, 0xB5, 0xA1, 
        0xB6, 0x7D, 0x17, 0xAF, 0xDD, 0x78, 0xD4, 0xA8, 
        0x5B, 0xD7, 0xC7, 0xB4, 0x32, 0xDA, 0x02, 0x08, 
        0x60, 0xC6, 0x5B, 0xA0, 0xBB, 0x9E, 0xE7, 0x71, 
        0xBE, 0x26, 0x17, 0xF5, 0xD2, 0xD8, 0x47, 0x01, 
        0x22, 0x1B, 0x69, 0xBC, 0x97, 0x81, 0x9C, 0x5F, 
        0x97, 0x14, 0x04, 0x6B, 0xB4, 0x9C, 0xD5, 0x6A, 
        0x03, 0x37, 0x93, 0xB7, 0x04, 0x3B, 0x5D, 0xD8, 
        0x4A, 0x9F, 0x0A, 0x3E, 0x73, 0x3E, 0x9E, 0xF8, 
        0xAD, 0x5E, 0x61, 0x32, 0xD2, 0x87, 0x6F, 0x9B, 
        0x15, 0x48, 0x59, 0x25, 0x1D, 0xDF, 0x75, 0x1A, 
        0x77, 0x9B, 0xCD, 0x0D, 0x70, 0xD4, 0x05, 0xB2, 
        0x7F, 0xE5, 0xED, 0x8E, 0x71, 0xCA, 0xE0, 0x16, 
        0x9A, 0xDF, 0xCF, 0x64, 0x63, 0x7F, 0x59, 0x4E, 
        0xF0, 0x11, 0x8D, 0xB6, 0x07, 0x3D, 0xCC, 0x91, 
        0x74, 0x2B, 0xB3, 0x6A, 0xE2, 0x4B, 0xCD, 0x16, 
        0x35, 0x7D, 0xE8, 0x02, 0x2D, 0x04, 0x6C, 0xF4, 
        0x4C, 0x84, 0xE3, 0x9E, 0xAB, 0x8C, 0x9F, 0x1A, 
        0xDE, 0xDE, 0xAF, 0x45, 0xC2, 0xCB, 0x5C, 0x8A, 
        0x83, 0xF9, 0x39, 0x15, 0x07, 0xC4, 0xE2, 0x9D, 
        0xBD, 0x14, 0x9D, 0x46, 0xE5, 0x43, 0x8F, 0xDF, 
        0xE2, 0x79, 0x2C, 0x96, 0x64, 0xBB, 0x10, 0x1D, 
        0x97, 0x4A, 0x75, 0x81, 0x34, 0x3F, 0xD7, 0x7D, 
        0xA6, 0x61, 0x44, 0xC0, 0xD2, 0x10, 0x6F, 0x77, 
        0xB5, 0x53, 0x43, 0x54, 0xF1, 0x93, 0x96, 0x82, 
        0xB5, 0x6E, 0x33, 0xE9, 0x5B, 0xF0, 0x78, 0x52, 
        0xF4, 0x41, 0x95, 0x62, 0x52, 0xE8, 0x3F, 0xCA, 
        0x1A, 0x42, 0x13, 0x1D, 0xB1, 0x07, 0x41, 0x38, 
        0x12, 0x88, 0xC6, 0x93, 0x6C, 0xF4, 0x6A, 0x59, 
        0x24, 0x69, 0x2B, 0x27, 0xF8, 0xF9, 0xA7, 0x1E, 
        0x96, 0x8D, 0x7D, 0x8B, 0xD6, 0x5F, 0xF1, 0x48, 
        0xA8, 0x63, 0x4A, 0x8B, 0x47, 0x50, 0x35, 0x12, 
        0x10, 0x96, 0xD6, 0xFC, 0x50, 0x57, 0xFE, 0xE7, 
        0x45, 0x7B, 0x89, 0x7E, 0x3D, 0x39, 0x1B, 0x56, 
        0x7C, 0xAE, 0x78, 0x72, 0x75, 0x1A, 0xAD, 0x04, 
        0xE7, 0x06, 0x50, 0x78, 0xA9, 0x19, 0x0F, 0x88, 
        0x7B, 0x12, 0xED, 0xA1, 0xF3, 0x26, 0x65, 0xB0, 
        0x5D, 0x47, 0x1C, 0xE9, 0x0B, 0x36, 0xB5, 0x11, 
        0x78, 0x2F, 0x46, 0xC6, 0x34, 0x83, 0xEB, 0x1D, 
        0x89, 0x69, 0x70, 0x9B, 0xD1, 0xB4, 0xCF, 0x31, 
        0x9D, 0x37, 0xC1, 0xA9, 0xD7, 0x47, 0xBC, 0x3F, 
        0xCE, 0x6D, 0x40, 0xCA, 0x3C, 0x33, 0x39, 0x59, 
        0xC2, 0x3E, 0xD2, 0x1C, 0x7D, 0xA2, 0x21, 0x22, 
        0x22, 0xC6, 0x54, 0x6E, 0xA0, 0x46, 0xDF, 0xB5, 
        0xAF, 0x52, 0xE1, 0x25, 0xCC, 0x75, 0xE8, 0x3F, 
        0xAC, 0x9F, 0xDB, 0x91, 0xC5, 0xAF, 0xCB, 0xF5, 
        0xB6, 0xFA, 0x61, 0xC6, 0x89, 0x58, 0x59, 0x66, 
        0x22, 0xBC, 0x30, 0xF6, 0x0D, 0x09, 0x4D, 0xBB, 
        0x13, 0xE9, 0x62, 0x04, 0x93, 0x3E, 0xAE, 0x8B, 
        0x4E, 0x43, 0xEC, 0x89, 0x79, 0x1C, 0x63, 0xE7, 
        0x4D, 0xFB, 0xAF, 0xBC, 0x1C, 0x95, 0x6B, 0x11, 
        0x57, 0xFD, 0x13, 0x62, 0xF3, 0xFE, 0x1F, 0x53, 
        0x2C, 0x0F, 0x4A, 0xC8, 0x7A, 0xAB, 0x23, 0x80, 
        0xE7, 0xC7, 0x39, 0x1F, 0x0B, 0x82, 0xFC, 0xFB, 
        0x21, 0xD6, 0x1E, 0x84, 0x72, 0xA4, 0x9A, 0x31, 
        0x73, 0x92, 0x98, 0xC8, 0xE0, 0xFB, 0xDF, 0xBE, 
        0x25, 0x87, 0x00, 0x56, 0x0E, 0xD5, 0x06, 0x1F, 
        0x8A, 0x34, 0x7E, 0x2D, 0x42, 0x9A, 0xC3, 0xDC, 
        0x27, 0x36, 0x6F, 0x25, 0x15, 0x8F, 0xCD, 0x5B, 
        0x95, 0x04, 0xC8, 0x06, 0x29, 0x9B, 0xC2, 0xFF, 
        0xA2, 0x1B, 0x06, 0xCE, 0xDB, 0x0B, 0xF9, 0x76, 
        0x16, 0x14, 0x7A, 0x38, 0xAE, 0xA2, 0xB0, 0x4C, 
        0xE0, 0x36, 0x14, 0x98, 0x85, 0xA9, 0x9F, 0xAD, 
        0x53, 0xCE, 0xB0, 0x00, 0x06, 0xB2, 0x31, 0xBF, 
        0x6B, 0xA2, 0xD5, 0xC6, 0xF3, 0x12, 0x84, 0xE7, 
        0xF2, 0xCE, 0x0C, 0xB8, 0xFA, 0x3F, 0x22, 0xEE, 
        0xF3, 0x4B, 0xD6, 0xBE, 0x40, 0x4A, 0x27, 0x9A, 
        0x78, 0x3A, 0xC1, 0xC3, 0x2E, 0x04, 0x0F, 0xD4, 
        0x0B, 0xD3, 0xF6, 0xEF, 0x6A, 0x0D, 0xD1, 0xF0, 
        0xF9, 0xFD, 0x24, 0x1A, 0xB5, 0xE8, 0x47, 0x75, 
        0x94, 0xB9, 0x38, 0x56, 0xEC, 0xFC, 0x59, 0xF9, 
        0x81, 0x57, 0x94, 0x76, 0x16, 0xBE, 0x17, 0x12, 
        0xBD, 0x1B, 0x7A, 0x95, 0x89, 0xBF, 0x76, 0xBD, 
        0x36, 0xB5
    };
    const unsigned char t[TAGLEN] = {
        0xFC, 0x39, 0xEE, 0x75, 0xD7, 0x5E, 0xEF, 0x72, 
        0xA9, 0x3B, 0x81, 0x5F, 0x3F, 0xD1, 0x68, 0x58
    };
    return run_test((const unsigned char*)k, (const unsigned char*)h, hlen,
                    (unsigned char*)m, mlen, c, clen, t);
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
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes128_128_128_2_0.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0xC7, 0x4C, 0x93, 0xDB, 0x54, 0xB3, 0x6C, 0xB0, 
        0x5A, 0x03, 0xED, 0x73, 0xD8, 0x4E, 0x94, 0xF6
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
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes128_128_128_2_1.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0xE9, 0xBB, 0x7A, 0xB1, 0x21, 0xBB, 0x30, 0xF5, 
        0x94, 0x87, 0x76, 0xA6, 0xA0, 0x84, 0xD5, 0x09
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
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes128_128_128_2_full.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0x1E, 0x93, 0xB2, 0x65, 0x34, 0x1D, 0x12, 0x54, 
        0xBA, 0xC2, 0xDA, 0xE2, 0xAE, 0x8D, 0x2C, 0x6A
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
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes128_128_128_16_0.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0xA0, 0xA4, 0x2D, 0xAD, 0xD6, 0x46, 0x81, 0xB2, 
        0x17, 0xAC, 0x0F, 0x78, 0x5C, 0x0E, 0xCC, 0x15
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
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes128_128_128_16_1.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0x3B, 0xA0, 0xA1, 0x2C, 0xDF, 0x36, 0x88, 0x38, 
        0x42, 0xCD, 0x8B, 0xD4, 0x71, 0xF7, 0x99, 0xAA
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
    unsigned char* c = read_from_file("testvectors/aes128poetv2aes128_128_128_16_full.txt", &clen);
    const unsigned char t[TAGLEN] = {
        0x27, 0x8F, 0x04, 0x09, 0x2B, 0x3E, 0x1A, 0xAD, 
        0x7F, 0x0F, 0x98, 0xC4, 0x2C, 0x7D, 0x25, 0x18
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