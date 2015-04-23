#include <stdio.h>
#include <string.h>
#include "api.h"

#define NSEC NULL

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

static void test_output(const unsigned char *k, const unsigned klen,
                        const unsigned char *h, const unsigned hlen,
                        const unsigned char *npub, 
                        const unsigned char *m, const unsigned long long mlen,
                        const unsigned char *c, const long long clen)

{
    print_hex("SK: ", k, klen);
    print_hex("Header: ", h, hlen);
    print_hex("Nonce: ", npub, 16);
    print_hex("Plaintext:", m, mlen);
    print_hex("Ciphertext:", c, clen);
    puts("\n\n");
}

// ---------------------------------------------------------------------

static int run_test(const unsigned char *k,
                    const unsigned char *h,
                    const unsigned long long hlen,
                    const unsigned char *npub,
                    const unsigned char *expected_m,
                    unsigned long long mlen,
                    const unsigned char *expected_c)
{
    unsigned char c[mlen+16];
    unsigned long long clen = 0;
    unsigned char m[mlen];
    int result;

    result = crypto_aead_encrypt(c, &clen, expected_m, mlen, h, hlen, NSEC, npub, k);

    if (memcmp(expected_c, c, clen)) {
        test_output(k, 16, h, hlen, npub, expected_m, mlen, c, clen);
        puts("Encryption produced incorrect result");
        return -1;
    }

    result = crypto_aead_decrypt(m, &mlen, NSEC, c, clen, h, hlen, npub, k);
    test_output(k, 16, h, hlen, npub, m, mlen, c, clen);

    if (memcmp(expected_m, m, mlen)) {
        puts("Decryption produced incorrect result");
        return -1;
    }

    return result;
}

// ---------------------------------------------------------------------

static int test4()
{
    unsigned long long mlen = 52;
    const unsigned long long hlen = 8;
    const unsigned char k[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const unsigned char h[8] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };
    const unsigned char npub[16] = {
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
    const unsigned char c[68] = {
        0x73, 0x01, 0x02, 0x1f, 0x92, 0x64, 0x34, 0xa8, 
        0xdf, 0x06, 0xe1, 0x83, 0x97, 0x92, 0x54, 0xb7, 
        0xc4, 0x35, 0x25, 0xca, 0x30, 0xca, 0xfb, 0x1c, 
        0xb8, 0xb5, 0xcc, 0x25, 0xfc, 0x05, 0xcd, 0x2c, 
        0x7f, 0x6f, 0x0a, 0x4d, 0xd3, 0x6a, 0x6f, 0x9a, 
        0x1c, 0x46, 0x24, 0x61, 0xca, 0x74, 0xec, 0x1c, 
        0x7a, 0x26, 0x7d, 0x85, 
        0x86, 0x59, 0x63, 0x94, 0x3c, 0x62, 0x96, 0xf3, 
        0x61, 0xf8, 0x14, 0x7a, 0x34, 0x8e, 0xe7, 0x61
    };
    return run_test(k, h, hlen, npub, m, mlen, c);
}

// ---------------------------------------------------------------------

int main()
{
    int result = test4();
    
    if (result) {
        puts("Test result:  FAILED");
    } else {
        puts("Tests result: SUCCESS");
    }

    return 0;
}