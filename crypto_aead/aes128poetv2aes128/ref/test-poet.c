#include <stdio.h>
#include <string.h>
#include "poet.h"

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

static void dump_context(struct poet_ctx_t *ctx)
{
    print_hex("Header key", ctx->l, BLOCKLEN);
    print_hex("Tau", ctx->tau, BLOCKLEN);
}

// ---------------------------------------------------------------------

static int run_test(const unsigned char *k,
                    const unsigned char *h, 
                    const unsigned long long hlen,
                    unsigned char *m, 
                    unsigned long long mlen)
{
    struct poet_ctx_t ctx;
    unsigned char c[mlen];
    const unsigned long long clen = mlen;
    unsigned char t[TAGLEN];

    keysetup(&ctx, k);
    process_header(&ctx, h, hlen);
    encrypt_final(&ctx, m, mlen, c, t);

    dump_context(&ctx);
    puts("Encryption");
    print_hex("Tag", t, BLOCKLEN);
    print_hex("Message", m, mlen);
    print_hex("Ciphertext", c, mlen);

    memset(m, 0x00, mlen);

    keysetup(&ctx, k);
    process_header(&ctx, h, hlen);
    int result = decrypt_final(&ctx, c, clen, t, m);

    puts("Encryption");
    dump_context(&ctx);
    print_hex("Message", m, mlen);

    return result;
}

// ---------------------------------------------------------------------

int main()
{
    const unsigned long long hlen = 24;
    unsigned long long mlen = 52;
    const unsigned char k[BLOCKLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const unsigned char h[24] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe
    };
    unsigned char m[52] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0xfe, 0xfe, 0xba, 0xbe
    };

    int result = run_test(k, h, hlen, m, mlen);

    if (result) {
        puts("Test result:  FAILED");
    } else {
        puts("Tests result: SUCCESS");
    }

    return 0;
}
