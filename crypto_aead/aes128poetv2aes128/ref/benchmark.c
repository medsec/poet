#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "poet.h"

// ---------------------------------------------------------------------

#define _Is_X86_             1
#define HI_RES_CLK_OK
#define TIMER_SAMPLE_CNT     10000

#define HEADER_LENGTH       0
#define NUM_MESSAGE_LENGTHS 11
#define KEYLEN              CRYPTO_KEYBYTES
#define MAX_BUFFER_LEN      65536

static const uint32_t MESSAGE_LENGTHS[NUM_MESSAGE_LENGTHS] = {
    64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
};

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n)))
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#else
#define ALIGN(n)
#endif

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

/**
 * Quicksort comparison
 */
int compare_doubles(const void *aPtr, const void *bPtr)
{
    double a = *((double*) aPtr);
    double b = *((double*) bPtr);

    if (a > b) return  1;
    if (a < b) return -1;
    return 0;
}

// ---------------------------------------------------------------------

inline uint64_t get_time(void)
{
    uint64_t x[2];
    __asm__ volatile("rdtsc" : "=a"(x[0]), "=d"(x[1]));
    return x[0];
}

/**
 * Measures the overhead for measuring time.
 */
uint64_t calibrate_timer()
{
    // big number to start
    uint64_t dtMin = 0xFFFFFFFFL; 
    uint64_t t0, t1;
    int i;

    for (i = 0; i < TIMER_SAMPLE_CNT; ++i)
    {
        t0 = get_time();
        t1 = get_time();

        if (dtMin > t1 - t0) {
            dtMin = t1 - t0;
        }
    }

    return dtMin;
}

// ---------------------------------------------------------------------

int benchmark(const uint32_t num_iterations)
{
    ALIGN(16) uint8_t iv[HEADER_LENGTH];
    ALIGN(16) uint8_t key[KEYLEN];
    ALIGN(16) uint8_t header[HEADER_LENGTH];
    ALIGN(16) uint8_t plaintext[MAX_BUFFER_LEN];
    ALIGN(16) uint8_t ciphertext[MAX_BUFFER_LEN + BLOCKLEN];
    uint8_t secret_message_number;
    unsigned long long ciphertext_length;

    const uint64_t calibration = calibrate_timer();
    uint64_t t0, t1;
    uint32_t i, j;
#ifdef DECRYPT
    puts("Testing decryption");
#else
    puts("Testing encryption");
#endif
    printf("#mlen cpb\n");

    // Warm up
    for (j = 0; j < NUM_MESSAGE_LENGTHS; ++j)
    {
        for (i = 0; i < num_iterations / 4; ++i)
        {
#ifdef DECRYPT
            crypto_aead_decrypt(
                plaintext,  
                &ciphertext_length, 
                &secret_message_number, 
                ciphertext, 
                MESSAGE_LENGTHS[j],
                header,     
                HEADER_LENGTH, 
                iv,
                key
            );
#else
            crypto_aead_encrypt(
                ciphertext, 
                &ciphertext_length,
                plaintext,  
                MESSAGE_LENGTHS[j],
                header,     
                HEADER_LENGTH,
                &secret_message_number, 
                iv,
                key
            );
#endif
        }
    }

    double timings[num_iterations];
    const uint32_t median = num_iterations / 2;
    // To load the timing code into the instruction cache
    get_time(); 

    for (j = 0; j < NUM_MESSAGE_LENGTHS; ++j)
    {
        t0 = get_time();
        t1 = get_time();

        for (i = 0; i < num_iterations; ++i)
        {
            t0 = get_time();

#ifdef DECRYPT
            crypto_aead_decrypt(
                plaintext,  
                &ciphertext_length, 
                &secret_message_number, 
                ciphertext, 
                MESSAGE_LENGTHS[j],
                header,     
                HEADER_LENGTH, 
                iv,
                key
            );
#else
            crypto_aead_encrypt(
                ciphertext, 
                &ciphertext_length,
                plaintext,  
                MESSAGE_LENGTHS[j],
                header,     
                HEADER_LENGTH,
                &secret_message_number, 
                iv,
                key
            );
#endif

            t1 = get_time();
            timings[i] = (double)(t1 - t0 - calibration) / MESSAGE_LENGTHS[j];
        }

        // Sort the measurements and print the median
        qsort(timings, num_iterations, sizeof(double), compare_doubles);
        printf("%5d %4.2lf \n", MESSAGE_LENGTHS[j], timings[median]);
    }

    return 0;
}

// ---------------------------------------------------------------------

int main()
{
    int result = benchmark(TIMER_SAMPLE_CNT);
    return result;
}
