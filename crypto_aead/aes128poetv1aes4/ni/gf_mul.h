#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

/*
  Perform a Galois Field multiplication using Intel's pclmulqdq instruction.
  This code was taken from David McGrew's GCM implementation.

  a    Input vector1
  b    Input vector2
  res  Result vector
  return     Void
*/
static void gfmul (__m128i a, __m128i b, __m128i *res)
{
    __m128i tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
 
    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);
 
    tmp7 = _mm_srli_epi32(tmp3, 31);
    tmp8 = _mm_srli_epi32(tmp6, 31);
    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);
    tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);
 
    tmp7 = _mm_slli_epi32(tmp3, 31);
    tmp8 = _mm_slli_epi32(tmp3, 30);
    tmp9 = _mm_slli_epi32(tmp3, 25);
 
    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);
    tmp8 = _mm_srli_si128(tmp7, 4);
    tmp7 = _mm_slli_si128(tmp7, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp7);
 
    tmp2 = _mm_srli_epi32(tmp3, 1);
    tmp4 = _mm_srli_epi32(tmp3, 2);

    tmp5 = _mm_srli_epi32(tmp3, 7);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp8);
    tmp3 = _mm_xor_si128(tmp3, tmp2);
    tmp6 = _mm_xor_si128(tmp6, tmp3);
 
    *res = tmp6;
}
/*
  Uses Intel instructions to multiplye two blocks over GF field.
  This code was taken from David McGrew's GCM implementation.

  Z  Result vector
  X  Input vector1
  Y  Input vector2.
  return 0 == O.K.
*/
static int gf_mul(unsigned char *Z,
		  unsigned char *X,
		  unsigned char *Y)
{
    __m128i Z_128;
    __m128i Y_128;
    __m128i X_128;
    __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                      13, 14, 15);
    
    Y_128 = _mm_loadu_si128((__m128i*)Y);
    Y_128 = _mm_shuffle_epi8(Y_128, BSWAP_MASK);

    X_128 = _mm_loadu_si128((__m128i*)X);
    X_128 = _mm_shuffle_epi8(X_128, BSWAP_MASK);
    gfmul(X_128, Y_128, &Z_128);
    Z_128 = _mm_shuffle_epi8(Z_128, BSWAP_MASK);
    _mm_storeu_si128(((__m128i*)Z), Z_128);

    return 0;
}



