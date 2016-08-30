#ifndef AVX_H
#define AVX_H

#include <immintrin.h>

#define FN_ATTRIBUTES_AVX2 __attribute__((__always_inline__, target("avx2")))

/**
 * \brief Perform a left shift on a 256 bit value.
 */
static inline __m256i FN_ATTRIBUTES_AVX2 m256_shift_left(__m256i data, unsigned int count) {
  __m256i carry  = _mm256_srli_epi64(data, 64 - count);
  __m256i rotate = _mm256_permute4x64_epi64(carry, _MM_SHUFFLE(2, 1, 0, 3));
  carry          = _mm256_blend_epi32(_mm256_setzero_si256(), rotate, _MM_SHUFFLE(3, 3, 3, 0));
  data           = _mm256_slli_epi64(data, count);
  return _mm256_or_si256(data, carry);
}

/**
 * \brief Perform a right shift on a 256 bit value.
 */
static inline __m256i FN_ATTRIBUTES_AVX2 m256_shift_right(__m256i data, unsigned int count) {
  __m256i carry  = _mm256_slli_epi64(data, 64 - count);
  __m256i rotate = _mm256_permute4x64_epi64(carry, _MM_SHUFFLE(0, 3, 2, 1));
  carry          = _mm256_blend_epi32(_mm256_setzero_si256(), rotate, _MM_SHUFFLE(0, 3, 3, 3));
  data           = _mm256_srli_epi64(data, count);
  return _mm256_or_si256(data, carry);
}

#endif
