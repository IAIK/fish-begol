#ifndef AVX_H
#define AVX_H

#include <immintrin.h>

#define FN_ATTRIBUTES_AVX2 __attribute__((__always_inline__, target("avx2")))
#define FN_ATTRIBUTES_SSE2 __attribute__((__always_inline__, target("sse2")))

/**
 * \brief Perform a left shift on a 256 bit value.
 */
static inline __m256i FN_ATTRIBUTES_AVX2 mm256_shift_left(__m256i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m256i carry  = _mm256_srli_epi64(data, 64 - count);
  __m256i rotate = _mm256_permute4x64_epi64(carry, _MM_SHUFFLE(2, 1, 0, 3));
  carry          = _mm256_blend_epi32(_mm256_setzero_si256(), rotate, _MM_SHUFFLE(3, 3, 3, 0));
  data           = _mm256_slli_epi64(data, count);
  return _mm256_or_si256(data, carry);
}

/**
 * \brief Perform a right shift on a 256 bit value.
 */
static inline __m256i FN_ATTRIBUTES_AVX2 mm256_shift_right(__m256i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m256i carry  = _mm256_slli_epi64(data, 64 - count);
  __m256i rotate = _mm256_permute4x64_epi64(carry, _MM_SHUFFLE(0, 3, 2, 1));
  carry          = _mm256_blend_epi32(_mm256_setzero_si256(), rotate, _MM_SHUFFLE(0, 3, 3, 3));
  data           = _mm256_srli_epi64(data, count);
  return _mm256_or_si256(data, carry);
}

/**
 * \brief Perform a left shift on a 128 bit value.
 */
static inline __m128i FN_ATTRIBUTES_SSE2 mm128_shift_left(__m128i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m128i carry  = _mm_srli_epi64(data, 64 - count);
  __m128i upper  = _mm_slli_si128(carry, 8);
  __m128i lower  = _mm_srli_si128(carry, 8);
  carry          = _mm_or_si128(upper, lower);
  data           = _mm_slli_epi64(data, count);
  return _mm_or_si128(data, carry);
}

/**
 * \brief Perform a right shift on a 128 bit value.
 */
static inline __m128i FN_ATTRIBUTES_SSE2 mm128_shift_right(__m128i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m128i carry  = _mm_slli_epi64(data, 64 - count);
  __m128i upper  = _mm_slli_si128(carry, 8);
  __m128i lower  = _mm_srli_si128(carry, 8);
  carry          = _mm_or_si128(upper, lower);
  data           = _mm_srli_epi64(data, count);
  return _mm_or_si128(data, carry);
}

static inline void FN_ATTRIBUTES_SSE2 mm128_xor_region(__m128i* dst, __m128i const* src, unsigned int count) {
  for (unsigned int i = count; i; --i, ++dst, ++src) {
    *dst = _mm_xor_si128(*dst, *src);
  }
}

static inline void FN_ATTRIBUTES_AVX2 mm256_xor_region(__m256i* dst, __m256i const* src, unsigned int count) {
  for (unsigned int i = count; i; --i, ++dst, ++src) {
    *dst = _mm256_xor_si256(*dst, *src);
  }
}

#endif
