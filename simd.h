/*
 * fish-begol - Implementation of the Fish and Begol signature schemes
 * Copyright (C) 2016 Graz University of Technology
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef AVX_H
#define AVX_H

#include <immintrin.h>

#define FN_ATTRIBUTES_AVX2 __attribute__((__always_inline__, target("avx2"), pure))
#define FN_ATTRIBUTES_SSE2 __attribute__((__always_inline__, target("sse2"), pure))

#define FN_ATTRIBUTES_AVX2_NP __attribute__((__always_inline__, target("avx2")))
#define FN_ATTRIBUTES_SSE2_NP __attribute__((__always_inline__, target("sse2")))

#define CPU_SUPPORTS_AVX2 __builtin_cpu_supports("avx2")
#define CPU_SUPPORTS_SSE4_1 __builtin_cpu_supports("sse4.1")

#ifdef __x86_64__
#define CPU_SUPPORTS_SSE2 1
#else
#define CPU_SUPPORTS_SSE2 __builtin_cpu_supports("sse2")
#endif

/* backwards compatibility macros for GCC 4.8 and 4.9
 *
 * bs{l,r}i was introduced in GCC 5 and in clang as macros sometime in 2015.
 * */
#if (!defined(__clang__) && defined(__GNUC__) && __GNUC__ < 5) || (defined(__clang__) && !defined(_mm_bslli_si128))
#define _mm_bslli_si128(a, imm) _mm_slli_si128((a), (imm))
#define _mm_bsrli_si128(a, imm) _mm_srli_si128((a), (imm))
#endif

#ifdef WITH_AVX2
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
 * \brief xor multiple 256 bit values.
 */
static inline void FN_ATTRIBUTES_AVX2_NP mm256_xor_region(__m256i* restrict dst,
                                                          __m256i const* restrict src,
                                                          unsigned int count) {
  for (unsigned int i = count; i; --i, ++dst, ++src) {
    *dst = _mm256_xor_si256(*dst, *src);
  }
}
#endif

#ifdef WITH_SSE2
/**
 * \brief Perform a left shift on a 128 bit value.
 */
static inline __m128i FN_ATTRIBUTES_SSE2 mm128_shift_left(__m128i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m128i carry = _mm_bslli_si128(data, 8);
  /* if (count >= 64) {
    return _mm_slli_epi64(carry, count - 64);
  } */
  carry = _mm_srli_epi64(carry, 64 - count);
  data  = _mm_slli_epi64(data, count);
  return _mm_or_si128(data, carry);
}

/**
 * \brief Perform a right shift on a 128 bit value.
 */
static inline __m128i FN_ATTRIBUTES_SSE2 mm128_shift_right(__m128i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m128i carry = _mm_bsrli_si128(data, 8);
  /* if (count >= 64) {
    return _mm_srli_epi64(carry, count - 64);
  } */
  carry = _mm_slli_epi64(carry, 64 - count);
  data  = _mm_srli_epi64(data, count);
  return _mm_or_si128(data, carry);
}

/**
 * \brief xor multiple 128 bit values.
 */
static inline void FN_ATTRIBUTES_SSE2_NP mm128_xor_region(__m128i* restrict dst,
                                                          __m128i const* restrict src,
                                                          unsigned int count) {
  for (unsigned int i = count; i; --i, ++dst, ++src) {
    *dst = _mm_xor_si128(*dst, *src);
  }
}
#endif

#endif
