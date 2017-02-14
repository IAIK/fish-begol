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

#include "mzd_additional.h"
#include "randomness.h"

// #include <assert.h>
#include <stdlib.h>

#ifdef WITH_OPT
#include "simd.h"

#ifdef WITH_SSE2
static const unsigned int sse_bound = 128 / (8 * sizeof(word));
#endif
#if defined(WITH_SSE2) || defined(WITH_AVX2)
static const unsigned int word_size_bits = 8 * sizeof(word);
#endif
#endif
static const unsigned int avx_bound         = 256 / (8 * sizeof(word));
static const uint8_t mzd_flag_custom_layout = 0x40;

static rci_t calculate_rowstride(rci_t width) {
  // As soon as we hit the AVX bound, use 32 byte alignment. Otherwise use 16
  // byte alignment for SSE.
  if ((size_t)width >= avx_bound) {
    return ((width * sizeof(word) + 31) & ~31) / sizeof(word);
  } else {
    return ((width * sizeof(word) + 15) & ~15) / sizeof(word);
  }
}

static size_t calculate_row_alignment(size_t width) {
  if (width >= avx_bound) {
    return 32;
  } else {
    return 16;
  }
}

// Notes on the memory layout: mzd_init allocates multiple memory blocks (one
// for mzd_t, one for rows and multiple for the buffers). We use one memory
// block for mzd_t, rows and the buffer. This improves memory locality and
// requires less calls to malloc.
//
// In mzd_local_init_multiple we do the same, but store n mzd_t instances in one
// memory block.

mzd_t* mzd_local_init_ex(rci_t r, rci_t c, bool clear) {
  const rci_t width       = (c + m4ri_radix - 1) / m4ri_radix;
  const rci_t rowstride   = calculate_rowstride(width);
  const word high_bitmask = __M4RI_LEFT_BITMASK(c % m4ri_radix);
  const uint8_t flags =
      mzd_flag_custom_layout | ((high_bitmask != m4ri_ffff) ? mzd_flag_nonzero_excess : 0);

  const size_t row_alignment = calculate_row_alignment(width);
  const size_t buffer_size   = r * rowstride * sizeof(word);
  const size_t rows_size     = r * sizeof(word*);
  // sizeof(mzd_t) == 64 is only ensured after
  // a41f75a72f8a84d9318d44b6f01aac1453dfffe6, but a version including this
  // commit is not available on any recent Debian based distribution.
  const size_t mzd_t_size = (sizeof(mzd_t) + row_alignment - 1) & ~(row_alignment - 1);

  unsigned char* buffer = aligned_alloc(32, (mzd_t_size + buffer_size + rows_size + 31) & ~31);

  mzd_t* A = (mzd_t*)buffer;
  buffer += mzd_t_size;

  if (clear) {
    memset(buffer, 0, buffer_size);
  }

  A->rows = (word**)(buffer + buffer_size);
  for (rci_t i = 0; i < r; ++i, buffer += rowstride * sizeof(word)) {
    A->rows[i] = (word*)(buffer);
  }

  // assign in order
  A->nrows         = r;
  A->ncols         = c;
  A->width         = width;
  A->rowstride     = rowstride;
  A->offset_vector = 0;
  A->row_offset    = 0;
  A->flags         = flags;
  A->blockrows_log = 0;
  A->high_bitmask  = high_bitmask;
  A->blocks        = NULL;

#if M4RI_VERSION < 20130808
  // workaround for old m4ri versions (untested)
  A->offset = 0;
  if (width == 1) {
    A->low_bitmask = A->high_bitmask = __M4RI_MIDDLE_BITMASK(c, 0);
  } else {
    A->low_bitmask = m4ri_ffff;
  }
#endif

  return A;
}

void mzd_local_free(mzd_t* v) {
  // assert(!v || (v->flags & mzd_flag_custom_layout));
  free(v);
}

void mzd_local_init_multiple_ex(mzd_t** dst, size_t n, rci_t r, rci_t c, bool clear) {
  const rci_t width       = (c + m4ri_radix - 1) / m4ri_radix;
  const rci_t rowstride   = calculate_rowstride(width);
  const word high_bitmask = __M4RI_LEFT_BITMASK(c % m4ri_radix);
  const uint8_t flags =
      mzd_flag_custom_layout | ((high_bitmask != m4ri_ffff) ? mzd_flag_nonzero_excess : 0);

  const size_t row_alignment = calculate_row_alignment(width);
  const size_t buffer_size   = r * rowstride * sizeof(word);
  const size_t rows_size     = r * sizeof(word*);
  const size_t mzd_t_size    = (sizeof(mzd_t) + row_alignment - 1) & ~(row_alignment - 1);
  const size_t size_per_elem = (mzd_t_size + buffer_size + rows_size + 31) & ~31;

  unsigned char* full_buffer = aligned_alloc(32, size_per_elem * n);

  for (size_t s = 0; s < n; ++s, full_buffer += size_per_elem) {
    unsigned char* buffer = full_buffer;
    mzd_t* A              = (mzd_t*)buffer;
    dst[s]                = A;

    buffer += mzd_t_size;

    if (clear) {
      memset(buffer, 0, buffer_size);
    }

    A->rows = (word**)(buffer + buffer_size);
    for (rci_t i = 0; i < r; ++i, buffer += rowstride * sizeof(word)) {
      A->rows[i] = (word*)(buffer);
    }

    // assign in order
    A->nrows         = r;
    A->ncols         = c;
    A->width         = width;
    A->rowstride     = rowstride;
    A->offset_vector = 0;
    A->row_offset    = 0;
    A->flags         = flags;
    A->blockrows_log = 0;
    A->high_bitmask  = high_bitmask;
    A->blocks        = NULL;

#if M4RI_VERSION < 20130808
    // workaround for old m4ri versions (untested)
    A->offset = 0;
    if (width == 1) {
      A->low_bitmask = A->high_bitmask = __M4RI_MIDDLE_BITMASK(c, 0);
    } else {
      A->low_bitmask = m4ri_ffff;
    }
#endif
  }
}

void mzd_local_free_multiple(mzd_t** vs) {
  if (vs) {
    // assert(!vs[0] || (vs[0]->flags & mzd_flag_custom_layout));
    free(vs[0]);
  }
}

mzd_t* mzd_local_copy(mzd_t* dst, mzd_t const* src) {
  if (dst == src) {
    return dst;
  }

  if (!dst) {
    dst = mzd_local_init(src->nrows, src->ncols);
  }

  if ((dst->flags & mzd_flag_custom_layout) && dst->nrows >= src->nrows &&
      dst->ncols == src->ncols) {
    if (src->flags & mzd_flag_custom_layout) {
      memcpy(__builtin_assume_aligned(FIRST_ROW(dst), 32),
             __builtin_assume_aligned(CONST_FIRST_ROW(src), 32),
             src->nrows * sizeof(word) * src->width);
    } else {
      // src can be a mzd_t* from mzd_init, so we can only copy row wise
      for (rci_t i = 0; i < src->nrows; ++i) {
        unsigned char* d       = __builtin_assume_aligned(dst->rows[i], 16);
        unsigned char const* s = (unsigned char const*)src->rows[i];

        memcpy(d, s, src->width * sizeof(word));
      }
    }
    return dst;
  } else {
    return mzd_copy(dst, src);
  }
}

void mzd_local_clear(mzd_t* c) {
  if (c->flags & mzd_flag_custom_layout) {
    memset(__builtin_assume_aligned(FIRST_ROW(c), 32), 0, c->nrows * sizeof(word) * c->width);
  } else {
    mzd_row_clear_offset(c, 0, 0);
  }
}

void mzd_randomize_ssl(mzd_t* val) {
  // similar to mzd_randomize but using RAND_Bytes instead
  const word mask_end = val->high_bitmask;
  const size_t len1   = val->width - 1;

  for (rci_t i = 0; i < val->nrows; ++i) {
    rand_bytes((unsigned char*)val->rows[i], val->width * sizeof(word));
    val->rows[i][len1] &= mask_end;
  }
}

static void mzd_randomize_aes_prng(mzd_t* v, aes_prng_t* aes_prng) {
  // similar to mzd_randomize but using aes_prng_t instead
  const word mask_end = v->high_bitmask;
  aes_prng_get_randomness(aes_prng, (unsigned char*)FIRST_ROW(v),
                          v->width * sizeof(word) * v->nrows);
  if (mask_end != m4ri_ffff) {
    const size_t len1 = v->width - 1;
    for (rci_t i = 0; i < v->nrows; ++i) {
      v->rows[i][len1] &= mask_end;
    }
  }
}

mzd_t* mzd_init_random_vector(rci_t n) {
  mzd_t* A = mzd_local_init_ex(1, n, false);
  mzd_randomize_ssl(A);

  return A;
}

mzd_t* mzd_init_random_vector_prng(rci_t n, aes_prng_t* aes_prng) {
  mzd_t* v = mzd_local_init_ex(1, n, false);
  mzd_randomize_aes_prng(v, aes_prng);
  return v;
}

void mzd_randomize_from_seed(mzd_t* vector, const unsigned char key[16]) {
  aes_prng_t aes_prng;
  aes_prng_init(&aes_prng, key);
  mzd_randomize_aes_prng(vector, &aes_prng);
  aes_prng_clear(&aes_prng);
}

mzd_t* mzd_init_random_vector_from_seed(const unsigned char key[16], rci_t n) {
  mzd_t* vector = mzd_local_init_ex(1, n, false);
  mzd_randomize_from_seed(vector, key);
  return vector;
}

void mzd_randomize_multiple_from_seed(mzd_t** vectors, unsigned int count,
                                      const unsigned char key[16]) {
  aes_prng_t aes_prng;
  aes_prng_init(&aes_prng, key);

  for (unsigned int v = 0; v < count; ++v) {
    mzd_randomize_aes_prng(vectors[v], &aes_prng);
  }

  aes_prng_clear(&aes_prng);
}

mzd_t** mzd_init_random_vectors_from_seed(const unsigned char key[16], rci_t n,
                                          unsigned int count) {
  mzd_t** vectors = malloc(count * sizeof(mzd_t*));
  mzd_local_init_multiple_ex(vectors, count, 1, n, false);
  mzd_randomize_multiple_from_seed(vectors, count, key);
  return vectors;
}

void mzd_shift_right(mzd_t* res, mzd_t const* val, unsigned count) {
  if (!count) {
    mzd_local_copy(res, val);
    return;
  }

  const unsigned int nwords     = val->width;
  const unsigned int left_count = 8 * sizeof(word) - count;

  word* resptr       = FIRST_ROW(res);
  word const* valptr = CONST_FIRST_ROW(val);

  for (unsigned int i = nwords - 1; i; --i, ++resptr) {
    const word tmp = *valptr >> count;
    *resptr        = tmp | (*++valptr << left_count);
  }
  *resptr = *valptr >> count;
}

void mzd_shift_left(mzd_t* res, mzd_t const* val, unsigned count) {
  if (!count) {
    mzd_local_copy(res, val);
    return;
  }

  const unsigned int nwords      = val->width;
  const unsigned int right_count = 8 * sizeof(word) - count;

  word* resptr       = FIRST_ROW(res) + nwords - 1;
  word const* valptr = CONST_FIRST_ROW(val) + nwords - 1;

  for (unsigned int i = nwords - 1; i; --i, --resptr) {
    const word tmp = *valptr << count;
    *resptr        = tmp | (*--valptr >> right_count);
  }
  *resptr = *valptr << count;
}

#ifdef WITH_OPT
#ifdef WITH_SSE2
__attribute__((target("sse2"))) static inline mzd_t* mzd_and_sse(mzd_t* res, mzd_t const* first,
                                                                 mzd_t const* second) {
  unsigned int width    = first->width;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  if (width >= sse_bound) {
    __m128i* mresptr          = __builtin_assume_aligned(resptr, 16);
    __m128i const* mfirstptr  = __builtin_assume_aligned(firstptr, 16);
    __m128i const* msecondptr = __builtin_assume_aligned(secondptr, 16);

    do {
      *mresptr++ = _mm_and_si128(*mfirstptr++, *msecondptr++);
      width -= sizeof(__m128i) / sizeof(word);
    } while (width >= sse_bound);

    resptr    = (word*)mresptr;
    firstptr  = (word*)mfirstptr;
    secondptr = (word*)msecondptr;
  }

  while (width--) {
    *resptr++ = *firstptr++ & *secondptr++;
  }

  return res;
}
#endif

#ifdef WITH_AVX2
__attribute__((target("avx2"))) static inline mzd_t* mzd_and_avx(mzd_t* res, mzd_t const* first,
                                                                 mzd_t const* second) {
  unsigned int width    = first->width;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  if (width >= avx_bound) {
    __m256i* mresptr          = __builtin_assume_aligned(resptr, 32);
    __m256i const* mfirstptr  = __builtin_assume_aligned(firstptr, 32);
    __m256i const* msecondptr = __builtin_assume_aligned(secondptr, 32);

    do {
      *mresptr++ = _mm256_and_si256(*mfirstptr++, *msecondptr++);
      width -= sizeof(__m256i) / sizeof(word);
    } while (width >= avx_bound);

    resptr    = (word*)mresptr;
    firstptr  = (word*)mfirstptr;
    secondptr = (word*)msecondptr;
  }

  while (width--) {
    *resptr++ = *firstptr++ & *secondptr++;
  }

  return res;
}
#endif
#endif

mzd_t* mzd_and(mzd_t* res, mzd_t const* first, mzd_t const* second) {
#ifdef WITH_OPT
#ifdef WITH_AVX2
  if (CPU_SUPPORTS_AVX2 && first->ncols >= 256 && first->ncols % word_size_bits == 0) {
    return mzd_and_avx(res, first, second);
  }
#endif
#ifdef WITH_SSE2
  if (CPU_SUPPORTS_SSE2 && first->ncols % word_size_bits == 0) {
    return mzd_and_sse(res, first, second);
  }
#endif
#endif

  unsigned int width    = first->width;
  const word mask       = first->high_bitmask;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  while (width--) {
    *resptr++ = *firstptr++ & *secondptr++;
  }
  *(resptr - 1) &= mask;

  return res;
}

#ifdef WITH_OPT
#ifdef WITH_SSE2
__attribute__((target("sse2"))) static inline mzd_t* mzd_xor_sse(mzd_t* res, mzd_t const* first,
                                                                 mzd_t const* second) {
  unsigned int width    = first->width;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  if (width >= sse_bound) {
    __m128i* mresptr          = __builtin_assume_aligned(resptr, 16);
    __m128i const* mfirstptr  = __builtin_assume_aligned(firstptr, 16);
    __m128i const* msecondptr = __builtin_assume_aligned(secondptr, 16);

    do {
      *mresptr++ = _mm_xor_si128(*mfirstptr++, *msecondptr++);
      width -= sizeof(__m128i) / sizeof(word);
    } while (width >= sse_bound);

    resptr    = (word*)mresptr;
    firstptr  = (word*)mfirstptr;
    secondptr = (word*)msecondptr;
  }

  while (width--) {
    *resptr++ = *firstptr++ ^ *secondptr++;
  }

  return res;
}
#endif

#ifdef WITH_AVX2
__attribute__((target("avx2"))) static inline mzd_t* mzd_xor_avx(mzd_t* res, mzd_t const* first,
                                                                 mzd_t const* second) {
  unsigned int width    = first->width;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  if (width >= avx_bound) {
    __m256i* mresptr          = __builtin_assume_aligned(resptr, 32);
    __m256i const* mfirstptr  = __builtin_assume_aligned(firstptr, 32);
    __m256i const* msecondptr = __builtin_assume_aligned(secondptr, 32);

    do {
      *mresptr++ = _mm256_xor_si256(*mfirstptr++, *msecondptr++);
      width -= sizeof(__m256i) / sizeof(word);
    } while (width >= avx_bound);

    resptr    = (word*)mresptr;
    firstptr  = (word*)mfirstptr;
    secondptr = (word*)msecondptr;
  }

  while (width--) {
    *resptr++ = *firstptr++ ^ *secondptr++;
  }

  return res;
}
#endif
#endif

mzd_t* mzd_xor(mzd_t* res, mzd_t const* first, mzd_t const* second) {
#ifdef WITH_OPT
#ifdef WITH_AVX2
  if (CPU_SUPPORTS_AVX2 && first->ncols >= 256 && first->ncols % word_size_bits == 0) {
    return mzd_xor_avx(res, first, second);
  }
#endif
#ifdef WITH_SSE2
  if (CPU_SUPPORTS_SSE2 && first->ncols % word_size_bits == 0) {
    return mzd_xor_sse(res, first, second);
  }
#endif
#endif

  unsigned int width    = first->width;
  const word mask       = first->high_bitmask;
  word* resptr          = FIRST_ROW(res);
  word const* firstptr  = CONST_FIRST_ROW(first);
  word const* secondptr = CONST_FIRST_ROW(second);

  while (width--) {
    *resptr++ = *firstptr++ ^ *secondptr++;
  }
  *(resptr - 1) &= mask;

  return res;
}

mzd_t* mzd_mul_v(mzd_t* c, mzd_t const* v, mzd_t const* At) {
  if (At->nrows != v->ncols) {
    // number of columns does not match
    return NULL;
  }

  mzd_local_clear(c);
  return mzd_addmul_v(c, v, At);
}

#ifdef WITH_OPT
#ifdef WITH_SSE2
__attribute__((target("sse2"))) static inline mzd_t* mzd_addmul_v_sse(mzd_t* c, mzd_t const* v,
                                                                      mzd_t const* A) {
  const unsigned int len        = A->width * sizeof(word) / sizeof(__m128i);
  word* cptr                    = FIRST_ROW(c);
  word const* vptr              = CONST_FIRST_ROW(v);
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(__m128i);

  __m128i* mcptr = __builtin_assume_aligned(cptr, 16);

  for (unsigned int w = 0; w < width; ++w, ++vptr) {
    word idx             = *vptr;
    word const* Aptr     = A->rows[w * sizeof(word) * 8];
    __m128i const* mAptr = __builtin_assume_aligned(Aptr, 16);

    while (idx) {
      switch (idx & 0x0F) {
      case 0x00:
        break;

      case 0x01:
        mm128_xor_region(mcptr, mAptr, len);
        break;

      case 0x02:
        mm128_xor_region(mcptr, mAptr + mrowstride, len);
        break;

      case 0x03:
        mm128_xor_region(mcptr, mAptr, len);
        mm128_xor_region(mcptr, mAptr + mrowstride, len);
        break;

      case 0x04:
        mm128_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        break;

      case 0x05:
        mm128_xor_region(mcptr, mAptr, len);
        mm128_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        break;

      case 0x06:
        mm128_xor_region(mcptr, mAptr + mrowstride, len);
        mm128_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        break;

      case 0x07:
        mm128_xor_region(mcptr, mAptr, len);
        mm128_xor_region(mcptr, mAptr + mrowstride, len);
        mm128_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        break;

      case 0x08:
        mm128_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x09:
        mm128_xor_region(mcptr, mAptr, len);
        mm128_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0a:
        mm128_xor_region(mcptr, mAptr + mrowstride, len);
        mm128_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0b:
        mm128_xor_region(mcptr, mAptr, len);
        mm128_xor_region(mcptr, mAptr + mrowstride, len);
        mm128_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0c:
        mm128_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        mm128_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0d:
        mm128_xor_region(mcptr, mAptr, len);
        mm128_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        mm128_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0e:
        mm128_xor_region(mcptr, mAptr + mrowstride, len);
        mm128_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        mm128_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0f:
        mm128_xor_region(mcptr, mAptr, len);
        mm128_xor_region(mcptr, mAptr + mrowstride, len);
        mm128_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        mm128_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;
      }

      mAptr += 4 * mrowstride;
      idx >>= 4;
    }
  }

  return c;
}
#endif

#ifdef WITH_AVX2
__attribute__((target("avx2"))) static inline mzd_t* mzd_addmul_v_avx(mzd_t* c, mzd_t const* v,
                                                                      mzd_t const* A) {
  const unsigned int len        = A->width * sizeof(word) / sizeof(__m256i);
  word* cptr                    = FIRST_ROW(c);
  word const* vptr              = CONST_FIRST_ROW(v);
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(__m256i);

  __m256i* mcptr = __builtin_assume_aligned(cptr, 32);

  for (unsigned int w = 0; w < width; ++w, ++vptr) {
    word idx             = *vptr;
    word const* Aptr     = A->rows[w * sizeof(word) * 8];
    __m256i const* mAptr = __builtin_assume_aligned(Aptr, 32);

    while (idx) {
      switch (idx & 0x0F) {
      case 0x00:
        break;

      case 0x01:
        mm256_xor_region(mcptr, mAptr, len);
        break;

      case 0x02:
        mm256_xor_region(mcptr, mAptr + mrowstride, len);
        break;

      case 0x03:
        mm256_xor_region(mcptr, mAptr, len);
        mm256_xor_region(mcptr, mAptr + mrowstride, len);
        break;

      case 0x04:
        mm256_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        break;

      case 0x05:
        mm256_xor_region(mcptr, mAptr, len);
        mm256_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        break;

      case 0x06:
        mm256_xor_region(mcptr, mAptr + mrowstride, len);
        mm256_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        break;

      case 0x07:
        mm256_xor_region(mcptr, mAptr, len);
        mm256_xor_region(mcptr, mAptr + mrowstride, len);
        mm256_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        break;

      case 0x08:
        mm256_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x09:
        mm256_xor_region(mcptr, mAptr, len);
        mm256_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0a:
        mm256_xor_region(mcptr, mAptr + mrowstride, len);
        mm256_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0b:
        mm256_xor_region(mcptr, mAptr, len);
        mm256_xor_region(mcptr, mAptr + mrowstride, len);
        mm256_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0c:
        mm256_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        mm256_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0d:
        mm256_xor_region(mcptr, mAptr, len);
        mm256_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        mm256_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0e:
        mm256_xor_region(mcptr, mAptr + mrowstride, len);
        mm256_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        mm256_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;

      case 0x0f:
        mm256_xor_region(mcptr, mAptr, len);
        mm256_xor_region(mcptr, mAptr + mrowstride, len);
        mm256_xor_region(mcptr, mAptr + 2 * mrowstride, len);
        mm256_xor_region(mcptr, mAptr + 3 * mrowstride, len);
        break;
      }

      mAptr += 4 * mrowstride;
      idx >>= 4;
    }
  }

  return c;
}
#endif
#endif

mzd_t* mzd_addmul_v(mzd_t* c, mzd_t const* v, mzd_t const* A) {
  if (A->ncols != c->ncols || A->nrows != v->ncols) {
    // number of columns does not match
    return NULL;
  }

#ifdef WITH_OPT
  if (A->nrows % (sizeof(word) * 8) == 0) {
#ifdef WITH_AVX2
    if (CPU_SUPPORTS_AVX2 && (A->ncols & 0xff) == 0) {
      return mzd_addmul_v_avx(c, v, A);
    }
#endif
#ifdef WITH_SSE2
    if (CPU_SUPPORTS_SSE2 && (A->ncols & 0x7f) == 0) {
      return mzd_addmul_v_sse(c, v, A);
    }
#endif
  }
#endif

  const unsigned int len       = A->width;
  const word mask              = A->high_bitmask;
  const unsigned int rowstride = A->rowstride;
  word* cptr                   = FIRST_ROW(c);
  word const* vptr             = CONST_FIRST_ROW(v);
  const unsigned int width     = v->width;

  for (unsigned int w = 0; w < width; ++w, ++vptr) {
    word idx = *vptr;

    word const* Aptr = A->rows[w * sizeof(word) * 8];
    while (idx) {
      if (idx & 0x1) {
        for (unsigned int i = 0; i < len - 1; ++i) {
          cptr[i] ^= Aptr[i];
        }
        cptr[len - 1] = (cptr[len - 1] ^ Aptr[len - 1]) & mask;
      }

      Aptr += rowstride;
      idx >>= 1;
    }
  }

  return c;
}

#ifdef WITH_OPT
#ifdef WITH_SSE2
__attribute__((target("sse2"))) static inline bool mzd_equal_sse(mzd_t const* restrict first,
                                                                 mzd_t const* restrict second) {
  unsigned int width             = first->width;
  word const* restrict firstptr  = CONST_FIRST_ROW(first);
  word const* restrict secondptr = CONST_FIRST_ROW(second);

  if (width >= sse_bound) {
    __m128i const* restrict mfirstptr  = __builtin_assume_aligned(firstptr, 16);
    __m128i const* restrict msecondptr = __builtin_assume_aligned(secondptr, 16);

    do {
      const unsigned int notequal =
          _mm_movemask_epi8(_mm_cmpeq_epi8(*mfirstptr++, *msecondptr++)) - 0xffff;
      if (notequal) {
        return false;
      }

      width -= sizeof(__m128i) / sizeof(word);
    } while (width >= sse_bound);

    firstptr  = (word*)mfirstptr;
    secondptr = (word*)msecondptr;
  }

  while (width--) {
    if (*firstptr++ != *secondptr++) {
      return false;
    }
  }

  return true;
}
#endif

#ifdef WITH_SSE4_1
__attribute__((target("sse4.1"))) static inline bool mzd_equal_sse41(mzd_t const* restrict first,
                                                                     mzd_t const* restrict second) {
  unsigned int width             = first->width;
  word const* restrict firstptr  = CONST_FIRST_ROW(first);
  word const* restrict secondptr = CONST_FIRST_ROW(second);

  if (width >= sse_bound) {
    __m128i const* restrict mfirstptr  = __builtin_assume_aligned(firstptr, 16);
    __m128i const* restrict msecondptr = __builtin_assume_aligned(secondptr, 16);

    do {
      __m128i tmp = _mm_xor_si128(*mfirstptr++, *msecondptr++);
      if (!_mm_testz_si128(tmp, tmp)) {
        return false;
      }

      width -= sizeof(__m128i) / sizeof(word);
    } while (width >= sse_bound);

    firstptr  = (word*)mfirstptr;
    secondptr = (word*)msecondptr;
  }

  while (width--) {
    if (*firstptr++ != *secondptr++) {
      return false;
    }
  }

  return true;
}
#endif

#ifdef WITH_AVX2
__attribute__((target("avx2"))) static inline bool mzd_equal_avx(mzd_t const* restrict first,
                                                                 mzd_t const* restrict second) {
  unsigned int width             = first->width;
  word const* restrict firstptr  = CONST_FIRST_ROW(first);
  word const* restrict secondptr = CONST_FIRST_ROW(second);

  if (width >= avx_bound) {
    __m256i const* restrict mfirstptr  = __builtin_assume_aligned(firstptr, 32);
    __m256i const* restrict msecondptr = __builtin_assume_aligned(secondptr, 32);

    do {
      __m256i tmp = _mm256_xor_si256(*mfirstptr++, *msecondptr++);
      if (!_mm256_testz_si256(tmp, tmp)) {
        return false;
      }

      width -= sizeof(__m256i) / sizeof(word);
    } while (width >= avx_bound);

    firstptr  = (word*)mfirstptr;
    secondptr = (word*)msecondptr;
  }

  while (width--) {
    if (*firstptr++ != *secondptr++) {
      return false;
    }
  }

  return true;
}
#endif
#endif

bool mzd_local_equal(mzd_t const* first, mzd_t const* second) {
  if (first == second) {
    return true;
  }
  if (first->ncols != second->ncols || first->nrows != second->nrows) {
    return false;
  }

  if ((first->flags & mzd_flag_custom_layout) && (second->flags & mzd_flag_custom_layout)) {
#ifdef WITH_OPT
#ifdef WITH_AVX2
    if (CPU_SUPPORTS_AVX2) {
      return mzd_equal_avx(first, second);
    }
#endif
#ifdef WITH_SSE4_1
    if (CPU_SUPPORTS_SSE4_1) {
      return mzd_equal_sse41(first, second);
    }
#endif
#ifdef WITH_SSE2
    if (CPU_SUPPORTS_SSE2) {
      return mzd_equal_sse(first, second);
    }
#endif
#endif
    return memcmp(__builtin_assume_aligned(CONST_FIRST_ROW(first), 32),
                  __builtin_assume_aligned(CONST_FIRST_ROW(second), 32),
                  first->nrows * sizeof(word) * first->width) == 0;
  }

  return mzd_cmp(first, second) == 0;
}

static void xor_comb(const unsigned int len, const word mask, word* Brow, word** const Arows,
                     unsigned int r_offset, unsigned comb) {
  while (comb) {
    const word* Arow = Arows[r_offset];
    if (comb & 0x1) {
      for (unsigned int i = 0; i < len - 1; ++i) {
        Brow[i] ^= Arow[i];
      }
      Brow[len - 1] = (Brow[len - 1] ^ Arow[len - 1]) & mask;
    }

    comb >>= 1;
    ++r_offset;
  }
}

/**
 * Pre-compute matrices for faster mzd_addmul_v computions.
 *
 */
mzd_t* mzd_precompute_matrix_lookup(mzd_t const* A) {
  mzd_t* B = mzd_local_init_ex(32 * A->nrows, A->ncols, true);

  const unsigned int len = A->width;
  const word mask        = A->high_bitmask;
  word** const Arows     = A->rows;

  for (unsigned int r = 0; r < B->nrows; ++r) {
    const unsigned int comb     = r & 0xff;
    const unsigned int r_offset = (r >> 8) * 8;
    if (!comb) {
      continue;
    }

    xor_comb(len, mask, B->rows[r], Arows, r_offset, comb);
  }

  return B;
}

#ifdef WITH_OPT
#ifdef WITH_SSE2
__attribute__((target("sse2"))) static inline mzd_t* mzd_mul_vl_sse_128(mzd_t* c, mzd_t const* v,
                                                                        mzd_t const* A) {
  word const* vptr                = __builtin_assume_aligned(CONST_FIRST_ROW(v), 16);
  const unsigned int width        = v->width;
  static const unsigned int moff1 = sizeof(word) * 128;
  static const unsigned int moff2 = 128;

  __m128i mc           = _mm_setzero_si128();
  __m128i const* mAptr = __builtin_assume_aligned(CONST_FIRST_ROW(A), 16);

  for (unsigned int w = width; w; --w, ++vptr, mAptr += moff1) {
    word idx              = *vptr;
    __m128i const* mAptri = mAptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptri += moff2) {
      const word comb = idx & 0xff;
      mc              = _mm_xor_si128(mc, mAptri[comb]);
    }
  }

  __m128i* mcptr = __builtin_assume_aligned(FIRST_ROW(c), 16);
  *mcptr         = mc;
  return c;
}

__attribute__((target("sse2"))) static inline mzd_t* mzd_addmul_vl_sse_128(mzd_t* c, mzd_t const* v,
                                                                           mzd_t const* A) {
  word const* vptr                = __builtin_assume_aligned(CONST_FIRST_ROW(v), 16);
  const unsigned int width        = v->width;
  static const unsigned int moff1 = sizeof(word) * 128;
  static const unsigned int moff2 = 128;

  __m128i* mcptr       = __builtin_assume_aligned(FIRST_ROW(c), 16);
  __m128i mc           = *mcptr;
  __m128i const* mAptr = __builtin_assume_aligned(CONST_FIRST_ROW(A), 16);

  for (unsigned int w = width; w; --w, ++vptr, mAptr += moff1) {
    word idx              = *vptr;
    __m128i const* mAptri = mAptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptri += moff2) {
      const word comb = idx & 0xff;
      mc              = _mm_xor_si128(mc, mAptri[comb]);
    }
  }

  *mcptr = mc;
  return c;
}

__attribute__((target("sse2"))) static inline mzd_t* mzd_addmul_vl_sse(mzd_t* c, mzd_t const* v,
                                                                       mzd_t const* A) {
  const unsigned int len        = A->width * sizeof(word) / sizeof(__m128i);
  word const* vptr              = __builtin_assume_aligned(CONST_FIRST_ROW(v), 16);
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(__m128i);
  const unsigned int moff1      = sizeof(word) * 128 * mrowstride;
  const unsigned int moff2      = 128 * mrowstride;

  __m128i* mcptr       = __builtin_assume_aligned(FIRST_ROW(c), 16);
  __m128i const* mAptr = __builtin_assume_aligned(CONST_FIRST_ROW(A), 16);

  for (unsigned int w = width; w; --w, ++vptr, mAptr += moff1) {
    word idx              = *vptr;
    __m128i const* mAptri = mAptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptri += moff2) {
      const word comb = idx & 0xff;
      mm128_xor_region(mcptr, mAptri + comb * mrowstride, len);
    }
  }

  return c;
}
#endif

#ifdef WITH_AVX2
__attribute__((target("avx2"))) static inline mzd_t* mzd_mul_vl_avx_256(mzd_t* c, mzd_t const* v,
                                                                        mzd_t const* A) {
  word const* vptr                = __builtin_assume_aligned(CONST_FIRST_ROW(v), 16);
  const unsigned int width        = v->width;
  static const unsigned int moff1 = sizeof(word) * 256;
  static const unsigned int moff2 = 256;

  __m256i mc = _mm256_setzero_si256();
  ;
  __m256i const* mAptr = __builtin_assume_aligned(CONST_FIRST_ROW(A), 32);

  for (unsigned int w = width; w; --w, ++vptr, mAptr += moff1) {
    word idx              = *vptr;
    __m256i const* mAptri = mAptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptri += moff2) {
      const word comb = idx & 0xff;
      mc              = _mm256_xor_si256(mc, mAptri[comb]);
    }
  }

  __m256i* mcptr = __builtin_assume_aligned(FIRST_ROW(c), 32);
  *mcptr         = mc;
  return c;
}

__attribute__((target("avx2"))) static inline mzd_t* mzd_addmul_vl_avx_256(mzd_t* c, mzd_t const* v,
                                                                           mzd_t const* A) {
  word const* vptr                = __builtin_assume_aligned(CONST_FIRST_ROW(v), 16);
  const unsigned int width        = v->width;
  static const unsigned int moff1 = sizeof(word) * 256;
  static const unsigned int moff2 = 256;

  __m256i* mcptr       = __builtin_assume_aligned(FIRST_ROW(c), 32);
  __m256i mc           = *mcptr;
  __m256i const* mAptr = __builtin_assume_aligned(CONST_FIRST_ROW(A), 32);

  for (unsigned int w = width; w; --w, ++vptr, mAptr += moff1) {
    word idx              = *vptr;
    __m256i const* mAptri = mAptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptri += moff2) {
      const word comb = idx & 0xff;
      mc              = _mm256_xor_si256(mc, mAptri[comb]);
    }
  }

  *mcptr = mc;
  return c;
}

__attribute__((target("avx2"))) static inline mzd_t* mzd_addmul_vl_avx(mzd_t* c, mzd_t const* v,
                                                                       mzd_t const* A) {
  const unsigned int len        = A->width * sizeof(word) / sizeof(__m256i);
  word const* vptr              = __builtin_assume_aligned(CONST_FIRST_ROW(v), 16);
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(__m256i);
  const unsigned int moff1      = sizeof(word) * 256 * mrowstride;
  const unsigned int moff2      = 256 * mrowstride;

  __m256i* mcptr       = __builtin_assume_aligned(FIRST_ROW(c), 32);
  __m256i const* mAptr = __builtin_assume_aligned(CONST_FIRST_ROW(A), 32);

  for (unsigned int w = width; w; --w, ++vptr, mAptr += moff1) {
    word idx              = *vptr;
    __m256i const* mAptri = mAptr;
    for (unsigned int s = sizeof(word); s; --s, idx >>= 8, mAptri += moff2) {
      const word comb = idx & 0xff;
      mm256_xor_region(mcptr, mAptri + comb * mrowstride, len);
    }
  }

  return c;
}
#endif
#endif

mzd_t* mzd_mul_vl(mzd_t* c, mzd_t const* v, mzd_t const* A) {
  if (A->nrows != 32 * v->ncols) {
    // number of columns does not match
    return NULL;
  }

#ifdef WITH_OPT
  if (A->nrows % (sizeof(word) * 8) == 0) {
#ifdef WITH_AVX2
    if (CPU_SUPPORTS_AVX2) {
      if (A->ncols == 256) {
        return mzd_mul_vl_avx_256(c, v, A);
      }
    }
#endif
#ifdef WITH_SSE2
    if (CPU_SUPPORTS_SSE2) {
      if (A->ncols == 128) {
        return mzd_mul_vl_sse_128(c, v, A);
      }
    }
#endif
  }
#endif

  mzd_local_clear(c);
  return mzd_addmul_vl(c, v, A);
}

mzd_t* mzd_addmul_vl(mzd_t* c, mzd_t const* v, mzd_t const* A) {
  if (A->ncols != c->ncols || A->nrows != 32 * v->ncols) {
    // number of columns does not match
    return NULL;
  }

#ifdef WITH_OPT
  if (A->nrows % (sizeof(word) * 8) == 0) {
#ifdef WITH_AVX2
    if (CPU_SUPPORTS_AVX2) {
      if (A->ncols == 256) {
        return mzd_addmul_vl_avx_256(c, v, A);
      }
      if ((A->ncols & 0xff) == 0) {
        return mzd_addmul_vl_avx(c, v, A);
      }
    }
#endif
#ifdef WITH_SSE2
    if (CPU_SUPPORTS_SSE2) {
      if (A->ncols == 128) {
        return mzd_addmul_vl_sse_128(c, v, A);
      }
      if ((A->ncols & 0x7f) == 0) {
        return mzd_addmul_vl_sse(c, v, A);
      }
    }
#endif
  }
#endif

  const unsigned int len   = A->width;
  const word mask          = A->high_bitmask;
  word* cptr               = FIRST_ROW(c);
  word const* vptr         = CONST_FIRST_ROW(v);
  const unsigned int width = v->width;

  for (unsigned int w = 0; w < width; ++w, ++vptr) {
    word idx         = *vptr;
    unsigned int add = 0;

    while (idx) {
      const word comb = idx & 0xff;

      word const* Aptr = A->rows[w * sizeof(word) * 8 * 32 + add + comb];
      for (unsigned int i = 0; i < len - 1; ++i) {
        cptr[i] ^= Aptr[i];
      }
      cptr[len - 1] = (cptr[len - 1] ^ Aptr[len - 1]) & mask;

      idx >>= 8;
      add += 256;
    }
  }

  return c;
}
