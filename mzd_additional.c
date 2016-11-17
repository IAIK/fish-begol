#include "mzd_additional.h"
#include "randomness.h"

#ifdef WITH_OPT
#include "avx.h"

static const unsigned int sse_bound = 128 / (8 * sizeof(word));
#endif
static const unsigned int avx_bound      = 256 / (8 * sizeof(word));
static const unsigned int word_size_bits = 8 * sizeof(word);

static rci_t calculate_rowstride(rci_t width) {
  // As soon as we hit the AVX bound, use 32 byte alignment. Otherwise use 6
  // byte alignment for SSE.
  if ((size_t)width >= avx_bound) {
    return ((width * sizeof(word) + 31) & ~31) / sizeof(word);
  } else {
    return ((width * sizeof(word) + 15) & ~15) / sizeof(word);
  }
}

// Notes on the memory layout: mzd_init allocates multiple memory blocks (one
// for mzd_t, one for rows and multiple for the buffers). We use one memory
// block for mzd_t, rows and the buffer. This improves memory locality and
// requires less calls to malloc.
//
// In mzd_local_init_multiple we do the same, but store n mzd_t instances in one
// memory block.

mzd_t* mzd_local_init(rci_t r, rci_t c) {
  const rci_t width       = (c + m4ri_radix - 1) / m4ri_radix;
  const rci_t rowstride   = calculate_rowstride(width);
  const word high_bitmask = __M4RI_LEFT_BITMASK(c % m4ri_radix);
  const uint8_t flags     = (high_bitmask != m4ri_ffff) ? mzd_flag_nonzero_excess : 0;

  const size_t buffer_size = r * rowstride * sizeof(word);
  const size_t rows_size   = r * sizeof(word*);

  unsigned char* buffer = aligned_alloc(32, (sizeof(mzd_t) + buffer_size + rows_size + 31) & ~31);

  mzd_t* A = (mzd_t*)buffer;
  buffer += sizeof(mzd_t);

  memset(buffer, 0, buffer_size);

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

  return A;
}

void mzd_local_free(mzd_t* v) {
  free(v);
}

void mzd_local_init_multiple(mzd_t** dst, size_t n, rci_t r, rci_t c) {
  const rci_t width       = (c + m4ri_radix - 1) / m4ri_radix;
  const rci_t rowstride   = calculate_rowstride(width);
  const word high_bitmask = __M4RI_LEFT_BITMASK(c % m4ri_radix);
  const uint8_t flags     = (high_bitmask != m4ri_ffff) ? mzd_flag_nonzero_excess : 0;

  const size_t buffer_size   = r * rowstride * sizeof(word);
  const size_t rows_size     = r * sizeof(word*);
  const size_t size_per_elem = (sizeof(mzd_t) + buffer_size + rows_size + 31) & ~31;

  unsigned char* full_buffer = aligned_alloc(32, size_per_elem * n);

  for (size_t s = 0; s < n; ++s, full_buffer += size_per_elem) {
    unsigned char* buffer = full_buffer;
    mzd_t* A              = (mzd_t*)buffer;
    dst[s]                = A;

    buffer += sizeof(mzd_t);

    memset(buffer, 0, buffer_size);

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
  }
}

void mzd_local_free_multiple(mzd_t** vs) {
  if (vs) {
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

  if (dst->nrows >= src->nrows || dst->ncols == src->ncols) {
    unsigned char* d       = __builtin_assume_aligned(dst->rows[0], 16);
    unsigned char const* s = __builtin_assume_aligned(src->rows[0], 16);

    memcpy(d, s, src->nrows * src->rowstride * sizeof(word));
    return dst;
  } else {
    return mzd_copy(dst, src);
  }
}
// #endif

void mzd_randomize_ssl(mzd_t* val) {
  // similar to mzd_randomize but using RAND_Bytes instead
  const word mask_end = val->high_bitmask;
  for (rci_t i = 0; i < val->nrows; ++i) {
    rand_bytes((unsigned char*)val->rows[i], val->width * sizeof(word));
    val->rows[i][val->width - 1] &= mask_end;
  }
}

static void mzd_randomize_aes_prng(mzd_t* v, aes_prng_t* aes_prng) {
  // similar to mzd_randomize but using aes_prng_t instead
  const word mask_end = v->high_bitmask;
  for (rci_t i = 0; i < v->nrows; ++i) {
    aes_prng_get_randomness(aes_prng, (unsigned char*)v->rows[i], v->width * sizeof(word));
    v->rows[i][v->width - 1] &= mask_end;
  }
}

mzd_t* mzd_init_random_vector(rci_t n) {
  mzd_t* A = mzd_local_init(1, n);
  mzd_randomize_ssl(A);

  return A;
}

mzd_t* mzd_init_random_vector_prng(rci_t n, aes_prng_t* aes_prng) {
  mzd_t* v = mzd_local_init(1, n);
  mzd_randomize_aes_prng(v, aes_prng);
  return v;
}

mzd_t** mzd_init_random_vectors_from_seed(const unsigned char key[16], rci_t n,
                                          unsigned int count) {
  aes_prng_t aes_prng;
  aes_prng_init(&aes_prng, key);

  mzd_t** vectors = calloc(count, sizeof(mzd_t*));
  mzd_local_init_multiple(vectors, count, 1, n);
  for (unsigned int v = 0; v < count; ++v) {
    mzd_randomize_aes_prng(vectors[v], &aes_prng);
  }

  aes_prng_clear(&aes_prng);
  return vectors;
}

void mzd_shift_right(mzd_t* res, mzd_t const* val, unsigned count) {
  if (!count) {
    mzd_local_copy(res, val);
    return;
  }

  const unsigned int nwords     = val->width;
  const unsigned int left_count = 8 * sizeof(word) - count;

  word* resptr       = res->rows[0];
  word const* valptr = val->rows[0];

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

  word* resptr       = res->rows[0] + nwords - 1;
  word const* valptr = val->rows[0] + nwords - 1;

  for (unsigned int i = nwords - 1; i; --i, --resptr) {
    const word tmp = *valptr << count;
    *resptr        = tmp | (*--valptr >> right_count);
  }
  *resptr = *valptr << count;
}

#ifdef WITH_OPT
__attribute__((target("sse2"))) static inline mzd_t* mzd_and_sse(mzd_t* res, mzd_t const* first,
                                                                 mzd_t const* second) {
  unsigned int width    = first->width;
  word* resptr          = res->rows[0];
  word const* firstptr  = first->rows[0];
  word const* secondptr = second->rows[0];

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

__attribute__((target("avx2"))) static inline mzd_t* mzd_and_avx(mzd_t* res, mzd_t const* first,
                                                                 mzd_t const* second) {
  unsigned int width    = first->width;
  word* resptr          = res->rows[0];
  word const* firstptr  = first->rows[0];
  word const* secondptr = second->rows[0];

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

mzd_t* mzd_and(mzd_t* res, mzd_t const* first, mzd_t const* second) {
  if (res == 0) {
    res = mzd_local_init(1, first->ncols);
  }

#ifdef WITH_OPT
  if (CPU_SUPPORTS_AVX2 && first->ncols >= 256 && first->ncols % word_size_bits == 0) {
    return mzd_and_avx(res, first, second);
  } else if (CPU_SUPPORTS_SSE2 && first->ncols % word_size_bits == 0) {
    return mzd_and_sse(res, first, second);
  }
#endif

  unsigned int width    = first->width;
  const word mask       = first->high_bitmask;
  word const* firstptr  = first->rows[0];
  word const* secondptr = second->rows[0];
  word* resptr          = res->rows[0];

  while (width--) {
    *resptr++ = *firstptr++ & *secondptr++;
  }
  *(resptr - 1) &= mask;

  return res;
}

#ifdef WITH_OPT
__attribute__((target("sse2"))) static inline mzd_t* mzd_xor_sse(mzd_t* res, mzd_t const* first,
                                                                 mzd_t const* second) {
  unsigned int width    = first->width;
  word* resptr          = res->rows[0];
  word const* firstptr  = first->rows[0];
  word const* secondptr = second->rows[0];

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

__attribute__((target("avx2"))) static inline mzd_t* mzd_xor_avx(mzd_t* res, mzd_t const* first,
                                                                 mzd_t const* second) {
  unsigned int width    = first->width;
  word* resptr          = res->rows[0];
  word const* firstptr  = first->rows[0];
  word const* secondptr = second->rows[0];

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

mzd_t* mzd_xor(mzd_t* res, mzd_t const* first, mzd_t const* second) {
  if (!res) {
    res = mzd_local_init(1, first->ncols);
  }

#ifdef WITH_OPT
  if (CPU_SUPPORTS_AVX2 && first->ncols >= 256 && first->ncols % word_size_bits == 0) {
    return mzd_xor_avx(res, first, second);
  } else if (CPU_SUPPORTS_SSE2 && first->ncols % word_size_bits == 0) {
    return mzd_xor_sse(res, first, second);
  }
#endif

  unsigned int width    = first->width;
  const word mask       = first->high_bitmask;
  word const* firstptr  = first->rows[0];
  word const* secondptr = second->rows[0];
  word* resptr          = res->rows[0];

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

  if (!c) {
    c = mzd_local_init(1, At->ncols);
  } else {
    mzd_row_clear_offset(c, 0, 0);
  }

  return mzd_addmul_v(c, v, At);
}

#ifdef WITH_OPT
__attribute__((target("sse2"))) static inline mzd_t* mzd_addmul_v_sse(mzd_t* c, mzd_t const* v,
                                                                      mzd_t const* A) {
  const unsigned int len        = A->width * sizeof(word) / sizeof(__m128i);
  word* cptr                    = c->rows[0];
  word const* vptr              = v->rows[0];
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(__m128i);

  __m128i* mcptr = __builtin_assume_aligned(cptr, 16);

  for (unsigned int w = 0; w < width; ++w, ++vptr) {
    word idx         = *vptr;
    word const* Aptr = A->rows[w * sizeof(word) * 8];
    __m128i* mAptr   = __builtin_assume_aligned(Aptr, 16);

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

__attribute__((target("avx2"))) static inline mzd_t* mzd_addmul_v_avx(mzd_t* c, mzd_t const* v,
                                                                      mzd_t const* A) {
  const unsigned int len        = A->width * sizeof(word) / sizeof(__m256i);
  word* cptr                    = c->rows[0];
  word const* vptr              = v->rows[0];
  const unsigned int width      = v->width;
  const unsigned int rowstride  = A->rowstride;
  const unsigned int mrowstride = rowstride * sizeof(word) / sizeof(__m256i);

  __m256i* mcptr = __builtin_assume_aligned(cptr, 32);

  for (unsigned int w = 0; w < width; ++w, ++vptr) {
    word idx         = *vptr;
    word const* Aptr = A->rows[w * sizeof(word) * 8];
    __m256i* mAptr   = __builtin_assume_aligned(Aptr, 32);

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

mzd_t* mzd_addmul_v(mzd_t* c, mzd_t const* v, mzd_t const* A) {
  if (A->ncols != c->ncols || A->nrows != v->ncols) {
    // number of columns does not match
    return NULL;
  }

#ifdef WITH_OPT
  if (CPU_SUPPORTS_AVX2 && A->ncols % 256 == 0) {
    return mzd_addmul_v_avx(c, v, A);
  } else if (CPU_SUPPORTS_SSE2 && A->ncols % 128 == 0) {
    return mzd_addmul_v_sse(c, v, A);
  }
#endif

  const unsigned int len   = A->width;
  const word mask          = A->high_bitmask;
  word* cptr               = c->rows[0];
  word const* vptr         = v->rows[0];
  const unsigned int width = v->width;

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

      Aptr += A->rowstride;
      idx >>= 1;
    }
  }

  return c;
}

#ifdef WITH_OPT
__attribute__((target("sse2"))) static inline int mzd_equal_sse(mzd_t const* first,
                                                                mzd_t const* second) {
  unsigned int width    = first->width;
  word const* firstptr  = first->rows[0];
  word const* secondptr = second->rows[0];

  if (width >= sse_bound) {
    __m128i const* mfirstptr  = __builtin_assume_aligned(firstptr, 16);
    __m128i const* msecondptr = __builtin_assume_aligned(secondptr, 16);

    do {
      const unsigned int notequal =
          _mm_movemask_epi8(_mm_cmpeq_epi8(*mfirstptr++, *msecondptr++)) - 0xffff;
      if (notequal) {
        return notequal;
      }

      width -= sizeof(__m128i) / sizeof(word);
    } while (width >= sse_bound);

    firstptr  = (word*)mfirstptr;
    secondptr = (word*)msecondptr;
  }

  while (width--) {
    if (*firstptr++ != *secondptr++) {
      return 1;
    }
  }

  return 0;
}

__attribute__((target("sse4.1"))) static inline int mzd_equal_sse41(mzd_t const* first,
                                                                    mzd_t const* second) {
  unsigned int width    = first->width;
  word const* firstptr  = first->rows[0];
  word const* secondptr = second->rows[0];

  if (width >= sse_bound) {
    __m128i const* mfirstptr  = __builtin_assume_aligned(firstptr, 16);
    __m128i const* msecondptr = __builtin_assume_aligned(secondptr, 16);

    do {
      __m128i tmp = _mm_xor_si128(*mfirstptr++, *msecondptr++);
      if (!_mm_testz_si128(tmp, tmp)) {
        return 1;
      }

      width -= sizeof(__m128i) / sizeof(word);
    } while (width >= sse_bound);

    firstptr  = (word*)mfirstptr;
    secondptr = (word*)msecondptr;
  }

  while (width--) {
    if (*firstptr++ != *secondptr++) {
      return 1;
    }
  }

  return 0;
}

__attribute__((target("avx2"))) static inline int mzd_equal_avx(mzd_t const* first,
                                                                mzd_t const* second) {
  unsigned int width    = first->width;
  word const* firstptr  = first->rows[0];
  word const* secondptr = second->rows[0];

  if (width >= avx_bound) {
    __m256i const* mfirstptr  = __builtin_assume_aligned(firstptr, 32);
    __m256i const* msecondptr = __builtin_assume_aligned(secondptr, 32);

    do {
      __m256i tmp = _mm256_xor_si256(*mfirstptr++, *msecondptr++);
      if (!_mm256_testz_si256(tmp, tmp)) {
        return 1;
      }

      width -= sizeof(__m256i) / sizeof(word);
    } while (width >= avx_bound);

    firstptr  = (word*)mfirstptr;
    secondptr = (word*)msecondptr;
  }

  while (width--) {
    if (*firstptr++ != *secondptr++) {
      return 1;
    }
  }

  return 0;
}
#endif

int mzd_equal(mzd_t const* first, mzd_t const* second) {
  if (first->ncols != second->ncols) {
    return 1;
  }

#ifdef WITH_OPT
  if (CPU_SUPPORTS_AVX2 && first->ncols >= 256) {
    return mzd_equal_avx(first, second);
  } else if (CPU_SUPPORTS_SSE4) {
    return mzd_equal_sse41(first, second);
  } else if (CPU_SUPPORTS_SSE2) {
    return mzd_equal_sse(first, second);
  }
#endif

  return mzd_cmp(first, second);
}
