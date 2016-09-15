#include "mzd_additional.h"
#include "randomness.h"

#ifdef WITH_OPT
#include "avx.h"

static const unsigned int sse_bound = 128 / (8 * sizeof(word));
static const unsigned int avx_bound = 256 / (8 * sizeof(word));
#endif
static const unsigned int word_size_bits = 8 * sizeof(word);

// #if WITH_OPENMP
mzd_t* mzd_local_init(rci_t r, rci_t c) {
  const rci_t width = (c + m4ri_radix - 1) / m4ri_radix;
  const rci_t rowstride = (width < mzd_paddingwidth || (width & 1) == 0) ? width : width + 1;

  const size_t buffer_size = r * rowstride * sizeof(word);
  const size_t rows_size = r * sizeof(word*);

  unsigned char* buffer = aligned_alloc(32, sizeof(mzd_t) + buffer_size + rows_size);
  memset(buffer, 0, sizeof(mzd_t) + buffer_size + rows_size);

  mzd_t* A = (mzd_t*) buffer;
  buffer += sizeof(mzd_t);

  A->rows = (word**) (buffer + buffer_size);
  for (rci_t i = 0; i < r; ++i) {
    A->rows[i] = (word*) (buffer + i * rowstride * sizeof(word));
  }

  A->nrows = r;
  A->ncols = c;
  A->width = width;
  A->rowstride = rowstride;
  A->high_bitmask = __M4RI_LEFT_BITMASK(c % m4ri_radix);
  A->flags = (A->high_bitmask != m4ri_ffff) ? mzd_flag_nonzero_excess : 0;
  A->offset_vector = 0;
  A->row_offset = 0;
  A->blocks = 0;
  A->blockrows_log = 0;

  return A;
}

void mzd_local_free(mzd_t* v) {
  free(v);
}

mzd_t* mzd_local_copy(mzd_t* dst, mzd_t const* src) {
  if (!dst) {
    dst = mzd_local_init(src->nrows, src->ncols);
  }

  if (dst->nrows == src->nrows || dst->ncols == dst->ncols) {
    memcpy(((unsigned char*) dst) + sizeof(mzd_t), ((const unsigned char*) src) + sizeof(mzd_t), src->nrows * src->rowstride * sizeof(word));
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

void mzd_randomize_upper_triangular(mzd_t* val) {
  const word mask_end = val->high_bitmask;
  for (rci_t i = 0; i < val->nrows; ++i) {
    const unsigned int offset = i / word_size_bits;
    const unsigned int bit    = i % word_size_bits;
    word* row                 = val->rows[i];

    rand_bytes((unsigned char*)(row + offset), (val->width - offset) * sizeof(word));
    row[val->width - 1] &= mask_end;

    row[offset] |= ((word)1) << bit;
    if (bit) {
      row[offset] &= ~((((word)1) << bit) - 1);
    }
  }
}

mzd_t* mzd_init_random_vector(rci_t n) {
  mzd_t* A = mzd_local_init(1, n);
  mzd_randomize_ssl(A);

  return A;
}

static mzd_t* mzd_init_random_vector_prng(rci_t n, aes_prng_t* aes_prng) {
  mzd_t* v = mzd_local_init(1, n);
  aes_prng_get_randomness(aes_prng, (unsigned char*)v->rows[0], v->width * sizeof(word));
  v->rows[0][v->width - 1] &= v->high_bitmask;
  return v;
}

mzd_t** mzd_init_random_vectors_from_seed(const unsigned char key[16], rci_t n, unsigned int count) {
  aes_prng_t aes_prng;
  aes_prng_init(&aes_prng, key);

  mzd_t** vectors = calloc(count, sizeof(mzd_t*));
  for (unsigned int v = 0; v < count; ++v) {
    vectors[v] = mzd_init_random_vector_prng(n, &aes_prng);
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

  for (unsigned int i = 0; i < nwords - 1; ++i, ++resptr) {
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

  for (unsigned int i = nwords - 1; i > 0; --i, --resptr) {
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
  if (res == 0) {
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

void mzd_shared_init(mzd_shared_t* shared_value, mzd_t* value) {
  shared_value->share_count = 1;

  shared_value->shared    = calloc(1, sizeof(mzd_t*));
  shared_value->shared[0] = mzd_local_copy(NULL, value);
}

void mzd_shared_copy(mzd_shared_t* dst, mzd_shared_t* src) {
  mzd_shared_clear(dst);

  dst->shared = calloc(src->share_count, sizeof(mzd_t*));
  for (unsigned int i = 0; i < src->share_count; ++i) {
    dst->shared[i] = mzd_local_copy(NULL, src->shared[i]);
  }
  dst->share_count = src->share_count;
}

void mzd_shared_from_shares(mzd_shared_t* shared_value, mzd_t** shares, unsigned int share_count) {
  shared_value->share_count = share_count;
  shared_value->shared      = calloc(share_count, sizeof(mzd_t*));
  for (unsigned int i = 0; i < share_count; ++i) {
    shared_value->shared[i] = mzd_local_copy(NULL, shares[i]);
  }
}

void mzd_shared_share(mzd_shared_t* shared_value) {
  mzd_t** tmp = realloc(shared_value->shared, 3 * sizeof(mzd_t*));
  if (!tmp) {
    return;
  }

  shared_value->shared      = tmp;
  shared_value->share_count = 3;

  shared_value->shared[1] = mzd_init_random_vector(shared_value->shared[0]->ncols);
  shared_value->shared[2] = mzd_init_random_vector(shared_value->shared[0]->ncols);

  mzd_xor(shared_value->shared[0], shared_value->shared[0], shared_value->shared[1]);
  mzd_xor(shared_value->shared[0], shared_value->shared[0], shared_value->shared[2]);
}

void mzd_shared_share_prng(mzd_shared_t* shared_value, aes_prng_t* aes_prng) {
  mzd_t** tmp = realloc(shared_value->shared, 3 * sizeof(mzd_t*));
  if (!tmp) {
    return;
  }

  shared_value->shared      = tmp;
  shared_value->share_count = 3;

  shared_value->shared[1] = mzd_init_random_vector_prng(shared_value->shared[0]->ncols, aes_prng);
  shared_value->shared[2] = mzd_init_random_vector_prng(shared_value->shared[0]->ncols, aes_prng);

  mzd_xor(shared_value->shared[0], shared_value->shared[0], shared_value->shared[1]);
  mzd_xor(shared_value->shared[0], shared_value->shared[0], shared_value->shared[2]);
}

void mzd_shared_clear(mzd_shared_t* shared_value) {
  for (unsigned int i = 0; i < shared_value->share_count; ++i) {
    mzd_local_free(shared_value->shared[i]);
  }
  free(shared_value->shared);
  shared_value->share_count = 0;
  shared_value->shared      = NULL;
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
