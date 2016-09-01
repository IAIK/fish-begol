#include "mzd_additional.h"
#include "randomness.h"
#include "avx.h"

#include <openssl/rand.h>

void mzd_randomize_ssl(mzd_t* val) {
  // similar to mzd_randomize but using RAND_Bytes instead
  const word mask_end = val->high_bitmask;
  for (rci_t i = 0; i < val->nrows; ++i) {
    RAND_bytes((unsigned char*)val->rows[i], val->width * sizeof(word));
    val->rows[i][val->width - 1] &= mask_end;
  }
}

mzd_t* mzd_init_random_vector(rci_t n) {
  mzd_t* A = mzd_init(1, n);
  mzd_randomize_ssl(A);

  return A;
}

mzd_t** mzd_init_random_vectors_from_seed(unsigned char key[16], rci_t n, unsigned int count) {
  if (n % (8 * sizeof(word)) != 0)
    return NULL;

  aes_prng_t* aes_prng = aes_prng_init(key);

  mzd_t** vectors = calloc(count, sizeof(mzd_t*));
  for (unsigned int v = 0; v < count; ++v) {
    vectors[v] = mzd_init(1, n);
    aes_prng_get_randomness(aes_prng, (unsigned char*)vectors[v]->rows[0], n / 8);
    vectors[v]->rows[0][vectors[v]->width - 1] &= vectors[v]->high_bitmask;
  }

  aes_prng_free(aes_prng);
  return vectors;
}

void mzd_shift_right_inplace(mzd_t* val, unsigned int count) {
  if (!count) {
    return;
  }

  const unsigned int nwords     = val->ncols / (8 * sizeof(word));
  const unsigned int left_count = 8 * sizeof(word) - count;

  for (unsigned int i = 0; i < nwords - 1; ++i) {
    val->rows[0][i] = (val->rows[0][i] >> count) | (val->rows[0][i + 1] << left_count);
  }
  val->rows[0][nwords - 1] >>= count;
}

void mzd_shift_left_inplace(mzd_t* val, unsigned count) {
  if (!count) {
    return;
  }

  const unsigned int nwords      = val->ncols / (8 * sizeof(word));
  const unsigned int right_count = 8 * sizeof(word) - count;

  for (unsigned int i = nwords - 1; i > 0; --i) {
    val->rows[0][i] = (val->rows[0][i] << count) | (val->rows[0][i - 1] >> right_count);
  }
  val->rows[0][0] = val->rows[0][0] << count;
}

void mzd_shift_right(mzd_t* res, mzd_t* val, unsigned count) {
  if (!count) {
    mzd_copy(res, val);
    return;
  }

  const unsigned int nwords     = val->ncols / (8 * sizeof(word));
  const unsigned int left_count = 8 * sizeof(word) - count;

  for (unsigned int i = 0; i < nwords - 1; ++i) {
    res->rows[0][i] = (val->rows[0][i] >> count) | (val->rows[0][i + 1] << left_count);
  }
  res->rows[0][nwords - 1] = val->rows[0][nwords - 1] >> count;
}

void mzd_shift_left(mzd_t* res, mzd_t* val, unsigned count) {
  if (!count) {
    mzd_copy(res, val);
    return;
  }

  const unsigned int nwords      = val->ncols / (8 * sizeof(word));
  const unsigned int right_count = 8 * sizeof(word) - count;

  for (unsigned int i = nwords - 1; i > 0; --i) {
    res->rows[0][i] = (val->rows[0][i] << count) | (val->rows[0][i - 1] >> right_count);
  }
  res->rows[0][0] = val->rows[0][0] << count;
}

mzd_t *mzd_and(mzd_t *res, mzd_t *first, mzd_t *second) {
  if(res == 0) {
    res = mzd_init(1, first->ncols);
  }
  const unsigned int len = first->ncols / (8 * sizeof(word));
  word* first_ptr = first->rows[0];
  word* second_ptr = second->rows[0];
  word* result_ptr = res->rows[0];

  for(unsigned int i = 0 ; i < len; ++i) {
    result_ptr[i] = first_ptr[i] & second_ptr[i];
  }
  return res;
}

mzd_t *mzd_xor(mzd_t *res, mzd_t *first, mzd_t *second) {
  if(res == 0) {
    res = mzd_init(1, first->ncols);
  }

  const unsigned int len = first->ncols / (8 * sizeof(word));
  word* first_ptr = first->rows[0];
  word* second_ptr = second->rows[0];
  word* result_ptr = res->rows[0];

  for(unsigned int i = 0 ; i < len; ++i) {
    result_ptr[i] = first_ptr[i] ^ second_ptr[i];
  }

  return res;
}

void mzd_shared_init(mzd_shared_t* shared_value, mzd_t* value) {
  shared_value->share_count = 1;

  shared_value->shared    = calloc(1, sizeof(mzd_t*));
  shared_value->shared[0] = mzd_copy(NULL, value);
}

void mzd_shared_copy(mzd_shared_t* dst, mzd_shared_t* src) {
  mzd_shared_clear(dst);

  dst->shared = calloc(src->share_count, sizeof(mzd_t*));
  for (unsigned int i = 0; i < src->share_count; ++i) {
    dst->shared[i] = mzd_copy(NULL, src->shared[i]);
  }
  dst->share_count = src->share_count;
}

void mzd_shared_from_shares(mzd_shared_t* shared_value, mzd_t** shares, unsigned int share_count) {
  shared_value->share_count = share_count;
  shared_value->shared      = calloc(share_count, sizeof(mzd_t*));
  for (unsigned int i = 0; i < share_count; ++i) {
    shared_value->shared[i] = mzd_copy(NULL, shares[i]);
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

  mzd_add(shared_value->shared[0], shared_value->shared[0], shared_value->shared[1]);
  mzd_add(shared_value->shared[0], shared_value->shared[0], shared_value->shared[2]);
}

void mzd_shared_clear(mzd_shared_t* shared_value) {
  for (unsigned int i = 0; i < shared_value->share_count; ++i) {
    mzd_free(shared_value->shared[i]);
  }
  free(shared_value->shared);
  shared_value->share_count = 0;
  shared_value->shared      = NULL;
}

mzd_t *mzd_mul_v(mzd_t *c, mzd_t const *v, mzd_t const *At) {
  if (!c) {
    c = mzd_init(1, v->ncols);
  } else {
    mzd_row_clear_offset(c, 0, 0);
  }

  return mzd_addmul_v(c, v, At);
}

__attribute__((target("sse2")))
static inline mzd_t *mzd_addmul_v_sse(mzd_t *c, mzd_t const *v, mzd_t const *At) {
  unsigned int width = At->width;
  const word mask = At->high_bitmask;
  word* cptr = c->rows[0];
  word const* vptr = v->rows[0];
  word const* Atptr = At->rows[0];

  if (width * sizeof(word) * 8 >= 128) {
    __m128i* mcptr = __builtin_assume_aligned(cptr, 16);
    __m128i const* mvptr = __builtin_assume_aligned(vptr, 16);
    __m128i const* mAtptr = __builtin_assume_aligned(Atptr, 16);
    const unsigned int rowstride = At->rowstride * sizeof(word) / sizeof(__m128i);

    do
    {
      __m128i const* Atmp = mAtptr;
      __m128i mc = *mcptr;
      const __m128i mv = *mvptr;
      for (rci_t r = 0; r < At->nrows; ++r, Atmp += rowstride) {
        __m128i tmp = _mm_and_si128(*Atmp, mv);
        mc = _mm_xor_si128(mc, tmp);
      }
      *mcptr = mc;

      width -= sizeof(__m128i) / sizeof(word);
      ++mcptr;
      ++mvptr;
      ++mAtptr;
    } while (width * sizeof(word) * 8 >= 128);

    cptr = (word*) mcptr;
    vptr = (word*) mvptr;
    Atptr = (word*) mAtptr;
  }

  while (width)
  {
    word const* Atmp = Atptr;
    for (rci_t r = 0; r < At->nrows; ++r, Atmp += At->rowstride) {
        *cptr ^= *Atmp & *vptr;
    }

    ++cptr;
    ++vptr;
    ++Atptr;
    --width;
  }

  *(--cptr) &= mask;
  return c;
}

__attribute__((target("avx2")))
static inline mzd_t *mzd_addmul_v_avx(mzd_t *c, mzd_t const *v, mzd_t const *At) {
  unsigned int width = At->width;
  const word mask = At->high_bitmask;
  word* cptr = c->rows[0];
  word const* vptr = v->rows[0];
  word const* Atptr = At->rows[0];

  if (width * sizeof(word) * 8 >= 256) {
    __m256i* mcptr = __builtin_assume_aligned(cptr, 32);
    __m256i const* mvptr = __builtin_assume_aligned(vptr, 32);
    __m256i const* mAtptr = __builtin_assume_aligned(Atptr, 32);
    const unsigned int rowstride = At->rowstride * sizeof(word) / sizeof(__m256i);

    do
    {
      __m256i const* Atmp = mAtptr;
      __m256i mc = *mcptr;
      const __m256i mv = *mvptr;
      for (rci_t r = 0; r < At->nrows; ++r, Atmp += rowstride) {
        __m256i tmp = _mm256_and_si256(*Atmp, mv);
        mc = _mm256_xor_si256(mc, tmp);
      }
      *mcptr = mc;

      width -= sizeof(__m256i) / sizeof(word);
      ++mcptr;
      ++mvptr;
      ++mAtptr;
    } while (width * sizeof(word) * 8 >= 256);

    cptr = (word*) mcptr;
    vptr = (word*) mvptr;
    Atptr = (word*) mAtptr;
  }

  while (width)
  {
    word const* Atmp = Atptr;
    for (rci_t r = 0; r < At->nrows; ++r, Atmp += At->rowstride) {
        *cptr ^= *Atmp & *vptr;
    }

    ++cptr;
    ++vptr;
    ++Atptr;
    --width;
  }

  *(--cptr) &= mask;
  return c;
}


mzd_t *mzd_addmul_v(mzd_t *c, mzd_t const *v, mzd_t const *At) {
  if (At->ncols != c->ncols) {
    // number of columns does not match
    return NULL;
  }

  if (__builtin_cpu_supports("avx2") && At->ncols >= 256) {
    return mzd_addmul_v_avx(c, v, At);
  } else if (__builtin_cpu_supports("sse2")) {
    return mzd_addmul_v_sse(c, v, At);
  }

  const unsigned int len = At->width;
  const word mask = At->high_bitmask;
  word* cptr = c->rows[0];
  word const* vptr = v->rows[0];

  for (rci_t r = 0; r < At->nrows; ++r) {
    word* Atptr = At->rows[r];
    for (unsigned int i = 0 ; i < len - 1; ++i) {
      cptr[i] ^= Atptr[i] & vptr[i];
    }
    cptr[len - 1] = (cptr[len - 1] ^ (Atptr[len -1] & vptr[len - 1])) & mask;
  }

  return c;
}
