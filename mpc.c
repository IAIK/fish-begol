#include "mpc.h"
#include "avx.h"
#include "mzd_additional.h"

void mpc_clear(mzd_t** res, unsigned sc) {
  for (unsigned int i = 0; i < sc; i++)
    for (int j = 0; j < res[i]->nrows; j++)
      mzd_row_clear_offset(res[i], j, 0);
}

void mpc_shift_right(mzd_t** res, mzd_t** val, unsigned count, unsigned sc) {
  for (unsigned i = 0; i < sc; ++i)
    mzd_shift_right(res[i], val[i], count);
}

void mpc_shift_left(mzd_t** res, mzd_t** val, unsigned count, unsigned sc) {
  for (unsigned i = 0; i < sc; ++i)
    mzd_shift_left(res[i], val[i], count);
}

mzd_t** mpc_and_const(mzd_t** res, mzd_t** first, mzd_t* second, unsigned sc) {
  if (res == 0) {
    res = (mzd_t**)calloc(sizeof(mzd_t*), 3);
  }

  for (unsigned i = 0; i < sc; i++) {
    res[i] = mzd_and(res[i], first[i], second);
  }
  return res;
}

mzd_t** mpc_xor(mzd_t** res, mzd_t** first, mzd_t** second, unsigned sc) {
  if (res == 0)
    res = (mzd_t**)calloc(sizeof(mzd_t*), 3);
  for (unsigned i = 0; i < sc; i++) {
    res[i] = mzd_xor(res[i], first[i], second[i]);
  }
  return res;
}

__attribute__((target("sse2"))) int mpc_and_sse(mzd_t** res, mzd_t** first, mzd_t** second,
                                                mzd_t** r, view_t* view, mzd_t* mask,
                                                unsigned viewshift, mzd_t** buffer) {
  (void)mask;

  for (unsigned m = 0; m < 3; ++m) {
    const unsigned j = (m + 1) % 3;

    __m128i firstm  = _mm_load_si128((__m128i*)first[m]->rows[0]);
    __m128i secondm = _mm_load_si128((__m128i*)second[m]->rows[0]);

    __m128i resm = _mm_and_si128(firstm, secondm);

    __m128i b = _mm_and_si128(secondm, _mm_load_si128((__m128i*)first[j]->rows[0]));
    resm      = _mm_xor_si128(resm, b);

    b    = _mm_and_si128(firstm, _mm_load_si128((__m128i*)second[j]->rows[0]));
    resm = _mm_xor_si128(resm, b);

    resm = _mm_xor_si128(resm, _mm_load_si128((__m128i*)r[m]->rows[0]));
    resm = _mm_xor_si128(resm, _mm_load_si128((__m128i*)r[j]->rows[0]));

    _mm_store_si128((__m128i*)res[m]->rows[0], resm);

    resm = mm128_shift_right(resm, viewshift);
    resm = _mm_xor_si128(resm, _mm_load_si128((__m128i*)view->s[m]->rows[0]));

    _mm_store_si128((__m128i*)view->s[m]->rows[0], resm);
  }

  return 0;
}


__attribute__((target("avx2"))) int mpc_and_avx(mzd_t** res, mzd_t** first, mzd_t** second,
                                                mzd_t** r, view_t* view, mzd_t* mask,
                                                unsigned viewshift, mzd_t** buffer) {
  (void)mask;

  for (unsigned m = 0; m < 3; ++m) {
    const unsigned j = (m + 1) % 3;

    __m256i firstm  = _mm256_load_si256((__m256i*)first[m]->rows[0]);
    __m256i secondm = _mm256_load_si256((__m256i*)second[m]->rows[0]);

    __m256i resm = _mm256_and_si256(firstm, secondm);

    __m256i b = _mm256_and_si256(secondm, _mm256_load_si256((__m256i*)first[j]->rows[0]));
    resm      = _mm256_xor_si256(resm, b);

    b    = _mm256_and_si256(firstm, _mm256_load_si256((__m256i*)second[j]->rows[0]));
    resm = _mm256_xor_si256(resm, b);

    resm = _mm256_xor_si256(resm, _mm256_load_si256((__m256i*)r[m]->rows[0]));
    resm = _mm256_xor_si256(resm, _mm256_load_si256((__m256i*)r[j]->rows[0]));

    _mm256_store_si256((__m256i*)res[m]->rows[0], resm);

    resm = mm256_shift_right(resm, viewshift);
    resm = _mm256_xor_si256(resm, _mm256_load_si256((__m256i*)view->s[m]->rows[0]));

    _mm256_store_si256((__m256i*)view->s[m]->rows[0], resm);
  }

  return 0;
}

int mpc_and(mzd_t** res, mzd_t** first, mzd_t** second, mzd_t** r, view_t* view, mzd_t* mask,
            unsigned viewshift, mzd_t** buffer) {
  (void)mask;

  mzd_t* b = NULL;
  mzd_t* c = NULL;

  for (unsigned m = 0; m < 3; ++m) {
    unsigned j = (m + 1) % 3;
    res[m]     = mzd_and(res[m], first[m], second[m]);

    b = mzd_and(b, first[j], second[m]);
    c = mzd_and(c, first[m], second[j]);

    mzd_xor(res[m], res[m], b);
    mzd_xor(res[m], res[m], c);
    mzd_xor(res[m], res[m], r[m]);
    mzd_xor(res[m], res[m], r[j]);
  }

  mzd_free(b);
  mzd_free(c);

  mpc_shift_right(buffer, res, viewshift, 3);
  mpc_xor(view->s, view->s, buffer, 3);
  return 0;
}

__attribute__((target("sse2"))) int mpc_and_verify_sse(mzd_t** res, mzd_t** first, mzd_t** second,
                                                       mzd_t** r, view_t* view, mzd_t* mask,
                                                       unsigned viewshift,
                                                       mzd_t** buffer) {
  (void)buffer;

  for (unsigned m = 0; m < 1; ++m) {
    const unsigned j = (m + 1);

    __m128i firstm  = _mm_load_si128((__m128i*)first[m]->rows[0]);
    __m128i secondm = _mm_load_si128((__m128i*)second[m]->rows[0]);

    __m128i resm = _mm_and_si128(firstm, secondm);

    __m128i b = _mm_and_si128(secondm, _mm_load_si128((__m128i*)first[j]->rows[0]));
    resm      = _mm_xor_si128(resm, b);

    b    = _mm_and_si128(firstm, _mm_load_si128((__m128i*)second[j]->rows[0]));
    resm = _mm_xor_si128(resm, b);

    resm = _mm_xor_si128(resm, _mm_load_si128((__m128i*)r[m]->rows[0]));
    resm = _mm_xor_si128(resm, _mm_load_si128((__m128i*)r[j]->rows[0]));

    _mm_store_si128((__m128i*)res[m]->rows[0], resm);

    __m128i sm = _mm_load_si128((__m128i*)view->s[m]->rows[0]);
    sm         = mm128_shift_left(sm, viewshift);
    sm         = _mm_and_si128(sm, resm);

    const unsigned int same = _mm_movemask_epi8(_mm_cmpeq_epi8(sm, resm));
    if (same != 0xffff) {
      return 1;
    }
  }

  __m128i rsc = _mm_load_si128((__m128i*)view->s[2 - 1]->rows[0]);
  rsc         = mm128_shift_left(rsc, viewshift);
  rsc         = _mm_and_si128(rsc, _mm_load_si128((__m128i*)mask->rows[0]));
  _mm_store_si128((__m128i*)res[2 - 1]->rows[0], rsc);

  return 0;
}

__attribute__((target("avx2"))) int mpc_and_verify_avx(mzd_t** res, mzd_t** first, mzd_t** second,
                                                       mzd_t** r, view_t* view, mzd_t* mask,
                                                       unsigned viewshift,
                                                       mzd_t** buffer) {
  (void)buffer;

  for (unsigned m = 0; m < 1; ++m) {
    const unsigned j = (m + 1);

    __m256i firstm  = _mm256_load_si256((__m256i*)first[m]->rows[0]);
    __m256i secondm = _mm256_load_si256((__m256i*)second[m]->rows[0]);

    __m256i resm = _mm256_and_si256(firstm, secondm);

    __m256i b = _mm256_and_si256(secondm, _mm256_load_si256((__m256i*)first[j]->rows[0]));
    resm      = _mm256_xor_si256(resm, b);

    b    = _mm256_and_si256(firstm, _mm256_load_si256((__m256i*)second[j]->rows[0]));
    resm = _mm256_xor_si256(resm, b);

    resm = _mm256_xor_si256(resm, _mm256_load_si256((__m256i*)r[m]->rows[0]));
    resm = _mm256_xor_si256(resm, _mm256_load_si256((__m256i*)r[j]->rows[0]));

    _mm256_store_si256((__m256i*)res[m]->rows[0], resm);

    __m256i sm = _mm256_load_si256((__m256i*)view->s[m]->rows[0]);
    sm         = mm256_shift_left(sm, viewshift);
    sm         = _mm256_and_si256(sm, resm);

    sm = _mm256_xor_si256(sm, resm);
    if (!_mm256_testz_si256(sm, sm)) {
      return 1;
    }
  }

  __m256i rsc = _mm256_load_si256((__m256i*)view->s[2 - 1]->rows[0]);
  rsc         = mm256_shift_left(rsc, viewshift);
  rsc         = _mm256_and_si256(rsc, _mm256_load_si256((__m256i*)mask->rows[0]));
  _mm256_store_si256((__m256i*)res[2 - 1]->rows[0], rsc);

  return 0;
}

int mpc_and_verify(mzd_t** res, mzd_t** first, mzd_t** second, mzd_t** r, view_t* view, mzd_t* mask,
                   unsigned viewshift, mzd_t** buffer) {
  mzd_t* b = NULL;
  mzd_t* c = NULL;

  for (unsigned m = 0; m < 1; m++) {
    unsigned j = m + 1;
    res[m]     = mzd_and(res[m], first[m], second[m]);

    b = mzd_and(b, first[j], second[m]);
    c = mzd_and(c, first[m], second[j]);

    mzd_xor(res[m], res[m], b);
    mzd_xor(res[m], res[m], c);
    mzd_xor(res[m], res[m], r[m]);
    mzd_xor(res[m], res[m], r[j]);
  }

  mzd_free(b);
  mzd_free(c);

  for (unsigned m = 0; m < 1; m++) {
    mzd_shift_left(buffer[m], view->s[m], viewshift);
    mzd_and(buffer[m], buffer[m], res[m]);
    if (mzd_equal(buffer[m], res[m])) {
      return -1;
    }
  }

  mzd_shift_left(res[2 - 1], view->s[2 - 1], viewshift);
  mzd_and(res[2 - 1], res[2 - 1], mask);

  return 0;
}

int mpc_and_bit(BIT* a, BIT* b, BIT* r, view_t* views, int* i, unsigned bp, unsigned sc) {
  BIT* wp = (BIT*)malloc(sc * sizeof(BIT));
  for (unsigned m = 0; m < sc; ++m) {
    unsigned j = (m + 1) % 3;
    wp[m]      = (a[m] & b[m]) ^ (a[j] & b[m]) ^ (a[m] & b[j]) ^ r[m] ^ r[j];
  }
  for (unsigned m = 0; m < sc; ++m) {
    a[m]          = wp[m];
  }
  mpc_write_bit(views[*i].s, bp, a, sc);
  free(wp);
  return 0;
}

int mpc_and_bit_verify(BIT* a, BIT* b, BIT* r, view_t* views, int* i, unsigned bp, unsigned sc) {
  BIT* wp = (BIT*)malloc(sc * sizeof(BIT));
  for (unsigned m = 0; m < sc - 1; m++) {
    unsigned j = m + 1;
    wp[m]      = (a[m] & b[m]) ^ (a[j] & b[m]) ^ (a[m] & b[j]) ^ r[m] ^ r[j];
  }
  for (unsigned m = 0; m < sc - 1; m++) {
    a[m] = wp[m];
    if (a[m] != mzd_read_bit(views[*i].s[m], 0, bp)) {
      return -1;
    }
  }
  a[sc - 1] = mzd_read_bit(views[*i].s[sc - 1], 0, bp);
  free(wp);
  return 0;
}

void mpc_xor_bit(BIT* a, BIT* b, unsigned sc) {
  for (unsigned i = 0; i < sc; i++) {
    a[i] ^= b[i];
  }
}

void mpc_read_bit(BIT* out, mzd_t** vec, rci_t n, unsigned sc) {
  for (unsigned i = 0; i < sc; i++)
    out[i]        = mzd_read_bit(vec[i], 0, n);
}

void mpc_write_bit(mzd_t** vec, rci_t n, BIT* bit, unsigned sc) {
  for (unsigned i = 0; i < sc; i++)
    mzd_write_bit(vec[i], 0, n, bit[i]);
}

mzd_t** mpc_add(mzd_t** result, mzd_t** first, mzd_t** second, unsigned sc) {
  if (result == 0)
    result = mpc_init_empty_share_vector(first[0]->ncols, sc);
  for (unsigned i = 0; i < sc; i++) {
    mzd_xor(result[i], first[i], second[i]);
  }
  return result;
}

mzd_t** mpc_const_add(mzd_t** result, mzd_t** first, mzd_t* second, unsigned sc, unsigned c) {
  if (result == 0)
    result = mpc_init_empty_share_vector(first[0]->ncols, sc);
  if (c == 0)
    mzd_xor(result[0], first[0], second);
  else if (c == sc)
    mzd_xor(result[sc - 1], first[sc - 1], second);
  return result;
}

mzd_t** mpc_const_mat_mul(mzd_t** result, mzd_t* matrix, mzd_t** vector, unsigned sc) {
  if (result == 0)
    result = mpc_init_empty_share_vector(vector[0]->ncols, sc);
  for (unsigned i = 0; i < sc; ++i) {
    mzd_mul_v(result[i], vector[i], matrix);
  }
  return result;
}

void mpc_copy(mzd_t** out, mzd_t** in, unsigned sc) {
  for (unsigned i = 0; i < sc; ++i) {
    mzd_copy(out[i], in[i]);
  }
}

mzd_t* mpc_reconstruct_from_share(mzd_t** shared_vec) {
  mzd_t* res = mzd_xor(0, shared_vec[0], shared_vec[1]);
  mzd_xor(res, res, shared_vec[2]);
  return res;
}

void mpc_print(mzd_t** shared_vec) {
  mzd_t* r = mpc_reconstruct_from_share(shared_vec);
  mzd_print(r);
  mzd_free(r);
}

void mpc_free(mzd_t** vec, unsigned sc) {
  for (unsigned i = 0; i < sc; ++i) {
    mzd_free(vec[i]);
  }
  free(vec);
}

mzd_t** mpc_init_empty_share_vector(rci_t n, unsigned sc) {
  mzd_t** s = calloc(sc, sizeof(mzd_t*));
  for (unsigned i = 0; i < sc; ++i) {
    s[i] = mzd_init(1, n);
  }
  return s;
}

mzd_t** mpc_init_random_vector(rci_t n, unsigned sc) {
  mzd_t** s = calloc(sc, sizeof(mzd_t*));
  for (unsigned i = 0; i < sc; ++i) {
    s[i]  = mzd_init_random_vector(n);
  }
  return s;
}

mzd_t** mpc_init_plain_share_vector(mzd_t* v) {
  mzd_t** s = calloc(3, sizeof(mzd_t*));
  s[0]      = mzd_copy(NULL, v);
  s[1]      = mzd_copy(NULL, v);
  s[2]      = mzd_copy(NULL, v);

  return s;
}

mzd_t** mpc_init_share_vector(mzd_t* v) {
  mzd_t** s = calloc(3, sizeof(mzd_t*));
  s[0]      = mzd_init_random_vector(v->ncols);
  s[1]      = mzd_init_random_vector(v->ncols);
  s[2]      = mzd_init(1, v->ncols);

  mzd_xor(s[2], s[0], s[1]);
  mzd_xor(s[2], s[2], v);

  return s;
}
