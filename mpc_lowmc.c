#include "mpc_lowmc.h"
#include "avx.h"
#include "lowmc_pars.h"
#include "mpc.h"
#include "mzd_additional.h"

#include <stdbool.h>

static void sbox_vars_free(sbox_vars_t* vars, unsigned int sc);

typedef int (*BIT_and_ptr)(BIT*, BIT*, BIT*, view_t*, int*, unsigned, unsigned);
typedef int (*and_ptr)(mzd_t**, mzd_t**, mzd_t**, mzd_t**, view_t*, mzd_t*, unsigned, unsigned,
                       mzd_t**);

static int _mpc_sbox_layer_bitsliced(mzd_t** out, mzd_t** in, rci_t m, view_t* view, mzd_t** rvec,
                                     unsigned sc, and_ptr andPtr, mask_t* mask, sbox_vars_t* vars) {
  if (in[0]->ncols - 3 * m < 2) {
    printf("Bitsliced implementation requires in->ncols - 3 * m >= 2\n");
    return 0;
  }

  mpc_and_const(out, in, mask->mask, sc);

  mpc_and_const(vars->x0m, in, mask->x0, sc);
  mpc_and_const(vars->x1m, in, mask->x1, sc);
  mpc_and_const(vars->x2m, in, mask->x2, sc);
  mpc_and_const(vars->r0m, rvec, mask->x0, sc);
  mpc_and_const(vars->r1m, rvec, mask->x1, sc);
  mpc_and_const(vars->r2m, rvec, mask->x2, sc);

  mpc_shift_left(vars->x0s, vars->x0m, 2, sc);
  mpc_shift_left(vars->r0s, vars->r0m, 2, sc);

  mpc_shift_left(vars->x1s, vars->x1m, 1, sc);
  mpc_shift_left(vars->r1s, vars->r1m, 1, sc);

  if (andPtr(vars->r0m, vars->x0s, vars->x1s, vars->r2m, view, mask->x2, 0, sc, vars->v) ||
      andPtr(vars->r2m, vars->x1s, vars->x2m, vars->r0s, view, mask->x2, 2, sc, vars->v) ||
      andPtr(vars->r1m, vars->x0s, vars->x2m, vars->r1s, view, mask->x2, 1, sc, vars->v)) {
    return -1;
  }

  mpc_xor(vars->r2m, vars->r2m, vars->x0s, sc);

  mpc_xor(vars->x0s, vars->x0s, vars->x1s, sc);
  mpc_xor(vars->r1m, vars->r1m, vars->x0s, sc);

  mpc_xor(vars->r0m, vars->r0m, vars->x0s, sc);
  mpc_xor(vars->r0m, vars->r0m, vars->x2m, sc);

  mpc_shift_right(vars->x0s, vars->r2m, 2, sc);
  mpc_shift_right(vars->x1s, vars->r1m, 1, sc);

  mpc_xor(out, out, vars->r0m, sc);
  mpc_xor(out, out, vars->x0s, sc);
  mpc_xor(out, out, vars->x1s, sc);

  return 0;
}

__attribute__((target("sse2"))) static int
_mpc_sbox_layer_bitsliced_sse(mzd_t** out, mzd_t** in, rci_t m, view_t* view, mzd_t** rvec,
                              unsigned sc, and_ptr andPtr, mask_t* mask, sbox_vars_t* vars) {
  __m128i mx0 = _mm_load_si128((__m128i*)mask->x0->rows[0]);
  __m128i mx1 = _mm_load_si128((__m128i*)mask->x1->rows[0]);
  __m128i mx2 = _mm_load_si128((__m128i*)mask->x2->rows[0]);

  for (unsigned int m = 0; m < sc; ++m) {
    __m128i min = _mm_load_si128((__m128i*)in[m]->rows[0]);

    __m128i x0m = _mm_and_si128(min, mx0);
    __m128i x1m = _mm_and_si128(min, mx1);
    __m128i x2m = _mm_and_si128(min, mx2);

    __m128i x0s = m128_shift_left(x0m, 2);
    __m128i x1s = m128_shift_left(x1m, 1);

    _mm_store_si128((__m128i*)vars->x2m[m]->rows[0], x2m);
    _mm_store_si128((__m128i*)vars->x0s[m]->rows[0], x0s);
    _mm_store_si128((__m128i*)vars->x1s[m]->rows[0], x1s);

    min = _mm_load_si128((__m128i*)rvec[m]->rows[0]);

    x0m = _mm_and_si128(min, mx0);
    x1m = _mm_and_si128(min, mx1);
    x2m = _mm_and_si128(min, mx2);

    _mm_store_si128((__m128i*)vars->r0m[m]->rows[0], x0m);
    _mm_store_si128((__m128i*)vars->r1m[m]->rows[0], x1m);
    _mm_store_si128((__m128i*)vars->r2m[m]->rows[0], x2m);

    x0s = m128_shift_left(x0m, 2);
    x1s = m128_shift_left(x1m, 1);

    _mm_store_si128((__m128i*)vars->r0s[m]->rows[0], x0s);
    _mm_store_si128((__m128i*)vars->r1s[m]->rows[0], x1s);
  }

  if (andPtr(vars->r0m, vars->x0s, vars->x1s, vars->r2m, view, mask->x2, 0, sc, vars->v) ||
      andPtr(vars->r2m, vars->x1s, vars->x2m, vars->r0s, view, mask->x2, 2, sc, vars->v) ||
      andPtr(vars->r1m, vars->x0s, vars->x2m, vars->r1s, view, mask->x2, 1, sc, vars->v)) {
    return -1;
  }

  __m128i mmask = _mm_load_si128((__m128i*)mask->mask->rows[0]);
  for (unsigned int m = 0; m < sc; ++m) {
    // mpc_xor(vars->r2m, vars->r2m, vars->x0s, sc);
    __m128i x0s = _mm_load_si128((__m128i*)vars->x0s[m]->rows[0]);
    __m128i r2m = _mm_load_si128((__m128i*)vars->r2m[m]->rows[0]);
    r2m         = _mm_xor_si128(r2m, x0s);

    // mpc_xor(vars->x0s, vars->x0s, vars->x1s, sc);
    __m128i x1s = _mm_load_si128((__m128i*)vars->x1s[m]->rows[0]);
    x0s         = _mm_xor_si128(x0s, x1s);
    // mpc_xor(vars->r1m, vars->r1m, vars->x0s, sc);
    __m128i r1m = _mm_xor_si128(x0s, _mm_load_si128((__m128i*)vars->r1m[m]->rows[0]));

    // mpc_and_const(out, in, mask->mask, sc);
    __m128i mout = _mm_and_si128(mmask, _mm_load_si128((__m128i*)in[m]->rows[0]));

    // mpc_xor(vars->r0m, vars->r0m, vars->x0s, sc);
    __m128i r0m = _mm_xor_si128(x0s, _mm_load_si128((__m128i*)vars->r0m[m]->rows[0]));
    // mpc_xor(vars->r0m, vars->r0m, vars->x2m, sc);
    r0m = _mm_xor_si128(r0m, _mm_load_si128((__m128i*)vars->x2m[m]->rows[0]));
    // mpc_xor(out, out, vars->r0m, sc);
    mout = _mm_xor_si128(mout, r0m);

    // mpc_shift_right(vars->x0s, vars->r2m, 2, sc);
    x0s = m128_shift_right(r2m, 2);
    // mpc_xor(out, out, vars->x0s, sc);
    mout = _mm_xor_si128(mout, x0s);

    // mpc_shift_right(vars->x1s, vars->r1m, 1, sc);
    x1s = m128_shift_right(r1m, 1);
    // mpc_xor(out, out, vars->x1s, sc);
    mout = _mm_xor_si128(mout, x1s);

    _mm_store_si128((__m128i*)out[m]->rows[0], mout);
  }

  return 0;
}

__attribute__((target("avx2"))) static int
_mpc_sbox_layer_bitsliced_avx(mzd_t** out, mzd_t** in, rci_t m, view_t* view, mzd_t** rvec,
                              unsigned sc, and_ptr andPtr, mask_t* mask, sbox_vars_t* vars) {
  __m256i mx0 = _mm256_load_si256((__m256i*)mask->x0->rows[0]);
  __m256i mx1 = _mm256_load_si256((__m256i*)mask->x1->rows[0]);
  __m256i mx2 = _mm256_load_si256((__m256i*)mask->x2->rows[0]);

  for (unsigned int m = 0; m < sc; ++m) {
    __m256i min = _mm256_load_si256((__m256i*)in[m]->rows[0]);

    __m256i x0m = _mm256_and_si256(min, mx0);
    __m256i x1m = _mm256_and_si256(min, mx1);
    __m256i x2m = _mm256_and_si256(min, mx2);

    __m256i x0s = m256_shift_left(x0m, 2);
    __m256i x1s = m256_shift_left(x1m, 1);

    _mm256_store_si256((__m256i*)vars->x2m[m]->rows[0], x2m);
    _mm256_store_si256((__m256i*)vars->x0s[m]->rows[0], x0s);
    _mm256_store_si256((__m256i*)vars->x1s[m]->rows[0], x1s);

    min = _mm256_load_si256((__m256i*)rvec[m]->rows[0]);

    x0m = _mm256_and_si256(min, mx0);
    x1m = _mm256_and_si256(min, mx1);
    x2m = _mm256_and_si256(min, mx2);

    _mm256_store_si256((__m256i*)vars->r0m[m]->rows[0], x0m);
    _mm256_store_si256((__m256i*)vars->r1m[m]->rows[0], x1m);
    _mm256_store_si256((__m256i*)vars->r2m[m]->rows[0], x2m);

    x0s = m256_shift_left(x0m, 2);
    x1s = m256_shift_left(x1m, 1);

    _mm256_store_si256((__m256i*)vars->r0s[m]->rows[0], x0s);
    _mm256_store_si256((__m256i*)vars->r1s[m]->rows[0], x1s);
  }

  if (andPtr(vars->r0m, vars->x0s, vars->x1s, vars->r2m, view, mask->x2, 0, sc, vars->v) ||
      andPtr(vars->r2m, vars->x1s, vars->x2m, vars->r0s, view, mask->x2, 2, sc, vars->v) ||
      andPtr(vars->r1m, vars->x0s, vars->x2m, vars->r1s, view, mask->x2, 1, sc, vars->v)) {
    return -1;
  }

  __m256i mmask = _mm256_load_si256((__m256i*)mask->mask->rows[0]);
  for (unsigned int m = 0; m < sc; ++m) {
    // mpc_xor(vars->r2m, vars->r2m, vars->x0s, sc);
    __m256i x0s = _mm256_load_si256((__m256i*)vars->x0s[m]->rows[0]);
    __m256i r2m = _mm256_load_si256((__m256i*)vars->r2m[m]->rows[0]);
    r2m         = _mm256_xor_si256(r2m, x0s);

    // mpc_xor(vars->x0s, vars->x0s, vars->x1s, sc);
    __m256i x1s = _mm256_load_si256((__m256i*)vars->x1s[m]->rows[0]);
    x0s         = _mm256_xor_si256(x0s, x1s);
    // mpc_xor(vars->r1m, vars->r1m, vars->x0s, sc);
    __m256i r1m = _mm256_xor_si256(x0s, _mm256_load_si256((__m256i*)vars->r1m[m]->rows[0]));

    // mpc_and_const(out, in, mask->mask, sc);
    __m256i mout = _mm256_and_si256(mmask, _mm256_load_si256((__m256i*)in[m]->rows[0]));

    // mpc_xor(vars->r0m, vars->r0m, vars->x0s, sc);
    __m256i r0m = _mm256_xor_si256(x0s, _mm256_load_si256((__m256i*)vars->r0m[m]->rows[0]));
    // mpc_xor(vars->r0m, vars->r0m, vars->x2m, sc);
    r0m = _mm256_xor_si256(r0m, _mm256_load_si256((__m256i*)vars->x2m[m]->rows[0]));
    // mpc_xor(out, out, vars->r0m, sc);
    mout = _mm256_xor_si256(mout, r0m);

    // mpc_shift_right(vars->x0s, vars->r2m, 2, sc);
    x0s = m256_shift_right(r2m, 2);
    // mpc_xor(out, out, vars->x0s, sc);
    mout = _mm256_xor_si256(mout, x0s);

    // mpc_shift_right(vars->x1s, vars->r1m, 1, sc);
    x1s = m256_shift_right(r1m, 1);
    // mpc_xor(out, out, vars->x1s, sc);
    mout = _mm256_xor_si256(mout, x1s);

    _mm256_store_si256((__m256i*)out[m]->rows[0], mout);
  }

  return 0;
}

static int _mpc_sbox_layer(mzd_t** out, mzd_t** in, rci_t m, view_t* views, int* i, mzd_t** rvec,
                           unsigned sc, BIT_and_ptr andBitPtr) {
  mpc_copy(out, in, sc);

  BIT* x0 = malloc(sizeof(BIT) * sc);
  BIT* x1 = malloc(sizeof(BIT) * sc);
  BIT* x2 = malloc(sizeof(BIT) * sc);
  BIT* r0 = malloc(sizeof(BIT) * sc);
  BIT* r1 = malloc(sizeof(BIT) * sc);
  BIT* r2 = malloc(sizeof(BIT) * sc);

  for (rci_t n = out[0]->ncols - 3 * m; n < out[0]->ncols; n += 3) {
    mpc_read_bit(x0, in, n + 0, sc);
    mpc_read_bit(x1, in, n + 1, sc);
    mpc_read_bit(x2, in, n + 2, sc);
    mpc_read_bit(r0, rvec, n + 0, sc);
    mpc_read_bit(r1, rvec, n + 1, sc);
    mpc_read_bit(r2, rvec, n + 2, sc);

    BIT tmp1[sc], tmp2[sc], tmp3[sc];
    for (unsigned m = 0; m < sc; m++) {
      tmp1[m] = x1[m];
      tmp2[m] = x0[m];
      tmp3[m] = x0[m];
    }
    if (andBitPtr(tmp1, x2, r0, views, i, n, sc) || andBitPtr(tmp2, x2, r1, views, i, n + 1, sc) ||
        andBitPtr(tmp3, x1, r2, views, i, n + 2, sc)) {
      return -1;
    }

    mpc_xor_bit(tmp1, x0, sc);
    mpc_write_bit(out, n + 0, tmp1, sc);

    mpc_xor_bit(tmp2, x0, sc);
    mpc_xor_bit(tmp2, x1, sc);
    mpc_write_bit(out, n + 1, tmp2, sc);

    mpc_xor_bit(tmp3, x0, sc);
    mpc_xor_bit(tmp3, x1, sc);
    mpc_xor_bit(tmp3, x2, sc);
    mpc_write_bit(out, n + 2, tmp3, sc);
  }
  free(x0);
  free(x1);
  free(x2);
  free(r0);
  free(r1);
  free(r2);

  (*i)++;
  return 0;
}

static mzd_t** _mpc_lowmc_call(lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_t* p, view_t* views,
                               mzd_t*** rvec, unsigned sc, unsigned ch, BIT_and_ptr andBitPtr,
                               int* status) {
  int vcnt = 0;

  for (unsigned i = 0; i < sc; i++)
    mzd_copy(views[vcnt].s[i], lowmc_key->shared[i]);
  vcnt++;

  mzd_t** c = mpc_init_empty_share_vector(lowmc->n, sc);

  mzd_t** x = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t** y = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t** z = mpc_init_empty_share_vector(lowmc->n, sc);

  mpc_const_mat_mul(x, lowmc->KMatrix[0], lowmc_key->shared, sc);
  mpc_const_add(x, x, p, sc, ch);

  mzd_t* r[3];
  for (unsigned i = 0; i < lowmc->r; i++) {
    for (unsigned j = 0; j < sc; j++) {
      r[j] = rvec[j][i];
    }
    if (_mpc_sbox_layer(y, x, lowmc->m, views, &vcnt, r, sc, andBitPtr)) {
      *status = -1;
      return 0;
    }
    mpc_const_mat_mul(z, lowmc->LMatrix[i], y, sc);
    mpc_const_add(z, z, lowmc->Constants[i], sc, ch);
    mzd_t** t = mpc_init_empty_share_vector(lowmc->n, sc);
    mpc_const_mat_mul(t, lowmc->KMatrix[i + 1], lowmc_key->shared, sc);
    mpc_add(z, z, t, sc);
    mpc_free(t, sc);
    mpc_copy(x, z, sc);
  }
  mpc_copy(c, x, sc);
  mpc_copy(views[vcnt].s, c, sc);

  mpc_free(z, sc);
  mpc_free(y, sc);
  mpc_free(x, sc);
  return c;
}

static mzd_t** _mpc_lowmc_call_bitsliced(lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_t* p,
                                         view_t* views, mzd_t*** rvec, unsigned sc, unsigned ch,
                                         and_ptr andPtr, int* status, bool save_key) {
  unsigned int vcnt = 0;

  if (save_key) {
    for (unsigned i = 0; i < sc; i++)
      mzd_copy(views[vcnt].s[i], lowmc_key->shared[i]);
  }
  vcnt++;

  mzd_t** c = mpc_init_empty_share_vector(lowmc->n, sc);

  mzd_t** x = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t** y = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t** z = mpc_init_empty_share_vector(lowmc->n, sc);

  mpc_const_mat_mul(x, lowmc->KMatrix[0], lowmc_key->shared, sc);
  mpc_const_add(x, x, p, sc, ch);

  sbox_vars_t* vars = sbox_vars_init(0, lowmc->n, sc);

  mzd_t** t = mpc_init_empty_share_vector(lowmc->n, sc);

  mzd_t* r[3];
  for (unsigned i = 0; i < lowmc->r; ++i, ++vcnt) {
    for (unsigned j = 0; j < sc; j++) {
      r[j] = rvec[j][i];
    }

    int ret = 0;
    if (__builtin_cpu_supports("sse2") && lowmc->n == 128) {
      ret = _mpc_sbox_layer_bitsliced_sse(y, x, lowmc->m, &views[vcnt], r, sc, andPtr, &lowmc->mask,
                                          vars);
    } else if (__builtin_cpu_supports("avx2") && lowmc->n == 256) {
      ret = _mpc_sbox_layer_bitsliced_avx(y, x, lowmc->m, &views[vcnt], r, sc, andPtr, &lowmc->mask,
                                          vars);
    } else {
      ret = _mpc_sbox_layer_bitsliced(y, x, lowmc->m, &views[vcnt], r, sc, andPtr, &lowmc->mask,
                                      vars);
    }
    if (ret) {
      *status = -1;
      return 0;
    }

    mpc_const_mat_mul(z, lowmc->LMatrix[i], y, sc);
    mpc_const_add(z, z, lowmc->Constants[i], sc, ch);
    mpc_const_mat_mul(t, lowmc->KMatrix[i + 1], lowmc_key->shared, sc);
    mpc_add(z, z, t, sc);
    mpc_copy(x, z, sc);
  }
  mpc_free(t, sc);
  mpc_copy(c, x, sc);
  mpc_copy(views[vcnt].s, c, sc);

  sbox_vars_free(vars, sc);

  mpc_free(z, sc);
  mpc_free(y, sc);
  mpc_free(x, sc);
  return c;
}

static mzd_t** _mpc_lowmc_call_bitsliced_shared_p(lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_t** p,
                                                  view_t* views, mzd_t*** rvec, unsigned sc,
                                                  unsigned ch, and_ptr andPtr, int* status,
                                                  bool store_shared) {
  unsigned int vcnt = 0;
  if (store_shared) {
    for (unsigned i = 0; i < sc; i++)
      mzd_copy(views[vcnt].s[i], lowmc_key->shared[i]);
  }
  vcnt++;

  mzd_t** c = mpc_init_empty_share_vector(lowmc->n, sc);

  mzd_t** x = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t** y = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t** z = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t** t = mpc_init_empty_share_vector(lowmc->n, sc);

  mpc_const_mat_mul(x, lowmc->KMatrix[0], lowmc_key->shared, sc);
  mpc_copy(t, p, sc);
  mpc_add(x, x, t, sc);

  sbox_vars_t* vars = sbox_vars_init(0, lowmc->n, sc);

  mzd_t* r[3];
  for (unsigned i = 0; i < lowmc->r; ++i, ++vcnt) {
    for (unsigned j = 0; j < sc; j++) {
      r[j] = rvec[j][i];
    }

    int ret = 0;
    if (__builtin_cpu_supports("sse2") && lowmc->n == 128) {
      ret = _mpc_sbox_layer_bitsliced_sse(y, x, lowmc->m, &views[vcnt], r, sc, andPtr, &lowmc->mask,
                                          vars);
    } if (__builtin_cpu_supports("avx2") && lowmc->n == 256) {
      ret = _mpc_sbox_layer_bitsliced_avx(y, x, lowmc->m, &views[vcnt], r, sc, andPtr, &lowmc->mask,
                                          vars);
    } else {
      ret = _mpc_sbox_layer_bitsliced(y, x, lowmc->m, &views[vcnt], r, sc, andPtr, &lowmc->mask,
                                      vars);
    }
    if (ret) {
      *status = -1;
      return 0;
    }

    mpc_const_mat_mul(z, lowmc->LMatrix[i], y, sc);
    mpc_const_add(z, z, lowmc->Constants[i], sc, ch);
    mpc_const_mat_mul(t, lowmc->KMatrix[i + 1], lowmc_key->shared, sc);
    mpc_add(z, z, t, sc);
    mpc_copy(x, z, sc);
  }
  mpc_free(t, sc);
  mpc_copy(c, x, sc);
  mpc_copy(views[vcnt].s, c, sc);

  sbox_vars_free(vars, sc);

  mpc_free(z, sc);
  mpc_free(y, sc);
  mpc_free(x, sc);
  return c;
}

static inline and_ptr select_and(lowmc_t* lowmc) {
  if (__builtin_cpu_supports("sse2") && lowmc->n == 128) {
    return &mpc_and_sse;
  } else if (__builtin_cpu_supports("avx2") && lowmc->n == 256) {
    return &mpc_and_avx;
  } else {
    return &mpc_and;
  }
}

static inline and_ptr select_and_verify(lowmc_t* lowmc) {
  if (__builtin_cpu_supports("sse4.1") && lowmc->n == 128) {
    return &mpc_and_verify_sse;
  } else if (__builtin_cpu_supports("avx2") && lowmc->n == 256) {
    return &mpc_and_verify_avx;
  } else {
    return &mpc_and_verify;
  }
}

mzd_t** mpc_lowmc_call(lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_t* p, view_t* views,
                       mzd_t*** rvec) {
  // return _mpc_lowmc_call(lowmc, lowmc_key, p, views, rvec, 3, 0,
  // &mpc_and_bit, 0);
  return _mpc_lowmc_call_bitsliced(
      lowmc, lowmc_key, p, views, rvec, 3, 0,
      select_and(lowmc), 0, true);
}

mzd_t** mpc_lowmc_call_shared_p(lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_shared_t* p,
                                view_t* views, mzd_t*** rvec) {
  // return _mpc_lowmc_call(lowmc, lowmc_key, p, views, rvec, 3, 0,
  // &mpc_and_bit, 0);
  return _mpc_lowmc_call_bitsliced_shared_p(
      lowmc, lowmc_key, p->shared, views, rvec, 3, 0,
      select_and(lowmc), 0, true);
}

mzd_t** _mpc_lowmc_call_verify(lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_t* p, view_t* views,
                               mzd_t*** rvec, int* status, int c) {
  // return _mpc_lowmc_call(lowmc, lowmc_key, p, views, rvec, 2, c,
  // &mpc_and_bit_verify, status);
  return _mpc_lowmc_call_bitsliced(
      lowmc, lowmc_key, p, views, rvec, 2, c,
      select_and_verify(lowmc),
      status, false);
}

mzd_t** _mpc_lowmc_call_verify_shared_p(lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_shared_t* p,
                                        view_t* views, mzd_t*** rvec, int* status, int c) {
  // return _mpc_lowmc_call(lowmc, lowmc_key, p, views, rvec, 2, c,
  // &mpc_and_bit_verify, status);
  return _mpc_lowmc_call_bitsliced_shared_p(
      lowmc, lowmc_key, p->shared, views, rvec, 2, c,
      select_and_verify(lowmc),
      status, false);
}

int mpc_lowmc_verify(lowmc_t* lowmc, mzd_t* p, view_t* views, mzd_t*** rvec, int c) {
  // initialize two key shares from v0
  lowmc_key_t lowmc_key;
  mzd_shared_from_shares(&lowmc_key, views[0].s, 2);

  int status = 0;
  mzd_t** v  = _mpc_lowmc_call_verify(lowmc, &lowmc_key, p, views, rvec, &status, c);
  if (v)
    mpc_free(v, 2);

  mzd_shared_clear(&lowmc_key);

  return status;
}

int mpc_lowmc_verify_shared_p(lowmc_t* lowmc, mzd_shared_t* shared_p, view_t* views, mzd_t*** rvec,
                              int c) {
  // initialize two key shares from v0
  lowmc_key_t lowmc_key;
  mzd_shared_from_shares(&lowmc_key, views[0].s, 2);

  int status = 0;
  mzd_t** v = _mpc_lowmc_call_verify_shared_p(lowmc, &lowmc_key, shared_p, views, rvec, &status, c);
  if (v)
    mpc_free(v, 2);

  mzd_shared_clear(&lowmc_key);

  return status;
}

void sbox_vars_free(sbox_vars_t* vars, unsigned int sc) {
  mpc_free(vars->x0m, sc);
  mpc_free(vars->x1m, sc);
  mpc_free(vars->x2m, sc);
  mpc_free(vars->r0m, sc);
  mpc_free(vars->r1m, sc);
  mpc_free(vars->r2m, sc);
  mpc_free(vars->x0s, sc);
  mpc_free(vars->r0s, sc);
  mpc_free(vars->x1s, sc);
  mpc_free(vars->r1s, sc);
  mpc_free(vars->v, sc);
  free(vars);
}

sbox_vars_t* sbox_vars_init(sbox_vars_t* vars, rci_t n, unsigned sc) {
  if (vars == 0)
    vars = (sbox_vars_t*)malloc(sizeof(sbox_vars_t));

  vars->x0m = mpc_init_empty_share_vector(n, sc);
  vars->x1m = mpc_init_empty_share_vector(n, sc);
  vars->x2m = mpc_init_empty_share_vector(n, sc);
  vars->r0m = mpc_init_empty_share_vector(n, sc);
  vars->r1m = mpc_init_empty_share_vector(n, sc);
  vars->r2m = mpc_init_empty_share_vector(n, sc);
  vars->x0s = mpc_init_empty_share_vector(n, sc);
  vars->x1s = mpc_init_empty_share_vector(n, sc);
  vars->r0s = mpc_init_empty_share_vector(n, sc);
  vars->r1s = mpc_init_empty_share_vector(n, sc);
  vars->v   = mpc_init_empty_share_vector(n, sc);

  return vars;
}

void clear_proof(lowmc_t* lowmc, proof_t* proof) {
  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    mpc_free(proof->y[i], 3);
    for (unsigned j = 0; j < 2 + lowmc->r; j++) {
      mzd_free(proof->views[i][j].s[0]);
      mzd_free(proof->views[i][j].s[1]);
      free(proof->views[i][j].s);
    }
    free(proof->views[i]);

    free(proof->keys[i][0]);
    free(proof->keys[i][1]);
    free(proof->keys[i]);

    free(proof->r[i][0]);
    free(proof->r[i][1]);
    free(proof->r[i]);
  }
  free(proof->y);
  free(proof->views);
  free(proof->keys);
  free(proof->r);
}

void free_proof(lowmc_t* lowmc, proof_t* proof) {
  clear_proof(lowmc, proof);
  free(proof);
}
