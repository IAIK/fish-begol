#include "lowmc.h"
#include "lowmc_pars.h"
#include "mzd_additional.h"

static void sbox_layer_bitsliced(mzd_t *out, mzd_t *in, rci_t m, mask_t *mask) {
  if (in->ncols - 3 * m < 2) {
    printf("Bitsliced implementation requires in->ncols - 3 * m >= 2\n");
    return;
  }

  mzd_copy(out, in);
  mzd_and(out, out, mask->mask);

  mzd_t *x0m = mzd_and(0, mask->x0, in);
  mzd_t *x1m = mzd_and(0, mask->x1, in);
  mzd_t *x2m = mzd_and(0, mask->x2, in);

  mzd_t *x0s = mzd_init(1, out->ncols);
  mzd_shift_left(x0s, x0m, 2, 0);
  mzd_t *x1s = mzd_init(1, out->ncols);
  mzd_shift_left(x1s, x1m, 1, 0);

  mzd_t *t0 = mzd_and(0, x1s, x2m);
  mzd_t *t1 = mzd_and(0, x0s, x2m);
  mzd_t *t2 = mzd_and(0, x0s, x1s);

  mzd_xor(t0, t0, x0s);

  mzd_xor(t1, t1, x0s);
  mzd_xor(t1, t1, x1s);

  mzd_xor(t2, t2, x0s);
  mzd_xor(t2, t2, x1s);
  mzd_xor(t2, t2, x2m);

  mzd_t *x0r = mzd_init(1, out->ncols);
  mzd_t *x1r = mzd_init(1, out->ncols);
  mzd_shift_right(x0r, t0, 2, 0);
  mzd_shift_right(x1r, t1, 1, 0);

  mzd_xor(out, out, t2);
  mzd_xor(out, out, x0r);
  mzd_xor(out, out, x1r);

  mzd_free(x1r);
  mzd_free(x0r);
  mzd_free(t2);
  mzd_free(t1);
  mzd_free(t0);
  mzd_free(x1s);
  mzd_free(x0s);
  mzd_free(x2m);
  mzd_free(x1m);
  mzd_free(x0m);
}

#include <immintrin.h>

/**
 * AVX2 version of LowMC. It assumes that mzd_t's row[0] is always 32 byte
 * aligned.
 */
__attribute__((target("avx2")))
static void sbox_layer_avx(mzd_t *out, mzd_t *in, mask_t *mask, mzd_t* tmp0, mzd_t* tmp1) {
  __m256i min = _mm256_load_si256((__m256i*) in->rows[0]);

  __m256i x0m = _mm256_and_si256(min, _mm256_load_si256((__m256i*) mask->x0->rows[0]));
  __m256i x1m = _mm256_and_si256(min, _mm256_load_si256((__m256i*) mask->x1->rows[0]));
  __m256i x2m = _mm256_and_si256(min, _mm256_load_si256((__m256i*) mask->x2->rows[0]));

  _mm256_store_si256((__m256i*) tmp0->rows[0], x0m);
  _mm256_store_si256((__m256i*) tmp1->rows[0], x1m);

  mzd_shift_left_inplace(tmp0, 2);
  mzd_shift_left_inplace(tmp1, 1);

  x0m = _mm256_load_si256((__m256i*) tmp0->rows[0]);
  x1m = _mm256_load_si256((__m256i*) tmp1->rows[0]);

  __m256i t0 = _mm256_and_si256(x1m, x2m);
  __m256i t1 = _mm256_and_si256(x0m, x2m);
  __m256i t2 = _mm256_and_si256(x0m, x1m);

  t0 = _mm256_xor_si256(t0, x0m);

  x0m = _mm256_xor_si256(x0m, x1m);
  t1 = _mm256_xor_si256(t1, x0m);

  t2 = _mm256_xor_si256(t2, x0m);
  t2 = _mm256_xor_si256(t2, x2m);

  _mm256_store_si256((__m256i*) tmp0->rows[0], t0);
  _mm256_store_si256((__m256i*) tmp1->rows[0], t1);

  mzd_shift_right_inplace(tmp0, 2);
  mzd_shift_right_inplace(tmp1, 1);

  t0 = _mm256_load_si256((__m256i*) tmp0->rows[0]);
  t1 = _mm256_load_si256((__m256i*) tmp1->rows[0]);

  __m256i mout = _mm256_and_si256(min, _mm256_load_si256((__m256i*) mask->mask->rows[0]));

  mout = _mm256_xor_si256(mout, t2);
  mout = _mm256_xor_si256(mout, t1);
  mout = _mm256_xor_si256(mout, t0);
  _mm256_store_si256((__m256i*) out->rows[0], mout);
}


void sbox_layer(mzd_t *out, mzd_t *in, rci_t m) {
  mzd_copy(out, in);
  for (rci_t n = out->ncols - 3 * m; n < out->ncols; n += 3) {
    word x0 = mzd_read_bit(in, 0, n + 0);
    word x1 = mzd_read_bit(in, 0, n + 1);
    word x2 = mzd_read_bit(in, 0, n + 2);

    mzd_write_bit(out, 0, n + 0, (x1 & x2) ^ x0);
    mzd_write_bit(out, 0, n + 1, (x0 & x2) ^ x0 ^ x1);
    mzd_write_bit(out, 0, n + 2, (x0 & x1) ^ x0 ^ x1 ^ x2);
  }
}


mzd_t *lowmc_call(lowmc_t *lowmc, lowmc_key_t *lowmc_key, mzd_t *p) {
  mzd_t *c = mzd_init(1, lowmc->n);

  mzd_t *x = mzd_init(1, lowmc->n);
  mzd_t *y = mzd_init(1, lowmc->n);
  mzd_t *z = mzd_init(1, lowmc->n);

  mzd_t *tmp0 = mzd_init(1, lowmc->n);
  mzd_t *tmp1 = mzd_init(1, lowmc->n);

  mzd_copy(x, p);
  mzd_addmul(x, lowmc_key->key[0], lowmc->KMatrix[0], 0);

  mask_t mask;
  prepare_masks(&mask, lowmc->n, lowmc->m);

  for (unsigned i = 0; i < lowmc->r; i++) {
    // sbox_layer(y, x, lowmc->m);
    if (__builtin_cpu_supports("avx2") && y->ncols == 256) {
      sbox_layer_avx(y, x, &mask, tmp0, tmp1);
    } else {
      sbox_layer_bitsliced(y, x, lowmc->m, &mask);
    }
    mzd_mul(z, y, lowmc->LMatrix[i], 0);
    mzd_add(z, z, lowmc->Constants[i]);
    mzd_addmul(z, lowmc_key->key[0], lowmc->KMatrix[i + 1], 0);
    mzd_copy(x, z);
  }

  mzd_copy(c, x);

  mzd_free(mask.x0);
  mzd_free(mask.x1);
  mzd_free(mask.x2);
  mzd_free(mask.mask);

  mzd_free(tmp1);
  mzd_free(tmp0);

  mzd_free(z);
  mzd_free(y);
  mzd_free(x);

  return c;
}
