#include "lowmc.h"
#include "lowmc_pars.h"
#include "mzd_additional.h"

#include "avx.h"

static void sbox_layer_bitsliced(mzd_t* out, mzd_t* in, rci_t m, mask_t* mask) {
  if (in->ncols - 3 * m < 2) {
    printf("Bitsliced implementation requires in->ncols - 3 * m >= 2\n");
    return;
  }

  mzd_and(out, in, mask->mask);

  mzd_t* x0m = mzd_and(0, mask->x0, in);
  mzd_t* x1m = mzd_and(0, mask->x1, in);
  mzd_t* x2m = mzd_and(0, mask->x2, in);

  mzd_shift_left(x0m, x0m, 2);
  mzd_shift_left(x1m, x1m, 1);

  mzd_t* t0 = mzd_and(0, x1m, x2m);
  mzd_t* t1 = mzd_and(0, x0m, x2m);
  mzd_t* t2 = mzd_and(0, x0m, x1m);

  mzd_xor(t0, t0, x0m);

  mzd_xor(t1, t1, x0m);
  mzd_xor(t1, t1, x1m);

  mzd_xor(t2, t2, x0m);
  mzd_xor(t2, t2, x1m);
  mzd_xor(t2, t2, x2m);

  mzd_shift_right(t0, t0, 2);
  mzd_shift_right(t1, t1, 1);

  mzd_xor(out, out, t2);
  mzd_xor(out, out, t0);
  mzd_xor(out, out, t1);

  mzd_free(t2);
  mzd_free(t1);
  mzd_free(t0);
  mzd_free(x2m);
  mzd_free(x1m);
  mzd_free(x0m);
}

__attribute__((target("sse2"))) static void sbox_layer_sse(mzd_t* out, mzd_t* in, mask_t* mask) {
  __m128i min = _mm_load_si128((__m128i*)in->rows[0]);

  __m128i x0m = _mm_and_si128(min, _mm_load_si128((__m128i*)mask->x0->rows[0]));
  __m128i x1m = _mm_and_si128(min, _mm_load_si128((__m128i*)mask->x1->rows[0]));
  __m128i x2m = _mm_and_si128(min, _mm_load_si128((__m128i*)mask->x2->rows[0]));

  x0m = mm128_shift_left(x0m, 2);
  x1m = mm128_shift_left(x1m, 1);

  __m128i t0 = _mm_and_si128(x1m, x2m);
  __m128i t1 = _mm_and_si128(x0m, x2m);
  __m128i t2 = _mm_and_si128(x0m, x1m);

  t0 = _mm_xor_si128(t0, x0m);

  x0m = _mm_xor_si128(x0m, x1m);
  t1  = _mm_xor_si128(t1, x0m);

  t2 = _mm_xor_si128(t2, x0m);
  t2 = _mm_xor_si128(t2, x2m);

  t0 = mm128_shift_right(t0, 2);
  t1 = mm128_shift_right(t1, 1);

  __m128i mout = _mm_and_si128(min, _mm_load_si128((__m128i*)mask->mask->rows[0]));

  mout = _mm_xor_si128(mout, t2);
  mout = _mm_xor_si128(mout, t1);
  mout = _mm_xor_si128(mout, t0);
  _mm_store_si128((__m128i*)out->rows[0], mout);
}

/**
 * AVX2 version of LowMC. It assumes that mzd_t's row[0] is always 32 byte
 * aligned.
 */
__attribute__((target("avx2"))) static void sbox_layer_avx(mzd_t* out, mzd_t* in, mask_t* mask) {
  __m256i min = _mm256_load_si256((__m256i*)in->rows[0]);

  __m256i x0m = _mm256_and_si256(min, _mm256_load_si256((__m256i*)mask->x0->rows[0]));
  __m256i x1m = _mm256_and_si256(min, _mm256_load_si256((__m256i*)mask->x1->rows[0]));
  __m256i x2m = _mm256_and_si256(min, _mm256_load_si256((__m256i*)mask->x2->rows[0]));

  x0m = mm256_shift_left(x0m, 2);
  x1m = mm256_shift_left(x1m, 1);

  __m256i t0 = _mm256_and_si256(x1m, x2m);
  __m256i t1 = _mm256_and_si256(x0m, x2m);
  __m256i t2 = _mm256_and_si256(x0m, x1m);

  t0 = _mm256_xor_si256(t0, x0m);

  x0m = _mm256_xor_si256(x0m, x1m);
  t1  = _mm256_xor_si256(t1, x0m);

  t2 = _mm256_xor_si256(t2, x0m);
  t2 = _mm256_xor_si256(t2, x2m);

  t0 = mm256_shift_right(t0, 2);
  t1 = mm256_shift_right(t1, 1);

  __m256i mout = _mm256_and_si256(min, _mm256_load_si256((__m256i*)mask->mask->rows[0]));

  mout = _mm256_xor_si256(mout, t2);
  mout = _mm256_xor_si256(mout, t1);
  mout = _mm256_xor_si256(mout, t0);
  _mm256_store_si256((__m256i*)out->rows[0], mout);
}

void sbox_layer(mzd_t* out, mzd_t* in, rci_t m) {
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

mzd_t* lowmc_call(lowmc_t* lowmc, lowmc_key_t* lowmc_key, mzd_t* p) {
  if (p->ncols > lowmc->n) {
    printf("p larger than block size!");
    return NULL;
  }

  mzd_t* x = mzd_init(1, lowmc->n);
  mzd_t* y = mzd_init(1, lowmc->n);
  mzd_t* z = mzd_init(1, lowmc->n);

  mzd_copy(x, p);
  mzd_addmul_v(x, lowmc_key->shared[0], lowmc->KMatrix[0]);

  for (unsigned i = 0; i < lowmc->r; i++) {
    // sbox_layer(y, x, lowmc->m);
    if (__builtin_cpu_supports("sse2") && y->ncols == 128) {
      sbox_layer_sse(y, x, &lowmc->mask);
    } else if (__builtin_cpu_supports("avx2") && y->ncols == 256) {
      sbox_layer_avx(y, x, &lowmc->mask);
    } else {
      sbox_layer_bitsliced(y, x, lowmc->m, &lowmc->mask);
    }
    mzd_mul_v(z, y, lowmc->LMatrix[i]);
    mzd_xor(z, z, lowmc->Constants[i]);
    mzd_addmul(z, lowmc_key->shared[0], lowmc->KMatrix[i + 1], 0);
    mzd_copy(x, z);
  }

  mzd_free(z);
  mzd_free(y);

  return x;
}
