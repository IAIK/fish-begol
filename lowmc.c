#include "lowmc.h"
#include "lowmc_pars.h"
#include "mzd_additional.h"

#ifdef WITH_OPT
#include "simd.h"
#endif

static void sbox_layer_bitsliced(mzd_t* out, mzd_t* in, rci_t m, mask_t const* mask) {
  mzd_and(out, in, mask->mask);

  mzd_t* buffer[6] = {NULL};
  mzd_local_init_multiple_ex(buffer, 6, 1, in->ncols, false);

  mzd_t* x0m = mzd_and(buffer[0], mask->x0, in);
  mzd_t* x1m = mzd_and(buffer[1], mask->x1, in);
  mzd_t* x2m = mzd_and(buffer[2], mask->x2, in);

  mzd_shift_left(x0m, x0m, 2);
  mzd_shift_left(x1m, x1m, 1);

  mzd_t* t0 = mzd_and(buffer[3], x1m, x2m);
  mzd_t* t1 = mzd_and(buffer[4], x0m, x2m);
  mzd_t* t2 = mzd_and(buffer[5], x0m, x1m);

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

  mzd_local_free_multiple(buffer);
}

#ifdef WITH_OPT
#ifdef WITH_SSE2
__attribute__((target("sse2"))) static void sbox_layer_sse(mzd_t* out, mzd_t* in,
                                                           mask_t const* mask) {
  __m128i const* ip = __builtin_assume_aligned(CONST_FIRST_ROW(in), 16);
  __m128i const min = *ip;

  __m128i const* x0p = __builtin_assume_aligned(CONST_FIRST_ROW(mask->x0), 16);
  __m128i const* x1p = __builtin_assume_aligned(CONST_FIRST_ROW(mask->x1), 16);
  __m128i const* x2p = __builtin_assume_aligned(CONST_FIRST_ROW(mask->x2), 16);

  __m128i x0m = _mm_and_si128(min, *x0p);
  __m128i x1m = _mm_and_si128(min, *x1p);
  __m128i x2m = _mm_and_si128(min, *x2p);

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

  __m128i const* xmp = __builtin_assume_aligned(CONST_FIRST_ROW(mask->mask), 16);
  __m128i* op        = __builtin_assume_aligned(FIRST_ROW(out), 16);

  __m128i mout = _mm_and_si128(min, *xmp);

  mout = _mm_xor_si128(mout, t2);
  mout = _mm_xor_si128(mout, t1);
  *op  = _mm_xor_si128(mout, t0);
}
#endif

#ifdef WITH_AVX2
/**
 * AVX2 version of LowMC. It assumes that mzd_t's row[0] is always 32 byte
 * aligned.
 */
__attribute__((target("avx2"))) static void sbox_layer_avx(mzd_t* out, mzd_t* in,
                                                           mask_t const* mask) {
  __m256i const* ip = __builtin_assume_aligned(CONST_FIRST_ROW(in), 32);
  __m256i const min = *ip;

  __m256i const* x0p = __builtin_assume_aligned(CONST_FIRST_ROW(mask->x0), 32);
  __m256i const* x1p = __builtin_assume_aligned(CONST_FIRST_ROW(mask->x1), 32);
  __m256i const* x2p = __builtin_assume_aligned(CONST_FIRST_ROW(mask->x2), 32);

  __m256i x0m = _mm256_and_si256(min, *x0p);
  __m256i x1m = _mm256_and_si256(min, *x1p);
  __m256i x2m = _mm256_and_si256(min, *x2p);

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

  __m256i const* xmp = __builtin_assume_aligned(CONST_FIRST_ROW(mask->mask), 32);
  __m256i* op        = __builtin_assume_aligned(FIRST_ROW(out), 32);

  __m256i mout = _mm256_and_si256(min, *xmp);

  mout = _mm256_xor_si256(mout, t2);
  mout = _mm256_xor_si256(mout, t1);
  *op  = _mm256_xor_si256(mout, t0);
}
#endif
#endif

mzd_t* lowmc_call(lowmc_t const* lowmc, lowmc_key_t const* lowmc_key, mzd_t const* p) {
  if (p->ncols > lowmc->n) {
    printf("p larger than block size!\n");
    return NULL;
  }
  if (p->nrows != 1) {
    printf("p needs to have exactly one row!\n");
  }

  mzd_t* x = mzd_local_init_ex(1, lowmc->n, false);
  mzd_t* y = mzd_local_init_ex(1, lowmc->n, false);

  mzd_local_copy(x, p);
#ifdef NOSCR
  mzd_addmul_vl(x, lowmc_key, lowmc->k0_lookup);
#else
  mzd_addmul_v(x, lowmc_key, lowmc->k0_matrix);
#endif

  lowmc_round_t const* round = lowmc->rounds;
  for (unsigned i = 0; i < lowmc->r; ++i, ++round) {
#ifdef WITH_OPT
#ifdef WITH_SSE2
    if (CPU_SUPPORTS_SSE2 && lowmc->n == 128) {
      sbox_layer_sse(y, x, &lowmc->mask);
    } else
#endif
#ifdef WITH_AVX2
    if (CPU_SUPPORTS_AVX2 && lowmc->n == 256) {
      sbox_layer_avx(y, x, &lowmc->mask);
    } else
#endif
#endif
    {
      sbox_layer_bitsliced(y, x, lowmc->m, &lowmc->mask);
    }

#ifdef NOSCR
    mzd_mul_vl(x, y, round->l_lookup);
#else
    mzd_mul_v(x, y, round->l_matrix);
#endif
    mzd_xor(x, x, round->constant);
#ifdef NOSCR
    mzd_addmul_vl(x, lowmc_key, round->k_lookup);
#else
    mzd_addmul_v(x, lowmc_key, round->k_matrix);
#endif
  }

  mzd_local_free(y);

  return x;
}
