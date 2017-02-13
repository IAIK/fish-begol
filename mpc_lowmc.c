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

#include "mpc_lowmc.h"
#include "io.h"
#include "lowmc_pars.h"
#include "mpc.h"
#include "mzd_additional.h"

#include <stdalign.h>
#include <stdbool.h>

#ifdef WITH_OPT
#include "simd.h"
#endif

typedef struct {
  mzd_t* x0m[SC_PROOF];
  mzd_t* x1m[SC_PROOF];
  mzd_t* x2m[SC_PROOF];
  mzd_t* r0m[SC_PROOF];
  mzd_t* r1m[SC_PROOF];
  mzd_t* r2m[SC_PROOF];
  mzd_t* x0s[SC_PROOF];
  mzd_t* r0s[SC_PROOF];
  mzd_t* x1s[SC_PROOF];
  mzd_t* r1s[SC_PROOF];
  mzd_t* v[SC_PROOF];

  mzd_t** storage;
} sbox_vars_t;

static sbox_vars_t* sbox_vars_init(sbox_vars_t* vars, rci_t n, unsigned sc);
static void sbox_vars_clear(sbox_vars_t* vars);

typedef int (*BIT_and_ptr)(BIT*, BIT*, BIT*, view_t*, int*, unsigned, unsigned);
typedef int (*and_ptr)(mzd_t**, mzd_t**, mzd_t**, mzd_t**, view_t*, mzd_t*, unsigned, mzd_t**);

unsigned char* proof_to_char_array(mpc_lowmc_t* lowmc, proof_t* proof, unsigned* len,
                                   bool store_ch) {
  unsigned first_view_bytes = lowmc->k / 8;
  unsigned full_mzd_size    = lowmc->n / 8;
  unsigned single_mzd_bytes = ((3 * lowmc->m) + 7) / 8;
  unsigned mzd_bytes        = 2 * (lowmc->r * single_mzd_bytes + first_view_bytes + full_mzd_size);
  *len =
      NUM_ROUNDS * (COMMITMENT_LENGTH + 2 * (COMMITMENT_RAND_LENGTH + PRNG_KEYSIZE) + mzd_bytes) +
      (store_ch ? ((NUM_ROUNDS + 3) / 4) : 0);
  unsigned char* result = (unsigned char*)malloc(*len * sizeof(unsigned char));

  unsigned char* temp = result;
  memcpy(temp, proof->hashes, NUM_ROUNDS * COMMITMENT_LENGTH * sizeof(unsigned char));
  temp += NUM_ROUNDS * COMMITMENT_LENGTH;

  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    memcpy(temp, proof->r[i][0], COMMITMENT_RAND_LENGTH * sizeof(unsigned char));
    temp += COMMITMENT_RAND_LENGTH;
    memcpy(temp, proof->r[i][1], COMMITMENT_RAND_LENGTH * sizeof(unsigned char));
    temp += COMMITMENT_RAND_LENGTH;

    memcpy(temp, proof->keys[i][0], PRNG_KEYSIZE * sizeof(unsigned char));
    temp += PRNG_KEYSIZE;
    memcpy(temp, proof->keys[i][1], PRNG_KEYSIZE * sizeof(unsigned char));
    temp += PRNG_KEYSIZE;

    unsigned char* v0 = mzd_to_char_array(proof->views[i][0].s[0], first_view_bytes);
    unsigned char* v1 = mzd_to_char_array(proof->views[i][0].s[1], first_view_bytes);

    memcpy(temp, v0, first_view_bytes);
    temp += first_view_bytes;
    memcpy(temp, v1, first_view_bytes);
    temp += first_view_bytes;

    free(v0);
    free(v1);


    for (unsigned j = 1; j < 1 + lowmc->r; j++) {
      v0 = mzd_to_char_array(proof->views[i][j].s[0], single_mzd_bytes);
      v1 = mzd_to_char_array(proof->views[i][j].s[1], single_mzd_bytes);

      memcpy(temp, v0, single_mzd_bytes);
      temp += single_mzd_bytes;
      memcpy(temp, v1, single_mzd_bytes);
      temp += single_mzd_bytes;

      free(v0);
      free(v1);
    }

    v0 = mzd_to_char_array(proof->views[i][1 + lowmc->r].s[0], full_mzd_size);
    v1 = mzd_to_char_array(proof->views[i][1 + lowmc->r].s[1], full_mzd_size);

    memcpy(temp, v0, full_mzd_size);
    temp += full_mzd_size;
    memcpy(temp, v1, full_mzd_size);
    temp += full_mzd_size;

    free(v0);
    free(v1);
  }

  if (store_ch)
    memcpy(temp, proof->ch, (NUM_ROUNDS + 3) / 4);

  return result;
}

proof_t* proof_from_char_array(mpc_lowmc_t* lowmc, proof_t* proof, unsigned char* data,
                               unsigned* len, bool contains_ch) {
  if (!proof)
    proof = calloc(sizeof(proof_t), 1);

  unsigned first_view_bytes = lowmc->k / 8;
  unsigned full_mzd_size    = lowmc->n / 8;
  unsigned single_mzd_bytes = ((3 * lowmc->m) + 7) / 8;
  unsigned mzd_bytes        = 2 * (lowmc->r * single_mzd_bytes + first_view_bytes + full_mzd_size);
  *len =
      NUM_ROUNDS * (COMMITMENT_LENGTH + 2 * (COMMITMENT_RAND_LENGTH + PRNG_KEYSIZE) + mzd_bytes) +
      (contains_ch ? ((NUM_ROUNDS + 3) / 4) : 0);

  unsigned char* temp = data;

  proof->views = (view_t**)malloc(NUM_ROUNDS * sizeof(view_t*));

  memcpy(proof->hashes, temp, NUM_ROUNDS * COMMITMENT_LENGTH * sizeof(unsigned char));
  temp += NUM_ROUNDS * COMMITMENT_LENGTH;

  // proof->y = (mzd_t***)malloc(NUM_ROUNDS * sizeof(mzd_t**));

  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    memcpy(proof->r[i][0], temp, COMMITMENT_RAND_LENGTH * sizeof(unsigned char));
    temp += COMMITMENT_RAND_LENGTH;
    memcpy(proof->r[i][1], temp, COMMITMENT_RAND_LENGTH * sizeof(unsigned char));
    temp += COMMITMENT_RAND_LENGTH;

    memcpy(proof->keys[i][0], temp, PRNG_KEYSIZE * sizeof(char));
    temp += PRNG_KEYSIZE;
    memcpy(proof->keys[i][1], temp, PRNG_KEYSIZE * sizeof(char));
    temp += PRNG_KEYSIZE;

    proof->views[i]         = (view_t*)malloc((2 + lowmc->r) * sizeof(view_t));
    proof->views[i][0].s    = (mzd_t**)malloc(2 * sizeof(mzd_t*));
    proof->views[i][0].s[0] = mzd_from_char_array(temp, first_view_bytes, lowmc->k);
    temp += first_view_bytes;
    proof->views[i][0].s[1] = mzd_from_char_array(temp, first_view_bytes, lowmc->k);
    temp += first_view_bytes;
    for (unsigned j = 1; j < 1 + lowmc->r; j++) {
      proof->views[i][j].s    = (mzd_t**)malloc(2 * sizeof(mzd_t*));
      proof->views[i][j].s[0] = mzd_local_init(1, lowmc->n); //mzd_from_char_array(temp, single_mzd_bytes, lowmc->n);
      temp += single_mzd_bytes;
      proof->views[i][j].s[1] = mzd_from_char_array(temp, single_mzd_bytes, lowmc->n);
      temp += single_mzd_bytes;
    }
    proof->views[i][1 + lowmc->r].s    = (mzd_t**)malloc(2 * sizeof(mzd_t*));
    proof->views[i][1 + lowmc->r].s[0] = mzd_from_char_array(temp, full_mzd_size, lowmc->n);
    temp += full_mzd_size;
    proof->views[i][1 + lowmc->r].s[1] = mzd_from_char_array(temp, full_mzd_size, lowmc->n);
    temp += full_mzd_size;
  }

  if (contains_ch)
    memcpy(proof->ch, temp, (NUM_ROUNDS + 3) / 4);

  return proof;
}

proof_t* create_proof(proof_t* proof, mpc_lowmc_t const* lowmc,
                      unsigned char hashes[NUM_ROUNDS][SC_PROOF][COMMITMENT_LENGTH],
                      unsigned char ch[NUM_ROUNDS],
                      unsigned char r[NUM_ROUNDS][SC_PROOF][COMMITMENT_RAND_LENGTH],
                      unsigned char keys[NUM_ROUNDS][SC_PROOF][PRNG_KEYSIZE],
                      view_t* const views[NUM_ROUNDS]) {
  if (!proof)
    proof = calloc(sizeof(proof_t), 1);

  proof->views = (view_t**)malloc(NUM_ROUNDS * sizeof(view_t*));

  // memcpy(proof->hashes, hashes, NUM_ROUNDS * 3 * SHA256_DIGEST_LENGTH * sizeof(char));

  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    unsigned int a = ch[i];
    unsigned int b = (a + 1) % 3;
    unsigned int c = (a + 2) % 3;

    memcpy(proof->hashes[i], hashes[i][c], COMMITMENT_LENGTH * sizeof(char));

    memcpy(proof->r[i][0], r[i][a], COMMITMENT_RAND_LENGTH * sizeof(char));
    memcpy(proof->r[i][1], r[i][b], COMMITMENT_RAND_LENGTH * sizeof(char));

    memcpy(proof->keys[i][0], keys[i][a], PRNG_KEYSIZE * sizeof(char));
    memcpy(proof->keys[i][1], keys[i][b], PRNG_KEYSIZE * sizeof(char));

    proof->views[i] = (view_t*)malloc((2 + lowmc->r) * sizeof(view_t));
    for (unsigned j = 0; j < 2 + lowmc->r; j++) {
      proof->views[i][j].s    = (mzd_t**)malloc(2 * sizeof(mzd_t*));
      proof->views[i][j].s[0] = views[i][j].s[a];
      proof->views[i][j].s[1] = views[i][j].s[b];
      mzd_local_free(views[i][j].s[c]);
    }

    if ((i % 4) == 0) {
      int idx        = i / 4;
      proof->ch[idx] = 0;
      proof->ch[idx] |= (ch[i] & 3);
      proof->ch[idx] |= i + 1 < NUM_ROUNDS ? (ch[i + 1] & 3) << 2 : 0;
      proof->ch[idx] |= i + 2 < NUM_ROUNDS ? (ch[i + 2] & 3) << 4 : 0;
      proof->ch[idx] |= i + 3 < NUM_ROUNDS ? (ch[i + 3] & 3) << 6 : 0;
    }
  }

  return proof;
}

#define bitsliced_step_1(sc)                                                                       \
  mpc_and_const(out, in, mask->mask, sc);                                                          \
                                                                                                   \
  mpc_and_const(vars->x0m, in, mask->x0, sc);                                                      \
  mpc_and_const(vars->x1m, in, mask->x1, sc);                                                      \
  mpc_and_const(vars->x2m, in, mask->x2, sc);                                                      \
  mpc_and_const(vars->r0m, rvec, mask->x0, sc);                                                    \
  mpc_and_const(vars->r1m, rvec, mask->x1, sc);                                                    \
  mpc_and_const(vars->r2m, rvec, mask->x2, sc);                                                    \
                                                                                                   \
  mpc_shift_left(vars->x0s, vars->x0m, 2, sc);                                                     \
  mpc_shift_left(vars->r0s, vars->r0m, 2, sc);                                                     \
                                                                                                   \
  mpc_shift_left(vars->x1s, vars->x1m, 1, sc);                                                     \
  mpc_shift_left(vars->r1s, vars->r1m, 1, sc);

#define bitsliced_step_2(sc)                                                                       \
  mpc_xor(vars->r2m, vars->r2m, vars->x0s, sc);                                                    \
                                                                                                   \
  mpc_xor(vars->x0s, vars->x0s, vars->x1s, sc);                                                    \
  mpc_xor(vars->r1m, vars->r1m, vars->x0s, sc);                                                    \
                                                                                                   \
  mpc_xor(vars->r0m, vars->r0m, vars->x0s, sc);                                                    \
  mpc_xor(vars->r0m, vars->r0m, vars->x2m, sc);                                                    \
                                                                                                   \
  mpc_shift_right(vars->x0s, vars->r2m, 2, sc);                                                    \
  mpc_shift_right(vars->x1s, vars->r1m, 1, sc);                                                    \
                                                                                                   \
  mpc_xor(out, out, vars->r0m, sc);                                                                \
  mpc_xor(out, out, vars->x0s, sc);                                                                \
  mpc_xor(out, out, vars->x1s, sc)                                                                


static void _mpc_sbox_layer_bitsliced(mzd_t** out, mzd_t* const* in, view_t* view,
                                      mzd_t* const* rvec, mask_t const* mask,
                                      sbox_vars_t const* vars) {
  bitsliced_step_1(SC_PROOF);

  mpc_and(vars->r0m, vars->x0s, vars->x1s, vars->r2m, view, 0, vars->v);
  mpc_and(vars->r2m, vars->x1s, vars->x2m, vars->r0s, view, 2, vars->v);
  mpc_and(vars->r1m, vars->x0s, vars->x2m, vars->r1s, view, 1, vars->v);

  bitsliced_step_2(SC_PROOF);
}

static int _mpc_sbox_layer_bitsliced_verify(mzd_t** out, mzd_t* const* in, view_t const* view,
                                            mzd_t* const* rvec, mask_t const* mask,
                                            sbox_vars_t const* vars) {
  bitsliced_step_1(SC_VERIFY);

  if (mpc_and_verify(vars->r0m, vars->x0s, vars->x1s, vars->r2m, view, mask->x2, 0, vars->v) ||
      mpc_and_verify(vars->r2m, vars->x1s, vars->x2m, vars->r0s, view, mask->x2, 2, vars->v) ||
      mpc_and_verify(vars->r1m, vars->x0s, vars->x2m, vars->r1s, view, mask->x2, 1, vars->v)) {
    return -1;
  }

  bitsliced_step_2(SC_VERIFY);

  return 0;
}

#ifdef WITH_OPT
#define bitsliced_mm_step_1(sc, type, and, shift_left)                                             \
  type r0m[sc] __attribute__((aligned(alignof(type))));                                            \
  type r0s[sc] __attribute__((aligned(alignof(type))));                                            \
  type r1m[sc] __attribute__((aligned(alignof(type))));                                            \
  type r1s[sc] __attribute__((aligned(alignof(type))));                                            \
  type r2m[sc] __attribute__((aligned(alignof(type))));                                            \
  type x0s[sc] __attribute__((aligned(alignof(type))));                                            \
  type x1s[sc] __attribute__((aligned(alignof(type))));                                            \
  type x2m[sc] __attribute__((aligned(alignof(type))));                                            \
  const type mx2 __attribute__((aligned(alignof(type)))) =                                         \
      *((const type*)__builtin_assume_aligned(CONST_FIRST_ROW(mask->x2), alignof(type)));          \
  do {                                                                                             \
    const type mx0 __attribute__((aligned(alignof(type)))) =                                       \
        *((const type*)__builtin_assume_aligned(CONST_FIRST_ROW(mask->x0), alignof(type)));        \
    const type mx1 __attribute__((aligned(alignof(type)))) =                                       \
        *((const type*)__builtin_assume_aligned(CONST_FIRST_ROW(mask->x1), alignof(type)));        \
                                                                                                   \
    for (unsigned int m = 0; m < (sc); ++m) {                                                      \
      const type inm __attribute__((aligned(alignof(type)))) =                                     \
          *((const type*)__builtin_assume_aligned(CONST_FIRST_ROW(in[m]), alignof(type)));         \
      const type rvecm __attribute__((aligned(alignof(type)))) =                                   \
          *((const type*)__builtin_assume_aligned(CONST_FIRST_ROW(rvec[m]), alignof(type)));       \
                                                                                                   \
      type tmp1 = (and)(inm, mx0);                                                                 \
      type tmp2 = (and)(inm, mx1);                                                                 \
      x2m[m]    = (and)(inm, mx2);                                                                 \
                                                                                                   \
      x0s[m] = (shift_left)(tmp1, 2);                                                              \
      x1s[m] = (shift_left)(tmp2, 1);                                                              \
                                                                                                   \
      r0m[m] = tmp1 = (and)(rvecm, mx0);                                                           \
      r1m[m] = tmp2 = (and)(rvecm, mx1);                                                           \
      r2m[m]        = (and)(rvecm, mx2);                                                           \
                                                                                                   \
      r0s[m] = (shift_left)(tmp1, 2);                                                              \
      r1s[m] = (shift_left)(tmp2, 1);                                                              \
    }                                                                                              \
  } while (0)

#define bitsliced_mm_step_2(sc, type, and, xor, shift_right)                                       \
  do {                                                                                             \
    const type maskm __attribute__((aligned(alignof(type)))) =                                     \
        *((const type*)__builtin_assume_aligned(CONST_FIRST_ROW(mask->mask), alignof(type)));      \
    for (unsigned int m = 0; m < sc; ++m) {                                                        \
      const type inm __attribute__((aligned(alignof(type)))) =                                     \
          *((const type*)__builtin_assume_aligned(CONST_FIRST_ROW(in[m]), alignof(type)));         \
      type* outm = __builtin_assume_aligned(CONST_FIRST_ROW(out[m]), alignof(type));               \
                                                                                                   \
      type tmp1 = (xor)(r2m[m], x0s[m]);                                                           \
      type tmp2 = (xor)(x0s[m], x1s[m]);                                                           \
      type tmp3 = (xor)(tmp2, r1m[m]);                                                             \
                                                                                                   \
      type mout = (and)(maskm, inm);                                                               \
                                                                                                   \
      type tmp4 = (xor)(tmp2, r0m[m]);                                                             \
      tmp4      = (xor)(tmp4, x2m[m]);                                                             \
      mout      = (xor)(mout, tmp4);                                                               \
                                                                                                   \
      tmp2 = (shift_right)(tmp1, 2);                                                               \
      mout = (xor)(mout, tmp2);                                                                    \
                                                                                                   \
      tmp1  = (shift_right)(tmp3, 1);                                                              \
      *outm = (xor)(mout, tmp1);                                                                   \
    }                                                                                              \
  } while (0)

#ifdef WITH_SSE2
__attribute__((target("sse2"))) static void
_mpc_sbox_layer_bitsliced_sse(mzd_t** out, mzd_t* const* in, view_t const* view, mzd_t* const* rvec,
                              mask_t const* mask) {
  bitsliced_mm_step_1(SC_PROOF, __m128i, _mm_and_si128, mm128_shift_left);

  mpc_and_sse(r0m, x0s, x1s, r2m, view, 0);
  mpc_and_sse(r2m, x1s, x2m, r0s, view, 2);
  mpc_and_sse(r1m, x0s, x2m, r1s, view, 1);

  bitsliced_mm_step_2(SC_PROOF, __m128i, _mm_and_si128, _mm_xor_si128, mm128_shift_right);
}

__attribute__((target("sse2"))) static int
_mpc_sbox_layer_bitsliced_sse_verify(mzd_t** out, mzd_t* const* in, view_t const* view,
                                     mzd_t** rvec, mask_t const* mask) {
  bitsliced_mm_step_1(SC_VERIFY, __m128i, _mm_and_si128, mm128_shift_left);

  if (mpc_and_verify_sse(r0m, x0s, x1s, r2m, view, mx2, 0) ||
      mpc_and_verify_sse(r2m, x1s, x2m, r0s, view, mx2, 2) ||
      mpc_and_verify_sse(r1m, x0s, x2m, r1s, view, mx2, 1)) {
    return -1;
  }

  bitsliced_mm_step_2(SC_VERIFY, __m128i, _mm_and_si128, _mm_xor_si128, mm128_shift_right);

  return 0;
}
#endif

#ifdef WITH_AVX2
__attribute__((target("avx2"))) static void
_mpc_sbox_layer_bitsliced_avx(mzd_t** out, mzd_t* const* in, view_t const* view, mzd_t* const* rvec,
                              mask_t const* mask) {
  bitsliced_mm_step_1(SC_PROOF, __m256i, _mm256_and_si256, mm256_shift_left);

  mpc_and_avx(r0m, x0s, x1s, r2m, view, 0);
  mpc_and_avx(r2m, x1s, x2m, r0s, view, 2);
  mpc_and_avx(r1m, x0s, x2m, r1s, view, 1);

  bitsliced_mm_step_2(SC_PROOF, __m256i, _mm256_and_si256, _mm256_xor_si256, mm256_shift_right);
}

__attribute__((target("avx2"))) static int
_mpc_sbox_layer_bitsliced_avx_verify(mzd_t** out, mzd_t** in, view_t const* view,
                                     mzd_t* const* rvec, mask_t const* mask) {
  bitsliced_mm_step_1(SC_VERIFY, __m256i, _mm256_and_si256, mm256_shift_left);

  if (mpc_and_verify_avx(r0m, x0s, x1s, r2m, view, mx2, 0) ||
      mpc_and_verify_avx(r2m, x1s, x2m, r0s, view, mx2, 2) ||
      mpc_and_verify_avx(r1m, x0s, x2m, r1s, view, mx2, 1)) {
    return -1;
  }

  bitsliced_mm_step_2(SC_VERIFY, __m256i, _mm256_and_si256, _mm256_xor_si256, mm256_shift_right);

  return 0;
}
#endif
#endif

#if 0
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

static mzd_t** _mpc_lowmc_call(mpc_lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key, mzd_t* p,
                               view_t* views, mzd_t*** rvec, unsigned sc, unsigned ch,
                               BIT_and_ptr andBitPtr, int* status) {
  int vcnt = 0;

  for (unsigned i = 0; i < sc; i++)
    mzd_local_copy(views[vcnt].s[i], lowmc_key->shared[i]);
  vcnt++;

  mzd_t** c = mpc_init_empty_share_vector(lowmc->n, sc);

  mzd_t** x = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t** y = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t** z = mpc_init_empty_share_vector(lowmc->n, sc);

  mpc_const_mat_mul(x, lowmc->k0_matrix, lowmc_key->shared, sc);
  mpc_const_add(x, x, p, sc, ch);

  mzd_t* r[3];
  lowmc_round_t* round = lowmc->rounds;
  for (unsigned i = 0; i < lowmc->r; ++i, ++round) {
    for (unsigned j = 0; j < sc; j++) {
      r[j] = rvec[j][i];
    }
    if (_mpc_sbox_layer(y, x, lowmc->m, views, &vcnt, r, sc, andBitPtr)) {
      *status = -1;
      return 0;
    }
    mpc_const_mat_mul(z, round->l_matrix, y, sc);
    mpc_const_add(z, z, round->constant, sc, ch);
    mzd_t** t = mpc_init_empty_share_vector(lowmc->n, sc);
    mpc_const_mat_mul(t, round->k_matrix, lowmc_key->shared, sc);
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
#endif

static mzd_t** _mpc_lowmc_call_bitsliced(mpc_lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key,
                                         mzd_t const* p, bool xor_p, view_t* views, mzd_t*** rvec,
                                         unsigned ch) {
  mpc_copy(views->s, lowmc_key->shared, SC_PROOF);
  ++views;

  sbox_vars_t vars = {{NULL}};
  sbox_vars_init(&vars, lowmc->n, SC_PROOF);

  mzd_t** x = mpc_init_empty_share_vector(lowmc->n, SC_PROOF);
  mzd_t* y[SC_PROOF];
  mzd_local_init_multiple(y, SC_PROOF, 1, lowmc->n);

#ifdef NOSCR
  mpc_const_mat_mul_l(x, lowmc->k0_lookup, lowmc_key->shared, SC_PROOF);
#else
  mpc_const_mat_mul(x, lowmc->k0_matrix, lowmc_key->shared, SC_PROOF);
#endif
  mpc_const_add(x, x, p, SC_PROOF, ch);

  lowmc_round_t const* round = lowmc->rounds;
  for (unsigned i = 0; i < lowmc->r; ++i, ++views, ++round) {
    // TODO: fix for SC_PROOF != 3
    mzd_t* r[SC_PROOF] = {rvec[0][i], rvec[1][i], rvec[2][i]};

#ifdef WITH_OPT
#ifdef WITH_SSE2
    if (CPU_SUPPORTS_SSE2 && lowmc->n <= 128) {
      _mpc_sbox_layer_bitsliced_sse(y, x, views, r, &lowmc->mask);
    } else
#endif
#ifdef WITH_AVX2
    if (CPU_SUPPORTS_AVX2 && lowmc->n <= 256) {
      _mpc_sbox_layer_bitsliced_avx(y, x, views, r, &lowmc->mask);
    } else
#endif
#endif
    {
      _mpc_sbox_layer_bitsliced(y, x, views, r, &lowmc->mask, &vars);
    }

#ifdef NOSCR
    mpc_const_mat_mul_l(x, round->l_lookup, y, SC_PROOF);
#else
    mpc_const_mat_mul(x, round->l_matrix, y, SC_PROOF);
#endif
    mpc_const_add(x, x, round->constant, SC_PROOF, ch);
#ifdef NOSCR
    mpc_const_mat_mul_l(y, round->k_lookup, lowmc_key->shared, SC_PROOF);
#else
    mpc_const_mat_mul(y, round->k_matrix, lowmc_key->shared, SC_PROOF);
#endif
    mpc_add(x, x, y, SC_PROOF);
  }

  if (xor_p) {
    mpc_const_add(x, x, p, SC_PROOF, ch);
  }

  mpc_copy(views->s, x, SC_PROOF);
  sbox_vars_clear(&vars);

  mzd_local_free_multiple(y);
  return x;
}

static mzd_t** _mpc_lowmc_call_bitsliced_verify(mpc_lowmc_t const* lowmc,
                                                mpc_lowmc_key_t* lowmc_key, mzd_t const* p,
                                                bool xor_p, view_t const* views, mzd_t*** rvec,
                                                unsigned ch, int* status) {
  ++views;

  sbox_vars_t vars = {{NULL}};
  sbox_vars_init(&vars, lowmc->n, SC_VERIFY);

  mzd_t** x           = mpc_init_empty_share_vector(lowmc->n, SC_VERIFY);
  mzd_t* y[SC_VERIFY] = {NULL};
  mzd_local_init_multiple(y, SC_VERIFY, 1, lowmc->n);

#ifdef NOSCR
  mpc_const_mat_mul_l(x, lowmc->k0_lookup, lowmc_key->shared, SC_VERIFY);
#else
  mpc_const_mat_mul(x, lowmc->k0_matrix, lowmc_key->shared, SC_VERIFY);
#endif
  mpc_const_add(x, x, p, SC_VERIFY, ch);

  lowmc_round_t const* round = lowmc->rounds;
  for (unsigned i = 0; i < lowmc->r; ++i, ++views, ++round) {
    // TODO: fix for SC_VERIFY != 2
    mzd_t* r[SC_VERIFY] = {rvec[0][i], rvec[1][i]};

    int ret = 0;
#ifdef WITH_OPT
#ifdef WITH_SSE2
    if (CPU_SUPPORTS_SSE2 && lowmc->n <= 128) {
      ret = _mpc_sbox_layer_bitsliced_sse_verify(y, x, views, r, &lowmc->mask);
    } else
#endif
#ifdef WITH_AVX2
    if (CPU_SUPPORTS_AVX2 && lowmc->n <= 256) {
      ret = _mpc_sbox_layer_bitsliced_avx_verify(y, x, views, r, &lowmc->mask);
    } else
#endif
#endif
    {
      ret = _mpc_sbox_layer_bitsliced_verify(y, x, views, r, &lowmc->mask, &vars);
    }
    if (ret) {
      mpc_free(x, SC_VERIFY);
      x       = NULL;
      *status = -1;
      break;
    }

#ifdef NOSCR
    mpc_const_mat_mul_l(x, round->l_lookup, y, SC_VERIFY);
#else
    mpc_const_mat_mul(x, round->l_matrix, y, SC_VERIFY);
#endif
    mpc_const_add(x, x, round->constant, SC_VERIFY, ch);
#ifdef NOSCR
    mpc_const_mat_mul_l(y, round->k_lookup, lowmc_key->shared, SC_VERIFY);
#else
    mpc_const_mat_mul(y, round->k_matrix, lowmc_key->shared, SC_VERIFY);
#endif
    mpc_add(x, x, y, SC_VERIFY);
  }

  if (x && xor_p) {
    mpc_const_add(x, x, p, SC_VERIFY, ch);
  }

  sbox_vars_clear(&vars);
  mzd_local_free_multiple(y);
  return x;
}

mzd_t** mpc_lowmc_call(mpc_lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key, mzd_t const* p,
                       bool xor_p, view_t* views, mzd_t*** rvec) {
  return _mpc_lowmc_call_bitsliced(lowmc, lowmc_key, p, xor_p, views, rvec, 0);
}

int _mpc_lowmc_verify(mpc_lowmc_t const* lowmc, mpc_lowmc_key_t *lowmc_key, mzd_t const* p, 
                      bool xor_p, view_t const* views, mzd_t*** rvec, int c) {
  int status = 0;
  mzd_t** v =
      _mpc_lowmc_call_bitsliced_verify(lowmc, lowmc_key, p, xor_p, views, rvec, c, &status);
  if (v) {
    for (unsigned int i = 0; i < SC_VERIFY; ++i) {
      if (!mzd_local_equal(views[lowmc->r + 1].s[i], v[i])) {
        status = 1;
        break;
      }
    }
    mpc_free(v, SC_VERIFY);
  }
  mzd_shared_clear(lowmc_key);
  return status;
}

int mpc_lowmc_verify(mpc_lowmc_t const* lowmc, mzd_t const* p, bool xor_p, 
                     view_t const* views, mzd_t*** rvec, int c) {
  mpc_lowmc_key_t lowmc_key;
  mzd_shared_from_shares(&lowmc_key, views[0].s, SC_VERIFY);
  lowmc_key.share_count = 2;
  
  return _mpc_lowmc_verify(lowmc, &lowmc_key, p, xor_p, views, rvec, c);
}

int mpc_lowmc_verify_keys(mpc_lowmc_t const* lowmc, mzd_t const* p, bool xor_p, view_t const* views,
                     mzd_t*** rvec, int c, const unsigned char keys[2][16]) {
  mpc_lowmc_key_t lowmc_key;
  lowmc_key.share_count = 2;
  if(c == 0) {
    lowmc_key.shared[0] = mzd_init_random_vector_from_seed(keys[0], lowmc->n);
    lowmc_key.shared[1] = mzd_init_random_vector_from_seed(keys[1], lowmc->n);
  } else if(c == 1) {
    lowmc_key.shared[0] = mzd_init_random_vector_from_seed(keys[0], lowmc->n);
    lowmc_key.shared[1] = mzd_local_copy(NULL, views[0].s[1]);
  } else {
    lowmc_key.shared[0] = mzd_local_copy(NULL, views[0].s[0]);
    lowmc_key.shared[1] = mzd_init_random_vector_from_seed(keys[1], lowmc->n);
  }

  return _mpc_lowmc_verify(lowmc, &lowmc_key, p, xor_p, views, rvec, c);
}

void sbox_vars_clear(sbox_vars_t* vars) {
  if (vars->storage) {
    mzd_local_free_multiple(vars->storage);
    free(vars->storage);
    memset(vars, 0, sizeof(*vars));
  }
}

sbox_vars_t* sbox_vars_init(sbox_vars_t* vars, rci_t n, unsigned sc) {
#ifdef WITH_OPT
#ifdef WITH_AVX2
  if (CPU_SUPPORTS_AVX2 && n <= 256) {
    vars->storage = NULL;
    return vars;
  }
#endif
#ifdef WITH_SSE2
  if (CPU_SUPPORTS_SSE2 && n <= 128) {
    vars->storage = NULL;
    return vars;
  }
#endif
#endif

  vars->storage = calloc(11 * sc, sizeof(mzd_t*));
  mzd_local_init_multiple(vars->storage, 11 * sc, 1, n);

  for (unsigned int i = 0; i < sc; ++i) {
    vars->x0m[i] = vars->storage[11 * i + 0];
    vars->x1m[i] = vars->storage[11 * i + 1];
    vars->x2m[i] = vars->storage[11 * i + 2];
    vars->r0m[i] = vars->storage[11 * i + 3];
    vars->r1m[i] = vars->storage[11 * i + 4];
    vars->r2m[i] = vars->storage[11 * i + 5];
    vars->x0s[i] = vars->storage[11 * i + 6];
    vars->x1s[i] = vars->storage[11 * i + 7];
    vars->r0s[i] = vars->storage[11 * i + 8];
    vars->r1s[i] = vars->storage[11 * i + 9];
    vars->v[i]   = vars->storage[11 * i + 10];
  }

  return vars;
}

void clear_proof(mpc_lowmc_t const* lowmc, proof_t const* proof) {
  for (unsigned int i = 0; i < NUM_ROUNDS; ++i) {
    for (unsigned int j = 0; j < 2 + lowmc->r; ++j) {
      for (unsigned int k = 0; k < SC_VERIFY; ++k) {
        mzd_local_free(proof->views[i][j].s[k]);
      }
      free(proof->views[i][j].s);
    }
    free(proof->views[i]);
  }
  free(proof->views);
}

void free_proof(mpc_lowmc_t const* mpc_lowmc, proof_t* proof) {
  clear_proof(mpc_lowmc, proof);
  free(proof);
}
