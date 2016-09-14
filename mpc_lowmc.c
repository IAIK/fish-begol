#include "mpc_lowmc.h"
#include "io.h"
#include "lowmc_pars.h"
#include "mpc.h"
#include "mzd_additional.h"

#include <stdbool.h>

#ifdef WITH_OPT
#include "avx.h"
#endif

typedef struct {
  mzd_t** x0m;
  mzd_t** x1m;
  mzd_t** x2m;
  mzd_t** r0m;
  mzd_t** r1m;
  mzd_t** r2m;
  mzd_t** x0s;
  mzd_t** r0s;
  mzd_t** x1s;
  mzd_t** r1s;
  mzd_t** v;
} sbox_vars_t;

static sbox_vars_t* sbox_vars_init(sbox_vars_t* vars, rci_t n, unsigned sc);
static void sbox_vars_clear(sbox_vars_t* vars, unsigned int sc);

typedef int (*BIT_and_ptr)(BIT*, BIT*, BIT*, view_t*, int*, unsigned, unsigned);
typedef int (*and_ptr)(mzd_t**, mzd_t**, mzd_t**, mzd_t**, view_t*, mzd_t*, unsigned, mzd_t**);

unsigned char* proof_to_char_array(mpc_lowmc_t* lowmc, proof_t* proof, unsigned* len,
                                   bool store_ch) {
  unsigned first_view_bytes = lowmc->k / 8;
  unsigned full_mzd_size    = lowmc->n / 8;
  unsigned single_mzd_bytes = ((3 * lowmc->m) + 7) / 8;
  unsigned mzd_bytes =
      2 * (lowmc->r * single_mzd_bytes + first_view_bytes + full_mzd_size) + 3 * full_mzd_size;
  *len = NUM_ROUNDS * (COMMITMENT_LENGTH + 40 + mzd_bytes) +
         (store_ch ? ((NUM_ROUNDS + 3) / 4) : 0);
  unsigned char* result = (unsigned char*)malloc(*len * sizeof(unsigned char));

  unsigned char* temp = result;
  memcpy(temp, proof->hashes, NUM_ROUNDS * COMMITMENT_LENGTH * sizeof(unsigned char));
  temp += NUM_ROUNDS * COMMITMENT_LENGTH;

  for (unsigned i = 0; i < NUM_ROUNDS; i++) {
    memcpy(temp, proof->r[i][0], 4 * sizeof(unsigned char));
    temp += 4;
    memcpy(temp, proof->r[i][1], 4 * sizeof(unsigned char));
    temp += 4;

    memcpy(temp, proof->keys[i][0], 16 * sizeof(unsigned char));
    temp += 16;
    memcpy(temp, proof->keys[i][1], 16 * sizeof(unsigned char));
    temp += 16;

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

    unsigned char* c0 = mzd_to_char_array(proof->y[i][0], full_mzd_size);
    memcpy(temp, c0, full_mzd_size);
    temp += full_mzd_size;
    free(c0);

    unsigned char* c1 = mzd_to_char_array(proof->y[i][1], full_mzd_size);
    memcpy(temp, c1, full_mzd_size);
    temp += full_mzd_size;
    free(c1);

    unsigned char* c2 = mzd_to_char_array(proof->y[i][2], full_mzd_size);
    memcpy(temp, c2, full_mzd_size);
    temp += full_mzd_size;
    free(c2);
  }

  if (store_ch)
    memcpy(temp, proof->ch, (NUM_ROUNDS + 3) / 4);

  return result;
}

proof_t* proof_from_char_array(mpc_lowmc_t* lowmc, proof_t* proof, unsigned char* data,
                               unsigned* len, bool contains_ch) {
  if (!proof)
    proof = (proof_t*)malloc(sizeof(proof_t));

  unsigned first_view_bytes = lowmc->k / 8;
  unsigned full_mzd_size    = lowmc->n / 8;
  unsigned single_mzd_bytes = ((3 * lowmc->m) + 7) / 8;
  unsigned mzd_bytes =
      2 * (lowmc->r * single_mzd_bytes + first_view_bytes + full_mzd_size) + 3 * full_mzd_size;
  *len = NUM_ROUNDS * (COMMITMENT_LENGTH + 40 + mzd_bytes) +
         (contains_ch ? ((NUM_ROUNDS + 3) / 4) : 0);

  unsigned char* temp = data;

  proof->views = (view_t**)malloc(NUM_ROUNDS * sizeof(view_t*));

  proof->r    = (unsigned char***)malloc(NUM_ROUNDS * sizeof(unsigned char**));
  proof->keys = (unsigned char***)malloc(NUM_ROUNDS * sizeof(unsigned char**));
  memcpy(proof->hashes, temp, NUM_ROUNDS * COMMITMENT_LENGTH * sizeof(unsigned char));
  temp += NUM_ROUNDS * COMMITMENT_LENGTH;

  proof->y = (mzd_t***)malloc(NUM_ROUNDS * sizeof(mzd_t**));

#pragma omp parallel for
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    proof->r[i]    = (unsigned char**)malloc(2 * sizeof(unsigned char*));
    proof->r[i][0] = (unsigned char*)malloc(4 * sizeof(unsigned char));
    proof->r[i][1] = (unsigned char*)malloc(4 * sizeof(unsigned char));
    memcpy(proof->r[i][0], temp, 4 * sizeof(unsigned char));
    temp += 4;
    memcpy(proof->r[i][1], temp, 4 * sizeof(unsigned char));
    temp += 4;

    proof->keys[i]    = (unsigned char**)malloc(2 * sizeof(unsigned char*));
    proof->keys[i][0] = (unsigned char*)malloc(16 * sizeof(unsigned char));
    proof->keys[i][1] = (unsigned char*)malloc(16 * sizeof(unsigned char));
    memcpy(proof->keys[i][0], temp, 16 * sizeof(char));
    temp += 16;
    memcpy(proof->keys[i][1], temp, 16 * sizeof(char));
    temp += 16;

    proof->views[i]         = (view_t*)malloc((2 + lowmc->r) * sizeof(view_t));
    proof->views[i][0].s    = (mzd_t**)malloc(2 * sizeof(mzd_t*));
    proof->views[i][0].s[0] = mzd_from_char_array(temp, first_view_bytes, lowmc->k);
    temp += first_view_bytes;
    proof->views[i][0].s[1] = mzd_from_char_array(temp, first_view_bytes, lowmc->k);
    temp += first_view_bytes;
    for (unsigned j = 1; j < 1 + lowmc->r; j++) {
      proof->views[i][j].s    = (mzd_t**)malloc(2 * sizeof(mzd_t*));
      proof->views[i][j].s[0] = mzd_from_char_array(temp, single_mzd_bytes, lowmc->n);
      temp += single_mzd_bytes;
      proof->views[i][j].s[1] = mzd_from_char_array(temp, single_mzd_bytes, lowmc->n);
      temp += single_mzd_bytes;
    }
    proof->views[i][1 + lowmc->r].s    = (mzd_t**)malloc(2 * sizeof(mzd_t*));
    proof->views[i][1 + lowmc->r].s[0] = mzd_from_char_array(temp, full_mzd_size, lowmc->n);
    temp += full_mzd_size;
    proof->views[i][1 + lowmc->r].s[1] = mzd_from_char_array(temp, full_mzd_size, lowmc->n);
    temp += full_mzd_size;

    proof->y[i]    = (mzd_t**)malloc(3 * sizeof(mzd_t*));
    proof->y[i][0] = mzd_from_char_array(temp, full_mzd_size, lowmc->n);
    temp += full_mzd_size;
    proof->y[i][1] = mzd_from_char_array(temp, full_mzd_size, lowmc->n);
    temp += full_mzd_size;
    proof->y[i][2] = mzd_from_char_array(temp, full_mzd_size, lowmc->n);
    temp += full_mzd_size;
  }

  if (contains_ch)
    memcpy(proof->ch, temp, (NUM_ROUNDS + 3) / 4);

  return proof;
}

proof_t* create_proof(proof_t* proof, mpc_lowmc_t* lowmc,
                      unsigned char hashes[NUM_ROUNDS][3][COMMITMENT_LENGTH], unsigned char ch[NUM_ROUNDS],
                      unsigned char r[NUM_ROUNDS][3][4], unsigned char keys[NUM_ROUNDS][3][16],
                      mzd_t*** c_mpc, view_t* views[NUM_ROUNDS]) {
  if (!proof)
    proof = (proof_t*)malloc(sizeof(proof_t));

  proof->views = (view_t**)malloc(NUM_ROUNDS * sizeof(view_t*));

  proof->r    = (unsigned char***)malloc(NUM_ROUNDS * sizeof(unsigned char**));
  proof->keys = (unsigned char***)malloc(NUM_ROUNDS * sizeof(unsigned char**));
// memcpy(proof->hashes, hashes, NUM_ROUNDS * 3 * SHA256_DIGEST_LENGTH * sizeof(char));

#pragma omp parallel for
  for (unsigned int i = 0; i < NUM_ROUNDS; i++) {
    unsigned int a = ch[i];
    unsigned int b = (a + 1) % 3;
    unsigned int c = (a + 2) % 3;

    memcpy(proof->hashes[i], hashes[i][c], COMMITMENT_LENGTH * sizeof(char));

    proof->r[i]    = (unsigned char**)malloc(2 * sizeof(unsigned char*));
    proof->r[i][0] = (unsigned char*)malloc(4 * sizeof(unsigned char));
    proof->r[i][1] = (unsigned char*)malloc(4 * sizeof(unsigned char));
    memcpy(proof->r[i][0], r[i][a], 4 * sizeof(char));
    memcpy(proof->r[i][1], r[i][b], 4 * sizeof(char));

    proof->keys[i]    = (unsigned char**)malloc(2 * sizeof(unsigned char*));
    proof->keys[i][0] = (unsigned char*)malloc(16 * sizeof(unsigned char));
    proof->keys[i][1] = (unsigned char*)malloc(16 * sizeof(unsigned char));
    memcpy(proof->keys[i][0], keys[i][a], 16 * sizeof(char));
    memcpy(proof->keys[i][1], keys[i][b], 16 * sizeof(char));

    proof->views[i] = (view_t*)malloc((2 + lowmc->r) * sizeof(view_t));
    for (unsigned j = 0; j < 2 + lowmc->r; j++) {
      proof->views[i][j].s    = (mzd_t**)malloc(2 * sizeof(mzd_t*));
      proof->views[i][j].s[0] = views[i][j].s[a];
      proof->views[i][j].s[1] = views[i][j].s[b];
      mzd_free(views[i][j].s[c]);
    }

    if ((i % 4) == 0) {
      int idx        = i / 4;
      proof->ch[idx] = 0;
      proof->ch[idx] |= (ch[i] & 3);
      proof->ch[idx] |= (ch[i + 1] & 3) << 2;
      proof->ch[idx] |= (ch[i + 2] & 3) << 4;
      proof->ch[idx] |= (ch[i + 3] & 3) << 6;
    }
  }
  proof->y = c_mpc;

  return proof;
}

static int _mpc_sbox_layer_bitsliced(mzd_t** out, mzd_t** in, rci_t m, view_t* view, mzd_t** rvec,
                                     unsigned sc, and_ptr andPtr, mask_t const* mask, sbox_vars_t const* vars) {
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

  if (andPtr(vars->r0m, vars->x0s, vars->x1s, vars->r2m, view, mask->x2, 0, vars->v) ||
      andPtr(vars->r2m, vars->x1s, vars->x2m, vars->r0s, view, mask->x2, 2, vars->v) ||
      andPtr(vars->r1m, vars->x0s, vars->x2m, vars->r1s, view, mask->x2, 1, vars->v)) {
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

#ifdef WITH_OPT
__attribute__((target("sse2"))) static int
_mpc_sbox_layer_bitsliced_sse(mzd_t** out, mzd_t** in, rci_t m, view_t* view, mzd_t** rvec,
                              unsigned sc, and_ptr andPtr, mask_t const* mask, sbox_vars_t const* vars) {
  __m128i mx0 = _mm_load_si128((__m128i*)mask->x0->rows[0]);
  __m128i mx1 = _mm_load_si128((__m128i*)mask->x1->rows[0]);
  __m128i mx2 = _mm_load_si128((__m128i*)mask->x2->rows[0]);

  for (unsigned int m = 0; m < sc; ++m) {
    __m128i min = _mm_load_si128((__m128i*)in[m]->rows[0]);

    __m128i x0m = _mm_and_si128(min, mx0);
    __m128i x1m = _mm_and_si128(min, mx1);
    __m128i x2m = _mm_and_si128(min, mx2);

    __m128i x0s = mm128_shift_left(x0m, 2);
    __m128i x1s = mm128_shift_left(x1m, 1);

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

    x0s = mm128_shift_left(x0m, 2);
    x1s = mm128_shift_left(x1m, 1);

    _mm_store_si128((__m128i*)vars->r0s[m]->rows[0], x0s);
    _mm_store_si128((__m128i*)vars->r1s[m]->rows[0], x1s);
  }

  if (andPtr(vars->r0m, vars->x0s, vars->x1s, vars->r2m, view, mask->x2, 0, vars->v) ||
      andPtr(vars->r2m, vars->x1s, vars->x2m, vars->r0s, view, mask->x2, 2, vars->v) ||
      andPtr(vars->r1m, vars->x0s, vars->x2m, vars->r1s, view, mask->x2, 1, vars->v)) {
    return -1;
  }

  __m128i mmask = _mm_load_si128((__m128i*)mask->mask->rows[0]);
  for (unsigned int m = 0; m < sc; ++m) {
    __m128i x0s = _mm_load_si128((__m128i*)vars->x0s[m]->rows[0]);
    __m128i r2m = _mm_load_si128((__m128i*)vars->r2m[m]->rows[0]);
    r2m         = _mm_xor_si128(r2m, x0s);

    __m128i x1s = _mm_load_si128((__m128i*)vars->x1s[m]->rows[0]);
    x0s         = _mm_xor_si128(x0s, x1s);
    __m128i r1m = _mm_xor_si128(x0s, _mm_load_si128((__m128i*)vars->r1m[m]->rows[0]));

    __m128i mout = _mm_and_si128(mmask, _mm_load_si128((__m128i*)in[m]->rows[0]));

    __m128i r0m = _mm_xor_si128(x0s, _mm_load_si128((__m128i*)vars->r0m[m]->rows[0]));
    r0m         = _mm_xor_si128(r0m, _mm_load_si128((__m128i*)vars->x2m[m]->rows[0]));
    mout        = _mm_xor_si128(mout, r0m);

    x0s  = mm128_shift_right(r2m, 2);
    mout = _mm_xor_si128(mout, x0s);

    x1s  = mm128_shift_right(r1m, 1);
    mout = _mm_xor_si128(mout, x1s);

    _mm_store_si128((__m128i*)out[m]->rows[0], mout);
  }

  return 0;
}

__attribute__((target("avx2"))) static int
_mpc_sbox_layer_bitsliced_avx(mzd_t** out, mzd_t** in, rci_t m, view_t* view, mzd_t** rvec,
                              unsigned sc, and_ptr andPtr, mask_t const* mask, sbox_vars_t const* vars) {
  __m256i mx0 = _mm256_load_si256((__m256i*)mask->x0->rows[0]);
  __m256i mx1 = _mm256_load_si256((__m256i*)mask->x1->rows[0]);
  __m256i mx2 = _mm256_load_si256((__m256i*)mask->x2->rows[0]);

  for (unsigned int m = 0; m < sc; ++m) {
    __m256i min = _mm256_load_si256((__m256i*)in[m]->rows[0]);

    __m256i x0m = _mm256_and_si256(min, mx0);
    __m256i x1m = _mm256_and_si256(min, mx1);
    __m256i x2m = _mm256_and_si256(min, mx2);

    __m256i x0s = mm256_shift_left(x0m, 2);
    __m256i x1s = mm256_shift_left(x1m, 1);

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

    x0s = mm256_shift_left(x0m, 2);
    x1s = mm256_shift_left(x1m, 1);

    _mm256_store_si256((__m256i*)vars->r0s[m]->rows[0], x0s);
    _mm256_store_si256((__m256i*)vars->r1s[m]->rows[0], x1s);
  }

  if (andPtr(vars->r0m, vars->x0s, vars->x1s, vars->r2m, view, mask->x2, 0, vars->v) ||
      andPtr(vars->r2m, vars->x1s, vars->x2m, vars->r0s, view, mask->x2, 2, vars->v) ||
      andPtr(vars->r1m, vars->x0s, vars->x2m, vars->r1s, view, mask->x2, 1, vars->v)) {
    return -1;
  }

  __m256i mmask = _mm256_load_si256((__m256i*)mask->mask->rows[0]);
  for (unsigned int m = 0; m < sc; ++m) {
    __m256i x0s = _mm256_load_si256((__m256i*)vars->x0s[m]->rows[0]);
    __m256i r2m = _mm256_load_si256((__m256i*)vars->r2m[m]->rows[0]);
    r2m         = _mm256_xor_si256(r2m, x0s);

    __m256i x1s = _mm256_load_si256((__m256i*)vars->x1s[m]->rows[0]);
    x0s         = _mm256_xor_si256(x0s, x1s);
    __m256i r1m = _mm256_xor_si256(x0s, _mm256_load_si256((__m256i*)vars->r1m[m]->rows[0]));

    __m256i mout = _mm256_and_si256(mmask, _mm256_load_si256((__m256i*)in[m]->rows[0]));

    __m256i r0m = _mm256_xor_si256(x0s, _mm256_load_si256((__m256i*)vars->r0m[m]->rows[0]));
    r0m         = _mm256_xor_si256(r0m, _mm256_load_si256((__m256i*)vars->x2m[m]->rows[0]));
    mout        = _mm256_xor_si256(mout, r0m);

    x0s  = mm256_shift_right(r2m, 2);
    mout = _mm256_xor_si256(mout, x0s);

    x1s  = mm256_shift_right(r1m, 1);
    mout = _mm256_xor_si256(mout, x1s);

    _mm256_store_si256((__m256i*)out[m]->rows[0], mout);
  }

  return 0;
}
#endif

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
    mzd_copy(views[vcnt].s[i], lowmc_key->shared[i]);
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


static mzd_t** _mpc_lowmc_call_bitsliced(mpc_lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key, mzd_t* p, mzd_t** shared_p,
                                         view_t* views, mzd_t*** rvec, unsigned sc, unsigned ch,
                                         and_ptr andPtr, int* status, bool update_view) {
  if (update_view) {
    mpc_copy(views->s, lowmc_key->shared, sc);
  }
  ++views;

  sbox_vars_t vars;
  sbox_vars_init(&vars, lowmc->n, 2);
  mzd_t** x = mpc_init_empty_share_vector(lowmc->n, sc);
  mzd_t** y = mpc_init_empty_share_vector(lowmc->n, sc);

  mpc_const_mat_mul(x, lowmc->k0_matrix, lowmc_key->shared, sc);
  if (p) {
    mpc_const_add(x, x, p, sc, ch);
  } else {
    mpc_copy(y, shared_p, sc);
    mpc_add(x, x, y, sc);
  }

  lowmc_round_t* round = lowmc->rounds;
  mzd_t* r[3];
  for (unsigned i = 0; i < lowmc->r; ++i, ++views, ++round) {
    for (unsigned j = 0; j < sc; j++) {
      r[j] = rvec[j][i];
    }

    int ret = 0;
#ifdef WITH_OPT
    if (CPU_SUPPORTS_SSE2 && lowmc->n == 128) {
      ret = _mpc_sbox_layer_bitsliced_sse(y, x, lowmc->m, views, r, sc, andPtr, &lowmc->mask,
                                          vars);
    } else if (CPU_SUPPORTS_AVX2 && lowmc->n == 256) {
      ret = _mpc_sbox_layer_bitsliced_avx(y, x, lowmc->m, views, r, sc, andPtr, &lowmc->mask,
                                          vars);
    } else {
      ret = _mpc_sbox_layer_bitsliced(y, x, lowmc->m, views, r, sc, andPtr, &lowmc->mask,
                                      vars);
    }
#else
    ret =
        _mpc_sbox_layer_bitsliced(y, x, lowmc->m, views, r, sc, andPtr, &lowmc->mask, vars);
#endif
    if (ret) {
      *status = -1;
      return 0;
    }

    mpc_const_mat_mul(x, round->l_matrix, y, sc);
    mpc_const_add(x, x, round->constant, sc, ch);
    mpc_const_mat_mul(y, round->k_matrix, lowmc_key->shared, sc);
    mpc_add(x, x, y, sc);
  }

  if (update_view) {
    mpc_copy(views->s, x, sc);
  }

  sbox_vars_clear(&vars, 2);
  mpc_free(y, 2);
  return x;
}

static inline and_ptr select_and(mpc_lowmc_t const* lowmc) {
#ifdef WITH_OPT
  if (CPU_SUPPORTS_SSE2 && lowmc->n == 128) {
    return &mpc_and_sse;
  } else if (CPU_SUPPORTS_AVX2 && lowmc->n == 256) {
    return &mpc_and_avx;
  }
#else
  (void)lowmc;
#endif

  return &mpc_and;
}

static inline and_ptr select_and_verify(mpc_lowmc_t const* lowmc) {
#ifdef WITH_OPT
  if (CPU_SUPPORTS_SSE2 && lowmc->n == 128) {
    return &mpc_and_verify_sse;
  } else if (CPU_SUPPORTS_AVX2 && lowmc->n == 256) {
    return &mpc_and_verify_avx;
  }
#else
  (void)lowmc;
#endif

  return &mpc_and_verify;
}

mzd_t** mpc_lowmc_call(mpc_lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key, mzd_t* p, view_t* views,
                       mzd_t*** rvec) {
  // return _mpc_lowmc_call(lowmc, lowmc_key, p, views, rvec, 3, 0,
  // &mpc_and_bit, 0);
  return _mpc_lowmc_call_bitsliced(lowmc, lowmc_key, p, NULL, views, rvec, 3, 0, select_and(lowmc), 0,
                                   true);
}

mzd_t** mpc_lowmc_call_shared_p(mpc_lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key, mzd_shared_t* p,
                                view_t* views, mzd_t*** rvec) {
  // return _mpc_lowmc_call(lowmc, lowmc_key, p, views, rvec, 3, 0,
  // &mpc_and_bit, 0);
  return _mpc_lowmc_call_bitsliced(lowmc, lowmc_key, NULL, p->shared, views, rvec, 3, 0,
                                            select_and(lowmc), 0, true);
}

static mzd_t** _mpc_lowmc_call_verify(mpc_lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key, mzd_t* p,
                               view_t* views, mzd_t*** rvec, int* status, int c) {
  return _mpc_lowmc_call_bitsliced(lowmc, lowmc_key, p, NULL, views, rvec, 2, c, select_and_verify(lowmc),
                                   status, false);
}

static mzd_t** _mpc_lowmc_call_verify_shared_p(mpc_lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key,
                                        mzd_shared_t* p, view_t* views, mzd_t*** rvec, int* status,
                                        int c) {
  return _mpc_lowmc_call_bitsliced(lowmc, lowmc_key, NULL, p->shared, views, rvec, 2, c,
                                            select_and_verify(lowmc), status, false);
}

#define mpc_lowmc_verify_template(f)                                                               \
  mpc_lowmc_key_t lowmc_key;                                                                       \
  mzd_shared_from_shares(&lowmc_key, views[0].s, 2);                                               \
                                                                                                   \
  int status = 0;                                                                                  \
  mzd_t** v  = (f)(lowmc, &lowmc_key, p, views, rvec, &status, c);                                 \
  if (v) {                                                                                         \
    if (mzd_equal(views[lowmc->r + 1].s[0], v[0]) || mzd_equal(views[lowmc->r + 1].s[1], v[1])) {  \
      status = 1;                                                                                  \
    }                                                                                              \
    mpc_free(v, 2);                                                                                \
  }                                                                                                \
  mzd_shared_clear(&lowmc_key);                                                                    \
                                                                                                   \
  return status

int mpc_lowmc_verify(mpc_lowmc_t const* lowmc, mzd_t* p, view_t* views, mzd_t*** rvec, int c) {
  mpc_lowmc_verify_template(_mpc_lowmc_call_verify);
}

int mpc_lowmc_verify_shared_p(mpc_lowmc_t const* lowmc, mzd_shared_t* p, view_t* views, mzd_t*** rvec,
                              int c) {
  mpc_lowmc_verify_template(_mpc_lowmc_call_verify_shared_p);
}

void sbox_vars_clear(sbox_vars_t* vars, unsigned int sc) {
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
}

sbox_vars_t* sbox_vars_init(sbox_vars_t* vars, rci_t n, unsigned sc) {
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

void clear_proof(mpc_lowmc_t* lowmc, proof_t* proof) {
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

void free_proof(mpc_lowmc_t* mpc_lowmc, proof_t* proof) {
  clear_proof(mpc_lowmc, proof);
  free(proof);
}
