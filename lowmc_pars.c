#include "lowmc_pars.h"
#include "mpc.h"
#include "mzd_additional.h"
#include "randomness.h"

#include <m4ri/m4ri.h>
#include <stdbool.h>

mask_t* prepare_masks(mask_t* mask, rci_t n, rci_t m) {
  if (0 != n % (8 * sizeof(word)))
    return 0;
  if (mask == 0)
    mask = (mask_t*)malloc(sizeof(mask_t));

  mask->x0   = mzd_init(1, n);
  mask->x1   = mzd_init(1, n);
  mask->x2   = mzd_init(1, n);
  mask->mask = mzd_init(1, n);

  for (int i = 0; i < n - 3 * m; i++) {
    mzd_write_bit(mask->mask, 0, i, 1);
  }
  for (int i = n - 3 * m; i < n; i += 3) {
    mzd_write_bit(mask->x0, 0, i, 1);
  }
  mzd_shift_left(mask->x1, mask->x0, 1);
  mzd_shift_left(mask->x2, mask->x0, 2);

  return mask;
}

static mzd_t* mzd_sample_matrix_word(rci_t n, rci_t k, rci_t rank, bool with_xor) {
  mzd_t* A = mzd_init(n, k);
  mzd_t* B = mzd_init(n, k);
  do {
    mzd_randomize_ssl(A);
    if (with_xor) {
      for (rci_t i = 0; i < n; i++) {
        mzd_xor_bits(A, n - i - 1, (k + i + 1) % k, 1, 1);
      }
    }
    mzd_copy(B, A);
  } while (mzd_echelonize(A, 0) != rank);
  mzd_free(A);
  return B;
};

mzd_t* mzd_sample_lmatrix(rci_t n) {
  return mzd_sample_matrix_word(n, n, n, false);
}

mzd_t* mzd_sample_kmatrix(rci_t n, rci_t k) {
  return mzd_sample_matrix_word(n, k, MIN(n, k), true);
}

lowmc_t* lowmc_init(size_t m, size_t n, size_t r, size_t k) {
  lowmc_t* lowmc = calloc(sizeof(lowmc_t), 1);
  lowmc->m       = m;
  lowmc->n       = n;
  lowmc->r       = r;
  lowmc->k       = k;

  lowmc->LMatrix = calloc(sizeof(mzd_t*), r);
  for (unsigned i = 0; i < r; i++) {
    // We do not need to transpose here, since it is an nxn matrix.
    lowmc->LMatrix[i] = mzd_sample_lmatrix(n);
  }

  lowmc->Constants = calloc(sizeof(mzd_t*), r);
  for (unsigned i = 0; i < r; i++) {
    lowmc->Constants[i] = mzd_init_random_vector(n);
  }
  lowmc->KMatrix = calloc(sizeof(mzd_t*), r + 1);
  for (unsigned i = 0; i < r + 1; i++) {
    // Instead of transposing switch dimesnsions.
    lowmc->KMatrix[i] = mzd_sample_kmatrix(n, k);
  }

  prepare_masks(&lowmc->mask, n, m);

  return lowmc;
}

lowmc_key_t* lowmc_keygen(lowmc_t* lowmc) {
  lowmc_key_t* lowmc_key = malloc(sizeof(lowmc_key_t));

  mzd_t* key = mzd_init_random_vector(lowmc->k);
  mzd_shared_init(lowmc_key, key);
  mzd_free(key);

  return lowmc_key;
}

void lowmc_free(lowmc_t* lowmc) {
  for (unsigned i = 0; i < lowmc->r; i++) {
    mzd_free(lowmc->Constants[i]);
    mzd_free(lowmc->KMatrix[i]);
    mzd_free(lowmc->LMatrix[i]);
  }
  mzd_free(lowmc->KMatrix[lowmc->r]);
  free(lowmc->Constants);
  free(lowmc->LMatrix);
  free(lowmc->KMatrix);

  mzd_free(lowmc->mask.x0);
  mzd_free(lowmc->mask.x1);
  mzd_free(lowmc->mask.x2);
  mzd_free(lowmc->mask.mask);

  free(lowmc);
}

void lowmc_key_free(lowmc_key_t* lowmc_key) {
  mzd_shared_clear(lowmc_key);
  free(lowmc_key);
}

void lowmc_secret_share(lowmc_t* lowmc, lowmc_key_t* lowmc_key) {
  mzd_shared_share(lowmc_key);
}
